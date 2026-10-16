"""Async client for the PAN-OS XML API."""

from __future__ import annotations

import asyncio
import logging
import time
import xml.etree.ElementTree as ET
from collections.abc import Callable
from typing import Any

import aiohttp

_LOGGER = logging.getLogger(__name__)

DEFAULT_TIMEOUT = 30
LOG_POLL_SECONDS = 1
LARGE_RESPONSE = 200_000
LOG_FINISH_TIMEOUT = 10
FORBIDDEN_TTL = 6 * 3600


class PanOSError(Exception):
    """Base error."""


class PanOSConnectionError(PanOSError):
    """Firewall could not be reached."""


class PanOSAuthError(PanOSError):
    """Credentials or API key rejected."""


class PanOSApiError(PanOSError):
    """The API returned an error response."""

    def __init__(self, message: str, code: str | None = None) -> None:
        super().__init__(message)
        self.code = code


def parse_response(text: str) -> ET.Element:
    """Parse an API response and return its <result> element."""
    try:
        root = ET.fromstring(text)
    except ET.ParseError as err:
        raise PanOSApiError(f"Invalid XML from firewall: {err}") from err
    status = root.get("status")
    if status != "success":
        code = root.get("code")
        message = " ".join(t.strip() for t in root.itertext() if t.strip()) or "unknown error"
        lowered = message.lower()
        if "not authorized for user role" in lowered:
            # The key is fine; the admin role doesn't allow this request type
            # (e.g. "Type [log] not authorized for user role."). No keygen needed.
            raise PanOSApiError(f"Not permitted for this admin role: {message}", "403")
        if code == "403" or "invalid credential" in lowered or "invalid key" in lowered:
            raise PanOSAuthError(message)
        raise PanOSApiError(message, code)
    result = root.find("result")
    return result if result is not None else root


class PanOSClient:
    """Talks to a single firewall (one HA unit)."""

    def __init__(
        self,
        session: aiohttp.ClientSession,
        host: str,
        username: str,
        password: str,
        api_key: str | None = None,
        on_new_key: Callable[[str], None] | None = None,
    ) -> None:
        self._session = session
        self.host = host.strip().rstrip("/")
        if self.host.startswith(("http://", "https://")):
            self.host = self.host.split("://", 1)[1]
        self._url = f"https://{self.host}/api/"
        self._username = username
        self._password = password
        self.api_key = api_key
        # Small boxes (PA-4xx) have weak management planes; don't hammer them.
        self._sem = asyncio.Semaphore(2)
        self._key_lock = asyncio.Lock()
        # Request kinds the admin role was shown not to allow -> when; retried
        # with a fresh key once the verdict is old.
        self._forbidden: dict[str, float] = {}
        # Called with each newly generated key so it can be stored and reused
        # on the next start (keygen is slow on small firewalls).
        self._on_new_key = on_new_key
        self._inflight: set[asyncio.Task[Any]] = set()
        self._closed = False

    def close(self) -> None:
        """Refuse new requests and cancel those in flight."""
        self._closed = True
        for task in list(self._inflight):
            task.cancel()

    async def generate_key(self, stale_key: str | None = None) -> str:
        """Get a new API key; concurrent callers share one keygen.

        ``stale_key`` is the key the caller saw rejected (or None when there
        was no key). If another task already replaced it, that key is reused.
        """
        async with self._key_lock:
            if self.api_key and self.api_key != stale_key:
                return self.api_key
            result = await self._post(
                {"type": "keygen", "user": self._username, "password": self._password},
                with_key=False,
            )
            key = result.findtext("key")
            if not key:
                raise PanOSAuthError("Firewall returned no API key")
            self.api_key = key.strip()
            if self._on_new_key:
                self._on_new_key(self.api_key)
            return self.api_key

    async def op(self, cmd: str, timeout: int = DEFAULT_TIMEOUT, vsys: str | None = None) -> ET.Element:
        """Run an operational command and return its <result> element.

        ``vsys`` sets the target vsys for this request only (multi-vsys).
        """
        data = {"type": "op", "cmd": cmd}
        if vsys:
            data["vsys"] = vsys
        return await self._request(data, cmd, timeout)

    async def log_query(
        self, log_type: str, query: str, nlogs: int = 100, timeout: int = DEFAULT_TIMEOUT
    ) -> list[ET.Element]:
        """Run a log query (newest first) and return its <entry> elements.

        Log queries are asynchronous on the firewall: the first request
        enqueues a job, which is then fetched until it finishes. ``timeout``
        bounds the whole operation; a job that doesn't finish (or a query
        that's cancelled) is stopped on the firewall rather than abandoned.
        """
        key = f"log:{log_type}"
        job: str | None = None
        try:
            async with asyncio.timeout(timeout):
                started = await self._request(
                    {"type": "log", "log-type": log_type, "query": query, "nlogs": str(nlogs)}, key, timeout
                )
                job = (started.findtext("job") or "").strip() or None
                if job is None:
                    raise PanOSApiError(f"Log query on {self.host} returned no job")
                while True:
                    result = await self._request(
                        {"type": "log", "action": "get", "job-id": job}, key, timeout
                    )
                    if (result.findtext("job/status") or "").strip() == "FIN":
                        job = None  # finished: nothing to clean up
                        return result.findall("log/logs/entry")
                    await asyncio.sleep(LOG_POLL_SECONDS)
        except TimeoutError as err:
            raise PanOSConnectionError(f"Log query on {self.host} still running after {timeout} s") from err
        finally:
            if job is not None and not self._closed:
                # Best effort, and shielded so a cancellation can't skip it.
                await asyncio.shield(self._finish_log_job(job, key))

    async def _finish_log_job(self, job: str, key: str) -> None:
        try:
            # Bounds the whole cleanup, including waiting for a request slot.
            async with asyncio.timeout(LOG_FINISH_TIMEOUT):
                await self._request(
                    {"type": "log", "action": "finish", "job-id": job}, key, LOG_FINISH_TIMEOUT
                )
        except (PanOSError, TimeoutError) as err:
            _LOGGER.debug("Could not stop log job %s on %s: %s", job, self.host, err)

    def _is_forbidden(self, key: str) -> bool:
        since = self._forbidden.get(key)
        if since is not None and time.monotonic() - since > FORBIDDEN_TTL:
            del self._forbidden[key]
            return False
        return since is not None

    async def _request(self, data: dict[str, str], key: str, timeout: int) -> ET.Element:
        """POST with key handling; ``key`` identifies the call for role errors."""
        if not self.api_key:
            await self.generate_key(None)
        used_key = self.api_key
        try:
            return await self._post(data, timeout=timeout)
        except PanOSAuthError as err:
            if self._is_forbidden(key):
                # Already proven to be a role restriction, not an expired key.
                raise PanOSApiError(f"Not permitted for this admin role: {err}", "403") from err
            # API keys can expire (PAN-OS 10.2+ key lifetime) or be rotated by
            # a master-key change; regenerate once with the stored password.
            _LOGGER.debug("API key rejected by %s, regenerating", self.host)
            await self.generate_key(used_key)
        try:
            return await self._post(data, timeout=timeout)
        except PanOSAuthError as err:
            # The password just produced a working key, so a 403 now means the
            # admin role isn't allowed this request - not bad credentials.
            self._forbidden[key] = time.monotonic()
            raise PanOSApiError(f"Not permitted for this admin role: {err}", "403") from err

    async def _post(
        self, data: dict[str, str], with_key: bool = True, timeout: int = DEFAULT_TIMEOUT
    ) -> ET.Element:
        if self._closed:
            raise PanOSConnectionError(f"{self.host}: shutting down")
        headers = {"X-PAN-KEY": self.api_key} if with_key and self.api_key else {}
        task = asyncio.current_task()
        if task is not None:
            self._inflight.add(task)
        try:
            text, status = await self._send(data, headers, timeout)
        finally:
            if task is not None:
                self._inflight.discard(task)
        if status in (401, 403):
            if "not authorized for user role" in text.lower():
                parse_response(text)  # raises PanOSApiError(code "403"): a role limit, not a bad key
            raise PanOSAuthError(f"HTTP {status} from {self.host}")
        if status >= 400 and not text.lstrip().startswith("<"):
            raise PanOSConnectionError(f"HTTP {status} from {self.host}")
        if len(text) > LARGE_RESPONSE:
            # e.g. the running config: parse off the event loop.
            return await asyncio.get_running_loop().run_in_executor(None, parse_response, text)
        return parse_response(text)

    async def _send(self, data: dict[str, str], headers: dict[str, str], timeout: int) -> tuple[str, int]:
        async with self._sem:
            try:
                async with self._session.post(
                    self._url,
                    data=data,
                    headers=headers,
                    timeout=aiohttp.ClientTimeout(total=timeout),
                ) as resp:
                    text = await resp.text()
                    status = resp.status
            except (TimeoutError, aiohttp.ClientError) as err:
                raise PanOSConnectionError(
                    f"Error talking to {self.host}: {err or type(err).__name__}"
                ) from err
        return text, status
