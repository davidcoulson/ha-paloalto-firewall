"""Async client for the PAN-OS XML API."""

from __future__ import annotations

import asyncio
import logging
import xml.etree.ElementTree as ET

import aiohttp

_LOGGER = logging.getLogger(__name__)

DEFAULT_TIMEOUT = 30


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
        self._forbidden: set[str] = set()

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
            return self.api_key

    async def op(self, cmd: str, timeout: int = DEFAULT_TIMEOUT, vsys: str | None = None) -> ET.Element:
        """Run an operational command and return its <result> element.

        ``vsys`` sets the target vsys for this request only (multi-vsys).
        """
        if not self.api_key:
            await self.generate_key(None)
        data = {"type": "op", "cmd": cmd}
        if vsys:
            data["vsys"] = vsys
        used_key = self.api_key
        try:
            return await self._post(data, timeout=timeout)
        except PanOSAuthError as err:
            if cmd in self._forbidden:
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
            # admin role isn't allowed this command - not bad credentials.
            self._forbidden.add(cmd)
            raise PanOSApiError(f"Not permitted for this admin role: {err}", "403") from err

    async def _post(
        self, data: dict[str, str], with_key: bool = True, timeout: int = DEFAULT_TIMEOUT
    ) -> ET.Element:
        headers = {"X-PAN-KEY": self.api_key} if with_key and self.api_key else {}
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
        if status in (401, 403):
            raise PanOSAuthError(f"HTTP {status} from {self.host}")
        if status >= 400 and not text.lstrip().startswith("<"):
            raise PanOSConnectionError(f"HTTP {status} from {self.host}")
        return parse_response(text)
