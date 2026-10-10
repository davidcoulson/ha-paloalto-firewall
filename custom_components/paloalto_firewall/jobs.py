"""Run a PAN-OS asynchronous job (download, activate, ...) to completion."""

from __future__ import annotations

import asyncio
import xml.etree.ElementTree as ET
from collections.abc import Callable

from .api import PanOSApiError, PanOSClient
from .const import CMD_JOB

POLL_SECONDS = 5


def job_id(result: ET.Element) -> int | None:
    """The job a `request ...` command enqueued, if it enqueued one."""
    text = (result.findtext("job") or "").strip()
    return int(text) if text.isdigit() else None


def _messages(job: ET.Element) -> str:
    lines = [(line.text or "").strip() for line in job.iter("line")]
    return "; ".join(line for line in lines if line)


async def run_job(
    client: PanOSClient,
    cmd: str,
    *,
    timeout: float = 900,
    on_progress: Callable[[int], None] | None = None,
) -> None:
    """Send ``cmd``, wait for the job it starts, and raise if it doesn't finish OK."""
    result = await client.op(cmd, timeout=120)
    jid = job_id(result)
    if jid is None:
        return  # Completed synchronously.
    loop = asyncio.get_running_loop()
    deadline = loop.time() + timeout
    while True:
        await asyncio.sleep(POLL_SECONDS)
        status = (await client.op(CMD_JOB.format(jid))).find("job")
        if status is None:
            raise PanOSApiError(f"Job {jid} disappeared")
        progress = (status.findtext("progress") or "").strip()
        if on_progress and progress.isdigit():
            on_progress(int(progress))
        if (status.findtext("status") or "").strip() == "FIN":
            if (status.findtext("result") or "").strip() != "OK":
                raise PanOSApiError(f"Job {jid} failed: {_messages(status) or 'no details'}")
            return
        if loop.time() > deadline:
            raise PanOSApiError(f"Job {jid} still running after {int(timeout)} s")
