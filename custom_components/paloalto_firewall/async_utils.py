"""Helpers for concurrent firewall reads."""

from __future__ import annotations

import asyncio
from collections.abc import Coroutine
from typing import Any


async def gather_reads(*reads: Coroutine[Any, Any, Any]) -> list[Any]:
    """Cancel and await every sibling before propagating a failed read."""
    tasks = [asyncio.create_task(read) for read in reads]
    try:
        return await asyncio.gather(*tasks)
    except BaseException:
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        raise
