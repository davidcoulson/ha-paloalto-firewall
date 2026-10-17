"""Raw command samples for diagnostics.

Only collected when the integration's logger is at DEBUG, because the output
includes addresses and routing details. Captures the raw output of the
network commands the integration parses, so a parser problem can be fixed
from a diagnostics download instead of guessing at PAN-OS output formats.
"""

from __future__ import annotations

import logging
import xml.etree.ElementTree as ET
from copy import deepcopy
from typing import Any

from .api import PanOSClient, PanOSError
from .const import (
    CMD_BGP_PEERS_LR,
    CMD_BGP_SUMMARY,
    CMD_CERTS_DEVICE,
    CMD_CERTS_STORE,
    CMD_FIB,
    CMD_GP_PREVIOUS,
    CMD_GP_USERS,
    CMD_INTERFACE_ALL,
    CMD_JOBS,
    CMD_PATH_MONITOR,
    CMD_PD_POOLS,
    CMD_PENDING_CHANGES,
    CMD_RUNNING_NAT,
)

_LOGGER = logging.getLogger(__package__)
MAX_CHARS = 25000
REDACT_XML_FIELDS = {
    "username",
    "primary-username",
    "computer",
    "public-ip",
    "public-ipv6",
    "virtual-ip",
    "virtual-ipv6",
    "srcuser",
    "misc",
}

STATIC_PROBES: dict[str, str] = {
    "interface_all": CMD_INTERFACE_ALL,
    "fib": CMD_FIB,
    "path_monitor": CMD_PATH_MONITOR,
    "jobs": CMD_JOBS,
    "pending_changes": CMD_PENDING_CHANGES,
    "pd_pools": CMD_PD_POOLS,
    "bgp_summary": CMD_BGP_SUMMARY,
    "gp_current": CMD_GP_USERS,
    "gp_previous": CMD_GP_PREVIOUS,
    "certs_device": CMD_CERTS_DEVICE,
    "certs_store": CMD_CERTS_STORE,
    "routes_ipv6": "<show><advanced-routing><route><afi>ipv6</afi></route></advanced-routing></show>",
    "routes_ipv4": "<show><advanced-routing><route><afi>ipv4</afi></route></advanced-routing></show>",
    "drop_counters": (
        "<show><counter><global><filter><severity>drop</severity>"
        "<delta>no</delta></filter></global></counter></show>"
    ),
}


def debug_enabled() -> bool:
    return _LOGGER.isEnabledFor(logging.DEBUG)


def _dump(el: ET.Element) -> str:
    # Scrub the XML before serializing or truncating it; callers may still
    # need the original response for parsing.
    el = deepcopy(el)
    for field in el.iter():
        if field.tag in REDACT_XML_FIELDS:
            field.clear()
            field.text = "**REDACTED**"
    text = ET.tostring(el, encoding="unicode")
    return text if len(text) <= MAX_CHARS else text[:MAX_CHARS] + f"... [{len(text)} chars]"


async def _run(client: PanOSClient, cmd: str, vsys: str | None = None) -> dict[str, Any]:
    try:
        result = await client.op(cmd, timeout=60, vsys=vsys)
    except PanOSError as err:
        return {"cmd": cmd, "vsys": vsys, "error": str(err)}
    return {"cmd": cmd, "vsys": vsys, "xml": _dump(result)}


async def collect(client: PanOSClient) -> dict[str, Any]:
    from .parsers import parse_interfaces

    out: dict[str, Any] = {}
    for name, cmd in STATIC_PROBES.items():
        out[name] = await _run(client, cmd)

    try:
        entries = await client.log_query("threat", "(severity geq high)", nlogs=3, timeout=60)
        out["threat_log"] = {"entries": [_dump(e) for e in entries]}
    except PanOSError as err:
        out["threat_log"] = {"error": str(err)}

    # Per-vsys / per-router commands, driven by what `show interface all` reports.
    try:
        ifaces = parse_interfaces(ET.fromstring(out["interface_all"].get("xml", "")))
    except (ET.ParseError, ValueError):
        ifaces = {}
    vsys_names = sorted({i["vsys"] for i in ifaces.values() if i.get("vsys")}) or ["vsys1"]
    for vsys in vsys_names:
        out[f"running_nat_{vsys}"] = await _run(client, CMD_RUNNING_NAT, vsys)
    routers = sorted({i["logical_router"] for i in ifaces.values() if i.get("logical_router")})
    for lr in routers:
        out[f"bgp_peers_{lr}"] = await _run(client, CMD_BGP_PEERS_LR.format(lr))
    hw = next((n for n in sorted(ifaces) if n.startswith("ethernet") and "." not in n), None)
    if hw:
        out["interface_detail"] = await _run(client, f"<show><interface>{hw}</interface></show>")
    return out
