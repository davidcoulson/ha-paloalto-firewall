"""Raw command samples for diagnostics.

Only collected when the integration's logger is at DEBUG, because the output
includes addresses and routing details. Captures the raw output of the
network commands the integration parses, so a parser problem can be fixed
from a diagnostics download instead of guessing at PAN-OS output formats.
"""

from __future__ import annotations

import logging
import re
import xml.etree.ElementTree as ET
from typing import Any

from .api import PanOSClient, PanOSError
from .const import (
    CMD_BGP_PEERS_LR,
    CMD_BGP_SUMMARY,
    CMD_FIB,
    CMD_INTERFACE_ALL,
    CMD_JOBS,
    CMD_PATH_MONITOR,
    CMD_PD_POOLS,
    CMD_PENDING_CHANGES,
    CMD_RUNNING_NAT,
)

_LOGGER = logging.getLogger(__package__)
MAX_CHARS = 25000

STATIC_PROBES: dict[str, str] = {
    "interface_all": CMD_INTERFACE_ALL,
    "fib": CMD_FIB,
    "path_monitor": CMD_PATH_MONITOR,
    "jobs": CMD_JOBS,
    "pending_changes": CMD_PENDING_CHANGES,
    "pd_pools": CMD_PD_POOLS,
    "bgp_summary": CMD_BGP_SUMMARY,
    "drop_counters": (
        "<show><counter><global><filter><severity>drop</severity>"
        "<delta>no</delta></filter></global></counter></show>"
    ),
}


def debug_enabled() -> bool:
    return _LOGGER.isEnabledFor(logging.DEBUG)


def _dump(el: ET.Element) -> str:
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
    out.update(await _new_feature_probes(client))
    return out


async def _new_feature_probes(client: PanOSClient) -> dict[str, Any]:
    """Temporary: sessions, GlobalProtect and certificate command formats."""
    out: dict[str, Any] = {}
    for label, cmd in {
        "sess_filter_src": "<show><session><all><filter><source>10.2.4.159</source></filter></all></session></show>",
        "sess_filter_dport": "<show><session><all><filter><destination-port>443</destination-port><count>yes</count></filter></all></session></show>",
        "sess_filter_app": "<show><session><all><filter><application>dns-base</application></filter></all></session></show>",
        "gp_previous": "<show><global-protect-gateway><previous-user></previous-user></global-protect-gateway></show>",
        "gp_gateway": "<show><global-protect-gateway><gateway></gateway></global-protect-gateway></show>",
        "gp_portal": "<show><global-protect-portal><summary><all></all></summary></global-protect-portal></show>",
        "gp_client_check": "<request><global-protect-client><software><check></check></software></global-protect-client></request>",
        "gp_client_info": "<request><global-protect-client><software><info></info></software></global-protect-client></request>",
        "cert_config_info": "<show><sslmgr-store><config-certificate-info></config-certificate-info></sslmgr-store></show>",
        "cert_config_ca": "<show><sslmgr-store><config-ca-certificate></config-ca-certificate></sslmgr-store></show>",
        "cert_device": "<show><device-certificate><status></status></device-certificate></show>",
        "cert_ssl_decrypt": "<show><system><setting><ssl-decrypt><certificate></certificate></ssl-decrypt></setting></system></show>",
    }.items():
        out[label] = await _run(client, cmd)
    xml = out["sess_filter_src"].get("xml", "") + out["sess_filter_app"].get("xml", "")
    idx = re.search(r"<idx>(\d+)</idx>", xml)
    if idx:
        out["sess_id"] = await _run(client, f"<show><session><id>{idx.group(1)}</id></session></show>")
    for label, xpath in {
        "cfg_shared_certs": "/config/shared/certificate",
        "cfg_vsys_certs": "/config/devices/entry/vsys/entry/certificate",
    }.items():
        try:
            out[label] = {"xpath": xpath, "xml": _dump(await client.config_get(xpath, timeout=60))}
        except PanOSError as err:
            out[label] = {"xpath": xpath, "error": str(err)}
    return out
