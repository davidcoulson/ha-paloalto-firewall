"""Raw command samples for diagnostics.

Only collected when the integration's logger is at DEBUG, because the output
includes addresses and routing details. Used to develop/fix parsers against a
real firewall without guessing at PAN-OS output formats.
"""

from __future__ import annotations

import logging
import re
import xml.etree.ElementTree as ET
from typing import Any

from .api import PanOSClient, PanOSError

_LOGGER = logging.getLogger(__package__)
MAX_CHARS = 25000

STATIC_PROBES: dict[str, str] = {
    "are_route": "<show><advanced-routing><route></route></advanced-routing></show>",
    "are_fib": "<show><advanced-routing><fib></fib></advanced-routing></show>",
    "are_path_monitor": (
        "<show><advanced-routing><static-route-path-monitor>"
        "</static-route-path-monitor></advanced-routing></show>"
    ),
    "legacy_route_summary": "<show><routing><summary></summary></routing></show>",
    "legacy_path_monitor": "<show><routing><path-monitor></path-monitor></routing></show>",
    "interface_all": "<show><interface>all</interface></show>",
    "pbf_rules": "<show><pbf><rule><all></all></rule></pbf></show>",
    "jobs": "<show><jobs><all></all></jobs></show>",
    "pending_changes": "<check><pending-changes></pending-changes></check>",
    "target_vsys": "<show><system><setting><target-vsys></target-vsys></setting></system></show>",
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


def _first(pattern: str, text: str) -> str | None:
    match = re.search(pattern, text)
    return match.group(1) if match else None


async def collect(client: PanOSClient) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for name, cmd in STATIC_PROBES.items():
        out[name] = await _run(client, cmd)

    # Follow-ups that need a name discovered above.
    iface_xml = out["interface_all"].get("xml", "")
    hw = _first(r"<name>(ethernet\d+/\d+)</name>", iface_xml)
    if hw:
        out["interface_hw_detail"] = await _run(client, f"<show><interface>{hw}</interface></show>")
    ae = _first(r"<name>(ae\d+)</name>", iface_xml)
    if ae:
        out["interface_ae_detail"] = await _run(client, f"<show><interface>{ae}</interface></show>")
    sub = _first(r"<name>((?:ae|ethernet)[\d/]+\.\d+)</name>", iface_xml)
    if sub:
        out["interface_sub_detail"] = await _run(client, f"<show><interface>{sub}</interface></show>")
    vsys = _first(r"<vsys>(?:vsys)?(\d+)</vsys>", iface_xml)
    vsys_name = f"vsys{vsys}" if vsys else "vsys1"

    route_xml = out["are_route"].get("xml", "") + out["are_fib"].get("xml", "")
    lr = _first(r'logical-router[^>]*name="([^"]+)"', route_xml) or _first(
        r"<logical-router>([^<]+)</logical-router>", route_xml
    ) or _first(r"<entry name=\"([^\"]+)\"", route_xml)
    out["discovered"] = {"hw": hw, "ae": ae, "sub": sub, "vsys": vsys_name, "logical_router": lr}
    for label, cmd in {
        "are_lr_detail": f"<show><advanced-routing><logical-router>{lr}</logical-router></advanced-routing></show>",
        "are_fib_lookup": (
            "<test><advanced-routing><fib-lookup>"
            f"<logical-router>{lr}</logical-router><ip>1.1.1.1</ip>"
            "</fib-lookup></advanced-routing></test>"
        ),
        "legacy_fib_lookup": (
            "<test><routing><fib-lookup><virtual-router>default</virtual-router>"
            "<ip>1.1.1.1</ip></fib-lookup></routing></test>"
        ),
    }.items():
        if lr or label.startswith("legacy"):
            out[label] = await _run(client, cmd)

    nat = (
        "<test><nat-policy-match><source>10.2.4.159</source><destination>1.1.1.1</destination>"
        "<destination-port>443</destination-port><protocol>6</protocol></nat-policy-match></test>"
    )
    out["nat_test_default"] = await _run(client, nat)
    out["nat_test_vsys"] = await _run(client, nat, vsys_name)
    sec = (
        "<test><security-policy-match><source>10.2.4.159</source><destination>1.1.1.1</destination>"
        "<destination-port>443</destination-port><protocol>6</protocol></security-policy-match></test>"
    )
    out["sec_test_vsys"] = await _run(client, sec, vsys_name)
    return out
