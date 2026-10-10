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
    out.update(await _ipv6_wan(client, iface_xml))
    out.update(await _pd_and_nat(client, iface_xml))
    return out


async def _pd_and_nat(client: PanOSClient, iface_xml: str) -> dict[str, Any]:
    """DHCPv6-PD state and NAT-test variants against known rules."""
    out: dict[str, Any] = {}
    ifaces = _ifaces_from(iface_xml)
    wan = [n for n, i in ifaces.items() if (i.get("zone") or "").lower() == "internet"
           and "." not in n and not n.startswith("loopback")]
    for name in wan:
        for label, cmd in {
            "a": f"<show><dhcp><client><ipv6><state><interface>{name}</interface></state></ipv6></client></dhcp></show>",
            "b": f"<show><dhcp><client><ipv6><state><interface><entry name='{name}'/></interface></state></ipv6></client></dhcp></show>",
        }.items():
            out[f"pd_state_{label}_{name}"] = await _run(client, cmd)
    for label, cmd in {
        "a": "<show><dhcp><client><ipv6><pool-details>all</pool-details></ipv6></client></dhcp></show>",
        "b": "<show><dhcp><client><ipv6><pool-details><all/></pool-details></ipv6></client></dhcp></show>",
    }.items():
        out[f"pd_pools_{label}"] = await _run(client, cmd)

    v4 = ("<source>10.2.4.159</source><destination>1.1.1.1</destination>"
          "<destination-port>443</destination-port><protocol>6</protocol>")
    v6 = ("<source>fd69:deca:fbad:0:1ccc:a68d:1569:5377</source>"
          "<destination>2606:4700:4700::1111</destination><protocol>58</protocol>")
    for label, body, vsys in (
        ("v4_vsys3_toif", f"<from>Core</from><to>Internet</to>{v4}<to-interface>ethernet1/13</to-interface>", "vsys3"),
        ("v4_vsys3_noif", f"<from>Core</from><to>Internet</to>{v4}", "vsys3"),
        ("v4_novsys_toif", f"<from>Core</from><to>Internet</to>{v4}<to-interface>ethernet1/13</to-interface>", None),
        ("v6_vsys3_toif", f"<from>Core</from><to>Internet</to>{v6}<to-interface>ethernet1/13</to-interface>", "vsys3"),
        ("v6_vsys3_noif", f"<from>Core</from><to>Internet</to>{v6}", "vsys3"),
    ):
        out[f"nat_{label}"] = await _run(
            client, f"<test><nat-policy-match>{body}</nat-policy-match></test>", vsys
        )
    return out


def _ifaces_from(iface_xml: str) -> dict[str, Any]:
    from .parsers import parse_interfaces

    try:
        return parse_interfaces(ET.fromstring(iface_xml))
    except ET.ParseError:
        return {}


async def _ipv6_wan(client: PanOSClient, iface_xml: str) -> dict[str, Any]:
    """WAN/IPv6 troubleshooting: NAT rules per vsys, v6 sessions, drops, pings."""
    out: dict[str, Any] = {}
    ifaces = _ifaces_from(iface_xml)
    vsys_names = sorted({i["vsys"] for i in ifaces.values() if i.get("vsys")}) or ["vsys1"]
    for v in vsys_names:
        out[f"nat_running_{v}"] = await _run(
            client, "<show><running><nat-policy></nat-policy></running></show>", v
        )
    for dst in ("2606:4700:4700::1111", "1.1.1.1"):
        out[f"sessions_to_{dst}"] = await _run(
            client,
            f"<show><session><all><filter><destination>{dst}</destination></filter></all></session></show>",
        )
    out["drop_counters"] = await _run(
        client,
        "<show><counter><global><filter><severity>drop</severity><delta>no</delta></filter></global></counter></show>",
    )
    # Uplink details and pings sourced from each WAN-side interface address.
    wan = [n for n, i in ifaces.items() if (i.get("zone") or "").lower() == "internet"]
    for name in wan + [n for n, i in ifaces.items() if n.startswith(("ae11.", "ae12."))]:
        out[f"iface_{name}"] = await _run(client, f"<show><interface>{name}</interface></show>")
    for name in wan:
        out[f"neighbors_{name}"] = await _run(
            client, f"<show><neighbor><interface>{name}</interface></neighbor></show>"
        )
    for name, iface in ifaces.items():
        if name not in wan and not name.startswith(("ae11.", "ae12.")):
            continue
        for cidr in iface["ips"]:
            addr = cidr.split("/")[0]
            if ":" not in addr or addr.startswith("fe80"):
                continue
            out[f"ping_from_{name}_{addr}"] = await _run(
                client,
                f"<ping><source>{addr}</source><count>3</count>"
                "<host>2606:4700:4700::1111</host></ping>",
            )
    return out
