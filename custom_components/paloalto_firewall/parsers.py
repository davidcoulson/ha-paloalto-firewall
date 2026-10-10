"""Pure parsers for PAN-OS XML API responses.

Nothing in this module imports Home Assistant, so it can be unit tested on its
own. Every parser takes the <result> element of a successful API response.
"""

from __future__ import annotations

import ipaddress
import json
import re
import xml.etree.ElementTree as ET
from datetime import UTC, date, datetime
from statistics import mean
from typing import Any

HA_STATES = [
    "standalone",
    "initial",
    "active",
    "passive",
    "active-primary",
    "active-secondary",
    "tentative",
    "non-functional",
    "suspended",
    "unknown",
]


def _text(el: ET.Element | None, path: str, default: str | None = None) -> str | None:
    if el is None:
        return default
    node = el.find(path)
    if node is None or node.text is None:
        return default
    value = node.text.strip()
    return value if value else default


def _int(value: str | None) -> int | None:
    if value is None:
        return None
    try:
        return int(value.strip())
    except ValueError:
        try:
            return int(float(value.strip()))
        except ValueError:
            return None


def _float(value: str | None) -> float | None:
    if value is None:
        return None
    try:
        return float(value.strip())
    except ValueError:
        return None


def _yes(value: str | None) -> bool:
    return (value or "").strip().lower() in ("yes", "true", "1")


# --------------------------------------------------------------------------
# show system info
# --------------------------------------------------------------------------

_SYSTEM_FIELDS = {
    "hostname": "hostname",
    "model": "model",
    "family": "family",
    "serial": "serial",
    "mgmt_ip": "ip-address",
    "sw_version": "sw-version",
    "app_version": "app-version",
    "threat_version": "threat-version",
    "av_version": "av-version",
    "wildfire_version": "wildfire-version",
    "url_filtering_version": "url-filtering-version",
    "gp_client_version": "global-protect-client-package-version",
    "logdb_version": "logdb-version",
    "operational_mode": "operational-mode",
    "device_cert_status": "device-certificate-status",
    "uptime_raw": "uptime",
    "multi_vsys": "multi-vsys",
    "time": "time",
}

_UPTIME_RE = re.compile(r"(?:(\d+)\s+days?,?\s*)?(\d+):(\d{2}):(\d{2})")


def parse_uptime(raw: str | None) -> int | None:
    """Convert '12 days, 3:04:05' to seconds."""
    if not raw:
        return None
    match = _UPTIME_RE.search(raw)
    if not match:
        return None
    days, hours, minutes, seconds = (int(g) if g else 0 for g in match.groups())
    return ((days * 24 + hours) * 60 + minutes) * 60 + seconds


def parse_system_info(result: ET.Element) -> dict[str, Any]:
    system = result.find("system")
    if system is None:
        raise ValueError("No <system> element in system info response")
    data: dict[str, Any] = {k: _text(system, v) for k, v in _SYSTEM_FIELDS.items()}
    if not data["serial"]:
        raise ValueError("System info response has no serial number")
    data["uptime_seconds"] = parse_uptime(data["uptime_raw"])
    return data


# --------------------------------------------------------------------------
# show high-availability state
# --------------------------------------------------------------------------


def _ha_state(value: str | None) -> str:
    state = (value or "unknown").strip().lower()
    return state if state in HA_STATES else "unknown"


def parse_ha_state(result: ET.Element) -> dict[str, Any]:
    if not _yes(_text(result, "enabled")):
        return {"enabled": False}
    group = result.find("group")
    local = group.find("local-info") if group is not None else None
    peer = group.find("peer-info") if group is not None else None
    peer_conn = _text(peer, "conn-status")
    return {
        "enabled": True,
        "mode": _text(group, "mode"),
        "local_state": _ha_state(_text(local, "state")),
        "local_state_duration": _int(_text(local, "state-duration")),
        "local_priority": _int(_text(local, "priority")),
        "preemptive": _yes(_text(local, "preemptive")),
        "state_sync": _text(local, "state-sync"),
        "peer_state": _ha_state(_text(peer, "state")) if peer is not None else None,
        "peer_conn_status": peer_conn.lower() if peer_conn else None,
        "peer_mgmt_ip": _text(peer, "mgmt-ip"),
        "peer_priority": _int(_text(peer, "priority")),
        "peer_serial": _text(peer, "serial-num"),
        "ha1_status": _text(peer, "conn-ha1/conn-status"),
        "ha1_backup_status": _text(peer, "conn-ha1-backup/conn-status"),
        "ha2_status": _text(peer, "conn-ha2/conn-status"),
        "running_sync": (_text(group, "running-sync") or "").lower() or None,
        "running_sync_enabled": _yes(_text(group, "running-sync-enabled")),
    }


# --------------------------------------------------------------------------
# show session info
# --------------------------------------------------------------------------


def parse_session_info(result: ET.Element) -> dict[str, Any]:
    data: dict[str, Any] = {
        "num_active": _int(_text(result, "num-active")),
        "num_max": _int(_text(result, "num-max")),
        "num_tcp": _int(_text(result, "num-tcp")),
        "num_udp": _int(_text(result, "num-udp")),
        "num_icmp": _int(_text(result, "num-icmp")),
        "cps": _int(_text(result, "cps")),
        "kbps": _int(_text(result, "kbps")),
        "pps": _int(_text(result, "pps")),
    }
    if data["num_active"] is None and data["num_max"] is None:
        raise ValueError("Session info response has no session counters")
    if data["num_active"] is not None and data["num_max"]:
        data["utilization_pct"] = round(data["num_active"] / data["num_max"] * 100, 2)
    else:
        data["utilization_pct"] = None
    return data


# --------------------------------------------------------------------------
# show system resources  (management plane 'top' output)
# --------------------------------------------------------------------------

_CPU_IDLE_RE = re.compile(r"Cpu\(s\):.*?([\d.]+)[%\s]*id", re.IGNORECASE)
_LOAD_RE = re.compile(r"load average:\s*([\d.]+),\s*([\d.]+),\s*([\d.]+)")
_MEM_NEW_RE = re.compile(
    r"([KMG]iB)\s+Mem\s*:\s*([\d.]+)\s*total,\s*([\d.]+)\s*free,\s*([\d.]+)\s*used",
    re.IGNORECASE,
)
_AVAIL_RE = re.compile(r"([\d.]+)\s*avail\s+Mem", re.IGNORECASE)
_MEM_OLD_RE = re.compile(
    r"Mem:\s*([\d.]+)k\s*total,\s*([\d.]+)k\s*used,\s*([\d.]+)k\s*free(?:,\s*([\d.]+)k\s*buffers)?",
    re.IGNORECASE,
)
_CACHED_OLD_RE = re.compile(r"([\d.]+)k\s*cached", re.IGNORECASE)


def parse_system_resources(result: ET.Element) -> dict[str, Any]:
    text = "".join(result.itertext())
    data: dict[str, Any] = {
        "mgmt_cpu_pct": None,
        "mgmt_memory_pct": None,
        "load_1m": None,
        "load_5m": None,
        "load_15m": None,
    }
    if match := _CPU_IDLE_RE.search(text):
        data["mgmt_cpu_pct"] = round(max(0.0, 100.0 - float(match.group(1))), 1)
    if match := _LOAD_RE.search(text):
        data["load_1m"], data["load_5m"], data["load_15m"] = (float(g) for g in match.groups())
    if match := _MEM_NEW_RE.search(text):
        total = float(match.group(2))
        used = float(match.group(4))
        if avail := _AVAIL_RE.search(text):
            used = total - float(avail.group(1))
        if total:
            data["mgmt_memory_pct"] = round(used / total * 100, 1)
    elif match := _MEM_OLD_RE.search(text):
        total = float(match.group(1))
        used = float(match.group(2))
        buffers = float(match.group(4) or 0)
        cached = _CACHED_OLD_RE.search(text)
        used -= buffers + (float(cached.group(1)) if cached else 0)
        if total:
            data["mgmt_memory_pct"] = round(max(used, 0) / total * 100, 1)
    if data["mgmt_cpu_pct"] is None and data["mgmt_memory_pct"] is None:
        raise ValueError("Could not parse system resources output")
    return data


# --------------------------------------------------------------------------
# show running resource-monitor minute last 1  (dataplane)
# --------------------------------------------------------------------------


def _first_number(value: str | None) -> float | None:
    if not value:
        return None
    return _float(value.split(",")[0])


def parse_dataplane(result: ET.Element) -> dict[str, Any]:
    processors = result.find("resource-monitor/data-processors")
    if processors is None:
        raise ValueError("No data-processors in resource-monitor response")
    per_dp: dict[str, float] = {}
    all_avg: list[float] = []
    all_max: list[float] = []
    packet_buffer: list[float] = []
    for dp in processors:
        minute = dp.find("minute")
        if minute is None:
            continue
        avgs = [
            v
            for e in minute.findall("cpu-load-average/entry")
            if (v := _first_number(_text(e, "value"))) is not None
        ]
        maxes = [
            v
            for e in minute.findall("cpu-load-maximum/entry")
            if (v := _first_number(_text(e, "value"))) is not None
        ]
        if avgs:
            per_dp[dp.tag] = round(mean(avgs), 1)
            all_avg.extend(avgs)
        all_max.extend(maxes)
        for entry in minute.findall("resource-utilization/entry"):
            is_buffer = (_text(entry, "name") or "").lower() == "packet buffer (average)"
            if is_buffer and (v := _first_number(_text(entry, "value"))) is not None:
                packet_buffer.append(v)
    if not all_avg:
        raise ValueError("No dataplane CPU values found")
    return {
        "cpu_avg_pct": round(mean(all_avg), 1),
        "cpu_max_pct": round(max(all_max), 1) if all_max else None,
        "per_dataplane": per_dp,
        "packet_buffer_pct": round(max(packet_buffer), 1) if packet_buffer else None,
    }


# --------------------------------------------------------------------------
# show system environmentals
# --------------------------------------------------------------------------


def parse_environmentals(result: ET.Element) -> dict[str, Any]:
    temps: dict[str, float] = {}
    alarms: list[str] = []
    seen = False
    for section in ("thermal", "fan", "fantray", "power", "power-supply"):
        for entry in result.findall(f"{section}/*/entry"):
            seen = True
            desc = _text(entry, "description") or f"{section} {_text(entry, 'slot', '')}".strip()
            if _yes(_text(entry, "alarm")):
                alarms.append(f"{section}: {desc}")
            if section == "thermal" and (deg := _float(_text(entry, "DegreesC"))) is not None:
                temps[desc] = round(deg, 1)
    if not seen:
        raise ValueError("No environmental data (virtual firewall?)")
    return {
        "max_temp_c": max(temps.values()) if temps else None,
        "temperatures": temps,
        "alarms": alarms,
        "alarm": bool(alarms),
    }


# --------------------------------------------------------------------------
# Users / tunnels
# --------------------------------------------------------------------------


def parse_gp_users(result: ET.Element) -> dict[str, Any]:
    users = [_text(e, "username") or _text(e, "primary-username") or "?" for e in result.findall("entry")]
    return {"count": len(users), "users": users, "sessions": parse_gp_sessions(result)}


def parse_admins(result: ET.Element) -> dict[str, Any]:
    admins = [_text(e, "admin") or "?" for e in result.findall("admins/entry")]
    return {"count": len(admins), "users": admins}


def parse_ipsec_sa(result: ET.Element) -> dict[str, Any]:
    names = sorted({_text(e, "name") or "?" for e in result.findall("entries/entry")})
    count = _int(_text(result, "ntun"))
    return {"count": count if count is not None else len(names), "tunnels": names}


# --------------------------------------------------------------------------
# Software / content update checks and licences
# --------------------------------------------------------------------------


def parse_software_check(result: ET.Element) -> dict[str, Any]:
    versions = []
    for e in result.findall("sw-updates/versions/entry"):
        version = _text(e, "version")
        if not version:
            continue
        versions.append(
            {
                "version": version,
                "downloaded": _yes(_text(e, "downloaded")),
                "current": _yes(_text(e, "current")),
                "latest": _yes(_text(e, "latest")),
                "released_on": _text(e, "released-on"),
                "release_notes": _text(e, "release-notes"),
            }
        )
    return {"versions": versions}


def parse_content_check(result: ET.Element) -> dict[str, Any]:
    versions = []
    for e in result.findall("content-updates/entry"):
        version = _text(e, "version")
        if not version:
            continue
        versions.append(
            {
                "version": version,
                "downloaded": _yes(_text(e, "downloaded")),
                "current": _yes(_text(e, "current")),
                "released_on": _text(e, "released-on"),
                "release_notes": _text(e, "release-notes"),
            }
        )
    return {"versions": versions}


def _parse_license_date(value: str | None) -> date | None:
    if not value or value.strip().lower() == "never":
        return None
    for fmt in ("%B %d, %Y", "%b %d, %Y", "%Y/%m/%d", "%Y-%m-%d"):
        try:
            return datetime.strptime(value.strip(), fmt).date()
        except ValueError:
            continue
    return None


def parse_licenses(result: ET.Element) -> dict[str, Any]:
    licenses: list[dict[str, Any]] = []
    for e in result.findall("licenses/entry"):
        # The hardware/software warranty is listed alongside subscriptions but
        # is not a licence; its expiry shouldn't raise a problem.
        if "warranty" in (_text(e, "feature") or "").lower():
            continue
        licenses.append(
            {
                "feature": _text(e, "feature") or "?",
                "description": _text(e, "description"),
                "expires": _parse_license_date(_text(e, "expires")),
                "expires_raw": _text(e, "expires"),
                "expired": _yes(_text(e, "expired")),
            }
        )
    upcoming = [lic for lic in licenses if lic["expires"] and not lic["expired"]]
    next_expiry = min(upcoming, key=lambda lic: lic["expires"]) if upcoming else None
    return {
        "licenses": licenses,
        "next_expiry": next_expiry["expires"] if next_expiry else None,
        "next_expiry_feature": next_expiry["feature"] if next_expiry else None,
        "expired": [lic["feature"] for lic in licenses if lic["expired"]],
    }


# --------------------------------------------------------------------------
# Version helpers
# --------------------------------------------------------------------------

_PANOS_RE = re.compile(r"^(\d+)\.(\d+)\.(\d+)(?:-h(\d+))?")


def panos_version_key(version: str | None) -> tuple[int, int, int, int] | None:
    """'11.1.4-h7' -> (11, 1, 4, 7)."""
    if not version:
        return None
    match = _PANOS_RE.match(version.strip())
    if not match:
        return None
    major, minor, maint, hotfix = match.groups()
    return int(major), int(minor), int(maint), int(hotfix or 0)


def content_version_key(version: str | None) -> tuple[int, ...] | None:
    """'8800-9012' -> (8800, 9012)."""
    if not version:
        return None
    nums = re.findall(r"\d+", version)
    return tuple(int(n) for n in nums) if nums else None


def latest_panos(versions: list[dict[str, Any]], installed: str | None) -> dict[str, Any]:
    """Pick the newest release in the installed feature train, and overall."""
    parsed = [(key, v) for v in versions if (key := panos_version_key(v["version"])) is not None]
    if not parsed:
        return {"train": None, "overall": None}
    overall = max(parsed, key=lambda p: p[0])[1]
    inst_key = panos_version_key(installed)
    train = None
    if inst_key:
        same_train = [p for p in parsed if p[0][:2] == inst_key[:2]]
        if same_train:
            train = max(same_train, key=lambda p: p[0])[1]
    return {"train": train, "overall": overall}


def latest_content(versions: list[dict[str, Any]]) -> dict[str, Any] | None:
    parsed = [(key, v) for v in versions if (key := content_version_key(v["version"])) is not None]
    if not parsed:
        return None
    return max(parsed, key=lambda p: p[0])[1]


# --------------------------------------------------------------------------
# ARP table and DHCP leases (host lookup)
# --------------------------------------------------------------------------

ARP_STATUS = {"s": "static", "c": "complete", "e": "expiring", "i": "incomplete"}

_NON_HEX = re.compile(r"[^0-9a-f]")
_MAC_QUERY = re.compile(
    r"^(?:[0-9a-f]{2}(?:[:-][0-9a-f]{2})*[:-]?"  # 00:11:22 / 00-11-22
    r"|[0-9a-f]{4}(?:\.[0-9a-f]{4}){0,2}"  # 0011.2233.4455
    r"|[0-9a-f]{12})$"
)


def normalize_mac(mac: str | None) -> str:
    return _NON_HEX.sub("", (mac or "").lower())


def _clean_mac(mac: str | None) -> str | None:
    if not mac or len(normalize_mac(mac)) != 12:
        return None  # "(incomplete)" and similar
    return mac.lower()


def parse_arp(result: ET.Element) -> list[dict[str, Any]]:
    entries = []
    for e in result.findall("entries/entry"):
        ip = _text(e, "ip")
        if not ip:
            continue
        status = (_text(e, "status") or "").lower()
        entries.append(
            {
                "ip": ip,
                "mac": _clean_mac(_text(e, "mac")),
                "interface": _text(e, "interface"),
                "arp_status": ARP_STATUS.get(status, status or None),
                "arp_ttl": _int(_text(e, "ttl")),
            }
        )
    return entries


def parse_dhcp_leases(result: ET.Element) -> list[dict[str, Any]]:
    leases = []
    interfaces = result.findall("interface") or [result]
    for iface in interfaces:
        name = iface.get("name") or _text(iface, "name")
        for e in iface.iter("entry"):
            ip = _text(e, "ip") or e.get("name")
            mac = _clean_mac(_text(e, "mac"))
            if not ip or not mac:
                continue
            # PAN-OS 'leasetime' is when the lease was granted/renewed, not
            # when it expires; report it as-is with the lease duration.
            lease_time = " ".join((_text(e, "leasetime") or "").split()) or None
            leases.append(
                {
                    "ip": ip,
                    "mac": mac,
                    "hostname": _text(e, "hostname"),
                    "interface": name,
                    "lease_state": _text(e, "state"),
                    "lease_time": lease_time,
                    "lease_duration": _int(_text(e, "duration")),
                }
            )
    return leases


def merge_hosts(arp: list[dict[str, Any]], dhcp: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Combine ARP entries and DHCP leases describing the same IP+MAC."""
    hosts: dict[tuple[str, str], dict[str, Any]] = {}
    for source, records in (("dhcp", dhcp), ("arp", arp)):
        for rec in records:
            mac = rec.get("mac") or ""
            key = (rec["ip"], mac)
            if not mac:
                # Incomplete ARP entry: attach to a lease for the same IP.
                key = next((k for k in hosts if k[0] == rec["ip"]), key)
            host = hosts.setdefault(key, {"ip": rec["ip"], "mac": rec.get("mac"), "sources": []})
            if source not in host["sources"]:
                host["sources"].append(source)
            for field, value in rec.items():
                if value is not None and host.get(field) is None:
                    host[field] = value
    return sorted(hosts.values(), key=_ip_sort_key)


def _ip_sort_key(host: dict[str, Any]) -> tuple:
    try:
        addr = ipaddress.ip_address(host["ip"])
        return (addr.version, int(addr), host.get("mac") or "")
    except ValueError:
        return (9, 0, host["ip"])


def host_matches(host: dict[str, Any], query: str) -> bool:
    q = query.strip().lower()
    if not q:
        return True
    try:
        return host["ip"] == str(ipaddress.ip_address(q))
    except ValueError:
        pass
    if _MAC_QUERY.match(q) and host.get("mac") and normalize_mac(q) in normalize_mac(host["mac"]):
        return True
    return any(q in str(host.get(field) or "").lower() for field in ("ip", "mac", "hostname", "interface"))


# --------------------------------------------------------------------------
# test security-policy-match
# --------------------------------------------------------------------------

_RULE_TEXT_RE = re.compile(r"^(?P<name>.+?);\s*index:\s*(?P<index>\d+)")


def _rule_value(el: ET.Element) -> Any:
    members = [m.text.strip() for m in el.findall("member") if m.text and m.text.strip()]
    if members:
        return members
    if len(el):
        return None
    return el.text.strip() if el.text and el.text.strip() else None


def parse_policy_match(result: ET.Element) -> list[dict[str, Any]]:
    """Parse 'test security-policy-match' output, first match first.

    PAN-OS 9+ returns <entry name="rule"> with index/action/... children;
    older releases return the text "rule; index: N".
    """
    rules = []
    for entry in result.findall("rules/entry"):
        if entry.get("name"):
            rule: dict[str, Any] = {"name": entry.get("name")}
            for child in entry:
                value = _rule_value(child)
                if value is not None:
                    rule[child.tag.replace("-", "_")] = value
            if "index" in rule:
                rule["index"] = _int(rule["index"])
            rules.append(rule)
        elif entry.text and entry.text.strip():
            text = entry.text.strip()
            if match := _RULE_TEXT_RE.match(text):
                rules.append({"name": match["name"].strip(), "index": int(match["index"])})
            else:
                # NAT tests return just the rule name.
                rules.append({"name": text})
    return rules


# --------------------------------------------------------------------------
# Interfaces, FIB, path monitoring, jobs (Advanced Routing Engine)
# --------------------------------------------------------------------------


def _vsys_name(value: str | None) -> str | None:
    if not value or value in ("0", "N/A"):
        return None
    return value if value.startswith("vsys") else f"vsys{value}"


def parse_interfaces(result: ET.Element) -> dict[str, dict[str, Any]]:
    """'show interface all' -> {name: {...}} for hardware and logical interfaces."""
    hw: dict[str, dict[str, Any]] = {}
    for e in result.findall("hw/entry"):
        name = _text(e, "name")
        if name:
            hw[name] = {
                "state": _text(e, "state"),
                "speed": _int(_text(e, "speed")),
                "duplex": _text(e, "duplex") if _text(e, "duplex") != "[n/a]" else None,
                "mac": _text(e, "mac"),
            }
    interfaces: dict[str, dict[str, Any]] = {}
    for e in result.findall("ifnet/entry"):
        name = _text(e, "name")
        if not name:
            continue
        fwd = _text(e, "fwd") or ""
        ips = []
        for field in ("ip", "dyn-addr", "addr6"):
            for value in (_text(e, field) or "").replace(",", " ").split():
                if value != "N/A" and "/" in value:
                    ips.append(value)
        for m in e.findall("addr6/member") + e.findall("addr/member"):
            if m.text and "/" in m.text:
                ips.append(m.text.strip())
        base = hw.get(name.split(".")[0], {})
        interfaces[name] = {
            "name": name,
            "vsys": _vsys_name(_text(e, "vsys")),
            "zone": _text(e, "zone"),
            "logical_router": fwd[3:] if fwd.startswith("lr:") else None,
            "forwarding": fwd or None,
            "tag": _int(_text(e, "tag")),
            "ips": ips,
            "state": base.get("state"),
            "speed": base.get("speed"),
            "duplex": base.get("duplex"),
        }
    for name, data in hw.items():
        interfaces.setdefault(
            name,
            {
                "name": name,
                "vsys": None,
                "zone": None,
                "logical_router": None,
                "forwarding": None,
                "tag": 0,
                "ips": [],
                **data,
            },
        )
    return interfaces


def parse_interface_counters(result: ET.Element) -> dict[str, Any]:
    """'show interface <name>' -> byte/packet/error counters."""
    counters = result.find("ifnet/counters")
    if counters is None:
        raise ValueError("No counters in interface response")
    # Prefer hardware counters for physical/aggregate ports, logical for sub-ifs.
    entry = counters.find("hw/entry")
    if entry is None or _int(_text(entry, "ibytes")) is None:
        entry = counters.find("ifnet/entry")
    if entry is None:
        raise ValueError("No counter entry in interface response")
    return {
        k: _int(_text(entry, k)) for k in ("ibytes", "obytes", "ipackets", "opackets", "ierrors", "idrops")
    }


def parse_fib(result: ET.Element) -> list[dict[str, Any]]:
    routes = []
    for table in result.findall("fibs/entry"):
        vr = _text(table, "vr")
        for e in table.findall("entries/entry"):
            dst = _text(e, "dst")
            if not vr or not dst:
                continue
            try:
                network = ipaddress.ip_network(dst, strict=False)
            except ValueError:
                continue
            nexthop = _text(e, "nexthop")
            flags = _text(e, "flags") or ""
            routes.append(
                {
                    "logical_router": vr,
                    "destination": str(network),
                    "interface": _text(e, "interface"),
                    "nexthop": None if nexthop in ("0.0.0.0", "::") else nexthop,
                    "flags": flags,
                    "drop": nexthop == "drop",
                    "version": network.version,
                }
            )
    return routes


def fib_lookup(routes: list[dict[str, Any]], logical_router: str, address: str) -> list[dict[str, Any]]:
    """Longest-prefix match in one logical router's FIB (all ECMP paths)."""
    ip = ipaddress.ip_address(address)
    best: list[dict[str, Any]] = []
    best_len = -1
    for r in routes:
        if r["logical_router"] != logical_router or r["version"] != ip.version:
            continue
        net = ipaddress.ip_network(r["destination"])
        if ip not in net:
            continue
        if not r["flags"].startswith("u"):
            continue
        if net.prefixlen > best_len:
            best, best_len = [r], net.prefixlen
        elif net.prefixlen == best_len:
            best.append(r)
    return [dict(r) for r in best]


def parse_path_monitor(result: ET.Element) -> list[dict[str, Any]]:
    entries = []
    for e in result.findall("entry"):
        monitors = []
        i = 0
        while (dst := _text(e, f"monitordst-{i}")) is not None:
            monitors.append(
                {
                    "destination": dst,
                    "status": _text(e, f"monitorstatus-{i}"),
                    "interval_count": _text(e, f"interval-count-{i}"),
                }
            )
            i += 1
        entries.append(
            {
                "destination": _text(e, "destination"),
                "nexthop": _text(e, "nexthop"),
                "interface": _text(e, "interface"),
                "metric": _int(_text(e, "metric")),
                "condition": _text(e, "pathmonitor-cond"),
                "up": (_text(e, "pathmonitor-status") or "").lower() == "up",
                "monitors": monitors,
            }
        )
    return entries


def _job_time(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.strptime(value.strip(), "%Y/%m/%d %H:%M:%S")
    except ValueError:
        return None


def parse_jobs(result: ET.Element) -> dict[str, Any]:
    jobs: list[dict[str, Any]] = []
    for e in result.findall("job"):
        jobs.append(
            {
                "id": _int(_text(e, "id")),
                "type": _text(e, "type"),
                "user": _text(e, "user"),
                "status": _text(e, "status"),
                "result": _text(e, "result"),
                "progress": _text(e, "progress"),
                "queued": _text(e, "tenq"),
                "finished": _text(e, "tfin"),
                "description": _text(e, "description"),
            }
        )
    running = [j for j in jobs if j["status"] in ("ACT", "PEND")]
    commits = [
        j
        for j in jobs
        if (j["type"] or "").lower() in ("commit", "commitall", "commit-all") and j["status"] == "FIN"
    ]
    last_commit = max(commits, key=lambda j: j["id"] or 0) if commits else None
    return {
        "running": running,
        "last_commit": last_commit,
        "last_commit_time": _job_time(last_commit["finished"]) if last_commit else None,
        "total": len(jobs),
    }


def parse_pending_changes(result: ET.Element) -> bool:
    return (result.text or "").strip().lower() == "yes"


# --------------------------------------------------------------------------
# show running nat-policy (text) and DHCPv6 prefix-delegation pools
# --------------------------------------------------------------------------

_NAT_HEADER_RE = re.compile(r'^"(?P<name>.+?); index: (?P<index>\d+)" \{\s*$')
_NAT_LINE_RE = re.compile(r"^\s*(?P<key>[a-z0-9-]+)\s+(?P<value>.*?)\s*;\s*$")
_QUOTED_RE = re.compile(r'"([^"]*)"')
# An IPv6 prefix (must contain a colon; "(*)" markers are stripped first).
_PREFIX_RE = re.compile(r"(?<![\w:.])([0-9a-fA-F]*:[0-9a-fA-F:.]*/\d+)")


def _nat_value(raw: str) -> Any:
    raw = raw.strip()
    if raw.startswith("["):
        inner = raw.strip("[] ")
        quoted = _QUOTED_RE.findall(inner)
        return quoted if quoted else inner.split()
    if raw.startswith('"'):
        quoted = _QUOTED_RE.findall(raw)
        return quoted[0] if len(quoted) == 1 else quoted
    return raw or None


def parse_running_nat(result: ET.Element) -> dict[str, dict[str, Any]]:
    """'show running nat-policy' (vsys-scoped) -> {rule name: fields}.

    The first occurrence of a name is the configured rule; later ones (the
    implicit reverse of a bidirectional rule) are keyed "name (#index)".
    """
    text = "".join(result.itertext())
    rules: dict[str, dict[str, Any]] = {}
    current: dict[str, Any] | None = None
    for line in text.splitlines():
        if match := _NAT_HEADER_RE.match(line.strip()):
            name = match["name"]
            current = {"name": name, "index": int(match["index"])}
            # A bidirectional rule is listed twice under one name (forward and
            # reverse); keep both.
            key = name if name not in rules else f"{name} (#{match['index']})"
            rules[key] = current
            continue
        if current is None:
            continue
        if line.strip() == "}":
            current = None
            continue
        if match := _NAT_LINE_RE.match(line):
            current[match["key"].replace("-", "_")] = _nat_value(match["value"])
    return rules


def nptv6_prefixes(rule: dict[str, Any]) -> dict[str, Any]:
    """What an NPTv6 rule maps to the outside world.

    Returns {"direction", "public", "dynamic"}: for source translation the
    translated prefix; for inbound (destination) translation the matched
    destination prefix. ``dynamic`` is True for interface-address translation.
    """
    translate = rule.get("translate_to")
    items = translate if isinstance(translate, list) else [translate] if translate else []
    for item in items:
        item = item.strip().replace("(*)", "")
        if item.startswith("src:"):
            match = _PREFIX_RE.search(item)
            return {
                "direction": "outbound",
                "public": match.group(1) if match else None,
                "dynamic": "(dynamic-ip)" in item,
            }
        if item.startswith("dst:"):
            dest = rule.get("destination")
            dest = dest[0] if isinstance(dest, list) and dest else dest
            match = _PREFIX_RE.search(dest or "")
            return {"direction": "inbound", "public": match.group(1) if match else None, "dynamic": False}
    return {"direction": None, "public": None, "dynamic": False}


def parse_pd_pools(result: ET.Element) -> dict[str, dict[str, Any]]:
    """'show dhcp client ipv6 pool-details all' -> {pool name: {...}}."""
    pools: dict[str, dict[str, Any]] = {}
    for e in result.findall("pools/entry"):
        name = e.get("name")
        if not name:
            continue
        pools[name] = {
            "name": name,
            "prefix": _text(e, "prefix"),
            "interface": _text(e, "interface"),
            "state": _text(e, "state"),
            "lease": _text(e, "lease"),
            "preferred_lifetime": _int(_text(e, "preferred-lifetime")),
            "valid_lifetime": _int(_text(e, "valid-lifetime")),
            "inherited": {
                a.get("name"): _text(a, "address")
                for a in e.findall("address-assignment/entry")
                if a.get("name")
            },
        }
    return pools


def nptv6_mismatches(rules: dict[str, dict[str, Any]], pool: dict[str, Any]) -> tuple[list[str], list[str]]:
    """NPTv6 rules for this pool's WAN that don't fit the delegated prefix.

    A rule belongs to the pool's WAN when its to-interface is the pool's
    interface, or (for inbound rules without one) it sits in the same vsys.
    Returns (problems, rules checked).
    """
    problems: list[str] = []
    checked: list[str] = []
    try:
        delegated = ipaddress.ip_network(pool["prefix"], strict=False)
    except (TypeError, ValueError):
        return [f"{pool['name']}: no delegated prefix"], checked
    for name, rule in rules.items():
        if rule.get("nat_type") != "nptv6":
            continue
        to_if = rule.get("to_interface")
        if to_if and to_if != pool["interface"]:
            continue
        info = nptv6_prefixes(rule)
        if info["direction"] is None:
            continue
        checked.append(name)
        if info["dynamic"]:
            if info["public"] and info["public"].endswith("/128"):
                problems.append(
                    f"{name}: dynamic translation uses the interface's /128 address, "
                    f"not the delegated {pool['prefix']}"
                )
            continue
        try:
            public = ipaddress.ip_network(info["public"], strict=False)
        except (TypeError, ValueError):
            continue
        if public.version == delegated.version and not public.subnet_of(delegated):  # type: ignore[arg-type]
            problems.append(f"{name}: {info['direction']} uses {public}, outside delegated {delegated}")
    return problems, checked


# --------------------------------------------------------------------------
# Advanced Routing BGP (JSON wrapped in <json>)
# --------------------------------------------------------------------------


def _json_result(result: ET.Element) -> Any:
    node = result.find("json")
    text = node.text if node is not None else result.text
    if not text or not text.strip():
        return {}
    try:
        return json.loads(text)
    except json.JSONDecodeError as err:
        raise ValueError(f"Invalid JSON in response: {err}") from err


def parse_bgp_summary(result: ET.Element) -> dict[str, dict[str, Any]]:
    """{logical router: {enabled, router_id, local_as}}."""
    out = {}
    for lr, info in (_json_result(result) or {}).items():
        if isinstance(info, dict):
            out[lr] = {
                "enabled": str(info.get("enabled", "")).lower() in ("yes", "true"),
                "router_id": info.get("router-id"),
                "local_as": info.get("local-as"),
            }
    return out


def parse_bgp_peers(result: ET.Element) -> dict[str, dict[str, Any]]:
    """Per-logical-router 'bgp peer status' -> {peer name: {...}}."""
    peers: dict[str, dict[str, Any]] = {}
    for name, p in (_json_result(result) or {}).items():
        if not isinstance(p, dict) or "state" not in p:
            continue
        detail = p.get("detail") or {}
        prefixes = {
            afi: {
                "accepted": info.get("acceptedPrefixCounter"),
                "sent": info.get("sentPrefixCounter"),
            }
            for afi, info in (detail.get("addressFamilyInfo") or {}).items()
            if isinstance(info, dict)
        }
        status_time = p.get("status-time")
        peers[name] = {
            "state": p.get("state"),
            "established": p.get("state") == "Established",
            "peer_ip": p.get("peer-ip"),
            "local_ip": p.get("local-ip"),
            "remote_as": p.get("remote-as"),
            "local_as": p.get("local-as"),
            "peer_group": p.get("peer-group-name"),
            "ipv4": p.get("ipv4"),
            "ipv6": p.get("ipv6"),
            "state_seconds": int(status_time) if isinstance(status_time, (int, float)) else None,
            "uptime": detail.get("bgpTimerUpString"),
            "hostname": detail.get("hostname"),
            "last_reset": detail.get("lastResetDueTo"),
            "prefixes": prefixes,
        }
    return peers


# --------------------------------------------------------------------------
# Sessions
# --------------------------------------------------------------------------

_SESSION_FIELDS = {
    "idx": "id",
    "vsys": "vsys",
    "application": "application",
    "state": "state",
    "type": "type",
    "from": "from_zone",
    "to": "to_zone",
    "source": "source",
    "sport": "source_port",
    "dst": "destination",
    "dport": "destination_port",
    "proto": "protocol",
    "ingress": "ingress",
    "egress": "egress",
    "security-rule": "rule",
    "start-time": "start_time",
    "total-byte-count": "bytes",
}


def parse_sessions(result: ET.Element) -> list[dict[str, Any]]:
    """`show session all filter ...` entries, flattened."""
    sessions = []
    for e in result.findall("entry"):
        s: dict[str, Any] = {}
        for tag, key in _SESSION_FIELDS.items():
            text = _text(e, tag)
            numeric = key in ("id", "source_port", "destination_port", "protocol", "bytes")
            s[key] = _int(text) if numeric else text
        if _yes_bool(_text(e, "srcnat")):
            s["nat_source"] = f"{_text(e, 'xsource')}:{_text(e, 'xsport')}"
        if _yes_bool(_text(e, "dstnat")):
            s["nat_destination"] = f"{_text(e, 'xdst')}:{_text(e, 'xdport')}"
        sessions.append(s)
    return sessions


def parse_session_count(result: ET.Element) -> int | None:
    return _int(_text(result, "member"))


def _yes_bool(value: str | None) -> bool:
    return (value or "").strip().lower() in ("true", "yes")


def xml_to_dict(el: ET.Element) -> Any:
    """Generic element -> dict/str conversion (for detail views)."""
    children = list(el)
    if not children:
        return (el.text or "").strip() or None
    out: dict[str, Any] = {}
    for child in children:
        key = child.tag.replace("-", "_")
        value = xml_to_dict(child)
        if key in out:
            if not isinstance(out[key], list):
                out[key] = [out[key]]
            out[key].append(value)
        else:
            out[key] = value
    return out


# --------------------------------------------------------------------------
# GlobalProtect gateway users (current and previous)
# --------------------------------------------------------------------------


def _epoch_iso(value: str | None) -> str | None:
    ts = _int(value)
    if not ts:
        return None

    try:
        return datetime.fromtimestamp(ts, tz=UTC).isoformat()
    except (OverflowError, OSError, ValueError):
        return None


def _nonzero_ip(value: str | None) -> str | None:
    return None if value in (None, "::", "0.0.0.0") else value


def parse_gp_sessions(result: ET.Element) -> list[dict[str, Any]]:
    out = []
    for e in result.findall("entry"):
        user = _text(e, "username") or _text(e, "primary-username")
        if not user:
            continue
        out.append(
            {
                "username": user,
                "domain": _text(e, "domain"),
                "computer": _text(e, "computer"),
                "client": _text(e, "client"),
                "app_version": _text(e, "app-version"),
                "virtual_ip": _nonzero_ip(_text(e, "virtual-ip")),
                "virtual_ipv6": _nonzero_ip(_text(e, "virtual-ipv6")),
                "public_ip": _nonzero_ip(_text(e, "public-ip")),
                "public_ipv6": _nonzero_ip(_text(e, "public-ipv6")),
                "tunnel_type": _text(e, "tunnel-type"),
                "source_region": _text(e, "source-region"),
                "login_time": _epoch_iso(_text(e, "login-time-utc")),
                "logout_time": _epoch_iso(_text(e, "logout-time-utc")),
                "logout_reason": _text(e, "reason"),
            }
        )
    return out


def latest_gp_by_user(sessions: list[dict[str, Any]], time_key: str) -> dict[str, dict[str, Any]]:
    """Most recent session per username (by ``time_key``)."""
    out: dict[str, dict[str, Any]] = {}
    for s in sessions:
        prev = out.get(s["username"])
        if prev is None or (s.get(time_key) or "") > (prev.get(time_key) or ""):
            out[s["username"]] = s
    return out


# --------------------------------------------------------------------------
# GlobalProtect client package versions (6.3.3-c1199)
# --------------------------------------------------------------------------

_GP_RE = re.compile(r"^(\d+)\.(\d+)\.(\d+)(?:-c(\d+))?")


def gp_version_key(version: str | None) -> tuple[int, int, int, int] | None:
    if not version:
        return None
    match = _GP_RE.match(version.strip())
    if not match:
        return None
    major, minor, maint, build = match.groups()
    return int(major), int(minor), int(maint), int(build or 0)


def latest_gp_client(versions: list[dict[str, Any]], installed: str | None) -> dict[str, Any]:
    parsed = [(k, v) for v in versions if (k := gp_version_key(v["version"])) is not None]
    if not parsed:
        return {"train": None, "overall": None}
    overall = max(parsed, key=lambda p: p[0])[1]
    inst = gp_version_key(installed)
    train = None
    if inst:
        same = [p for p in parsed if p[0][:2] == inst[:2]]
        if same:
            train = max(same, key=lambda p: p[0])[1]
    return {"train": train, "overall": overall}


# --------------------------------------------------------------------------
# Certificates
# --------------------------------------------------------------------------

_ASN1_TIME = re.compile(r"^(\d{12})Z")


def _asn1_time(value: str | None) -> datetime | None:
    """'261020143727Z(Oct 20 ...)' -> aware datetime (UTCTime, YY < 50 => 20YY)."""
    if not value:
        return None
    match = _ASN1_TIME.match(value.strip())
    if not match:
        return None

    raw = match.group(1)
    year = int(raw[:2])
    year += 2000 if year < 50 else 1900
    return datetime.strptime(f"{year}{raw[2:]}", "%Y%m%d%H%M%S").replace(tzinfo=UTC)


def _cn(dn: str | None) -> str | None:
    if not dn:
        return None
    match = re.search(r"/CN=([^/]+)", dn)
    return match.group(1) if match else dn


_STORE_STATUS = {"V": "valid", "E": "expired", "R": "revoked"}


def parse_cert_store(result: ET.Element) -> list[dict[str, Any]]:
    """`show sslmgr-store config-certificate-info`: every cert in the config."""
    text = "".join(result.itertext())
    certs = []
    for block in re.split(r"\n\s*\n", text):
        fields = dict(re.findall(r"^\s*([\w-]+): ?(.*)$", block, re.M))
        expires = _asn1_time(fields.get("db-exp-date"))
        if expires is None:
            continue
        subject = fields.get("db-name")
        certs.append(
            {
                "name": _cn(subject),
                "subject": subject,
                "issuer": _cn(fields.get("issuer")),
                "serial": fields.get("db-serialno"),
                "expires": expires.isoformat(),
                "status": _STORE_STATUS.get(fields.get("db-status", "").strip(), fields.get("db-status")),
            }
        )
    return certs


_PEM_RE = re.compile(r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----", re.S)


def parse_device_certs(result: ET.Element) -> list[dict[str, Any]]:
    """`show sslmgr-store config-ca-certificate`: certs with private keys, by config name."""
    from cryptography import x509
    from cryptography.x509.oid import NameOID

    text = "".join(result.itertext())
    certs = []
    for block in re.split(r"\n\s*\n(?=[0-9A-F]{20,}:)", text):
        name = re.search(r"cert name: (.+)", block)
        pems = _PEM_RE.findall(block)
        if not name or not pems:
            continue
        entry: dict[str, Any] = {
            "name": name.group(1).strip(),
            "vsys": _int((re.search(r"vsys id: (\d+)", block) or [None, None])[1]),
            "private_key": bool(re.search(r"private key: exist", block)),
            "chain_length": len(pems),
        }
        try:
            cert = x509.load_pem_x509_certificate(pems[0].encode())
        except ValueError:
            continue

        def cn(n: x509.Name) -> str | None:
            attrs = n.get_attributes_for_oid(NameOID.COMMON_NAME)
            return str(attrs[0].value) if attrs else n.rfc4514_string() or None

        try:
            sans = cert.extensions.get_extension_for_class(
                x509.SubjectAlternativeName
            ).value.get_values_for_type(x509.DNSName)
        except x509.ExtensionNotFound:
            sans = []
        entry.update(
            {
                "subject": cn(cert.subject),
                "issuer": cn(cert.issuer),
                "not_before": cert.not_valid_before_utc.isoformat(),
                "expires": cert.not_valid_after_utc.isoformat(),
                "self_signed": cert.subject == cert.issuer,
                "san": sans,
            }
        )
        certs.append(entry)
    return certs


def certs_expiring(
    store: list[dict[str, Any]], now: datetime, warn_days: int
) -> dict[str, list[dict[str, Any]]]:
    """Split config certs into expiring-soon (still valid) and already-expired."""
    soon, expired = [], []
    for c in store:
        expires = datetime.fromisoformat(c["expires"])
        days = (expires - now).total_seconds() / 86400
        item = {"name": c["name"], "expires": c["expires"], "days_left": int(days // 1)}
        if c.get("status") == "revoked":
            continue
        if days < 0 or c.get("status") == "expired":
            expired.append(item)
        elif days <= warn_days:
            soon.append(item)
    soon.sort(key=lambda i: i["expires"])
    expired.sort(key=lambda i: i["expires"])
    return {"expiring": soon, "expired": expired}


def firewall_utc_offset(fw_time: str | None, utc_now: datetime) -> int | None:
    """Minutes the firewall's local clock is ahead of UTC (rounded to 15 min).

    ``fw_time`` is `show system info` <time>, e.g. 'Sat Oct 10 04:12:47 2026'.
    """
    if not fw_time:
        return None
    try:
        local = datetime.strptime(" ".join(fw_time.split()), "%a %b %d %H:%M:%S %Y")
    except ValueError:
        return None
    minutes = (local - utc_now.replace(tzinfo=None)).total_seconds() / 60
    offset = int(round(minutes / 15) * 15)
    return offset if -14 * 60 <= offset <= 14 * 60 else None
