"""Pure parsers for PAN-OS XML API responses.

Nothing in this module imports Home Assistant, so it can be unit tested on its
own. Every parser takes the <result> element of a successful API response.
"""

from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from datetime import date, datetime
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
    data = {
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
        data["load_1m"], data["load_5m"], data["load_15m"] = (
            float(g) for g in match.groups()
        )
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
            if (_text(entry, "name") or "").lower() == "packet buffer (average)":
                if (v := _first_number(_text(entry, "value"))) is not None:
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
            if section == "thermal":
                if (deg := _float(_text(entry, "DegreesC"))) is not None:
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
    users = [
        _text(e, "username") or _text(e, "primary-username") or "?"
        for e in result.findall("entry")
    ]
    return {"count": len(users), "users": users}


def parse_admins(result: ET.Element) -> dict[str, Any]:
    admins = [_text(e, "admin") or "?" for e in result.findall("admins/entry")]
    return {"count": len(admins), "users": admins}


def parse_ipsec_sa(result: ET.Element) -> dict[str, Any]:
    names = sorted(
        {_text(e, "name") or "?" for e in result.findall("entries/entry")}
    )
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
    licenses = []
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
    upcoming = [l for l in licenses if l["expires"] and not l["expired"]]
    next_expiry = min(upcoming, key=lambda l: l["expires"]) if upcoming else None
    return {
        "licenses": licenses,
        "next_expiry": next_expiry["expires"] if next_expiry else None,
        "next_expiry_feature": next_expiry["feature"] if next_expiry else None,
        "expired": [l["feature"] for l in licenses if l["expired"]],
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


def latest_panos(
    versions: list[dict[str, Any]], installed: str | None
) -> dict[str, Any]:
    """Pick the newest release in the installed feature train, and overall."""
    parsed = [
        (key, v) for v in versions if (key := panos_version_key(v["version"])) is not None
    ]
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
    parsed = [
        (key, v) for v in versions if (key := content_version_key(v["version"])) is not None
    ]
    if not parsed:
        return None
    return max(parsed, key=lambda p: p[0])[1]
