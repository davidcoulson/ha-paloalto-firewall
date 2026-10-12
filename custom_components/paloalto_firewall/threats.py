"""High and critical threat log entries from the active firewall.

Each poll reads the newest matching threat log entries. Entries newer than
the last one seen fire a ``paloalto_firewall_threat`` event, and a sensor
counts the last 24 hours. Needs the *Log* permission in the admin role's XML
API settings; without it the sensor stays unavailable.
"""

from __future__ import annotations

import logging
import xml.etree.ElementTree as ET
from datetime import UTC, datetime, timedelta, timezone
from typing import Any

from homeassistant.core import HomeAssistant
from homeassistant.exceptions import ConfigEntryAuthFailed
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator, UpdateFailed
from homeassistant.util import dt as dt_util

from .api import PanOSApiError, PanOSAuthError, PanOSError
from .const import DOMAIN, EVENT_THREAT, THREAT_QUERY
from .coordinator import PanOSConfigEntry
from .network import pick_unit

_LOGGER = logging.getLogger(__package__)

FIRST_READ = 500  # entries read to fill the 24 h count after startup or failover
POLL_READ = 100  # newest entries read on each later poll
KEEP = 24 * 3600
LATEST = 10

FIELDS = {
    "seqno": "seqno",
    "time_generated": "time",
    "severity": "severity",
    "threatid": "threat",
    "subtype": "type",
    "category": "category",
    "action": "action",
    "src": "source",
    "dst": "destination",
    "sport": "source_port",
    "dport": "destination_port",
    "app": "application",
    "proto": "protocol",
    "rule": "rule",
    "from": "from_zone",
    "to": "to_zone",
    "srcuser": "source_user",
    "direction": "direction",
    "misc": "detail",
}


def parse_threat(entry: ET.Element, utc_offset_minutes: int | None) -> dict[str, Any] | None:
    item: dict[str, Any] = {key: (entry.findtext(tag) or "").strip() or None for tag, key in FIELDS.items()}
    try:
        item["seqno"] = int(item["seqno"] or "")
    except ValueError:
        return None
    item["time"] = _to_utc(item["time"], utc_offset_minutes)
    return item


def _to_utc(text: str | None, offset_minutes: int | None) -> str | None:
    """Log times are the firewall's local clock ('2026/10/11 22:30:01')."""
    if not text:
        return None
    try:
        local = datetime.strptime(text, "%Y/%m/%d %H:%M:%S")
    except ValueError:
        return None
    if offset_minutes is None:
        aware = local.replace(tzinfo=dt_util.get_default_time_zone())
    else:
        aware = local.replace(tzinfo=timezone(timedelta(minutes=offset_minutes)))
    return aware.astimezone(UTC).isoformat()


class PanOSThreatCoordinator(DataUpdateCoordinator[dict[str, Any]]):
    config_entry: PanOSConfigEntry

    def __init__(self, hass: HomeAssistant, entry: PanOSConfigEntry, interval: timedelta) -> None:
        super().__init__(
            hass, _LOGGER, config_entry=entry, name=f"{DOMAIN} threats", update_interval=interval
        )
        self._unit: str | None = None
        self._last_seq: int | None = None
        self._recent: dict[int, dict[str, Any]] = {}
        self._denied_logged = False

    async def _async_update_data(self) -> dict[str, Any]:
        unit = pick_unit(self.config_entry)
        if unit.config.hostname != self._unit:
            # Sequence numbers are per firewall: start over after a failover.
            self._unit = unit.config.hostname
            self._last_seq = None
            self._recent.clear()
        first = self._last_seq is None
        try:
            entries = await unit.client.log_query(
                "threat", THREAT_QUERY, nlogs=FIRST_READ if first else POLL_READ, timeout=60
            )
        except PanOSAuthError as err:
            raise ConfigEntryAuthFailed(str(err)) from err
        except PanOSApiError as err:
            if err.code == "403":
                if not self._denied_logged:
                    self._denied_logged = True
                    _LOGGER.warning(
                        "Threat alerts need the Log permission in the admin role's XML API "
                        "settings (Device > Admin Roles); %s refused the log query",
                        unit.config.hostname,
                    )
                raise UpdateFailed("Log queries are not permitted for this admin role") from err
            raise UpdateFailed(f"Threat log query failed: {err}") from err
        except PanOSError as err:
            raise UpdateFailed(f"Threat log query failed: {err}") from err

        network = self.config_entry.runtime_data.network
        offset = (network.data or {}).get("utc_offset_minutes") if network else None
        threats = [t for e in entries if (t := parse_threat(e, offset))]
        threats.sort(key=lambda t: t["seqno"])
        if not first:
            for threat in threats:
                if threat["seqno"] > (self._last_seq or 0):
                    self.hass.bus.async_fire(
                        EVENT_THREAT,
                        {"entry_id": self.config_entry.entry_id, "firewall": self._unit, **threat},
                    )
        if threats:
            self._last_seq = max(self._last_seq or 0, threats[-1]["seqno"])
        elif first:
            self._last_seq = 0
        for threat in threats:
            self._recent[threat["seqno"]] = threat

        cutoff = dt_util.utcnow() - timedelta(seconds=KEEP)
        self._recent = {
            seq: t
            for seq, t in self._recent.items()
            if t["time"] and datetime.fromisoformat(t["time"]) >= cutoff
        }
        recent = sorted(self._recent.values(), key=lambda t: -t["seqno"])
        by_severity: dict[str, int] = {}
        for threat in recent:
            by_severity[threat["severity"] or "unknown"] = (
                by_severity.get(threat["severity"] or "unknown", 0) + 1
            )
        return {
            "firewall": self._unit,
            "count_24h": len(recent),
            "by_severity": by_severity,
            "latest": recent[:LATEST],
            # The first read is capped, so a very busy day may be undercounted.
            "capped": first and len(entries) >= FIRST_READ,
        }
