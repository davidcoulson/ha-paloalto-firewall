"""High and critical threat log entries from the active firewall.

Each poll reads the newest matching threat log entries. Entries newer than
the last one seen fire a ``paloalto_firewall_threat`` event, and a sensor
counts the last 24 hours. Needs the *Log* permission in the admin role's XML
API settings; without it the first query is refused at once, a repair issue
explains what to change, and polling stops until the integration is reloaded.
"""

from __future__ import annotations

import logging
import xml.etree.ElementTree as ET
from datetime import UTC, datetime, timedelta, timezone
from typing import Any

from homeassistant.core import HomeAssistant
from homeassistant.exceptions import ConfigEntryAuthFailed
from homeassistant.helpers import issue_registry as ir
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator, UpdateFailed
from homeassistant.util import dt as dt_util

from .api import PanOSApiError, PanOSAuthError, PanOSError
from .const import DOMAIN, EVENT_THREAT, THREAT_QUERY
from .coordinator import PanOSConfigEntry
from .network import pick_unit
from .parsers import firewall_utc_offset

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
        # No polling until start(): the sensor's listener would otherwise
        # schedule a poll one interval after setup, even mid-startup.
        super().__init__(hass, _LOGGER, config_entry=entry, name=f"{DOMAIN} threats", update_interval=None)
        self._interval = interval
        self._unit: str | None = None
        self._serial: str | None = None
        self._incomplete_until: datetime | None = None
        self._last_seq: int | None = None
        self._recent: dict[int, dict[str, Any]] = {}
        self._issue_id = f"{entry.entry_id}_permission_threat_log"

    async def async_start(self) -> None:
        """Begin polling (once Home Assistant has started)."""
        self.update_interval = self._interval
        await self.async_refresh()

    def _permission_denied(self, hostname: str) -> None:
        """The role can't read logs: say so once and stop asking."""
        _LOGGER.warning(
            "Threat alerts need the Log permission in the admin role's XML API settings "
            "(Device > Admin Roles); %s refused the log query. Threat polling is off "
            "until the integration is reloaded",
            hostname,
        )
        # No more scheduled polls; a reload (or restart) checks again.
        self.update_interval = None
        ir.async_create_issue(
            self.hass,
            DOMAIN,
            self._issue_id,
            is_fixable=False,
            is_persistent=False,
            severity=ir.IssueSeverity.WARNING,
            translation_key="threat_log_permission",
            translation_placeholders={"firewall": hostname},
        )

    def _utc_offset(self, unit: Any) -> int | None:
        """The firewall's UTC offset, from its own clock (always read during setup)."""
        system = (unit.coordinator.data or {}).get("system") or {}
        offset = firewall_utc_offset(system.get("time"), dt_util.utcnow())
        if offset is None:
            network = self.config_entry.runtime_data.network
            offset = (network.data or {}).get("utc_offset_minutes") if network else None
        return offset

    async def _async_update_data(self) -> dict[str, Any]:
        unit = pick_unit(self.config_entry)
        if unit.config.serial != self._serial:
            # Sequence numbers are per firewall: start over after a failover.
            self._serial = unit.config.serial
            self._last_seq = None
            self._recent.clear()
            self._incomplete_until = None
        self._unit = unit.config.hostname
        first = self._last_seq is None
        nlogs = FIRST_READ if first else POLL_READ
        try:
            entries = await unit.client.log_query("threat", THREAT_QUERY, nlogs=nlogs, timeout=60)
        except PanOSAuthError as err:
            raise ConfigEntryAuthFailed(str(err)) from err
        except PanOSApiError as err:
            # 403: "not authorized for user role"; 16: "Unauthorized request".
            if err.code in ("403", "16"):
                # Not an outage: report it once (warning + repair) rather
                # than as a failed update on every start.
                self._permission_denied(unit.config.hostname)
                return {"denied": True}
            raise UpdateFailed(f"Threat log query failed: {err}") from err
        except PanOSError as err:
            raise UpdateFailed(f"Threat log query failed: {err}") from err

        ir.async_delete_issue(self.hass, DOMAIN, self._issue_id)
        offset = self._utc_offset(unit)
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

        now = dt_util.utcnow()
        cutoff = now - timedelta(seconds=KEEP)
        if len(entries) >= nlogs:
            # The read hit its limit, so older matching entries were skipped.
            # That only matters if the oldest one returned is still inside the
            # 24 h window; the count is then a lower bound until it ages out.
            times = [datetime.fromisoformat(t["time"]) for t in threats if t["time"]]
            oldest = min(times) if times else None
            if oldest is not None and oldest >= cutoff:
                until = oldest + timedelta(seconds=KEEP)
                if self._incomplete_until is None or until > self._incomplete_until:
                    self._incomplete_until = until
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
            # A read hit its limit within the last 24 h: the count may be low.
            "capped": self._incomplete_until is not None and now < self._incomplete_until,
        }
