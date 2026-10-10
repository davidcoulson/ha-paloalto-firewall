"""Raise firewall problems that need a person as Home Assistant repair issues.

Expiring or expired certificates and licences, and an HA pair whose config
stays out of sync, appear under Settings -> Repairs and clear themselves once
fixed. Available software updates are not repeated here: the update entities
already put them in Settings -> Updates.
"""

from __future__ import annotations

from datetime import date, datetime, timedelta
from typing import Any

from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers import issue_registry as ir
from homeassistant.util import dt as dt_util

from .const import CERT_WARN_DAYS, DOMAIN, HA_SYNC_GRACE_MINUTES, LICENCE_WARN_DAYS
from .coordinator import PanOSConfigEntry
from .network import name_key, safe_key
from .parsers import certs_expiring


class PanOSRepairs:
    """Keeps this entry's repair issues in step with the latest poll data."""

    def __init__(self, hass: HomeAssistant, entry: PanOSConfigEntry) -> None:
        self.hass = hass
        self.entry = entry
        self.prefix = f"{entry.entry_id}_"
        # serial -> when its config was first seen out of sync
        self._unsynced_since: dict[str, datetime] = {}

    @callback
    def async_start(self) -> None:
        runtime = self.entry.runtime_data
        for unit in runtime.units:
            self.entry.async_on_unload(unit.coordinator.async_add_listener(self.async_evaluate))
            self.entry.async_on_unload(unit.updates.async_add_listener(self.async_evaluate))
        if runtime.network is not None:
            self.entry.async_on_unload(runtime.network.async_add_listener(self.async_evaluate))
        self.async_evaluate()

    @callback
    def async_evaluate(self) -> None:
        wanted: dict[str, dict[str, Any]] = {}
        known: set[str] = set()  # issue groups whose source data is current
        self._certificates(wanted, known)
        self._licences(wanted, known)
        self._ha_sync(wanted, known)

        registry = ir.async_get(self.hass)
        for (domain, issue_id), _issue in list(registry.issues.items()):
            if domain != DOMAIN or not issue_id.startswith(self.prefix) or issue_id in wanted:
                continue
            group = issue_id[len(self.prefix) :].split("_", 1)[0]
            if group in known:
                ir.async_delete_issue(self.hass, DOMAIN, issue_id)
        for issue_id, issue in wanted.items():
            ir.async_create_issue(
                self.hass,
                DOMAIN,
                issue_id,
                is_fixable=False,
                is_persistent=False,
                severity=issue["severity"],
                translation_key=issue["key"],
                translation_placeholders=issue["placeholders"],
            )

    def _certificates(self, wanted: dict[str, dict[str, Any]], known: set[str]) -> None:
        network = self.entry.runtime_data.network
        certs = (network.data or {}).get("certificates") if network else None
        if not certs or certs.get("store") is None:
            return
        known.add("cert")
        split = certs_expiring(certs["store"], dt_util.utcnow(), CERT_WARN_DAYS)
        for kind, severity in (("expiring", ir.IssueSeverity.WARNING), ("expired", ir.IssueSeverity.ERROR)):
            for cert in split[kind]:
                wanted[f"{self.prefix}cert_{name_key(cert['name'])}"] = {
                    "severity": severity,
                    "key": f"certificate_{kind}",
                    "placeholders": {
                        "name": cert["name"],
                        "firewall": self.entry.title,
                        "expires": cert["expires"][:10],
                        "days": str(abs(cert["days_left"])),
                    },
                }

    def _licences(self, wanted: dict[str, dict[str, Any]], known: set[str]) -> None:
        today = dt_util.now().date()
        units = self.entry.runtime_data.units
        all_current = True
        for unit in units:
            licences = (unit.updates.data or {}).get("licenses")
            if licences is None:
                all_current = False
                continue
            for lic in licences.get("licenses") or []:
                expires: date | None = lic.get("expires")
                days = (expires - today).days if expires else None
                if lic.get("expired") or (days is not None and days < 0):
                    kind, severity = "expired", ir.IssueSeverity.ERROR
                elif days is not None and days <= LICENCE_WARN_DAYS:
                    kind, severity = "expiring", ir.IssueSeverity.WARNING
                else:
                    continue
                issue_id = f"{self.prefix}licence_{unit.config.serial}_{safe_key(lic['feature'])}"
                wanted[issue_id] = {
                    "severity": severity,
                    "key": f"licence_{kind}",
                    "placeholders": {
                        "feature": lic["feature"],
                        "firewall": unit.config.hostname,
                        "expires": lic.get("expires_raw") or "unknown",
                        "days": str(abs(days)) if days is not None else "?",
                    },
                }
        if all_current:
            known.add("licence")

    def _ha_sync(self, wanted: dict[str, dict[str, Any]], known: set[str]) -> None:
        now = dt_util.utcnow()
        all_current = True
        for unit in self.entry.runtime_data.units:
            data = unit.coordinator.data if unit.coordinator.last_update_success else None
            if data is None:
                all_current = False
                continue
            ha = data.get("ha") or {}
            serial = unit.config.serial
            out_of_sync = (
                ha.get("enabled")
                and ha.get("running_sync_enabled")
                and ha.get("running_sync") != "synchronized"
            )
            if not out_of_sync:
                self._unsynced_since.pop(serial, None)
                continue
            since = self._unsynced_since.setdefault(serial, now)
            # A commit leaves the pair briefly out of sync; only raise it if it lasts.
            if now - since >= timedelta(minutes=HA_SYNC_GRACE_MINUTES):
                wanted[f"{self.prefix}hasync_{serial}"] = {
                    "severity": ir.IssueSeverity.WARNING,
                    "key": "ha_config_unsynced",
                    "placeholders": {
                        "firewall": unit.config.hostname,
                        "state": ha.get("running_sync") or "not synchronized",
                        "since": dt_util.as_local(since).strftime("%Y-%m-%d %H:%M"),
                    },
                }
        if all_current:
            known.add("hasync")


@callback
def async_remove_issues(hass: HomeAssistant, entry_id: str) -> None:
    """Drop every issue this entry raised (on unload or removal)."""
    registry = ir.async_get(hass)
    for domain, issue_id in list(registry.issues):
        if domain == DOMAIN and issue_id.startswith(f"{entry_id}_"):
            ir.async_delete_issue(hass, DOMAIN, issue_id)
