"""Raise firewall problems that need a person as Home Assistant repair issues.

Expiring or expired certificates and licences, an HA pair whose config
stays out of sync, and PAN-OS / GlobalProtect client releases waiting to be
installed appear under Settings -> Repairs and clear themselves once fixed.

Updates are raised here because the update entities are read-only (the API
account can't install anything), and Home Assistant's Settings -> Updates list
only shows updates it can install. Content updates are left out: the
firewall's own dynamic-update schedule normally installs those.
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
from .parsers import certs_expiring, gp_version_key, latest_gp_client, latest_panos, panos_version_key


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
        # Issue-id prefixes whose source data was read successfully this time:
        # only those issues may be withdrawn. A failed read never resolves one.
        known: set[str] = set()
        self._certificates(wanted, known)
        self._licences(wanted, known)
        self._ha_sync(wanted, known)
        self._updates(wanted, known)

        registry = ir.async_get(self.hass)
        for (domain, issue_id), _issue in list(registry.issues.items()):
            if domain != DOMAIN or not issue_id.startswith(self.prefix) or issue_id in wanted:
                continue
            suffix = issue_id[len(self.prefix) :]
            if any(suffix.startswith(group) for group in known):
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
        known.add("cert_")
        split = certs_expiring(certs["store"], dt_util.utcnow(), CERT_WARN_DAYS)
        for kind, severity in (("expiring", ir.IssueSeverity.WARNING), ("expired", ir.IssueSeverity.ERROR)):
            for cert in split[kind]:
                # Several certificates can share a CN (renewals, scopes): key by serial too.
                wanted[
                    f"{self.prefix}cert_{name_key(cert['name'], cert.get('serial'), cert.get('issuer'))}"
                ] = {
                    "severity": severity,
                    "key": f"certificate_{kind}",
                    "placeholders": {
                        "name": cert["name"],
                        "firewall": self._firewall_names(),
                        "expires": cert["expires"][:10],
                        "days": str(abs(cert["days_left"])),
                    },
                }

    def _firewall_names(self) -> str:
        """Certificates live in the shared config, so name every unit."""
        return " & ".join(u.config.hostname for u in self.entry.runtime_data.units)

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
            known.add("licence_")

    def _ha_sync(self, wanted: dict[str, dict[str, Any]], known: set[str]) -> None:
        now = dt_util.utcnow()
        all_current = True
        for unit in self.entry.runtime_data.units:
            data = unit.coordinator.data if unit.coordinator.last_update_success else None
            if data is None:
                all_current = False
                continue
            ha = data.get("ha")
            serial = unit.config.serial
            if ha is None:
                # HA state couldn't be read this poll: unknown, not "in sync".
                all_current = False
                continue
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
            known.add("hasync_")

    def _updates(self, wanted: dict[str, dict[str, Any]], known: set[str]) -> None:
        kinds = (
            ("panos", "software", "sw_version", latest_panos, panos_version_key),
            ("gpclient", "gp_client", "gp_client_version", latest_gp_client, gp_version_key),
        )
        read_ok = {k[0]: True for k in kinds}
        # kind -> newest version -> [(hostname, installed, HA state)]
        pending: dict[str, dict[str, list[tuple[str, str, str | None]]]] = {k[0]: {} for k in kinds}
        for unit in self.entry.runtime_data.units:
            checks = unit.updates.data
            system = (unit.coordinator.data or {}).get("system")
            if checks is None or system is None:
                read_ok = dict.fromkeys(read_ok, False)
                continue
            ha = (unit.coordinator.data or {}).get("ha") or {}
            ha_state = ha.get("local_state") if ha.get("enabled") else None
            for kind, section, installed_key, latest_fn, key_fn in kinds:
                installed = system.get(installed_key)
                if checks.get(section) is None:
                    # This unit's check failed: an existing repair stays.
                    read_ok[kind] = False
                    continue
                versions = checks[section].get("versions")
                if not installed or installed == "0.0.0" or versions is None:
                    continue
                train = latest_fn(versions, installed)["train"]
                if train is None:
                    continue
                newest, current = key_fn(train["version"]), key_fn(installed)
                if newest is not None and current is not None and newest > current:
                    pending[kind].setdefault(train["version"], []).append(
                        (unit.config.hostname, installed, ha_state)
                    )
        paired = len(self.entry.runtime_data.units) > 1
        for kind, by_version in pending.items():
            for version, units in by_version.items():
                # Passive firewall first: that's the order to upgrade an HA pair.
                units.sort(key=lambda u: _is_active(u[2]))
                wanted[f"{self.prefix}update_{kind}_{name_key(version)}"] = {
                    "severity": ir.IssueSeverity.WARNING,
                    "key": f"update_{kind}",
                    "placeholders": {
                        "version": version,
                        "names": " & ".join(u[0] for u in units),
                        "firewalls": ", ".join(f"{u[0]} ({u[1]})" for u in units),
                        "commands": _commands(kind, version, units, paired),
                    },
                }
        for kind, ok in read_ok.items():
            if ok:
                known.add(f"update_{kind}_")


def _is_active(state: str | None) -> bool:
    return bool(state) and str(state).startswith("active")


def _commands(kind: str, version: str, units: list[tuple[str, str, str | None]], paired: bool) -> str:
    """CLI to apply the update, one block per firewall in upgrade order."""
    blocks = []
    for host, _installed, state in units:
        label = f"# {host}" + (f" ({state})" if state else "")
        if kind == "gpclient":
            lines = [
                f"request global-protect-client software download version {version}",
                "show jobs all   # wait for the download to show FIN / OK",
                f"request global-protect-client software activate version {version}",
            ]
        else:
            # On a pair, the active unit hands over before it restarts, even if
            # its peer is already on this version.
            active = _is_active(state)
            lines = []
            if active and paired:
                lines.append("request high-availability state suspend   # fail over to the upgraded peer")
            lines += [
                f"request system software download version {version}",
                "show jobs all   # wait for the download to show FIN / OK",
                f"request system software install version {version}",
                "show jobs all   # wait for the install to show FIN / OK",
                "request restart system",
            ]
            if active and paired:
                lines.append("request high-availability state functional   # once it's back up")
        blocks.append("\n".join([label, *lines]))
    return "```\n" + "\n\n".join(blocks) + "\n```"


@callback
def async_remove_issues(hass: HomeAssistant, entry_id: str) -> None:
    """Drop every issue this entry raised (on unload or removal)."""
    registry = ir.async_get(hass)
    for domain, issue_id in list(registry.issues):
        if domain == DOMAIN and issue_id.startswith(f"{entry_id}_"):
            ir.async_delete_issue(hass, DOMAIN, issue_id)
