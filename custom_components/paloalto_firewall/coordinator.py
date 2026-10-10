"""Coordinators and HA-pair tracking for Palo Alto firewalls."""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any

from homeassistant.config_entries import ConfigEntry
from homeassistant.core import CALLBACK_TYPE, HomeAssistant, callback
from homeassistant.exceptions import ConfigEntryAuthFailed
from homeassistant.helpers import device_registry as dr
from homeassistant.helpers.device_registry import DeviceInfo
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator, UpdateFailed
from homeassistant.util import dt as dt_util

from . import parsers
from .api import PanOSAuthError, PanOSClient, PanOSError
from .const import (
    CMD_ADMINS,
    CMD_CONTENT_CHECK,
    CMD_DATAPLANE,
    CMD_ENVIRONMENTALS,
    CMD_GP_USERS,
    CMD_HA_STATE,
    CMD_IPSEC_SA,
    CMD_LICENSE_INFO,
    CMD_SESSION_INFO,
    CMD_SOFTWARE_CHECK,
    CMD_SYSTEM_INFO,
    CMD_SYSTEM_RESOURCES,
    DOMAIN,
    EVENT_FAILOVER,
    MANUFACTURER,
    UPDATE_CHECK_TIMEOUT,
    pair_identifier,
)

_LOGGER = logging.getLogger(__name__)

type PanOSConfigEntry = ConfigEntry[PanOSRuntimeData]


@dataclass
class UnitConfig:
    """Static info about one firewall, captured at config time."""

    index: int
    host: str
    serial: str
    hostname: str
    model: str | None


@dataclass
class PanOSUnit:
    config: UnitConfig
    client: PanOSClient
    coordinator: PanOSDeviceCoordinator
    updates: PanOSUpdatesCoordinator


@dataclass
class PanOSRuntimeData:
    name: str
    units: list[PanOSUnit]
    pair: PanOSPairTracker | None = None
    network: Any = None  # PanOSNetworkCoordinator (network.py)


def unit_device_info(entry: ConfigEntry, unit: UnitConfig, paired: bool) -> DeviceInfo:
    info = DeviceInfo(
        identifiers={(DOMAIN, unit.serial)},
        name=unit.hostname,
        manufacturer=MANUFACTURER,
        model=unit.model,
        serial_number=unit.serial,
        configuration_url=f"https://{unit.host}",
    )
    if paired:
        info["via_device"] = (DOMAIN, pair_identifier(entry.entry_id))
    return info


class _BaseCoordinator(DataUpdateCoordinator[dict[str, Any] | None]):
    config_entry: PanOSConfigEntry

    def __init__(
        self,
        hass: HomeAssistant,
        entry: PanOSConfigEntry,
        client: PanOSClient,
        unit: UnitConfig,
        name: str,
        interval: timedelta,
    ) -> None:
        super().__init__(
            hass,
            _LOGGER,
            config_entry=entry,
            name=f"{DOMAIN} {name} {unit.host}",
            update_interval=interval,
        )
        self.client = client
        self.unit = unit
        self._reported_unsupported: set[str] = set()

    async def _optional(
        self,
        key: str,
        cmd: str,
        parser: Callable[[Any], dict[str, Any]],
        timeout: int = 30,
    ) -> dict[str, Any] | None:
        """Run a command whose failure should not take the device offline."""
        try:
            return parser(await self.client.op(cmd, timeout=timeout))
        except PanOSAuthError as err:
            raise ConfigEntryAuthFailed(str(err)) from err
        except (PanOSError, ValueError, AttributeError) as err:
            if key not in self._reported_unsupported:
                self._reported_unsupported.add(key)
                _LOGGER.debug(
                    "%s: '%s' unavailable (%s); related entities will be unknown",
                    self.unit.host,
                    key,
                    err,
                )
            return None


class PanOSDeviceCoordinator(_BaseCoordinator):
    """Fast poll: status, HA state, performance."""

    def __init__(self, hass, entry, client, unit, interval: timedelta) -> None:
        super().__init__(hass, entry, client, unit, "status", interval)
        self._boot_time: datetime | None = None

    async def _async_update_data(self) -> dict[str, Any]:
        try:
            system = parsers.parse_system_info(await self.client.op(CMD_SYSTEM_INFO))
        except PanOSAuthError as err:
            raise ConfigEntryAuthFailed(str(err)) from err
        except (PanOSError, ValueError) as err:
            raise UpdateFailed(f"{self.unit.host}: {err}") from err

        if system["serial"] != self.unit.serial:
            _LOGGER.warning(
                "%s now reports serial %s but was configured as %s; is the "
                "management address pointing at the right firewall?",
                self.unit.host,
                system["serial"],
                self.unit.serial,
            )

        optional = {
            "ha": (CMD_HA_STATE, parsers.parse_ha_state),
            "session": (CMD_SESSION_INFO, parsers.parse_session_info),
            "resources": (CMD_SYSTEM_RESOURCES, parsers.parse_system_resources),
            "dataplane": (CMD_DATAPLANE, parsers.parse_dataplane),
            "environment": (CMD_ENVIRONMENTALS, parsers.parse_environmentals),
            "gp_users": (CMD_GP_USERS, parsers.parse_gp_users),
            "admins": (CMD_ADMINS, parsers.parse_admins),
            "ipsec": (CMD_IPSEC_SA, parsers.parse_ipsec_sa),
        }
        results = await asyncio.gather(
            *(self._optional(k, cmd, fn) for k, (cmd, fn) in optional.items())
        )
        data: dict[str, Any] = {"system": system, **dict(zip(optional, results))}
        data["boot_time"] = self._stable_boot_time(system.get("uptime_seconds"))
        self._sync_device_registry(system)
        return data

    def _stable_boot_time(self, uptime: int | None) -> datetime | None:
        if uptime is None:
            return None
        boot = (dt_util.utcnow() - timedelta(seconds=uptime)).replace(microsecond=0)
        # Avoid a new state every poll because of clock/rounding jitter.
        if self._boot_time and abs((boot - self._boot_time).total_seconds()) < 120:
            return self._boot_time
        self._boot_time = boot
        return boot

    @callback
    def _sync_device_registry(self, system: dict[str, Any]) -> None:
        registry = dr.async_get(self.hass)
        device = registry.async_get_device(identifiers={(DOMAIN, self.unit.serial)})
        if device is None:
            return
        changes: dict[str, Any] = {}
        if system.get("sw_version") and device.sw_version != system["sw_version"]:
            changes["sw_version"] = system["sw_version"]
        if system.get("hostname") and device.name != system["hostname"]:
            changes["name"] = system["hostname"]
        if changes:
            registry.async_update_device(device.id, **changes)


class PanOSUpdatesCoordinator(_BaseCoordinator):
    """Slow poll: software/content update checks and licences."""

    def __init__(self, hass, entry, client, unit, interval: timedelta) -> None:
        super().__init__(hass, entry, client, unit, "updates", interval)

    async def _async_update_data(self) -> dict[str, Any]:
        software, content, licenses = await asyncio.gather(
            self._optional(
                "software", CMD_SOFTWARE_CHECK, parsers.parse_software_check, UPDATE_CHECK_TIMEOUT
            ),
            self._optional(
                "content", CMD_CONTENT_CHECK, parsers.parse_content_check, UPDATE_CHECK_TIMEOUT
            ),
            self._optional("licenses", CMD_LICENSE_INFO, parsers.parse_licenses),
        )
        if software is None and content is None and licenses is None:
            raise UpdateFailed(
                f"{self.unit.host}: update and licence checks all failed "
                "(no route to the update server?)"
            )
        return {"software": software, "content": content, "licenses": licenses}


class PanOSPairTracker:
    """Combines the two units' views into a single HA-pair picture."""

    def __init__(self, hass: HomeAssistant, entry: PanOSConfigEntry, units: list[PanOSUnit]) -> None:
        self.hass = hass
        self.entry = entry
        self.units = units
        # active_index is the last known active unit (kept across gaps so a
        # failover during an outage is still detected); current_index is the
        # live view and is None when no unit is known to be active.
        self.active_index: int | None = None
        self.current_index: int | None = None
        self.last_failover: datetime | None = None
        self._listeners: list[CALLBACK_TYPE] = []

    @callback
    def async_start(self) -> None:
        for unit in self.units:
            self.entry.async_on_unload(unit.coordinator.async_add_listener(self._handle_update))
        self.active_index = self.current_index = self.compute_active_index()

    @callback
    def async_add_listener(self, update_callback: CALLBACK_TYPE) -> CALLBACK_TYPE:
        self._listeners.append(update_callback)

        @callback
        def remove() -> None:
            self._listeners.remove(update_callback)

        return remove

    def unit_data(self, index: int) -> dict[str, Any] | None:
        coordinator = self.units[index].coordinator
        return coordinator.data if coordinator.last_update_success else None

    @property
    def any_available(self) -> bool:
        return any(u.coordinator.last_update_success for u in self.units)

    def compute_active_index(self) -> int | None:
        data = [self.unit_data(i) for i in range(len(self.units))]
        # A unit that says it is active wins.
        for i, d in enumerate(data):
            ha = (d or {}).get("ha") or {}
            if ha.get("enabled") and ha.get("local_state") in ("active", "active-primary"):
                return i
        # Otherwise trust a reachable unit's view of its peer.
        for i, d in enumerate(data):
            ha = (d or {}).get("ha") or {}
            if ha.get("enabled") and ha.get("peer_state") in ("active", "active-primary"):
                return 1 - i
        return None

    @property
    def active_unit(self) -> PanOSUnit | None:
        return self.units[self.current_index] if self.current_index is not None else None

    def active_data(self) -> dict[str, Any] | None:
        return self.unit_data(self.current_index) if self.current_index is not None else None

    def health(self) -> tuple[bool, list[str]]:
        """Return (healthy, problems)."""
        if not self.any_available:
            return False, ["no firewall reachable"]
        problems: list[str] = []
        states = []
        for i, unit in enumerate(self.units):
            d = self.unit_data(i)
            if d is None:
                problems.append(f"{unit.config.hostname} unreachable")
                continue
            ha = d.get("ha")
            if ha is None:
                problems.append(f"{unit.config.hostname}: HA state unavailable")
                continue
            if not ha.get("enabled"):
                problems.append(f"{unit.config.hostname}: HA not enabled")
                continue
            states.append(ha.get("local_state"))
            if ha.get("peer_conn_status") != "up":
                problems.append(f"{unit.config.hostname}: peer connection {ha.get('peer_conn_status')}")
            if ha.get("running_sync_enabled") and ha.get("running_sync") != "synchronized":
                problems.append(f"{unit.config.hostname}: config {ha.get('running_sync') or 'not synchronized'}")
            if ha.get("local_state") in ("suspended", "non-functional", "tentative", "initial"):
                problems.append(f"{unit.config.hostname}: {ha.get('local_state')}")
        active = [s for s in states if s in ("active", "active-primary", "active-secondary")]
        if self.compute_active_index() is None:
            problems.append("no active firewall")
        elif len(active) > 1 and "active-primary" not in active:
            problems.append("both firewalls active (split brain)")
        return not problems, sorted(set(problems))

    @callback
    def _handle_update(self) -> None:
        new_index = self.compute_active_index()
        if (
            new_index is not None
            and self.active_index is not None
            and new_index != self.active_index
        ):
            old = self.units[self.active_index].config
            new = self.units[new_index].config
            self.last_failover = dt_util.utcnow()
            _LOGGER.warning("HA failover: %s -> %s is now active", old.hostname, new.hostname)
            self.hass.bus.async_fire(
                EVENT_FAILOVER,
                {
                    "entry_id": self.entry.entry_id,
                    "previous_active": old.hostname,
                    "previous_serial": old.serial,
                    "new_active": new.hostname,
                    "new_serial": new.serial,
                },
            )
        self.current_index = new_index
        if new_index is not None:
            self.active_index = new_index
        for listener in list(self._listeners):
            listener()
