"""Binary sensors for Palo Alto firewalls."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from homeassistant.components.binary_sensor import (
    BinarySensorDeviceClass,
    BinarySensorEntity,
    BinarySensorEntityDescription,
)
from homeassistant.const import EntityCategory
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers import entity_registry as er
from homeassistant.helpers.entity_platform import AddConfigEntryEntitiesCallback
from homeassistant.util import dt as dt_util

from .const import CERT_WARN_DAYS
from .parsers import certs_expiring

from .coordinator import PanOSConfigEntry
from .entity import PanOSNetworkEntity, PanOSPairEntity, PanOSUnitEntity, PanOSUpdatesEntity
from .network import lr_device_info, pm_key_suffix, safe_key

Data = dict[str, Any]


def _ha(data: Data) -> Data:
    ha = data.get("ha") or {}
    return ha if ha.get("enabled") else {}


@dataclass(frozen=True, kw_only=True)
class PanOSBinaryDescription(BinarySensorEntityDescription):
    value_fn: Callable[[Data], bool | None]
    attrs_fn: Callable[[Data], dict[str, Any]] | None = None
    exists_fn: Callable[[Data | None, bool], bool] = lambda data, paired: True


def _ha_exists(data: Data | None, paired: bool) -> bool:
    return paired or data is None or bool((data.get("ha") or {}).get("enabled"))


UNIT_BINARY: tuple[PanOSBinaryDescription, ...] = (
    PanOSBinaryDescription(
        key="ha_peer_connected",
        name="HA peer connection",
        device_class=BinarySensorDeviceClass.CONNECTIVITY,
        value_fn=lambda d: (_ha(d).get("peer_conn_status") == "up") if _ha(d) else None,
        attrs_fn=lambda d: {
            "ha1": _ha(d).get("ha1_status"),
            "ha1_backup": _ha(d).get("ha1_backup_status"),
            "ha2": _ha(d).get("ha2_status"),
        },
        exists_fn=_ha_exists,
    ),
    PanOSBinaryDescription(
        key="ha_config_synced",
        name="HA config synchronized",
        icon="mdi:sync",
        value_fn=lambda d: (_ha(d).get("running_sync") == "synchronized") if _ha(d) else None,
        attrs_fn=lambda d: {"running_sync": _ha(d).get("running_sync")},
        exists_fn=_ha_exists,
    ),
    PanOSBinaryDescription(
        key="hardware_alarm",
        name="Hardware alarm",
        device_class=BinarySensorDeviceClass.PROBLEM,
        entity_category=EntityCategory.DIAGNOSTIC,
        value_fn=lambda d: (d.get("environment") or {}).get("alarm"),
        attrs_fn=lambda d: {"alarms": (d.get("environment") or {}).get("alarms")},
        exists_fn=lambda data, paired: data is None or data.get("environment") is not None,
    ),
)

LICENSE_BINARY = PanOSBinaryDescription(
    key="license_expired",
    name="Licence expired",
    device_class=BinarySensorDeviceClass.PROBLEM,
    entity_category=EntityCategory.DIAGNOSTIC,
    value_fn=lambda d: bool((d.get("licenses") or {}).get("expired")),
    attrs_fn=lambda d: {"expired": (d.get("licenses") or {}).get("expired")},
)

PAIR_HEALTH = BinarySensorEntityDescription(
    key="ha_pair_problem",
    name="HA pair problem",
    device_class=BinarySensorDeviceClass.PROBLEM,
)


async def async_setup_entry(
    hass: HomeAssistant,
    entry: PanOSConfigEntry,
    async_add_entities: AddConfigEntryEntitiesCallback,
) -> None:
    runtime = entry.runtime_data
    paired = runtime.pair is not None
    entities: list[BinarySensorEntity] = []
    for unit in runtime.units:
        entities.extend(
            PanOSUnitBinary(entry, unit, desc)
            for desc in UNIT_BINARY
            if desc.exists_fn(unit.coordinator.data, paired)
        )
        entities.append(PanOSLicenseBinary(entry, unit, LICENSE_BINARY))
    if runtime.pair:
        entities.append(PanOSPairHealth(entry, runtime.pair, PAIR_HEALTH))
    async_add_entities(entities)
    _track_network_entities(entry, async_add_entities)
    _track_gp_users(hass, entry, async_add_entities)


GP_UID = "gp_user_"
GP_NAME = "GlobalProtect "


def _track_gp_users(
    hass: HomeAssistant, entry: PanOSConfigEntry, async_add_entities: AddConfigEntryEntitiesCallback
) -> None:
    """One connectivity sensor per GlobalProtect user, added as users appear.

    Users seen before (in the entity registry) are restored even when the
    firewall's previous-user history no longer lists them.
    """
    network = entry.runtime_data.network
    if network is None:
        return
    prefix = f"{entry.entry_id}_{GP_UID}"
    restored = {
        ent.original_name[len(GP_NAME):]
        for ent in er.async_entries_for_config_entry(er.async_get(hass), entry.entry_id)
        if ent.unique_id.startswith(prefix)
        and ent.original_name
        and ent.original_name.startswith(GP_NAME)
    }
    network.remember_gp_users(restored)
    added: set[str] = set()

    @callback
    def _add_new() -> None:
        users = set(((network.data or {}).get("gp_users") or {})) | restored
        new = sorted(users - added)
        if new:
            added.update(new)
            async_add_entities(PanOSGlobalProtectUser(entry, u) for u in new)

    _add_new()
    entry.async_on_unload(network.async_add_listener(_add_new))


class PanOSUnitBinary(PanOSUnitEntity, BinarySensorEntity):
    entity_description: PanOSBinaryDescription

    @property
    def is_on(self) -> bool | None:
        return self.entity_description.value_fn(self.data)

    @property
    def extra_state_attributes(self) -> dict[str, Any] | None:
        if fn := self.entity_description.attrs_fn:
            return fn(self.data)
        return None


class PanOSLicenseBinary(PanOSUpdatesEntity, BinarySensorEntity):
    entity_description: PanOSBinaryDescription

    @property
    def available(self) -> bool:
        return super().available and self.data.get("licenses") is not None

    @property
    def is_on(self) -> bool | None:
        return self.entity_description.value_fn(self.data)

    @property
    def extra_state_attributes(self) -> dict[str, Any] | None:
        return self.entity_description.attrs_fn(self.data)  # type: ignore[misc]


class PanOSPairHealth(PanOSPairEntity, BinarySensorEntity):
    @property
    def is_on(self) -> bool:
        healthy, _ = self.pair.health()
        return not healthy

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        _, problems = self.pair.health()
        return {"problems": problems}

    @property
    def available(self) -> bool:
        # Stays available when both units are down: that *is* the problem.
        return True


# --------------------------------------------------------------------------
# Pair-wide network binary sensors
# --------------------------------------------------------------------------


def network_binary_sensors(entry: PanOSConfigEntry) -> list[BinarySensorEntity]:
    network = entry.runtime_data.network
    if network is None or network.data is None:
        return []
    data = network.data
    entities: list[BinarySensorEntity] = [PanOSPendingChangesSensor(entry)]
    if data.get("certificates") is not None:
        entities.append(PanOSCertExpiringSensor(entry))
    for name in network.selected_interfaces(data):
        entities.append(PanOSInterfaceLinkSensor(entry, name))
    for name in data.get("prefix_pools", {}):
        entities.append(PanOSPrefixMismatchSensor(entry, name))
    for lr, info in data.get("bgp", {}).items():
        device = lr_device_info(entry, lr)
        for peer in info["peers"]:
            entities.append(PanOSBgpPeerSensor(entry, lr, peer, device))
    for key, group in data["path_groups"].items():
        entities.append(
            PanOSPathMonitorSensor(entry, key, group, lr_device_info(entry, group["logical_router"]))
        )
    return entities


class PanOSPendingChangesSensor(PanOSNetworkEntity, BinarySensorEntity):
    _attr_name = "Uncommitted changes"
    _attr_icon = "mdi:file-document-edit-outline"

    def __init__(self, entry: PanOSConfigEntry) -> None:
        super().__init__(entry, "pending_changes")

    @property
    def available(self) -> bool:
        return super().available and self.data.get("pending_changes") is not None

    @property
    def is_on(self) -> bool | None:
        return self.data.get("pending_changes")


class PanOSInterfaceLinkSensor(PanOSNetworkEntity, BinarySensorEntity):
    _attr_device_class = BinarySensorDeviceClass.CONNECTIVITY

    def __init__(self, entry: PanOSConfigEntry, name: str) -> None:
        safe = name.replace("/", "_").replace(".", "_")
        super().__init__(entry, f"if_{safe}_link")
        self._if = name
        self._attr_name = f"{name} link"

    def _iface(self) -> dict[str, Any]:
        return self.data.get("interfaces", {}).get(self._if, {})

    @property
    def is_on(self) -> bool | None:
        state = self._iface().get("state")
        return None if state is None else state == "up"

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        iface = self._iface()
        counters = self.data.get("counters", {}).get(self._if) or {}
        return {
            "zone": iface.get("zone"),
            "vsys": iface.get("vsys"),
            "logical_router": iface.get("logical_router"),
            "speed": iface.get("speed"),
            "input_errors": counters.get("ierrors"),
            "input_drops": counters.get("idrops"),
            "firewall": self.data.get("unit"),
        }


class PanOSPathMonitorSensor(PanOSNetworkEntity, BinarySensorEntity):
    _attr_device_class = BinarySensorDeviceClass.CONNECTIVITY

    def __init__(self, entry, key: str, group: dict[str, Any], device) -> None:
        super().__init__(entry, f"pm_{pm_key_suffix(key)}", device)
        self._key = key
        self._attr_name = f"Path monitor {group['interface']} via {group['nexthop']}"

    def _group(self) -> dict[str, Any] | None:
        return self.data.get("path_groups", {}).get(self._key)

    @property
    def available(self) -> bool:
        return super().available and self._group() is not None

    @property
    def is_on(self) -> bool | None:
        group = self._group()
        return group["up"] if group else None

    @property
    def extra_state_attributes(self) -> dict[str, Any] | None:
        group = self._group()
        if not group:
            return None
        return {
            "zone": group["zone"],
            "condition": group["condition"],
            "routes": group["routes"],
            "monitors": [
                f"{m['destination']}: {m['status']} ({m['interval_count']})" for m in group["monitors"]
            ],
            "firewall": self.data.get("unit"),
        }


class PanOSPrefixMismatchSensor(PanOSNetworkEntity, BinarySensorEntity):
    """On when NPTv6 rules on this WAN don't fit the current delegated prefix."""

    _attr_device_class = BinarySensorDeviceClass.PROBLEM

    def __init__(self, entry: PanOSConfigEntry, pool: str) -> None:
        super().__init__(entry, f"pd_{pool}_npt_mismatch")
        self._pool = pool
        self._attr_name = f"{pool} NPTv6 prefix mismatch"

    def _info(self) -> dict[str, Any] | None:
        return self.data.get("prefix_pools", {}).get(self._pool)

    @property
    def available(self) -> bool:
        info = self._info()
        return super().available and info is not None and info["nat_checked"]

    @property
    def is_on(self) -> bool | None:
        info = self._info()
        return bool(info["problems"]) if info else None

    @property
    def extra_state_attributes(self) -> dict[str, Any] | None:
        info = self._info()
        if not info:
            return None
        return {
            "delegated_prefix": info["prefix"],
            "vsys": info["vsys"],
            "problems": info["problems"],
            "nptv6_rules_checked": info["nptv6_rules"],
        }


class PanOSBgpPeerSensor(PanOSNetworkEntity, BinarySensorEntity):
    """On while the BGP session is Established."""

    _attr_device_class = BinarySensorDeviceClass.CONNECTIVITY

    def __init__(self, entry: PanOSConfigEntry, lr: str, peer: str, device) -> None:
        super().__init__(entry, f"bgp_{safe_key(lr)}_{safe_key(peer)}", device)
        self._lr = lr
        self._peer = peer
        self._attr_name = f"BGP {peer}"

    def _info(self) -> dict[str, Any] | None:
        lr = self.data.get("bgp", {}).get(self._lr)
        if not lr or not lr["ok"]:
            return None
        return lr["peers"].get(self._peer)

    @property
    def available(self) -> bool:
        lr = self.data.get("bgp", {}).get(self._lr)
        return super().available and lr is not None and lr["ok"]

    @property
    def is_on(self) -> bool:
        info = self._info()
        # A configured peer missing from the status output is not up.
        return bool(info and info["established"])

    @property
    def extra_state_attributes(self) -> dict[str, Any] | None:
        info = self._info()
        if not info:
            return {"state": "not present"}
        return {
            "state": info["state"],
            "peer_ip": info["peer_ip"],
            "local_ip": info["local_ip"],
            "remote_as": info["remote_as"],
            "local_as": info["local_as"],
            "peer_group": info["peer_group"],
            "hostname": info["hostname"],
            "uptime": info["uptime"],
            "seconds_in_state": info["state_seconds"],
            "prefixes": info["prefixes"],
            "last_reset": info["last_reset"],
            "firewall": self.data.get("unit"),
        }


class PanOSGlobalProtectUser(PanOSNetworkEntity, BinarySensorEntity):
    """On while the user has a GlobalProtect session on the active gateway."""

    _attr_device_class = BinarySensorDeviceClass.CONNECTIVITY
    _attr_icon = "mdi:vpn"

    def __init__(self, entry: PanOSConfigEntry, username: str) -> None:
        super().__init__(entry, f"{GP_UID}{safe_key(username)}")
        self._user = username
        self._attr_name = f"{GP_NAME}{username}"

    def _info(self) -> dict[str, Any]:
        return (self.data.get("gp_users") or {}).get(self._user) or {}

    @property
    def available(self) -> bool:
        return super().available and self.data.get("gp_current") is not None

    @property
    def is_on(self) -> bool:
        return bool(self._info().get("connected"))

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        info = self._info()
        sessions = info.get("sessions") or []
        attrs: dict[str, Any] = {"username": self._user}
        if sessions:
            s = sessions[0]
            attrs.update(
                {
                    "computer": s.get("computer"),
                    "client": s.get("client"),
                    "app_version": s.get("app_version"),
                    "virtual_ip": s.get("virtual_ip"),
                    "public_ip": s.get("public_ip"),
                    "source_region": s.get("source_region"),
                    "login_time": s.get("login_time"),
                    "sessions": len(sessions),
                }
            )
            if len(sessions) > 1:
                attrs["computers"] = [x.get("computer") for x in sessions]
        if last := info.get("last_session"):
            attrs.update(
                {
                    "last_logout": last.get("logout_time"),
                    "last_logout_reason": last.get("logout_reason"),
                    "last_computer": last.get("computer"),
                    "last_public_ip": last.get("public_ip"),
                }
            )
        attrs["firewall"] = self.data.get("unit")
        return attrs


class PanOSCertExpiringSensor(PanOSNetworkEntity, BinarySensorEntity):
    """On when any certificate in the firewall config expires within 30 days."""

    _attr_device_class = BinarySensorDeviceClass.PROBLEM
    _attr_name = "Certificate expiring"
    _attr_icon = "mdi:certificate-outline"

    def __init__(self, entry: PanOSConfigEntry) -> None:
        super().__init__(entry, "cert_expiring")

    def _status(self) -> dict[str, list[dict[str, Any]]] | None:
        certs = self.data.get("certificates")
        if certs is None:
            return None
        return certs_expiring(certs["store"], dt_util.utcnow(), CERT_WARN_DAYS)

    @property
    def available(self) -> bool:
        return super().available and self.data.get("certificates") is not None

    @property
    def is_on(self) -> bool | None:
        status = self._status()
        return None if status is None else bool(status["expiring"])

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        status = self._status() or {"expiring": [], "expired": []}
        return {**status, "warn_days": CERT_WARN_DAYS}


def _track_network_entities(
    entry: PanOSConfigEntry, async_add_entities: AddConfigEntryEntitiesCallback
) -> None:
    """Add network entities as their data appears, not just from the first poll.

    Covers a slow first poll at startup and things added on the firewall later
    (new BGP peers, path monitors, logical routers, selected interfaces).
    """
    network = entry.runtime_data.network
    if network is None:
        return
    added: set[str] = set()

    @callback
    def _sync() -> None:
        if network.data is None:
            return
        new = [e for e in network_binary_sensors(entry) if e.unique_id not in added]
        if new:
            added.update(e.unique_id for e in new)
            async_add_entities(new)

    _sync()
    entry.async_on_unload(network.async_add_listener(_sync))
