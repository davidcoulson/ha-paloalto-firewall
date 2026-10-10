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
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity_platform import AddConfigEntryEntitiesCallback

from .coordinator import PanOSConfigEntry
from .entity import PanOSNetworkEntity, PanOSPairEntity, PanOSUnitEntity, PanOSUpdatesEntity
from .network import lr_device_info

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
    entities.extend(network_binary_sensors(entry))
    async_add_entities(entities)


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
    for name in network.selected_interfaces(data):
        entities.append(PanOSInterfaceLinkSensor(entry, name))
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
        safe = key.replace("|", "_").replace("/", "_").replace(".", "_").replace(":", "_")
        super().__init__(entry, f"pm_{safe}", device)
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
