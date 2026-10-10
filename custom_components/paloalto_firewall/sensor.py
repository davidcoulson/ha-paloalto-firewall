"""Sensors for Palo Alto firewalls."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, time
from typing import Any

from homeassistant.components.sensor import (
    RestoreSensor,
    SensorDeviceClass,
    SensorEntity,
    SensorEntityDescription,
    SensorStateClass,
)
from homeassistant.const import PERCENTAGE, EntityCategory, UnitOfDataRate, UnitOfTemperature
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity_platform import AddConfigEntryEntitiesCallback
from homeassistant.util import dt as dt_util

from .const import DOMAIN
from .coordinator import PanOSConfigEntry
from .entity import PanOSNetworkEntity, PanOSPairEntity, PanOSUnitEntity, PanOSUpdatesEntity
from .network import lr_device_info
from .parsers import HA_STATES

Data = dict[str, Any]

BRAND_ICON = f"/api/brands/integration/{DOMAIN}/icon.png"


def _get(data: Data | None, section: str, key: str) -> Any:
    return ((data or {}).get(section) or {}).get(key)


def _ha_enabled(data: Data | None) -> bool:
    return bool(_get(data, "ha", "enabled"))


@dataclass(frozen=True, kw_only=True)
class PanOSSensorDescription(SensorEntityDescription):
    value_fn: Callable[[Data], Any]
    attrs_fn: Callable[[Data], dict[str, Any]] | None = None
    # (first data or None, unit is part of a configured pair) -> create?
    exists_fn: Callable[[Data | None, bool], bool] = lambda data, paired: True
    # Also expose on the HA-pair device, following the active unit.
    on_pair: bool = False
    # Show the Palo Alto Networks brand icon instead of an MDI icon.
    brand_picture: bool = False


def _ha_local_state(data: Data) -> str | None:
    ha = data.get("ha")
    if ha is None:
        return None
    return ha["local_state"] if ha.get("enabled") else "standalone"


def _ha_peer_state(data: Data) -> str | None:
    ha = data.get("ha")
    if not ha or not ha.get("enabled"):
        return None
    return ha.get("peer_state")


def _ha_exists(data: Data | None, paired: bool) -> bool:
    return paired or data is None or _ha_enabled(data)


def _section_exists(section: str) -> Callable[[Data | None, bool], bool]:
    # Create when the section answered at setup, or when we couldn't tell.
    return lambda data, paired: data is None or data.get(section) is not None


UNIT_SENSORS: tuple[PanOSSensorDescription, ...] = (
    PanOSSensorDescription(
        key="ha_state",
        translation_key="ha_state",
        name="HA state",
        icon="mdi:shield-sync",
        device_class=SensorDeviceClass.ENUM,
        options=HA_STATES,
        value_fn=_ha_local_state,
        attrs_fn=lambda d: {
            k: v
            for k, v in (d.get("ha") or {}).items()
            if k in ("mode", "local_priority", "preemptive", "local_state_duration", "state_sync")
        },
        exists_fn=_ha_exists,
    ),
    PanOSSensorDescription(
        key="ha_peer_state",
        translation_key="ha_peer_state",
        name="HA peer state",
        icon="mdi:shield-sync-outline",
        device_class=SensorDeviceClass.ENUM,
        options=HA_STATES,
        value_fn=_ha_peer_state,
        attrs_fn=lambda d: {
            k: v
            for k, v in (d.get("ha") or {}).items()
            if k in ("peer_mgmt_ip", "peer_priority", "ha1_status", "ha1_backup_status", "ha2_status")
        },
        exists_fn=_ha_exists,
    ),
    PanOSSensorDescription(
        key="boot_time",
        name="Last boot",
        device_class=SensorDeviceClass.TIMESTAMP,
        entity_category=EntityCategory.DIAGNOSTIC,
        value_fn=lambda d: d.get("boot_time"),
    ),
    PanOSSensorDescription(
        key="mgmt_cpu",
        name="Management CPU",
        icon="mdi:cpu-64-bit",
        native_unit_of_measurement=PERCENTAGE,
        state_class=SensorStateClass.MEASUREMENT,
        suggested_display_precision=0,
        value_fn=lambda d: _get(d, "resources", "mgmt_cpu_pct"),
    ),
    PanOSSensorDescription(
        key="mgmt_memory",
        name="Management memory",
        icon="mdi:memory",
        native_unit_of_measurement=PERCENTAGE,
        state_class=SensorStateClass.MEASUREMENT,
        suggested_display_precision=0,
        value_fn=lambda d: _get(d, "resources", "mgmt_memory_pct"),
    ),
    PanOSSensorDescription(
        key="mgmt_load",
        name="Management load (1m)",
        icon="mdi:gauge",
        state_class=SensorStateClass.MEASUREMENT,
        entity_registry_enabled_default=False,
        value_fn=lambda d: _get(d, "resources", "load_1m"),
        attrs_fn=lambda d: {
            "load_5m": _get(d, "resources", "load_5m"),
            "load_15m": _get(d, "resources", "load_15m"),
        },
    ),
    PanOSSensorDescription(
        key="dataplane_cpu",
        name="Dataplane CPU",
        icon="mdi:chip",
        native_unit_of_measurement=PERCENTAGE,
        state_class=SensorStateClass.MEASUREMENT,
        suggested_display_precision=0,
        value_fn=lambda d: _get(d, "dataplane", "cpu_avg_pct"),
        attrs_fn=lambda d: {"per_dataplane": _get(d, "dataplane", "per_dataplane")},
        on_pair=True,
    ),
    PanOSSensorDescription(
        key="dataplane_cpu_max",
        name="Dataplane CPU peak core",
        icon="mdi:chip",
        native_unit_of_measurement=PERCENTAGE,
        state_class=SensorStateClass.MEASUREMENT,
        entity_registry_enabled_default=False,
        value_fn=lambda d: _get(d, "dataplane", "cpu_max_pct"),
    ),
    PanOSSensorDescription(
        key="packet_buffer",
        name="Packet buffer utilization",
        icon="mdi:tray-full",
        native_unit_of_measurement=PERCENTAGE,
        state_class=SensorStateClass.MEASUREMENT,
        value_fn=lambda d: _get(d, "dataplane", "packet_buffer_pct"),
    ),
    PanOSSensorDescription(
        key="sessions_active",
        name="Active sessions",
        icon="mdi:lan-connect",
        native_unit_of_measurement="sessions",
        state_class=SensorStateClass.MEASUREMENT,
        value_fn=lambda d: _get(d, "session", "num_active"),
        attrs_fn=lambda d: {
            "tcp": _get(d, "session", "num_tcp"),
            "udp": _get(d, "session", "num_udp"),
            "icmp": _get(d, "session", "num_icmp"),
            "max": _get(d, "session", "num_max"),
        },
        on_pair=True,
    ),
    PanOSSensorDescription(
        key="session_utilization",
        name="Session table utilization",
        icon="mdi:table",
        native_unit_of_measurement=PERCENTAGE,
        state_class=SensorStateClass.MEASUREMENT,
        suggested_display_precision=1,
        value_fn=lambda d: _get(d, "session", "utilization_pct"),
    ),
    PanOSSensorDescription(
        key="connections_per_second",
        name="New connections",
        icon="mdi:connection",
        native_unit_of_measurement="conn/s",
        state_class=SensorStateClass.MEASUREMENT,
        value_fn=lambda d: _get(d, "session", "cps"),
        on_pair=True,
    ),
    PanOSSensorDescription(
        key="throughput",
        name="Throughput",
        device_class=SensorDeviceClass.DATA_RATE,
        native_unit_of_measurement=UnitOfDataRate.KILOBITS_PER_SECOND,
        suggested_unit_of_measurement=UnitOfDataRate.MEGABITS_PER_SECOND,
        suggested_display_precision=1,
        state_class=SensorStateClass.MEASUREMENT,
        value_fn=lambda d: _get(d, "session", "kbps"),
        on_pair=True,
    ),
    PanOSSensorDescription(
        key="packet_rate",
        name="Packet rate",
        icon="mdi:package-variant",
        native_unit_of_measurement="packets/s",
        state_class=SensorStateClass.MEASUREMENT,
        value_fn=lambda d: _get(d, "session", "pps"),
        on_pair=True,
    ),
    PanOSSensorDescription(
        key="temperature",
        name="Temperature",
        device_class=SensorDeviceClass.TEMPERATURE,
        native_unit_of_measurement=UnitOfTemperature.CELSIUS,
        state_class=SensorStateClass.MEASUREMENT,
        value_fn=lambda d: _get(d, "environment", "max_temp_c"),
        attrs_fn=lambda d: {"sensors": _get(d, "environment", "temperatures")},
        exists_fn=_section_exists("environment"),
    ),
    PanOSSensorDescription(
        key="globalprotect_users",
        name="GlobalProtect users",
        icon="mdi:vpn",
        native_unit_of_measurement="users",
        state_class=SensorStateClass.MEASUREMENT,
        value_fn=lambda d: _get(d, "gp_users", "count"),
        attrs_fn=lambda d: {"users": _get(d, "gp_users", "users")},
        exists_fn=_section_exists("gp_users"),
        on_pair=True,
    ),
    PanOSSensorDescription(
        key="admin_sessions",
        name="Logged-in admins",
        icon="mdi:account-key",
        native_unit_of_measurement="users",
        state_class=SensorStateClass.MEASUREMENT,
        value_fn=lambda d: _get(d, "admins", "count"),
        attrs_fn=lambda d: {"admins": _get(d, "admins", "users")},
    ),
    PanOSSensorDescription(
        key="ipsec_tunnels",
        name="IPsec tunnels up",
        icon="mdi:tunnel",
        native_unit_of_measurement="tunnels",
        state_class=SensorStateClass.MEASUREMENT,
        value_fn=lambda d: _get(d, "ipsec", "count"),
        attrs_fn=lambda d: {"tunnels": _get(d, "ipsec", "tunnels")},
        exists_fn=_section_exists("ipsec"),
        on_pair=True,
    ),
    *(
        PanOSSensorDescription(
            key=key,
            name=name,
            icon=icon,
            entity_category=EntityCategory.DIAGNOSTIC,
            entity_registry_enabled_default=enabled,
            brand_picture=key == "app_version",
            value_fn=lambda d, k=key: _get(d, "system", k),
        )
        for key, name, icon, enabled in (
            ("sw_version", "PAN-OS version", "mdi:package-variant-closed", True),
            ("app_version", "Apps & threats version", "mdi:shield-bug", True),
            ("av_version", "Antivirus version", "mdi:virus", True),
            ("wildfire_version", "WildFire version", "mdi:fire", False),
            ("url_filtering_version", "URL filtering version", "mdi:web", False),
            ("gp_client_version", "GlobalProtect client version", "mdi:vpn", False),
            ("device_cert_status", "Device certificate", "mdi:certificate", True),
        )
    ),
)


def _license_expiry(data: Data) -> datetime | None:
    expiry = _get(data, "licenses", "next_expiry")
    if expiry is None:
        return None
    return datetime.combine(expiry, time.min, tzinfo=dt_util.DEFAULT_TIME_ZONE)


LICENSE_SENSOR = PanOSSensorDescription(
    key="license_next_expiry",
    name="Next licence expiry",
    icon="mdi:license",
    device_class=SensorDeviceClass.TIMESTAMP,
    entity_category=EntityCategory.DIAGNOSTIC,
    value_fn=_license_expiry,
    attrs_fn=lambda d: {
        "feature": _get(d, "licenses", "next_expiry_feature"),
        "licences": {
            l["feature"]: l["expires_raw"] for l in (_get(d, "licenses", "licenses") or [])
        },
    },
)

PAIR_ACTIVE_SENSOR = SensorEntityDescription(
    key="active_unit", name="Active firewall", icon="mdi:shield-star"
)
PAIR_FAILOVER_SENSOR = SensorEntityDescription(
    key="last_failover",
    name="Last failover",
    icon="mdi:swap-horizontal-bold",
    device_class=SensorDeviceClass.TIMESTAMP,
)


async def async_setup_entry(
    hass: HomeAssistant,
    entry: PanOSConfigEntry,
    async_add_entities: AddConfigEntryEntitiesCallback,
) -> None:
    runtime = entry.runtime_data
    paired = runtime.pair is not None
    entities: list[SensorEntity] = []
    for unit in runtime.units:
        first = unit.coordinator.data
        entities.extend(
            PanOSUnitSensor(entry, unit, desc)
            for desc in UNIT_SENSORS
            if desc.exists_fn(first, paired)
        )
        entities.append(PanOSLicenseSensor(entry, unit, LICENSE_SENSOR))
    if runtime.pair:
        entities.append(PanOSActiveUnitSensor(entry, runtime.pair, PAIR_ACTIVE_SENSOR))
        entities.append(PanOSLastFailoverSensor(entry, runtime.pair, PAIR_FAILOVER_SENSOR))
        entities.extend(
            PanOSPairMirrorSensor(entry, runtime.pair, desc)
            for desc in UNIT_SENSORS
            if desc.on_pair
        )
    entities.extend(network_sensors(entry))
    async_add_entities(entities)


class PanOSUnitSensor(PanOSUnitEntity, SensorEntity):
    entity_description: PanOSSensorDescription

    def __init__(self, entry, unit, description: PanOSSensorDescription) -> None:
        super().__init__(entry, unit, description)
        if description.brand_picture:
            # Same brand-proxy path update entities use (HA 2026.3+), served
            # from this integration's brand/ folder.
            self._attr_entity_picture = BRAND_ICON

    @property
    def native_value(self) -> Any:
        return self.entity_description.value_fn(self.data)

    @property
    def extra_state_attributes(self) -> dict[str, Any] | None:
        if fn := self.entity_description.attrs_fn:
            return fn(self.data)
        return None


class PanOSLicenseSensor(PanOSUpdatesEntity, SensorEntity):
    entity_description: PanOSSensorDescription

    @property
    def available(self) -> bool:
        return super().available and self.data.get("licenses") is not None

    @property
    def native_value(self) -> Any:
        return self.entity_description.value_fn(self.data)

    @property
    def extra_state_attributes(self) -> dict[str, Any] | None:
        return self.entity_description.attrs_fn(self.data)  # type: ignore[misc]


class PanOSPairMirrorSensor(PanOSPairEntity, SensorEntity):
    """A unit metric, taken from whichever firewall is currently active."""

    entity_description: PanOSSensorDescription

    @property
    def available(self) -> bool:
        return self.pair.active_data() is not None

    @property
    def native_value(self) -> Any:
        return self.entity_description.value_fn(self.pair.active_data() or {})

    @property
    def extra_state_attributes(self) -> dict[str, Any] | None:
        data = self.pair.active_data() or {}
        attrs = dict(self.entity_description.attrs_fn(data)) if self.entity_description.attrs_fn else {}
        if unit := self.pair.active_unit:
            attrs["source"] = unit.config.hostname
        return attrs


class PanOSActiveUnitSensor(PanOSPairEntity, SensorEntity):
    @property
    def native_value(self) -> str | None:
        unit = self.pair.active_unit
        return unit.config.hostname if unit else None

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        unit = self.pair.active_unit
        if unit is None:
            return {}
        data = self.pair.active_data() or {}
        return {
            "serial": unit.config.serial,
            "host": unit.config.host,
            "mode": _get(data, "ha", "mode"),
            "active_for_seconds": _get(data, "ha", "local_state_duration"),
        }


class PanOSLastFailoverSensor(PanOSPairEntity, RestoreSensor):
    async def async_added_to_hass(self) -> None:
        await super().async_added_to_hass()
        if self.pair.last_failover is None and (last := await self.async_get_last_sensor_data()):
            if isinstance(last.native_value, datetime):
                self.pair.last_failover = last.native_value
            elif isinstance(last.native_value, str):
                self.pair.last_failover = dt_util.parse_datetime(last.native_value)

    @property
    def available(self) -> bool:
        return True

    @property
    def native_value(self) -> datetime | None:
        return self.pair.last_failover


# --------------------------------------------------------------------------
# Pair-wide network sensors (interfaces, logical routers, jobs)
# --------------------------------------------------------------------------


def network_sensors(entry: PanOSConfigEntry) -> list[SensorEntity]:
    network = entry.runtime_data.network
    if network is None or network.data is None:
        return []
    data = network.data
    entities: list[SensorEntity] = [PanOSRunningJobsSensor(entry), PanOSLastCommitSensor(entry)]
    for name in network.selected_interfaces(data):
        safe = name.replace("/", "_").replace(".", "_")
        for direction in ("in", "out"):
            entities.append(PanOSInterfaceRateSensor(entry, name, safe, direction))
        if data["interfaces"][name].get("speed"):
            entities.append(PanOSInterfaceSpeedSensor(entry, name, safe))
    for lr in data["egress"]:
        device = lr_device_info(entry, lr)
        entities.append(PanOSEgressSensor(entry, lr, "ipv4", device))
        entities.append(PanOSEgressSensor(entry, lr, "ipv6", device))
        entities.append(PanOSRouteCountSensor(entry, lr, device))
    return entities


class PanOSRunningJobsSensor(PanOSNetworkEntity, SensorEntity):
    _attr_name = "Running jobs"
    _attr_icon = "mdi:progress-clock"
    _attr_state_class = SensorStateClass.MEASUREMENT

    def __init__(self, entry: PanOSConfigEntry) -> None:
        super().__init__(entry, "running_jobs")

    @property
    def available(self) -> bool:
        return super().available and self.data.get("jobs") is not None

    @property
    def native_value(self) -> int:
        return len(self.data["jobs"]["running"])

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        return {
            "jobs": [
                {k: j[k] for k in ("id", "type", "user", "status", "progress")}
                for j in self.data["jobs"]["running"]
            ],
            "firewall": self.data.get("unit"),
        }


class PanOSLastCommitSensor(PanOSNetworkEntity, SensorEntity):
    """Most recent commit in the firewall's job history (unknown once it ages out)."""

    _attr_name = "Last commit"
    _attr_icon = "mdi:source-commit"
    _attr_device_class = SensorDeviceClass.TIMESTAMP

    def __init__(self, entry: PanOSConfigEntry) -> None:
        super().__init__(entry, "last_commit")
        self._last: tuple[datetime, dict[str, Any]] | None = None

    @property
    def available(self) -> bool:
        return super().available and self.data.get("jobs") is not None

    def _current(self) -> tuple[datetime, dict[str, Any]] | None:
        jobs = self.data.get("jobs") or {}
        if (when := jobs.get("last_commit_time")) and jobs.get("last_commit"):
            when = when.replace(tzinfo=dt_util.DEFAULT_TIME_ZONE)
            if self._last is None or when >= self._last[0]:
                self._last = (when, jobs["last_commit"])
        return self._last

    @property
    def native_value(self) -> datetime | None:
        cur = self._current()
        return cur[0] if cur else None

    @property
    def extra_state_attributes(self) -> dict[str, Any] | None:
        cur = self._current()
        if not cur:
            return None
        job = cur[1]
        return {"user": job["user"], "job_id": job["id"], "result": job["result"], "type": job["type"]}


class PanOSInterfaceRateSensor(PanOSNetworkEntity, SensorEntity):
    _attr_device_class = SensorDeviceClass.DATA_RATE
    _attr_native_unit_of_measurement = UnitOfDataRate.KILOBITS_PER_SECOND
    _attr_suggested_unit_of_measurement = UnitOfDataRate.MEGABITS_PER_SECOND
    _attr_suggested_display_precision = 1
    _attr_state_class = SensorStateClass.MEASUREMENT

    def __init__(self, entry, name: str, safe: str, direction: str) -> None:
        super().__init__(entry, f"if_{safe}_{direction}")
        self._if = name
        self._key = f"{direction}_kbps"
        self._attr_name = f"{name} {direction}"
        self._attr_icon = "mdi:download-network" if direction == "in" else "mdi:upload-network"

    @property
    def native_value(self) -> float | None:
        return (self.data.get("counters", {}).get(self._if) or {}).get(self._key)

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        iface = self.data.get("interfaces", {}).get(self._if, {})
        return {
            "zone": iface.get("zone"),
            "vsys": iface.get("vsys"),
            "logical_router": iface.get("logical_router"),
            "addresses": iface.get("ips"),
            "firewall": self.data.get("unit"),
        }


class PanOSInterfaceSpeedSensor(PanOSNetworkEntity, SensorEntity):
    _attr_device_class = SensorDeviceClass.DATA_RATE
    _attr_native_unit_of_measurement = UnitOfDataRate.MEGABITS_PER_SECOND
    _attr_entity_category = EntityCategory.DIAGNOSTIC

    def __init__(self, entry, name: str, safe: str) -> None:
        super().__init__(entry, f"if_{safe}_speed")
        self._if = name
        self._attr_name = f"{name} link speed"

    @property
    def native_value(self) -> int | None:
        return self.data.get("interfaces", {}).get(self._if, {}).get("speed")

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        return {"duplex": self.data.get("interfaces", {}).get(self._if, {}).get("duplex")}


class PanOSEgressSensor(PanOSNetworkEntity, SensorEntity):
    """Where this logical router sends internet traffic (FIB lookup of an anycast IP)."""

    _attr_icon = "mdi:routes"

    def __init__(self, entry, lr: str, family: str, device) -> None:
        super().__init__(entry, f"lr_{lr}_egress_{family}", device)
        self._lr = lr
        self._family = family
        self._attr_name = "Internet egress" if family == "ipv4" else "IPv6 internet egress"

    def _info(self) -> dict[str, Any] | None:
        return self.data.get("egress", {}).get(self._lr, {}).get(self._family)

    @property
    def native_value(self) -> str | None:
        info = self._info()
        if not info:
            return None
        if info["drop"]:
            return "drop"
        return info["zone"] or info["interface"]

    @property
    def extra_state_attributes(self) -> dict[str, Any] | None:
        info = self._info()
        if not info:
            return None
        return {
            "interface": info["interface"],
            "nexthop": info["nexthop"],
            "vsys": info["vsys"],
            "route": info["prefix"],
            "paths": info["paths"],
            "firewall": self.data.get("unit"),
        }


class PanOSRouteCountSensor(PanOSNetworkEntity, SensorEntity):
    _attr_name = "FIB routes"
    _attr_icon = "mdi:table-network"
    _attr_state_class = SensorStateClass.MEASUREMENT
    _attr_entity_category = EntityCategory.DIAGNOSTIC

    def __init__(self, entry, lr: str, device) -> None:
        super().__init__(entry, f"lr_{lr}_routes", device)
        self._lr = lr

    @property
    def native_value(self) -> int | None:
        info = self.data.get("egress", {}).get(self._lr)
        return info["routes_ipv4"] + info["routes_ipv6"] if info else None

    @property
    def extra_state_attributes(self) -> dict[str, Any] | None:
        info = self.data.get("egress", {}).get(self._lr)
        return {"ipv4": info["routes_ipv4"], "ipv6": info["routes_ipv6"]} if info else None
