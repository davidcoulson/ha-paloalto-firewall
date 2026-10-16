"""Base entities."""

from __future__ import annotations

from collections.abc import Callable
from functools import partial
from typing import Any

from homeassistant.core import callback
from homeassistant.helpers.device_registry import DeviceInfo
from homeassistant.helpers.entity import Entity, EntityDescription
from homeassistant.helpers.entity_platform import AddConfigEntryEntitiesCallback
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from .const import DOMAIN, MANUFACTURER, pair_identifier
from .coordinator import (
    PanOSConfigEntry,
    PanOSDeviceCoordinator,
    PanOSPairTracker,
    PanOSUnit,
    PanOSUpdatesCoordinator,
    unit_device_info,
)
from .network import PanOSNetworkCoordinator, parent_identifier


class PanOSUnitEntity(CoordinatorEntity[PanOSDeviceCoordinator]):
    """Entity bound to one firewall's status coordinator."""

    _attr_has_entity_name = True

    def __init__(self, entry: PanOSConfigEntry, unit: PanOSUnit, description: EntityDescription) -> None:
        super().__init__(unit.coordinator)
        self.entity_description = description
        self.unit = unit
        self._attr_unique_id = f"{unit.config.serial}_{description.key}"
        self._attr_device_info = unit_device_info(entry, unit.config, entry.runtime_data.pair is not None)

    @property
    def data(self) -> dict[str, Any]:
        return self.coordinator.data or {}


class PanOSUpdatesEntity(CoordinatorEntity[PanOSUpdatesCoordinator]):
    """Entity bound to one firewall's slow update/licence coordinator."""

    _attr_has_entity_name = True

    def __init__(self, entry: PanOSConfigEntry, unit: PanOSUnit, description: EntityDescription) -> None:
        super().__init__(unit.updates)
        self.entity_description = description
        self.unit = unit
        self._attr_unique_id = f"{unit.config.serial}_{description.key}"
        self._attr_device_info = unit_device_info(entry, unit.config, entry.runtime_data.pair is not None)

    @property
    def available(self) -> bool:
        return super().available and self.coordinator.data is not None

    @property
    def data(self) -> dict[str, Any]:
        return self.coordinator.data or {}


class PanOSPairEntity(Entity):
    """Entity on the virtual HA-pair device; follows whichever unit is active."""

    _attr_has_entity_name = True
    _attr_should_poll = False

    def __init__(
        self, entry: PanOSConfigEntry, pair: PanOSPairTracker, description: EntityDescription
    ) -> None:
        self.entity_description = description
        self.pair = pair
        self._attr_unique_id = f"{pair_identifier(entry.entry_id)}_{description.key}"
        self._attr_device_info = DeviceInfo(
            identifiers={(DOMAIN, pair_identifier(entry.entry_id))},
            name=f"{entry.runtime_data.name} HA pair",
            manufacturer=MANUFACTURER,
            model="High-availability pair",
        )

    async def async_added_to_hass(self) -> None:
        await super().async_added_to_hass()
        self.async_on_remove(self.pair.async_add_listener(self.async_write_ha_state))

    @property
    def available(self) -> bool:
        return self.pair.any_available


class PanOSNetworkEntity(CoordinatorEntity[PanOSNetworkCoordinator]):
    """Pair-wide network entity (data read from the active firewall)."""

    _attr_has_entity_name = True

    def __init__(
        self,
        entry: PanOSConfigEntry,
        key: str,
        device_info: DeviceInfo | None = None,
    ) -> None:
        super().__init__(entry.runtime_data.network)
        self._attr_unique_id = f"{entry.entry_id}_{key}"
        self._attr_device_info = device_info or DeviceInfo(identifiers={parent_identifier(entry)})

    @property
    def data(self) -> dict:
        return self.coordinator.data or {}

    @property
    def available(self) -> bool:
        return super().available and self.coordinator.data is not None


def track_unit_entities(
    entry: PanOSConfigEntry,
    async_add_entities: AddConfigEntryEntitiesCallback,
    build: Callable[[PanOSUnit], list[Entity]],
) -> None:
    """Discover optional entities after recovery; keep one of each until unload."""
    added: set[str] = set()

    @callback
    def _sync(unit: PanOSUnit) -> None:
        new = [entity for entity in build(unit) if entity.unique_id not in added]
        if new:
            added.update(str(entity.unique_id) for entity in new)
            async_add_entities(new)

    for unit in entry.runtime_data.units:
        _sync(unit)
        entry.async_on_unload(unit.coordinator.async_add_listener(partial(_sync, unit)))
