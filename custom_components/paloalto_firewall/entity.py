"""Base entities."""

from __future__ import annotations

from typing import Any

from homeassistant.helpers.device_registry import DeviceInfo
from homeassistant.helpers.entity import Entity, EntityDescription
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


class PanOSUnitEntity(CoordinatorEntity[PanOSDeviceCoordinator]):
    """Entity bound to one firewall's status coordinator."""

    _attr_has_entity_name = True

    def __init__(
        self, entry: PanOSConfigEntry, unit: PanOSUnit, description: EntityDescription
    ) -> None:
        super().__init__(unit.coordinator)
        self.entity_description = description
        self.unit = unit
        self._attr_unique_id = f"{unit.config.serial}_{description.key}"
        self._attr_device_info = unit_device_info(
            entry, unit.config, entry.runtime_data.pair is not None
        )

    @property
    def data(self) -> dict[str, Any]:
        return self.coordinator.data or {}


class PanOSUpdatesEntity(CoordinatorEntity[PanOSUpdatesCoordinator]):
    """Entity bound to one firewall's slow update/licence coordinator."""

    _attr_has_entity_name = True

    def __init__(
        self, entry: PanOSConfigEntry, unit: PanOSUnit, description: EntityDescription
    ) -> None:
        super().__init__(unit.updates)
        self.entity_description = description
        self.unit = unit
        self._attr_unique_id = f"{unit.config.serial}_{description.key}"
        self._attr_device_info = unit_device_info(
            entry, unit.config, entry.runtime_data.pair is not None
        )

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
