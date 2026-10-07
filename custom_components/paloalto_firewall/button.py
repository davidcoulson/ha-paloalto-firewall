"""Buttons for Palo Alto firewalls."""

from __future__ import annotations

from homeassistant.components.button import ButtonEntity, ButtonEntityDescription
from homeassistant.const import EntityCategory
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity_platform import AddConfigEntryEntitiesCallback

from .coordinator import PanOSConfigEntry
from .entity import PanOSUpdatesEntity

CHECK_UPDATES = ButtonEntityDescription(
    key="check_updates",
    name="Check for updates",
    icon="mdi:update",
    entity_category=EntityCategory.CONFIG,
)


async def async_setup_entry(
    hass: HomeAssistant,
    entry: PanOSConfigEntry,
    async_add_entities: AddConfigEntryEntitiesCallback,
) -> None:
    async_add_entities(
        PanOSCheckUpdatesButton(entry, unit, CHECK_UPDATES) for unit in entry.runtime_data.units
    )


class PanOSCheckUpdatesButton(PanOSUpdatesEntity, ButtonEntity):
    """Run the software/content/licence checks now instead of waiting."""

    @property
    def available(self) -> bool:
        # Pressable even if the last check failed; that's when you'd retry.
        return self.unit.coordinator.last_update_success

    async def async_press(self) -> None:
        await self.coordinator.async_refresh()
