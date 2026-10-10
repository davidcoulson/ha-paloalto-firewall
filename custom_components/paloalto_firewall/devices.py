"""Device registry helpers that work before and after HA 2026.8.

2026.8 scoped device identifiers to the config entry: `via_device` (an
identifier tuple) became `via_device_id` (a registry id) and
`async_get_device` became `async_get_device_by_identifier`.
"""

from __future__ import annotations

import inspect
from typing import Any

from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers import device_registry as dr


def get_device(
    registry: dr.DeviceRegistry, identifier: tuple[str, str], entry_id: str
) -> dr.DeviceEntry | None:
    if hasattr(registry, "async_get_device_by_identifier"):
        return registry.async_get_device_by_identifier(identifier, entry_id)
    return registry.async_get_device(identifiers={identifier})


def _supports_via_device_id(registry: dr.DeviceRegistry) -> bool:
    return "via_device_id" in inspect.signature(registry.async_get_or_create).parameters


def ensure_device(
    hass: HomeAssistant,
    entry: ConfigEntry,
    identifier: tuple[str, str],
    parent: dr.DeviceEntry | None = None,
    **info: Any,
) -> dr.DeviceEntry:
    """Create or update a device, linked to ``parent`` when given."""
    registry = dr.async_get(hass)
    kwargs: dict[str, Any] = {"config_entry_id": entry.entry_id, "identifiers": {identifier}, **info}
    if parent is not None:
        if _supports_via_device_id(registry):
            kwargs["via_device_id"] = parent.id
        else:
            kwargs["via_device"] = next(iter(parent.identifiers))
    return registry.async_get_or_create(**kwargs)
