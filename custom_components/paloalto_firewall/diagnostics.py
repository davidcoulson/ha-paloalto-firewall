"""Diagnostics support."""

from __future__ import annotations

from typing import Any

from homeassistant.components.diagnostics import async_redact_data
from homeassistant.const import CONF_PASSWORD, CONF_USERNAME
from homeassistant.core import HomeAssistant

from .coordinator import PanOSConfigEntry

TO_REDACT = {CONF_PASSWORD, CONF_USERNAME, "users", "admins", "mgmt_ip", "peer_mgmt_ip"}


async def async_get_config_entry_diagnostics(
    hass: HomeAssistant, entry: PanOSConfigEntry
) -> dict[str, Any]:
    runtime = entry.runtime_data
    pair = runtime.pair
    return async_redact_data(
        {
            "entry": {"data": dict(entry.data), "options": dict(entry.options)},
            "units": [
                {
                    "host": u.config.host,
                    "serial": u.config.serial,
                    "status_ok": u.coordinator.last_update_success,
                    "status": u.coordinator.data,
                    "updates_ok": u.updates.last_update_success,
                    "updates": u.updates.data,
                }
                for u in runtime.units
            ],
            "pair": None
            if pair is None
            else {
                "current_index": pair.current_index,
                "last_known_active_index": pair.active_index,
                "last_failover": pair.last_failover,
                "health": pair.health(),
            },
        },
        TO_REDACT,
    )
