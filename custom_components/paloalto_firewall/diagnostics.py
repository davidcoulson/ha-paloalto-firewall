"""Diagnostics support."""

from __future__ import annotations

from typing import Any

from homeassistant.components.diagnostics import async_redact_data
from homeassistant.const import CONF_PASSWORD, CONF_USERNAME
from homeassistant.core import HomeAssistant

from . import probes
from .coordinator import PanOSConfigEntry

TO_REDACT = {
    CONF_PASSWORD, CONF_USERNAME, "users", "admins", "mgmt_ip", "peer_mgmt_ip",
    "ips", "nexthop", "monitors", "host", "routes", "sessions", "gp_previous", "gp_current", "gp_users",
}


async def async_get_config_entry_diagnostics(
    hass: HomeAssistant, entry: PanOSConfigEntry
) -> dict[str, Any]:
    runtime = entry.runtime_data
    pair = runtime.pair
    raw: dict[str, Any] | None = None
    if probes.debug_enabled():
        unit = (pair.active_unit if pair else None) or runtime.units[0]
        raw = {"firewall": unit.config.hostname, **(await probes.collect(unit.client))}
    data = async_redact_data(
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
            "network": None
            if not runtime.network or not runtime.network.data
            else {
                "unit": runtime.network.data["unit"],
                "selected_interfaces": runtime.network.selected_interfaces(runtime.network.data),
                "egress": runtime.network.data["egress"],
                # Keys embed next-hop IPs; values are redacted below.
                "path_groups": list(runtime.network.data["path_groups"].values()),
                "pending_changes": runtime.network.data["pending_changes"],
                "running_jobs": (runtime.network.data["jobs"] or {}).get("running"),
                "interface_count": len(runtime.network.data["interfaces"]),
                "fib_entries": len(runtime.network.data["fib"]),
            },
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
    if raw is not None:
        data["raw_command_samples"] = raw
    return data
