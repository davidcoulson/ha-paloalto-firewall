"""Actions (services) for the Palo Alto Networks Firewall integration."""

from __future__ import annotations

import asyncio
from typing import Any

import voluptuous as vol

from homeassistant.config_entries import ConfigEntryState
from homeassistant.core import HomeAssistant, ServiceCall, ServiceResponse, SupportsResponse
from homeassistant.exceptions import HomeAssistantError, ServiceValidationError
from homeassistant.helpers import config_validation as cv

from . import parsers
from .api import PanOSConnectionError, PanOSError
from .const import CMD_ARP_ALL, CMD_DHCP_LEASES, DOMAIN, LOOKUP_TIMEOUT, SERVICE_LOOKUP
from .coordinator import PanOSConfigEntry, PanOSUnit

ATTR_CONFIG_ENTRY_ID = "config_entry_id"
ATTR_QUERY = "query"
ATTR_SOURCE = "source"

LOOKUP_SCHEMA = vol.Schema(
    {
        vol.Optional(ATTR_CONFIG_ENTRY_ID): cv.string,
        vol.Optional(ATTR_QUERY, default=""): cv.string,
        vol.Optional(ATTR_SOURCE, default="all"): vol.In(["all", "arp", "dhcp"]),
    }
)


def _get_entry(hass: HomeAssistant, entry_id: str | None) -> PanOSConfigEntry:
    loaded = [
        e
        for e in hass.config_entries.async_entries(DOMAIN)
        if e.state is ConfigEntryState.LOADED
    ]
    if entry_id:
        for entry in loaded:
            if entry.entry_id == entry_id:
                return entry
        raise ServiceValidationError(f"No loaded Palo Alto firewall entry with id {entry_id}")
    if not loaded:
        raise ServiceValidationError("No Palo Alto firewall is set up and loaded")
    if len(loaded) > 1:
        raise ServiceValidationError(
            "More than one firewall is configured; pass config_entry_id to pick one"
        )
    return loaded[0]


def _candidate_units(entry: PanOSConfigEntry) -> list[PanOSUnit]:
    """Active unit first (it owns the live ARP table), then any other reachable one."""
    runtime = entry.runtime_data
    units = list(runtime.units)
    first = runtime.pair.active_unit if runtime.pair else None
    if first is None:
        first = next((u for u in units if u.coordinator.last_update_success), units[0])
    return [first] + [u for u in units if u is not first]


async def _query_unit(unit: PanOSUnit, source: str) -> tuple[dict[str, list], dict[str, str]]:
    commands = {
        "arp": (CMD_ARP_ALL, parsers.parse_arp),
        "dhcp": (CMD_DHCP_LEASES, parsers.parse_dhcp_leases),
    }
    wanted = list(commands) if source == "all" else [source]
    results = await asyncio.gather(
        *(unit.client.op(commands[s][0], timeout=LOOKUP_TIMEOUT) for s in wanted),
        return_exceptions=True,
    )
    data: dict[str, list] = {"arp": [], "dhcp": []}
    errors: dict[str, str] = {}
    connection_errors = 0
    for name, result in zip(wanted, results):
        if isinstance(result, PanOSConnectionError):
            connection_errors += 1
            errors[name] = str(result)
        elif isinstance(result, (PanOSError, ValueError)):
            errors[name] = str(result)
        elif isinstance(result, BaseException):
            raise result
        else:
            data[name] = commands[name][1](result)
    if connection_errors == len(wanted):
        raise PanOSConnectionError(next(iter(errors.values())))
    return data, errors


async def _async_lookup(call: ServiceCall) -> ServiceResponse:
    entry = _get_entry(call.hass, call.data.get(ATTR_CONFIG_ENTRY_ID))
    query: str = call.data[ATTR_QUERY]
    source: str = call.data[ATTR_SOURCE]

    last_error: Exception | None = None
    for unit in _candidate_units(entry):
        try:
            data, errors = await _query_unit(unit, source)
        except PanOSConnectionError as err:
            last_error = err
            continue
        except PanOSError as err:
            raise HomeAssistantError(f"{unit.config.hostname}: {err}") from err
        hosts = parsers.merge_hosts(data["arp"], data["dhcp"])
        matches = [h for h in hosts if parsers.host_matches(h, query)]
        response: dict[str, Any] = {
            "firewall": unit.config.hostname,
            "query": query,
            "count": len(matches),
            "matches": matches,
        }
        if errors:
            response["errors"] = errors
        return response
    raise HomeAssistantError(f"No firewall could be reached: {last_error}")


def async_setup_services(hass: HomeAssistant) -> None:
    hass.services.async_register(
        DOMAIN,
        SERVICE_LOOKUP,
        _async_lookup,
        schema=LOOKUP_SCHEMA,
        supports_response=SupportsResponse.ONLY,
    )
