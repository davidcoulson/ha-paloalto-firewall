"""Actions (services) for the Palo Alto Networks Firewall integration."""

from __future__ import annotations

import asyncio
import ipaddress
from typing import Any
from xml.sax.saxutils import escape

import voluptuous as vol

from homeassistant.config_entries import ConfigEntryState
from homeassistant.core import HomeAssistant, ServiceCall, ServiceResponse, SupportsResponse
from homeassistant.exceptions import HomeAssistantError, ServiceValidationError
from homeassistant.helpers import config_validation as cv

from . import parsers
from .api import PanOSConnectionError, PanOSError
from .const import (
    CMD_ARP_ALL,
    CMD_DHCP_LEASES,
    DOMAIN,
    LOOKUP_TIMEOUT,
    SERVICE_LOOKUP,
    SERVICE_TEST_SECURITY_POLICY,
)
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


PROTOCOLS = {"icmp": 1, "tcp": 6, "udp": 17, "gre": 47, "esp": 50, "icmpv6": 58, "sctp": 132}


def _ip(value: Any) -> str:
    try:
        return str(ipaddress.ip_address(str(value).strip()))
    except ValueError as err:
        raise vol.Invalid(f"{value!r} is not an IP address") from err


def _protocol(value: Any) -> int:
    text = str(value).strip().lower()
    if text in PROTOCOLS:
        return PROTOCOLS[text]
    try:
        number = int(text)
    except ValueError as err:
        raise vol.Invalid(f"Unknown protocol {value!r}; use tcp, udp, icmp or a number") from err
    if not 0 <= number <= 255:
        raise vol.Invalid("Protocol number must be 0-255")
    return number


POLICY_SCHEMA = vol.Schema(
    {
        vol.Optional(ATTR_CONFIG_ENTRY_ID): cv.string,
        vol.Required("source"): _ip,
        vol.Required("destination"): _ip,
        vol.Optional("protocol", default="tcp"): _protocol,
        vol.Optional("destination_port"): vol.All(vol.Coerce(int), vol.Range(min=0, max=65535)),
        vol.Optional("from_zone"): cv.string,
        vol.Optional("to_zone"): cv.string,
        vol.Optional("application"): cv.string,
        vol.Optional("source_user"): cv.string,
        vol.Optional("category"): cv.string,
        vol.Optional("show_all", default=False): cv.boolean,
    }
)

# service field -> CLI keyword, in the order the CLI documents them
_POLICY_ARGS = (
    ("from_zone", "from"),
    ("to_zone", "to"),
    ("source", "source"),
    ("destination", "destination"),
    ("destination_port", "destination-port"),
    ("protocol", "protocol"),
    ("application", "application"),
    ("source_user", "source-user"),
    ("category", "category"),
)


def build_policy_match_cmd(data: dict[str, Any]) -> str:
    parts = [
        f"<{tag}>{escape(str(data[field]).strip())}</{tag}>"
        for field, tag in _POLICY_ARGS
        if data.get(field) not in (None, "")
    ]
    if data.get("show_all"):
        parts.append("<show-all>yes</show-all>")
    return f"<test><security-policy-match>{''.join(parts)}</security-policy-match></test>"


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


async def _async_test_policy(call: ServiceCall) -> ServiceResponse:
    entry = _get_entry(call.hass, call.data.get(ATTR_CONFIG_ENTRY_ID))
    cmd = build_policy_match_cmd(call.data)
    criteria = {
        k: v
        for k, v in call.data.items()
        if k not in (ATTR_CONFIG_ENTRY_ID, "show_all") and v not in (None, "")
    }

    last_error: Exception | None = None
    for unit in _candidate_units(entry):
        try:
            result = await unit.client.op(cmd, timeout=LOOKUP_TIMEOUT)
        except PanOSConnectionError as err:
            last_error = err
            continue
        except PanOSError as err:
            # e.g. an unknown zone or application name
            raise HomeAssistantError(f"{unit.config.hostname}: {err}") from err
        rules = parsers.parse_policy_match(result)
        first = rules[0] if rules else {}
        response: dict[str, Any] = {
            "firewall": unit.config.hostname,
            "criteria": criteria,
            "matched": bool(rules),
            "rule": first.get("name"),
            "action": first.get("action"),
            "rules": rules,
        }
        if not rules:
            response["note"] = (
                "No security rule matched; the default rules apply "
                "(intrazone-default allows, interzone-default denies)."
            )
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
    hass.services.async_register(
        DOMAIN,
        SERVICE_TEST_SECURITY_POLICY,
        _async_test_policy,
        schema=POLICY_SCHEMA,
        supports_response=SupportsResponse.ONLY,
    )
