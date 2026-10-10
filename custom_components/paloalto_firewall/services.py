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
    CMD_FIB,
    CMD_INTERFACE_ALL,
    DOMAIN,
    LOOKUP_TIMEOUT,
    SERVICE_LOOKUP,
    SERVICE_ROUTE_LOOKUP,
    SERVICE_TEST_NAT_POLICY,
    SERVICE_TEST_SECURITY_POLICY,
)
from .coordinator import PanOSConfigEntry, PanOSUnit
from .network import egress, source_interface

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


_PORT = vol.All(vol.Coerce(int), vol.Range(min=0, max=65535))

_TEST_BASE = {
    vol.Optional(ATTR_CONFIG_ENTRY_ID): cv.string,
    vol.Required("source"): _ip,
    vol.Required("destination"): _ip,
    vol.Optional("protocol", default="tcp"): _protocol,
    vol.Optional("destination_port"): _PORT,
    vol.Optional("from_zone"): cv.string,
    vol.Optional("to_zone"): cv.string,
    vol.Optional("vsys"): cv.string,
}

POLICY_SCHEMA = vol.Schema(
    {
        **_TEST_BASE,
        vol.Optional("application"): cv.string,
        vol.Optional("source_user"): cv.string,
        vol.Optional("category"): cv.string,
        vol.Optional("show_all", default=False): cv.boolean,
    }
)

NAT_SCHEMA = vol.Schema(
    {
        **_TEST_BASE,
        vol.Optional("source_port"): _PORT,
        vol.Optional("to_interface"): cv.string,
    }
)

ROUTE_SCHEMA = vol.Schema(
    {
        vol.Optional(ATTR_CONFIG_ENTRY_ID): cv.string,
        vol.Required("destination"): _ip,
        vol.Optional("logical_router"): cv.string,
        vol.Optional("source"): _ip,
    }
)

# service field -> CLI keyword, in CLI order
_SECURITY_ARGS = (
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
_NAT_ARGS = (
    ("from_zone", "from"),
    ("to_zone", "to"),
    ("source", "source"),
    ("destination", "destination"),
    ("source_port", "source-port"),
    ("destination_port", "destination-port"),
    ("protocol", "protocol"),
    ("to_interface", "to-interface"),
)


def _build(root: str, args: tuple, data: dict[str, Any]) -> str:
    parts = [
        f"<{tag}>{escape(str(data[field]).strip())}</{tag}>"
        for field, tag in args
        if data.get(field) not in (None, "")
    ]
    if data.get("show_all"):
        parts.append("<show-all>yes</show-all>")
    return f"<test><{root}>{''.join(parts)}</{root}></test>"


def build_policy_match_cmd(data: dict[str, Any]) -> str:
    return _build("security-policy-match", _SECURITY_ARGS, data)


def build_nat_match_cmd(data: dict[str, Any]) -> str:
    return _build("nat-policy-match", _NAT_ARGS, data)


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


async def _network_state(
    entry: PanOSConfigEntry, unit: PanOSUnit
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    """Interfaces (cached when from the same firewall) and a fresh FIB."""
    cached = getattr(entry.runtime_data.network, "data", None)
    if cached and cached.get("unit") == unit.config.hostname:
        interfaces = cached["interfaces"]
    else:
        interfaces = parsers.parse_interfaces(await unit.client.op(CMD_INTERFACE_ALL))
    fib = parsers.parse_fib(await unit.client.op(CMD_FIB, timeout=LOOKUP_TIMEOUT))
    return interfaces, fib


def infer_context(
    interfaces: dict[str, Any], fib: list[dict[str, Any]], source: str, destination: str
) -> dict[str, Any]:
    """Work out vsys, zones and egress the way the firewall would.

    Ingress: the interface whose connected subnet holds the source, else the
    interface the source is routed via. Egress: a FIB lookup of the
    destination in the ingress interface's logical router.
    """
    ingress = source_interface(interfaces, source)
    if ingress is None:
        best = None
        for lr in {r["logical_router"] for r in fib}:
            if (eg := egress(interfaces, fib, lr, source)) and not eg["drop"]:
                plen = int(eg["prefix"].split("/")[1])
                if best is None or plen > best[0]:
                    best = (plen, interfaces.get(eg["interface"] or ""))
        ingress = best[1] if best else None
    out: dict[str, Any] = {}
    if ingress:
        out.update(
            ingress_interface=ingress["name"],
            from_zone=ingress.get("zone"),
            vsys=ingress.get("vsys"),
            logical_router=ingress.get("logical_router"),
        )
        if ingress.get("logical_router") and (
            eg := egress(interfaces, fib, ingress["logical_router"], destination)
        ):
            out.update(
                egress_interface=eg["interface"],
                to_zone=eg["zone"],
                nexthop=eg["nexthop"],
                route=eg["prefix"],
                dropped=eg["drop"],
            )
    return out


async def _run_policy_test(call: ServiceCall, kind: str) -> ServiceResponse:
    entry = _get_entry(call.hass, call.data.get(ATTR_CONFIG_ENTRY_ID))
    last_error: Exception | None = None
    for unit in _candidate_units(entry):
        try:
            data = dict(call.data)
            inferred: dict[str, Any] = {}
            needs = ("vsys", "from_zone", "to_zone") + (("to_interface",) if kind == "nat" else ())
            if any(not data.get(k) for k in needs):
                try:
                    interfaces, fib = await _network_state(entry, unit)
                    ctx = infer_context(interfaces, fib, data["source"], data["destination"])
                except (PanOSError, ValueError) as err:
                    if isinstance(err, PanOSConnectionError):
                        raise
                    ctx = {}
                mapping = {"vsys": "vsys", "from_zone": "from_zone", "to_zone": "to_zone"}
                if kind == "nat":
                    mapping["to_interface"] = "egress_interface"
                for field, key in mapping.items():
                    if not data.get(field) and ctx.get(key):
                        data[field] = inferred[field] = ctx[key]
                path = {k: ctx[k] for k in ("ingress_interface", "logical_router", "egress_interface",
                                            "nexthop", "route", "dropped") if k in ctx}
            else:
                path = {}
            cmd = build_policy_match_cmd(data) if kind == "security" else build_nat_match_cmd(data)
            result = await unit.client.op(cmd, timeout=LOOKUP_TIMEOUT, vsys=data.get("vsys"))
        except PanOSConnectionError as err:
            last_error = err
            continue
        except PanOSError as err:
            # e.g. an unknown zone, application or vsys name
            raise HomeAssistantError(f"{unit.config.hostname}: {err}") from err

        rules = parsers.parse_policy_match(result)
        first = rules[0] if rules else {}
        response: dict[str, Any] = {
            "firewall": unit.config.hostname,
            "criteria": {
                k: v for k, v in data.items()
                if k not in (ATTR_CONFIG_ENTRY_ID, "show_all") and v not in (None, "")
            },
            "inferred": inferred,
            "path": path,
            "matched": bool(rules),
            "rule": first.get("name"),
            "rules": rules,
        }
        if kind == "security":
            response["action"] = first.get("action")
            if not rules:
                response["note"] = (
                    "No security rule matched; the default rules apply "
                    "(intrazone-default allows, interzone-default denies)."
                )
        elif not rules:
            response["note"] = "No NAT rule matched; the traffic is not translated."
        if path.get("dropped"):
            response["note"] = "The destination is routed to a drop (blackhole) route."
        return response
    raise HomeAssistantError(f"No firewall could be reached: {last_error}")


async def _async_test_policy(call: ServiceCall) -> ServiceResponse:
    return await _run_policy_test(call, "security")


async def _async_test_nat(call: ServiceCall) -> ServiceResponse:
    return await _run_policy_test(call, "nat")


async def _async_route_lookup(call: ServiceCall) -> ServiceResponse:
    entry = _get_entry(call.hass, call.data.get(ATTR_CONFIG_ENTRY_ID))
    destination = call.data["destination"]
    last_error: Exception | None = None
    for unit in _candidate_units(entry):
        try:
            interfaces, fib = await _network_state(entry, unit)
        except PanOSConnectionError as err:
            last_error = err
            continue
        except PanOSError as err:
            raise HomeAssistantError(f"{unit.config.hostname}: {err}") from err

        all_lrs = sorted({r["logical_router"] for r in fib})
        if lr := call.data.get("logical_router"):
            if lr not in all_lrs:
                raise ServiceValidationError(
                    f"Unknown logical router {lr!r}; known: {', '.join(all_lrs)}"
                )
            lrs, chosen_by = [lr], "logical_router"
        elif src := call.data.get("source"):
            ctx = infer_context(interfaces, fib, src, destination)
            if not ctx.get("logical_router"):
                raise ServiceValidationError(f"Could not tell which logical router {src} uses")
            lrs, chosen_by = [ctx["logical_router"]], f"source {src} ({ctx.get('ingress_interface')})"
        else:
            lrs, chosen_by = all_lrs, "all logical routers"

        results = []
        for name in lrs:
            eg = egress(interfaces, fib, name, destination)
            results.append(
                {"logical_router": name, "route": eg["prefix"], "paths": eg["paths"]}
                if eg
                else {"logical_router": name, "route": None, "paths": [], "note": "no route"}
            )
        return {
            "firewall": unit.config.hostname,
            "destination": destination,
            "searched": chosen_by,
            "results": results,
        }
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
    hass.services.async_register(
        DOMAIN,
        SERVICE_TEST_NAT_POLICY,
        _async_test_nat,
        schema=NAT_SCHEMA,
        supports_response=SupportsResponse.ONLY,
    )
    hass.services.async_register(
        DOMAIN,
        SERVICE_ROUTE_LOOKUP,
        _async_route_lookup,
        schema=ROUTE_SCHEMA,
        supports_response=SupportsResponse.ONLY,
    )
