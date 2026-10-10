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
    CMD_RUNNING_NAT,
    CMD_SESSION_FILTER,
    CMD_SESSION_ID,
    DOMAIN,
    LOOKUP_TIMEOUT,
    SERVICE_CHECK_UPDATES,
    SERVICE_LOOKUP,
    SERVICE_SESSION_LOOKUP,
    SERVICE_ROUTE_LOOKUP,
    SERVICE_TEST_NAT_POLICY,
    SERVICE_TEST_SECURITY_POLICY,
)
from .coordinator import PanOSConfigEntry, PanOSUnit
from .network import egress, ingress_interface, trace_path

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


_LIST_CAP = 20


def _compact_rule(rule: dict[str, Any]) -> dict[str, Any]:
    out = {}
    for k, v in rule.items():
        if isinstance(v, list) and len(v) > _LIST_CAP:
            v = v[:_LIST_CAP] + [f"... {len(v) - _LIST_CAP} more"]
        out[k] = v
    return out


async def _nat_details(
    unit: PanOSUnit, vsys: str | None, rule: str, cache: dict[str | None, dict[str, Any]]
) -> dict[str, Any] | None:
    """The matched NAT rule as running on the firewall (what it translates to)."""
    if vsys not in cache:
        try:
            cache[vsys] = parsers.parse_running_nat(
                await unit.client.op(CMD_RUNNING_NAT, timeout=LOOKUP_TIMEOUT, vsys=vsys)
            )
        except (PanOSError, ValueError):
            cache[vsys] = {}
    details = cache[vsys].get(rule)
    if not details:
        return None
    return {
        k: details.get(k)
        for k in ("nat_type", "translate_to", "source", "destination", "to_interface", "index")
        if details.get(k) is not None
    }


async def _run_policy_test(call: ServiceCall, kind: str) -> ServiceResponse:
    """Run a policy test at every hop the flow takes, or one explicit hop."""
    entry = _get_entry(call.hass, call.data.get(ATTR_CONFIG_ENTRY_ID))
    base = dict(call.data)
    explicit = any(base.get(k) for k in ("vsys", "from_zone", "to_zone"))
    last_error: Exception | None = None
    for unit in _candidate_units(entry):
        try:
            try:
                interfaces, fib = await _network_state(entry, unit)
                trace = trace_path(interfaces, fib, base["source"], base["destination"])
            except PanOSConnectionError:
                raise
            except (PanOSError, ValueError):
                trace = []

            if explicit:
                # One hop: the caller's values, gaps filled from the matching hop.
                match = next((h for h in trace if h["vsys"] == base.get("vsys")), None)
                match = match or (trace[0] if trace and not base.get("vsys") else {})
                hop = {**match}
                for field in ("vsys", "from_zone", "to_zone"):
                    if base.get(field):
                        hop[field] = base[field]
                if kind == "nat" and base.get("to_interface"):
                    hop["egress_interface"] = base["to_interface"]
                plan = [hop]
            else:
                plan = trace or [{}]

            hops = []
            running_nat: dict[str | None, dict[str, Any]] = {}
            for i, hop in enumerate(plan, 1):
                data = {**base, "vsys": hop.get("vsys"), "from_zone": hop.get("from_zone"),
                        "to_zone": hop.get("to_zone")}
                if kind == "nat":
                    data["to_interface"] = base.get("to_interface") or hop.get("egress_interface")
                cmd = build_policy_match_cmd(data) if kind == "security" else build_nat_match_cmd(data)
                result = await unit.client.op(cmd, timeout=LOOKUP_TIMEOUT, vsys=data.get("vsys"))
                rules = parsers.parse_policy_match(result)
                first = rules[0] if rules else {}
                entry_out = {
                    "hop": i,
                    **{k: v for k, v in hop.items() if v is not None},
                    "matched": bool(rules),
                    "rule": first.get("name"),
                }
                if kind == "security":
                    entry_out["action"] = first.get("action")
                elif rules:
                    entry_out["translation"] = await _nat_details(
                        unit, data.get("vsys"), first["name"], running_nat
                    )
                entry_out["rules"] = [_compact_rule(r) for r in rules]
                hops.append(entry_out)
                if hop.get("dropped"):
                    break
        except PanOSConnectionError as err:
            last_error = err
            continue
        except PanOSError as err:
            # e.g. an unknown zone, application or vsys name
            raise HomeAssistantError(f"{unit.config.hostname}: {err}") from err

        criteria = {
            k: v for k, v in base.items()
            if k not in (ATTR_CONFIG_ENTRY_ID, "show_all") and v not in (None, "")
        }
        response: dict[str, Any] = {
            "firewall": unit.config.hostname,
            "criteria": criteria,
            "mode": "explicit" if explicit else "traced",
            "hops": hops,
        }
        if kind == "security":
            # The flow is allowed only if every hop allows it.
            deciding = next(
                (h for h in hops if not h["matched"] or h["action"] != "allow"), None
            )
            if deciding is None and hops:
                response.update(verdict="allow", rule=hops[-1]["rule"], decided_at_hop=None)
            elif deciding is not None:
                response.update(
                    verdict=deciding["action"] or "default",
                    rule=deciding["rule"],
                    decided_at_hop=deciding["hop"],
                )
                if not deciding["matched"]:
                    response["note"] = (
                        f"No security rule matched at hop {deciding['hop']}; the default rule "
                        "applies there (intrazone-default allows, interzone-default denies)."
                    )
        else:
            translations = [
                {
                    "hop": h["hop"],
                    "vsys": h.get("vsys"),
                    "rule": h["rule"],
                    "translate_to": (h.get("translation") or {}).get("translate_to"),
                }
                for h in hops
                if h["matched"]
            ]
            response["translations"] = translations
            if not translations:
                response["note"] = "No NAT rule matched at any hop; the traffic is not translated."
        if any(h.get("dropped") for h in hops):
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
            ingress = ingress_interface(interfaces, fib, src)
            if not ingress or not ingress.get("logical_router"):
                raise ServiceValidationError(f"Could not tell which logical router {src} uses")
            lrs, chosen_by = [ingress["logical_router"]], f"source {src} ({ingress['name']})"
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


SESSION_FILTERS = {
    # service field -> PAN-OS filter element
    "source": "source",
    "destination": "destination",
    "source_port": "source-port",
    "destination_port": "destination-port",
    "protocol": "protocol",
    "application": "application",
    "from_zone": "from",
    "to_zone": "to",
    "rule": "rule",
    "source_user": "source-user",
    "state": "state",
}

SESSION_SCHEMA = vol.Schema(
    {
        vol.Optional(ATTR_CONFIG_ENTRY_ID): cv.string,
        vol.Optional("session_id"): vol.All(vol.Coerce(int), vol.Range(min=1)),
        vol.Optional("source"): _ip,
        vol.Optional("destination"): _ip,
        vol.Optional("source_port"): cv.port,
        vol.Optional("destination_port"): cv.port,
        vol.Optional("protocol"): _protocol,
        vol.Optional("application"): cv.string,
        vol.Optional("from_zone"): cv.string,
        vol.Optional("to_zone"): cv.string,
        vol.Optional("rule"): cv.string,
        vol.Optional("source_user"): cv.string,
        vol.Optional("state"): vol.In(["active", "discard", "closed", "closing", "initial", "opening"]),
        vol.Optional("limit", default=50): vol.All(vol.Coerce(int), vol.Range(min=1, max=500)),
    }
)


def build_session_filter(data: dict[str, Any]) -> str:
    return "".join(
        f"<{tag}>{escape(str(data[field]))}</{tag}>"
        for field, tag in SESSION_FILTERS.items()
        if data.get(field) not in (None, "")
    )


async def _async_session_lookup(call: ServiceCall) -> ServiceResponse:
    """Live sessions on the active firewall matching the given filters."""
    entry = _get_entry(call.hass, call.data.get(ATTR_CONFIG_ENTRY_ID))
    session_id = call.data.get("session_id")
    filters = build_session_filter(call.data)
    if not session_id and not filters:
        raise ServiceValidationError(
            "Give session_id or at least one filter (source, destination, port, application, zone, rule...)"
        )
    limit: int = call.data["limit"]
    last_error: Exception | None = None
    for unit in _candidate_units(entry):
        try:
            if session_id:
                detail = await unit.client.op(CMD_SESSION_ID.format(session_id), timeout=LOOKUP_TIMEOUT)
                return {
                    "firewall": unit.config.hostname,
                    "session_id": session_id,
                    "session": parsers.xml_to_dict(detail),
                }
            result, count = await asyncio.gather(
                unit.client.op(CMD_SESSION_FILTER.format(filters), timeout=LOOKUP_TIMEOUT),
                unit.client.op(
                    CMD_SESSION_FILTER.format(filters + "<count>yes</count>"), timeout=LOOKUP_TIMEOUT
                ),
            )
        except PanOSConnectionError as err:
            last_error = err
            continue
        except PanOSError as err:
            raise HomeAssistantError(f"{unit.config.hostname}: {err}") from err
        sessions = parsers.parse_sessions(result)
        total = parsers.parse_session_count(count)
        if total is None:
            total = len(sessions)
        return {
            "firewall": unit.config.hostname,
            "total": total,
            "returned": min(len(sessions), limit),
            "truncated": total > limit,
            "sessions": sessions[:limit],
        }
    raise HomeAssistantError(f"No firewall could be reached: {last_error}")


CHECK_UPDATES_SCHEMA = vol.Schema({vol.Optional(ATTR_CONFIG_ENTRY_ID): cv.string})


async def _async_check_updates(call: ServiceCall) -> ServiceResponse:
    """Run the software, content, GlobalProtect client and licence checks now."""
    entry = _get_entry(call.hass, call.data.get(ATTR_CONFIG_ENTRY_ID))
    units = entry.runtime_data.units
    await asyncio.gather(*(u.updates.async_refresh() for u in units))
    out: dict[str, Any] = {}
    for unit in units:
        data = unit.updates.data or {}
        system = (unit.coordinator.data or {}).get("system") or {}
        out[unit.config.hostname] = {
            "ok": unit.updates.last_update_success,
            "panos_installed": system.get("sw_version"),
            "panos_newest_in_train": (
                parsers.latest_panos(
                    (data.get("software") or {}).get("versions") or [], system.get("sw_version")
                )["train"]
                or {}
            ).get("version"),
            "content_installed": system.get("app_version"),
            "content_latest": (
                parsers.latest_content((data.get("content") or {}).get("versions") or []) or {}
            ).get("version"),
            "gp_client_installed": system.get("gp_client_version"),
            "gp_client_newest_in_train": (
                parsers.latest_gp_client(
                    (data.get("gp_client") or {}).get("versions") or [],
                    system.get("gp_client_version"),
                )["train"]
                or {}
            ).get("version"),
        }
    return {"firewalls": out} if call.return_response else None


def async_setup_services(hass: HomeAssistant) -> None:
    hass.services.async_register(
        DOMAIN,
        SERVICE_SESSION_LOOKUP,
        _async_session_lookup,
        schema=SESSION_SCHEMA,
        supports_response=SupportsResponse.ONLY,
    )
    hass.services.async_register(
        DOMAIN,
        SERVICE_CHECK_UPDATES,
        _async_check_updates,
        schema=CHECK_UPDATES_SCHEMA,
        supports_response=SupportsResponse.OPTIONAL,
    )
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
