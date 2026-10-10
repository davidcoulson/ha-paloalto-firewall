"""Pair-level network coordinator: interfaces, logical routers, path monitors, jobs.

Everything here describes the forwarding state of the HA pair, so it is read
from whichever firewall is active (or the only firewall, when standalone).
"""

from __future__ import annotations

import asyncio
import ipaddress
import logging
import time
from typing import TYPE_CHECKING, Any

from homeassistant.core import HomeAssistant
from homeassistant.exceptions import ConfigEntryAuthFailed
from homeassistant.helpers.device_registry import DeviceInfo
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator, UpdateFailed

from . import parsers
from .api import PanOSAuthError, PanOSError
from .const import (
    CMD_FIB,
    CMD_INTERFACE_ALL,
    CMD_JOBS,
    CMD_PATH_MONITOR,
    CMD_PD_POOLS,
    CMD_PENDING_CHANGES,
    CMD_RUNNING_NAT,
    DOMAIN,
    EVENT_EGRESS_CHANGE,
    EVENT_PREFIX_CHANGE,
    MANUFACTURER,
    PROBE_IPV4,
    PROBE_IPV6,
    lr_identifier,
    pair_identifier,
)

if TYPE_CHECKING:
    from datetime import timedelta

    from .coordinator import PanOSConfigEntry, PanOSUnit

_LOGGER = logging.getLogger(__name__)


def parent_identifier(entry: PanOSConfigEntry) -> tuple[str, str]:
    """The device everything pair-wide hangs off: the HA pair, or the lone firewall."""
    runtime = entry.runtime_data
    if runtime.pair is not None:
        return (DOMAIN, pair_identifier(entry.entry_id))
    return (DOMAIN, runtime.units[0].config.serial)


def lr_device_info(entry: PanOSConfigEntry, name: str) -> DeviceInfo:
    return DeviceInfo(
        identifiers={(DOMAIN, lr_identifier(entry.entry_id, name))},
        name=name,
        manufacturer=MANUFACTURER,
        model="Logical router",
        via_device=parent_identifier(entry),
    )


def pick_unit(entry: PanOSConfigEntry) -> PanOSUnit:
    """The active firewall, else any reachable one, else the first."""
    runtime = entry.runtime_data
    if runtime.pair is not None and runtime.pair.active_unit is not None:
        return runtime.pair.active_unit
    return next(
        (u for u in runtime.units if u.coordinator.last_update_success), runtime.units[0]
    )


def egress(
    interfaces: dict[str, dict[str, Any]],
    fib: list[dict[str, Any]],
    logical_router: str,
    address: str,
) -> dict[str, Any] | None:
    paths = parsers.fib_lookup(fib, logical_router, address)
    if not paths:
        return None
    out_paths = []
    for p in paths:
        iface = interfaces.get(p["interface"] or "", {})
        out_paths.append(
            {
                "interface": p["interface"],
                "nexthop": p["nexthop"],
                "zone": iface.get("zone"),
                "vsys": iface.get("vsys"),
                "drop": p["drop"],
            }
        )
    first = out_paths[0]
    return {
        "prefix": paths[0]["destination"],
        "interface": first["interface"],
        "zone": first["zone"],
        "vsys": first["vsys"],
        "nexthop": first["nexthop"],
        "drop": first["drop"],
        "paths": out_paths,
    }


def source_interface(
    interfaces: dict[str, dict[str, Any]], address: str
) -> dict[str, Any] | None:
    """The interface whose connected subnet contains ``address`` (longest match)."""
    ip = ipaddress.ip_address(address)
    best, best_len = None, -1
    for iface in interfaces.values():
        for cidr in iface["ips"]:
            try:
                net = ipaddress.ip_interface(cidr).network
            except ValueError:
                continue
            if net.version == ip.version and ip in net and net.prefixlen > best_len:
                if net.is_link_local and not ip.is_link_local:
                    continue
                best, best_len = iface, net.prefixlen
    return best


def pm_key_suffix(key: str) -> str:
    """Unique-id suffix for a path-monitor group key."""
    return key.replace("|", "_").replace("/", "_").replace(".", "_").replace(":", "_")


def logical_routers(data: dict[str, Any]) -> list[str]:
    names = {i["logical_router"] for i in data["interfaces"].values() if i["logical_router"]}
    names |= {r["logical_router"] for r in data["fib"]}
    return sorted(names)


class PanOSNetworkCoordinator(DataUpdateCoordinator[dict[str, Any] | None]):
    config_entry: PanOSConfigEntry

    def __init__(
        self,
        hass: HomeAssistant,
        entry: PanOSConfigEntry,
        interval: timedelta,
        selected_interfaces: list[str] | None,
    ) -> None:
        super().__init__(
            hass, _LOGGER, config_entry=entry, name=f"{DOMAIN} network", update_interval=interval
        )
        self.configured_interfaces = selected_interfaces
        self.unit_hostname: str | None = None
        self._prev_counters: dict[str, tuple[float, dict[str, Any]]] = {}
        self._prev_egress: dict[tuple[str, int], str | None] = {}
        self._prev_prefix: dict[str, str | None] = {}
        self._warned: set[str] = set()

    async def _optional(self, unit: PanOSUnit, key: str, cmd: str, parser) -> Any:
        try:
            return parser(await unit.client.op(cmd))
        except PanOSAuthError as err:
            raise ConfigEntryAuthFailed(str(err)) from err
        except (PanOSError, ValueError) as err:
            if key not in self._warned:
                self._warned.add(key)
                _LOGGER.debug("%s: '%s' unavailable: %s", unit.config.host, key, err)
            return None

    def selected_interfaces(self, data: dict[str, Any]) -> list[str]:
        """Configured interfaces, or by default the WAN-facing ones."""
        if self.configured_interfaces is not None:
            return [i for i in self.configured_interfaces if i in data["interfaces"]]
        auto: list[str] = []
        for pm in data["path_monitors"] or []:
            auto.append(pm["interface"])
        for lr in data["egress"].values():
            for fam in ("ipv4", "ipv6"):
                if lr.get(fam) and lr[fam]["interface"]:
                    auto.append(lr[fam]["interface"])
        return sorted({i for i in auto if i in data["interfaces"]})

    async def _async_update_data(self) -> dict[str, Any]:
        unit = pick_unit(self.config_entry)
        if unit.config.hostname != self.unit_hostname:
            # Different box (failover): counters aren't comparable.
            self._prev_counters.clear()
            self.unit_hostname = unit.config.hostname

        interfaces, fib, path_monitors, jobs, pending = await asyncio.gather(
            self._optional(unit, "interfaces", CMD_INTERFACE_ALL, parsers.parse_interfaces),
            self._optional(unit, "fib", CMD_FIB, parsers.parse_fib),
            self._optional(unit, "path_monitor", CMD_PATH_MONITOR, parsers.parse_path_monitor),
            self._optional(unit, "jobs", CMD_JOBS, parsers.parse_jobs),
            self._optional(unit, "pending", CMD_PENDING_CHANGES, parsers.parse_pending_changes),
        )
        if interfaces is None:
            raise UpdateFailed(f"{unit.config.host}: could not read interfaces")
        fib = fib or []
        data: dict[str, Any] = {
            "unit": unit.config.hostname,
            "interfaces": interfaces,
            "fib": fib,
            "path_monitors": path_monitors,
            "jobs": jobs,
            "pending_changes": pending,
        }

        data["egress"] = {
            lr: {
                "ipv4": egress(interfaces, fib, lr, PROBE_IPV4),
                "ipv6": egress(interfaces, fib, lr, PROBE_IPV6),
                "routes_ipv4": sum(1 for r in fib if r["logical_router"] == lr and r["version"] == 4),
                "routes_ipv6": sum(1 for r in fib if r["logical_router"] == lr and r["version"] == 6),
            }
            for lr in logical_routers(data)
        }
        data["path_groups"] = self._group_path_monitors(interfaces, path_monitors or [])
        data["counters"] = await self._counters(unit, self.selected_interfaces(data))
        data["prefix_pools"] = await self._prefix_pools(unit, interfaces)
        self._fire_egress_events(data["egress"])
        self._fire_prefix_events(data["prefix_pools"])
        return data

    async def _prefix_pools(
        self, unit: PanOSUnit, interfaces: dict[str, dict[str, Any]]
    ) -> dict[str, dict[str, Any]]:
        """DHCPv6-PD pools, each checked against its WAN vsys's NPTv6 rules."""
        pools = await self._optional(unit, "pd_pools", CMD_PD_POOLS, parsers.parse_pd_pools)
        if not pools:
            return {}
        nat_by_vsys: dict[str, dict[str, Any] | None] = {}
        out: dict[str, dict[str, Any]] = {}
        for name, pool in pools.items():
            vsys = interfaces.get(pool["interface"] or "", {}).get("vsys")
            if vsys not in nat_by_vsys:
                try:
                    nat_by_vsys[vsys] = parsers.parse_running_nat(
                        await unit.client.op(CMD_RUNNING_NAT, vsys=vsys)
                    )
                except PanOSAuthError as err:
                    raise ConfigEntryAuthFailed(str(err)) from err
                except (PanOSError, ValueError) as err:
                    _LOGGER.debug("running nat-policy for %s unavailable: %s", vsys, err)
                    nat_by_vsys[vsys] = None
            rules = nat_by_vsys[vsys]
            problems, checked = (
                parsers.nptv6_mismatches(rules, pool) if rules is not None else ([], [])
            )
            out[name] = {
                **pool,
                "vsys": vsys,
                "nat_checked": rules is not None,
                "nptv6_rules": checked,
                "problems": problems,
            }
        return out

    def _fire_prefix_events(self, pools: dict[str, dict[str, Any]]) -> None:
        for name, pool in pools.items():
            prefix = pool.get("prefix")
            if name in self._prev_prefix and self._prev_prefix[name] != prefix:
                _LOGGER.warning(
                    "Delegated prefix for %s changed: %s -> %s", name, self._prev_prefix[name], prefix
                )
                self.hass.bus.async_fire(
                    EVENT_PREFIX_CHANGE,
                    {
                        "entry_id": self.config_entry.entry_id,
                        "pool": name,
                        "interface": pool.get("interface"),
                        "previous_prefix": self._prev_prefix[name],
                        "prefix": prefix,
                    },
                )
            self._prev_prefix[name] = prefix

    @staticmethod
    def _group_path_monitors(
        interfaces: dict[str, dict[str, Any]], entries: list[dict[str, Any]]
    ) -> dict[str, dict[str, Any]]:
        """One group per (logical router, interface, next hop)."""
        groups: dict[str, dict[str, Any]] = {}
        for e in entries:
            iface = interfaces.get(e["interface"] or "", {})
            lr = iface.get("logical_router") or "unknown"
            key = f"{lr}|{e['interface']}|{e['nexthop']}"
            g = groups.setdefault(
                key,
                {
                    "logical_router": lr,
                    "interface": e["interface"],
                    "nexthop": e["nexthop"],
                    "zone": iface.get("zone"),
                    "routes": [],
                    "monitors": e["monitors"],
                    "condition": e["condition"],
                    "up": True,
                },
            )
            g["routes"].append(f"{e['destination']} ({'up' if e['up'] else 'down'})")
            g["up"] = g["up"] and e["up"]
        return groups

    async def _counters(self, unit: PanOSUnit, names: list[str]) -> dict[str, dict[str, Any]]:
        async def one(name: str):
            return name, await self._optional(
                unit,
                f"counters {name}",
                f"<show><interface>{name}</interface></show>",
                parsers.parse_interface_counters,
            )

        now = time.monotonic()
        out: dict[str, dict[str, Any]] = {}
        for name, counters in await asyncio.gather(*(one(n) for n in names)):
            if counters is None:
                continue
            rates = {"in_kbps": None, "out_kbps": None}
            if prev := self._prev_counters.get(name):
                dt = now - prev[0]
                for key, src in (("in_kbps", "ibytes"), ("out_kbps", "obytes")):
                    a, b = prev[1].get(src), counters.get(src)
                    if dt > 0 and a is not None and b is not None and b >= a:
                        rates[key] = round((b - a) * 8 / 1000 / dt, 1)
            self._prev_counters[name] = (now, counters)
            out[name] = {**counters, **rates}
        return out

    def _fire_egress_events(self, egress_data: dict[str, dict[str, Any]]) -> None:
        for lr, info in egress_data.items():
            for fam, version in (("ipv4", 4), ("ipv6", 6)):
                cur = info.get(fam)
                cur_if = cur["interface"] if cur else None
                key = (lr, version)
                if key in self._prev_egress and self._prev_egress[key] != cur_if:
                    old_if = self._prev_egress[key]
                    old_zone = (
                        (self.data or {}).get("interfaces", {}).get(old_if or "", {}).get("zone")
                    )
                    _LOGGER.warning(
                        "%s %s internet egress changed: %s -> %s", lr, fam, old_if, cur_if
                    )
                    self.hass.bus.async_fire(
                        EVENT_EGRESS_CHANGE,
                        {
                            "entry_id": self.config_entry.entry_id,
                            "logical_router": lr,
                            "family": fam,
                            "previous_interface": old_if,
                            "previous_zone": old_zone,
                            "interface": cur_if,
                            "zone": cur["zone"] if cur else None,
                            "nexthop": cur["nexthop"] if cur else None,
                        },
                    )
                self._prev_egress[key] = cur_if


def _local_addresses(interfaces: dict[str, dict[str, Any]]) -> dict[str, dict[str, Any]]:
    """The firewall's own addresses -> owning interface."""
    owned: dict[str, dict[str, Any]] = {}
    for iface in interfaces.values():
        for cidr in iface["ips"]:
            try:
                owned[str(ipaddress.ip_interface(cidr).ip)] = iface
            except ValueError:
                continue
    return owned


def ingress_interface(
    interfaces: dict[str, dict[str, Any]], fib: list[dict[str, Any]], source: str
) -> dict[str, Any] | None:
    """Where traffic from ``source`` enters: its connected interface, else the
    interface the source is routed via (most specific route in any logical router)."""
    if found := source_interface(interfaces, source):
        return found
    best = None
    for lr in {r["logical_router"] for r in fib}:
        if (eg := egress(interfaces, fib, lr, source)) and not eg["drop"]:
            plen = int(eg["prefix"].split("/")[1])
            if best is None or plen > best[0]:
                best = (plen, interfaces.get(eg["interface"] or ""))
    return best[1] if best else None


def trace_path(
    interfaces: dict[str, dict[str, Any]],
    fib: list[dict[str, Any]],
    source: str,
    destination: str,
    max_hops: int = 6,
) -> list[dict[str, Any]]:
    """Follow a flow through the firewall, one hop per vsys/logical router.

    A hop ends at the egress interface chosen by a FIB lookup. If that hop's
    next hop is one of the firewall's own addresses (vsys linked by a cable or
    loop), the flow re-enters on that interface and the trace continues there.
    """
    owned = _local_addresses(interfaces)
    hops: list[dict[str, Any]] = []
    ingress = ingress_interface(interfaces, fib, source)
    seen: set[str] = set()
    while ingress and ingress["name"] not in seen and len(hops) < max_hops:
        seen.add(ingress["name"])
        lr = ingress.get("logical_router")
        hop: dict[str, Any] = {
            "vsys": ingress.get("vsys"),
            "logical_router": lr,
            "ingress_interface": ingress["name"],
            "from_zone": ingress.get("zone"),
        }
        eg = egress(interfaces, fib, lr, destination) if lr else None
        if eg:
            hop.update(
                egress_interface=eg["interface"],
                to_zone=eg["zone"],
                nexthop=eg["nexthop"],
                route=eg["prefix"],
                dropped=eg["drop"],
            )
        hops.append(hop)
        if not eg or eg["drop"] or not eg["nexthop"]:
            break
        ingress = owned.get(eg["nexthop"])
    return hops
