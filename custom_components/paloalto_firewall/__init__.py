"""Palo Alto Networks firewall integration (standalone or active/passive HA pair)."""

from __future__ import annotations

import asyncio
from datetime import timedelta

from homeassistant.const import CONF_NAME, CONF_PASSWORD, CONF_USERNAME, CONF_VERIFY_SSL
from homeassistant.core import HomeAssistant, callback
from homeassistant.exceptions import ConfigEntryAuthFailed, ConfigEntryNotReady
from homeassistant.helpers import config_validation as cv
from homeassistant.helpers import entity_registry as er
from homeassistant.helpers.aiohttp_client import async_get_clientsession
from homeassistant.helpers.typing import ConfigType

from .api import PanOSClient
from .const import (
    CONF_INTERFACES,
    CONF_SCAN_INTERVAL,
    CONF_UNITS,
    CONF_UPDATE_INTERVAL,
    DEFAULT_SCAN_INTERVAL,
    DEFAULT_UPDATE_INTERVAL,
    DOMAIN,
    MANUFACTURER,
    PLATFORMS,
    lr_identifier,
    pair_identifier,
)
from .devices import ensure_device
from .coordinator import (
    PanOSConfigEntry,
    PanOSDeviceCoordinator,
    PanOSPairTracker,
    PanOSRuntimeData,
    PanOSUnit,
    PanOSUpdatesCoordinator,
    UnitConfig,
    unit_device_fields,
)
from .network import LR_DEVICE_FIELDS, PanOSNetworkCoordinator, pm_key_suffix, safe_key
from .services import async_setup_services

CONFIG_SCHEMA = cv.config_entry_only_config_schema(DOMAIN)


async def async_setup(hass: HomeAssistant, config: ConfigType) -> bool:
    async_setup_services(hass)
    return True


async def async_setup_entry(hass: HomeAssistant, entry: PanOSConfigEntry) -> bool:
    session = async_get_clientsession(hass, verify_ssl=entry.data[CONF_VERIFY_SSL])
    scan = timedelta(seconds=entry.options.get(CONF_SCAN_INTERVAL, DEFAULT_SCAN_INTERVAL))
    update_every = timedelta(hours=entry.options.get(CONF_UPDATE_INTERVAL, DEFAULT_UPDATE_INTERVAL))

    units: list[PanOSUnit] = []
    for index, raw in enumerate(entry.data[CONF_UNITS]):
        unit = UnitConfig(
            index=index,
            host=raw["host"],
            serial=raw["serial"],
            hostname=raw["hostname"],
            model=raw.get("model"),
        )
        client = PanOSClient(
            session, unit.host, entry.data[CONF_USERNAME], entry.data[CONF_PASSWORD]
        )
        units.append(
            PanOSUnit(
                config=unit,
                client=client,
                coordinator=PanOSDeviceCoordinator(hass, entry, client, unit, scan),
                updates=PanOSUpdatesCoordinator(hass, entry, client, unit, update_every),
            )
        )

    # One unit being down (e.g. mid-upgrade) must not stop the pair loading.
    results = await asyncio.gather(
        *(u.coordinator.async_config_entry_first_refresh() for u in units),
        return_exceptions=True,
    )
    errors = [r for r in results if isinstance(r, BaseException)]
    if len(errors) == len(units):
        for err in errors:
            if isinstance(err, ConfigEntryAuthFailed):
                raise err
        raise ConfigEntryNotReady(str(errors[0])) from errors[0]

    runtime = PanOSRuntimeData(name=entry.data[CONF_NAME], units=units)
    pair_device = None
    if len(units) == 2:
        pair_device = ensure_device(
            hass,
            entry,
            (DOMAIN, pair_identifier(entry.entry_id)),
            name=f"{entry.data[CONF_NAME]} HA pair",
            manufacturer=MANUFACTURER,
            model="High-availability pair",
        )
    unit_devices = [
        ensure_device(hass, entry, (DOMAIN, u.config.serial), pair_device, **unit_device_fields(u.config))
        for u in units
    ]
    if len(units) == 2:
        runtime.pair = PanOSPairTracker(hass, entry, units)
        runtime.pair.async_start()
    entry.runtime_data = runtime

    runtime.network = PanOSNetworkCoordinator(
        hass, entry, scan, entry.options.get(CONF_INTERFACES)
    )
    # Not fatal: if the interface/routing commands can't be read yet, the
    # network devices and entities are created after the first good poll.
    await runtime.network.async_refresh()
    lr_parent = pair_device or unit_devices[0]

    lr_devices: set[str] = set()

    @callback
    def _sync_lr_devices() -> None:
        # Logical routers hang off the HA pair (or the lone firewall). Runs on
        # every poll (before the platforms' listeners) so routers that appear
        # later get a device before their entities are added.
        if runtime.network.data is None:
            return
        for lr in runtime.network.data["egress"]:
            if lr not in lr_devices:
                lr_devices.add(lr)
                ensure_device(
                    hass, entry, (DOMAIN, lr_identifier(entry.entry_id, lr)), lr_parent,
                    name=lr, **LR_DEVICE_FIELDS,
                )

    _sync_lr_devices()
    entry.async_on_unload(runtime.network.async_add_listener(_sync_lr_devices))
    # Stale-entity cleanup once, from the first poll that has data.
    entry.async_on_unload(
        runtime.network.async_when_ready(lambda: _remove_stale_network_entities(hass, entry))
    )

    await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)

    # Update checks contact the update server and can take a minute; don't
    # hold up startup for them.
    for unit in units:
        entry.async_create_background_task(
            hass, unit.updates.async_refresh(), f"{DOMAIN} update check {unit.config.host}"
        )

    entry.async_on_unload(entry.add_update_listener(_async_options_updated))
    return True


async def _async_options_updated(hass: HomeAssistant, entry: PanOSConfigEntry) -> None:
    await hass.config_entries.async_reload(entry.entry_id)


async def async_unload_entry(hass: HomeAssistant, entry: PanOSConfigEntry) -> bool:
    return await hass.config_entries.async_unload_platforms(entry, PLATFORMS)


def _remove_stale_network_entities(hass: HomeAssistant, entry: PanOSConfigEntry) -> None:
    """Drop entities for deselected interfaces, vanished path monitors and BGP peers."""
    network = entry.runtime_data.network
    if network.data is None:
        return
    data = network.data
    ok = data.get("sources_ok", {})
    # Interface entities: exact ids, and only prune auto-selected interfaces
    # when the reads that drive auto-selection (FIB, path monitors) worked.
    prefix = f"{entry.entry_id}_if_"
    # Configured interfaces are kept even if a poll didn't list them.
    wanted = (
        network.configured_interfaces
        if network.configured_interfaces is not None
        else network.selected_interfaces(data)
    )
    if_keep = {
        f"{prefix}{name.replace('/', '_').replace('.', '_')}_{suffix}"
        for name in wanted
        for suffix in ("link", "in", "out", "speed")
    }
    prune_ifs = network.configured_interfaces is not None or (
        ok.get("fib") and ok.get("path_monitors")
    )
    pm_prefix = f"{entry.entry_id}_pm_"
    pm_keep = {f"{pm_prefix}{pm_key_suffix(k)}" for k in data["path_groups"]}
    bgp_prefix = f"{entry.entry_id}_bgp_"
    bgp_keep = {f"{bgp_prefix}{lr}_established" for lr in data.get("bgp", {})}
    bgp_keep |= {
        f"{bgp_prefix}{safe_key(lr)}_{safe_key(peer)}"
        for lr, info in data.get("bgp", {}).items()
        if info["ok"]
        for peer in info["peers"]
    }
    prune_bgp = ok.get("bgp") and all(info["ok"] for info in data.get("bgp", {}).values())
    cert_prefix = f"{entry.entry_id}_cert_"
    certs = data.get("certificates")
    cert_keep = {f"{cert_prefix}expiring"} | {
        f"{cert_prefix}{safe_key(c['name'])}" for c in (certs or {}).get("device", [])
    }
    registry = er.async_get(hass)
    for ent in er.async_entries_for_config_entry(registry, entry.entry_id):
        uid = ent.unique_id
        if uid.startswith(prefix) and prune_ifs and uid not in if_keep:
            registry.async_remove(ent.entity_id)
        elif uid.startswith(pm_prefix) and ok.get("path_monitors") and uid not in pm_keep:
            # Path monitor whose next hop no longer exists (e.g. renumbered).
            registry.async_remove(ent.entity_id)
        elif uid.startswith(bgp_prefix) and prune_bgp and uid not in bgp_keep:
            # BGP peer removed from the configuration.
            registry.async_remove(ent.entity_id)
        elif uid.startswith(cert_prefix) and ok.get("certs_device") and uid not in cert_keep:
            # Certificate deleted or renamed in the firewall config.
            registry.async_remove(ent.entity_id)
