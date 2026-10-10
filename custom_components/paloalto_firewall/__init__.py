"""Palo Alto Networks firewall integration (standalone or active/passive HA pair)."""

from __future__ import annotations

import asyncio
from datetime import timedelta

from homeassistant.const import CONF_NAME, CONF_PASSWORD, CONF_USERNAME, CONF_VERIFY_SSL
from homeassistant.core import HomeAssistant
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
    # Not fatal: logical-router and interface entities are skipped (until the
    # next reload) if the routing/interface commands can't be read yet.
    await runtime.network.async_refresh()
    _remove_stale_network_entities(hass, entry)
    if runtime.network.data:
        # Logical routers hang off the HA pair (or the lone firewall).
        lr_parent = pair_device or unit_devices[0]
        for lr in runtime.network.data["egress"]:
            ensure_device(
                hass, entry, (DOMAIN, lr_identifier(entry.entry_id, lr)), lr_parent,
                name=lr, **LR_DEVICE_FIELDS,
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
    keep = {
        f"{entry.entry_id}_if_{name.replace('/', '_').replace('.', '_')}_"
        for name in network.selected_interfaces(network.data)
    }
    prefix = f"{entry.entry_id}_if_"
    pm_prefix = f"{entry.entry_id}_pm_"
    pm_keep = {f"{pm_prefix}{pm_key_suffix(k)}" for k in network.data["path_groups"]}
    bgp_prefix = f"{entry.entry_id}_bgp_"
    bgp_keep = {f"{bgp_prefix}{lr}_established" for lr in network.data.get("bgp", {})}
    bgp_keep |= {
        f"{bgp_prefix}{safe_key(lr)}_{safe_key(peer)}"
        for lr, info in network.data.get("bgp", {}).items()
        if info["ok"]
        for peer in info["peers"]
    }
    bgp_lrs_ok = all(info["ok"] for info in network.data.get("bgp", {}).values())
    registry = er.async_get(hass)
    for ent in er.async_entries_for_config_entry(registry, entry.entry_id):
        uid = ent.unique_id
        if uid.startswith(prefix) and not any(uid.startswith(k) for k in keep):
            registry.async_remove(ent.entity_id)
        elif uid.startswith(pm_prefix) and uid not in pm_keep:
            # Path monitor whose next hop no longer exists (e.g. renumbered).
            registry.async_remove(ent.entity_id)
        elif uid.startswith(bgp_prefix) and uid not in bgp_keep and bgp_lrs_ok:
            # BGP peer removed from the configuration.
            registry.async_remove(ent.entity_id)
