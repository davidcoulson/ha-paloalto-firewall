"""Palo Alto Networks firewall integration (standalone or active/passive HA pair)."""

from __future__ import annotations

import asyncio
from datetime import timedelta

from homeassistant.const import CONF_NAME, CONF_PASSWORD, CONF_USERNAME, CONF_VERIFY_SSL
from homeassistant.core import HomeAssistant
from homeassistant.exceptions import ConfigEntryAuthFailed, ConfigEntryNotReady
from homeassistant.helpers import config_validation as cv, device_registry as dr
from homeassistant.helpers.aiohttp_client import async_get_clientsession
from homeassistant.helpers.typing import ConfigType

from .api import PanOSClient
from .const import (
    CONF_SCAN_INTERVAL,
    CONF_UNITS,
    CONF_UPDATE_INTERVAL,
    DEFAULT_SCAN_INTERVAL,
    DEFAULT_UPDATE_INTERVAL,
    DOMAIN,
    MANUFACTURER,
    PLATFORMS,
    pair_identifier,
)
from .coordinator import (
    PanOSConfigEntry,
    PanOSDeviceCoordinator,
    PanOSPairTracker,
    PanOSRuntimeData,
    PanOSUnit,
    PanOSUpdatesCoordinator,
    UnitConfig,
)
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
    if len(units) == 2:
        dr.async_get(hass).async_get_or_create(
            config_entry_id=entry.entry_id,
            identifiers={(DOMAIN, pair_identifier(entry.entry_id))},
            name=f"{entry.data[CONF_NAME]} HA pair",
            manufacturer=MANUFACTURER,
            model="High-availability pair",
        )
        runtime.pair = PanOSPairTracker(hass, entry, units)
        runtime.pair.async_start()
    entry.runtime_data = runtime

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
