"""Config flow for Palo Alto Networks firewalls."""

from __future__ import annotations

import logging
import re
from collections.abc import Mapping
from typing import Any

import voluptuous as vol

from homeassistant.config_entries import ConfigEntry, ConfigFlow, ConfigFlowResult, OptionsFlow
from homeassistant.const import CONF_NAME, CONF_PASSWORD, CONF_USERNAME, CONF_VERIFY_SSL
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers.aiohttp_client import async_get_clientsession
from homeassistant.helpers.selector import (
    NumberSelector,
    NumberSelectorConfig,
    NumberSelectorMode,
    SelectSelector,
    SelectSelectorConfig,
    SelectSelectorMode,
    TextSelector,
    TextSelectorConfig,
    TextSelectorType,
)

from . import parsers
from .api import PanOSAuthError, PanOSClient, PanOSError
from .const import (
    CMD_HA_STATE,
    CMD_SYSTEM_INFO,
    CONF_INTERFACES,
    CONF_PRIMARY_HOST,
    CONF_SCAN_INTERVAL,
    CONF_SECONDARY_HOST,
    CONF_UNITS,
    CONF_UPDATE_INTERVAL,
    DEFAULT_NAME,
    DEFAULT_SCAN_INTERVAL,
    DEFAULT_UPDATE_INTERVAL,
    DOMAIN,
    MIN_SCAN_INTERVAL,
)

_LOGGER = logging.getLogger(__name__)


class CannotConnect(Exception):
    def __init__(self, host: str) -> None:
        super().__init__(host)
        self.host = host


class InvalidAuth(Exception):
    def __init__(self, host: str) -> None:
        super().__init__(host)
        self.host = host


async def _probe(
    hass: HomeAssistant, host: str, username: str, password: str, verify_ssl: bool
) -> dict[str, Any]:
    """Log in to one firewall and return what we need to know about it."""
    client = PanOSClient(async_get_clientsession(hass, verify_ssl=verify_ssl), host, username, password)
    try:
        await client.generate_key()
        system = parsers.parse_system_info(await client.op(CMD_SYSTEM_INFO))
    except PanOSAuthError as err:
        raise InvalidAuth(host) from err
    except (PanOSError, ValueError) as err:
        _LOGGER.debug("Probe of %s failed: %s", host, err)
        raise CannotConnect(host) from err
    try:
        ha = parsers.parse_ha_state(await client.op(CMD_HA_STATE))
    except (PanOSError, ValueError):
        ha = None
    return {
        "host": client.host,
        "serial": system["serial"],
        "hostname": system["hostname"] or client.host,
        "model": system["model"],
        "ha": ha,
    }


def _user_schema(defaults: Mapping[str, Any]) -> vol.Schema:
    return vol.Schema(
        {
            vol.Required(CONF_NAME, default=defaults.get(CONF_NAME, DEFAULT_NAME)): str,
            vol.Required(CONF_PRIMARY_HOST, default=defaults.get(CONF_PRIMARY_HOST, "")): str,
            vol.Optional(
                CONF_SECONDARY_HOST,
                description={"suggested_value": defaults.get(CONF_SECONDARY_HOST)},
            ): str,
            vol.Required(CONF_USERNAME, default=defaults.get(CONF_USERNAME, "")): str,
            vol.Required(CONF_PASSWORD): TextSelector(
                TextSelectorConfig(type=TextSelectorType.PASSWORD)
            ),
            vol.Required(CONF_VERIFY_SSL, default=defaults.get(CONF_VERIFY_SSL, False)): bool,
        }
    )


class PanOSConfigFlow(ConfigFlow, domain=DOMAIN):
    VERSION = 1

    async def async_step_user(self, user_input: dict[str, Any] | None = None) -> ConfigFlowResult:
        errors: dict[str, str] = {}
        placeholders: dict[str, str] = {"host": ""}
        if user_input is not None:
            hosts = [user_input[CONF_PRIMARY_HOST].strip()]
            if secondary := (user_input.get(CONF_SECONDARY_HOST) or "").strip():
                hosts.append(secondary)
            try:
                units = [
                    await _probe(
                        self.hass,
                        host,
                        user_input[CONF_USERNAME],
                        user_input[CONF_PASSWORD],
                        user_input[CONF_VERIFY_SSL],
                    )
                    for host in hosts
                ]
            except InvalidAuth as err:
                errors["base"] = "invalid_auth"
                placeholders["host"] = err.host
            except CannotConnect as err:
                errors["base"] = "cannot_connect"
                placeholders["host"] = err.host
            except Exception:  # noqa: BLE001
                _LOGGER.exception("Unexpected error validating firewall")
                errors["base"] = "unknown"
            else:
                if len(units) == 2 and units[0]["serial"] == units[1]["serial"]:
                    errors["base"] = "same_device"
                else:
                    await self.async_set_unique_id("_".join(sorted(u["serial"] for u in units)))
                    self._abort_if_unique_id_configured()
                    for u in units:
                        if len(units) == 2 and not (u["ha"] or {}).get("enabled"):
                            _LOGGER.warning(
                                "%s does not report HA enabled; pair entities will flag a problem",
                                u["hostname"],
                            )
                        u.pop("ha")
                    return self.async_create_entry(
                        title=user_input[CONF_NAME],
                        data={
                            CONF_NAME: user_input[CONF_NAME],
                            CONF_USERNAME: user_input[CONF_USERNAME],
                            CONF_PASSWORD: user_input[CONF_PASSWORD],
                            CONF_VERIFY_SSL: user_input[CONF_VERIFY_SSL],
                            CONF_UNITS: units,
                        },
                    )
        return self.async_show_form(
            step_id="user",
            data_schema=_user_schema(user_input or {}),
            errors=errors,
            description_placeholders=placeholders,
        )

    async def async_step_reauth(self, entry_data: Mapping[str, Any]) -> ConfigFlowResult:
        return await self.async_step_reauth_confirm()

    async def async_step_reauth_confirm(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        entry = self._get_reauth_entry()
        errors: dict[str, str] = {}
        placeholders = {"host": ""}
        if user_input is not None:
            ok = False
            for unit in entry.data[CONF_UNITS]:
                try:
                    await _probe(
                        self.hass,
                        unit["host"],
                        user_input[CONF_USERNAME],
                        user_input[CONF_PASSWORD],
                        entry.data[CONF_VERIFY_SSL],
                    )
                    ok = True
                except InvalidAuth:
                    errors["base"] = "invalid_auth"
                    placeholders["host"] = unit["host"]
                    ok = False
                    break
                except CannotConnect:
                    # The peer may legitimately be down; one success is enough.
                    continue
            if ok:
                return self.async_update_reload_and_abort(
                    entry,
                    data_updates={
                        CONF_USERNAME: user_input[CONF_USERNAME],
                        CONF_PASSWORD: user_input[CONF_PASSWORD],
                    },
                )
            errors.setdefault("base", "cannot_connect")
        return self.async_show_form(
            step_id="reauth_confirm",
            data_schema=vol.Schema(
                {
                    vol.Required(CONF_USERNAME, default=entry.data[CONF_USERNAME]): str,
                    vol.Required(CONF_PASSWORD): TextSelector(
                        TextSelectorConfig(type=TextSelectorType.PASSWORD)
                    ),
                }
            ),
            errors=errors,
            description_placeholders=placeholders,
        )

    @staticmethod
    @callback
    def async_get_options_flow(config_entry: ConfigEntry) -> OptionsFlow:
        return PanOSOptionsFlow()


class PanOSOptionsFlow(OptionsFlow):
    async def async_step_init(self, user_input: dict[str, Any] | None = None) -> ConfigFlowResult:
        network = getattr(getattr(self.config_entry, "runtime_data", None), "network", None)
        available: list[str] = []
        current: list[str] = []
        if network is not None and network.data is not None:
            available = sorted(
                (
                    name
                    for name, i in network.data["interfaces"].items()
                    if i.get("zone") or i.get("logical_router")
                ),
                key=_iface_sort_key,
            )
            current = network.selected_interfaces(network.data)
        if user_input is not None:
            options = {
                CONF_SCAN_INTERVAL: int(user_input[CONF_SCAN_INTERVAL]),
                CONF_UPDATE_INTERVAL: int(user_input[CONF_UPDATE_INTERVAL]),
            }
            if CONF_INTERFACES in user_input:
                options[CONF_INTERFACES] = list(user_input[CONF_INTERFACES])
            elif CONF_INTERFACES in self.config_entry.options:
                options[CONF_INTERFACES] = self.config_entry.options[CONF_INTERFACES]
            return self.async_create_entry(data=options)
        options = self.config_entry.options
        extra: dict = {}
        if available:
            extra[vol.Optional(CONF_INTERFACES, default=current)] = SelectSelector(
                SelectSelectorConfig(
                    options=available, multiple=True, mode=SelectSelectorMode.DROPDOWN
                )
            )
        return self.async_show_form(
            step_id="init",
            data_schema=vol.Schema(
                {
                    vol.Required(
                        CONF_SCAN_INTERVAL,
                        default=options.get(CONF_SCAN_INTERVAL, DEFAULT_SCAN_INTERVAL),
                    ): NumberSelector(
                        NumberSelectorConfig(
                            min=MIN_SCAN_INTERVAL,
                            max=3600,
                            step=5,
                            unit_of_measurement="s",
                            mode=NumberSelectorMode.BOX,
                        )
                    ),
                    vol.Required(
                        CONF_UPDATE_INTERVAL,
                        default=options.get(CONF_UPDATE_INTERVAL, DEFAULT_UPDATE_INTERVAL),
                    ): NumberSelector(
                        NumberSelectorConfig(
                            min=1, max=168, step=1, unit_of_measurement="h", mode=NumberSelectorMode.BOX
                        )
                    ),
                    **extra,
                }
            ),
        )


def _iface_sort_key(name: str) -> tuple:
    return tuple(int(p) if p.isdigit() else p for p in re.split(r"(\d+)", name))
