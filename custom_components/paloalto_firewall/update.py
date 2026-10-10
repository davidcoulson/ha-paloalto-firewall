"""Update entities for PAN-OS software, content and the GlobalProtect client.

PAN-OS and content are read-only: upgrading a firewall needs planning (and a
reboot). The GlobalProtect client package can be installed from Home
Assistant: it is downloaded to the firewall and activated for the portal,
which needs no commit or reboot.
"""

from __future__ import annotations

from typing import Any

from homeassistant.components.update import (
    UpdateEntity,
    UpdateEntityDescription,
    UpdateEntityFeature,
)
from homeassistant.core import HomeAssistant
from homeassistant.exceptions import HomeAssistantError
from homeassistant.helpers.entity_platform import AddConfigEntryEntitiesCallback

from .api import PanOSError
from .const import CMD_GP_CLIENT_ACTIVATE, CMD_GP_CLIENT_DOWNLOAD
from .coordinator import PanOSConfigEntry, PanOSUnit
from .entity import PanOSUpdatesEntity
from .jobs import run_job
from .parsers import (
    content_version_key,
    gp_version_key,
    latest_content,
    latest_gp_client,
    latest_panos,
    panos_version_key,
)

SOFTWARE = UpdateEntityDescription(key="panos_update", name="PAN-OS")
CONTENT = UpdateEntityDescription(key="content_update", name="Apps & threats content")
GP_CLIENT = UpdateEntityDescription(key="gp_client_update", name="GlobalProtect client", icon="mdi:vpn")


async def async_setup_entry(
    hass: HomeAssistant,
    entry: PanOSConfigEntry,
    async_add_entities: AddConfigEntryEntitiesCallback,
) -> None:
    entities: list[UpdateEntity] = []
    for unit in entry.runtime_data.units:
        entities.append(PanOSSoftwareUpdate(entry, unit, SOFTWARE))
        entities.append(PanOSContentUpdate(entry, unit, CONTENT))
        system = (unit.coordinator.data or {}).get("system") or {}
        if system.get("gp_client_version") not in (None, "", "0.0.0"):
            entities.append(PanOSGPClientUpdate(entry, unit, GP_CLIENT))
    async_add_entities(entities)


class _PanOSUpdate(PanOSUpdatesEntity, UpdateEntity):
    """Installed version comes from the status poll; latest from the check."""

    _section: str
    _installed_key: str

    def __init__(self, entry: PanOSConfigEntry, unit: PanOSUnit, description) -> None:
        super().__init__(entry, unit, description)

    async def async_added_to_hass(self) -> None:
        await super().async_added_to_hass()
        self.async_on_remove(self.unit.coordinator.async_add_listener(self._handle_coordinator_update))

    @property
    def available(self) -> bool:
        return super().available and self.data.get(self._section) is not None

    @property
    def installed_version(self) -> str | None:
        system = (self.unit.coordinator.data or {}).get("system") or {}
        if value := system.get(self._installed_key):
            return value
        for v in self._versions:
            if v["current"]:
                return v["version"]
        return None

    @property
    def _versions(self) -> list[dict[str, Any]]:
        return (self.data.get(self._section) or {}).get("versions") or []


class PanOSSoftwareUpdate(_PanOSUpdate):
    """Tracks the newest release in the installed feature train (e.g. 11.1.x).

    Jumping to a new feature release is a planning decision, not a routine
    update, so the newest overall release is exposed as an attribute instead.
    """

    _section = "software"
    _installed_key = "sw_version"

    def _latest(self) -> dict[str, Any]:
        return latest_panos(self._versions, self.installed_version)

    @property
    def latest_version(self) -> str | None:
        train = self._latest()["train"]
        installed = self.installed_version
        if train is None:
            return installed
        if installed and not self.version_is_newer(train["version"], installed):
            return installed
        return train["version"]

    @property
    def release_url(self) -> str | None:
        latest = self.latest_version
        for v in self._versions:
            if v["version"] == latest and v.get("release_notes"):
                return v["release_notes"]
        return None

    def version_is_newer(self, latest_version: str, installed_version: str) -> bool:
        latest = panos_version_key(latest_version)
        installed = panos_version_key(installed_version)
        if latest is None or installed is None:
            return latest_version != installed_version
        return latest > installed

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        info = self._latest()
        overall = info["overall"]
        latest = self.latest_version
        downloaded = next((v["downloaded"] for v in self._versions if v["version"] == latest), None)
        return {
            "newest_release_any_train": overall["version"] if overall else None,
            "latest_downloaded": downloaded,
            "released_on": next((v["released_on"] for v in self._versions if v["version"] == latest), None),
        }


class PanOSContentUpdate(_PanOSUpdate):
    _section = "content"
    _installed_key = "app_version"

    @property
    def latest_version(self) -> str | None:
        latest = latest_content(self._versions)
        installed = self.installed_version
        if latest is None:
            return installed
        if installed and not self.version_is_newer(latest["version"], installed):
            return installed
        return latest["version"]

    def version_is_newer(self, latest_version: str, installed_version: str) -> bool:
        latest = content_version_key(latest_version)
        installed = content_version_key(installed_version)
        if latest is None or installed is None:
            return latest_version != installed_version
        return latest > installed

    @property
    def release_url(self) -> str | None:
        latest = self.latest_version
        for v in self._versions:
            if v["version"] == latest and v.get("release_notes"):
                return v["release_notes"]
        return None


class PanOSGPClientUpdate(_PanOSUpdate):
    """GlobalProtect app package hosted on the portal, newest in the installed train.

    The installed version is what the firewall has activated for clients to
    download (not what any one laptop runs).
    """

    _section = "gp_client"
    _installed_key = "gp_client_version"
    _attr_supported_features = UpdateEntityFeature.INSTALL | UpdateEntityFeature.PROGRESS
    _attr_in_progress = False

    async def async_install(self, version: str | None, backup: bool, **kwargs: Any) -> None:
        """Download (if needed) and activate the package on this firewall."""
        target = version or self.latest_version
        if not target or target == self.installed_version:
            return
        known = next((v for v in self._versions if v["version"] == target), None)
        if known is None:
            raise HomeAssistantError(
                f"{self.unit.config.hostname} doesn't list GlobalProtect {target}; check for updates first"
            )
        client = self.unit.client
        self._set_progress(0)
        try:
            if not known["downloaded"]:
                await run_job(
                    client,
                    CMD_GP_CLIENT_DOWNLOAD.format(target),
                    on_progress=lambda p: self._set_progress(p * 0.8),
                )
            self._set_progress(80)
            await run_job(
                client,
                CMD_GP_CLIENT_ACTIVATE.format(target),
                timeout=300,
                on_progress=lambda p: self._set_progress(80 + p * 0.2),
            )
        except PanOSError as err:
            raise HomeAssistantError(
                f"Installing GlobalProtect {target} on {self.unit.config.hostname} failed: {err}"
            ) from err
        finally:
            self._attr_in_progress = False
            self._attr_update_percentage = None
            self.async_write_ha_state()
        # The activated version comes from `show system info`; the version
        # list's downloaded/current flags from the update check.
        await self.unit.coordinator.async_refresh()
        await self.coordinator.async_refresh()

    def _set_progress(self, percent: float) -> None:
        self._attr_in_progress = True
        self._attr_update_percentage = int(percent)
        self.async_write_ha_state()

    def _latest(self) -> dict[str, Any]:
        return latest_gp_client(self._versions, self.installed_version)

    @property
    def latest_version(self) -> str | None:
        train = self._latest()["train"]
        installed = self.installed_version
        if train is None:
            return installed
        if installed and not self.version_is_newer(train["version"], installed):
            return installed
        return train["version"]

    def version_is_newer(self, latest_version: str, installed_version: str) -> bool:
        latest = gp_version_key(latest_version)
        installed = gp_version_key(installed_version)
        if latest is None or installed is None:
            return latest_version != installed_version
        return latest > installed

    @property
    def release_url(self) -> str | None:
        # Download links on the firewall are signed and expire within days.
        return "https://docs.paloaltonetworks.com/globalprotect/release-notes"

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        overall = self._latest()["overall"]
        latest = self.latest_version
        entry = next((v for v in self._versions if v["version"] == latest), {})
        return {
            "newest_release_any_train": overall["version"] if overall else None,
            "latest_downloaded": entry.get("downloaded"),
            "released_on": entry.get("released_on"),
        }
