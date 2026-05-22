"""Select platform for Aiper integration.

Design goals (community-friendly):
- Device-reported state is authoritative (no optimistic select state).
- Control entities become unavailable when the device is explicitly offline.
- Robust, explicit error handling to avoid taking the whole integration down
  on a single denied/failed command.
"""

from __future__ import annotations

import logging
from contextlib import suppress
from typing import Any

from homeassistant.components.select import SelectEntity
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.exceptions import HomeAssistantError
from homeassistant.helpers.device_registry import DeviceInfo
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from .const import (
    CLEAN_PATH_MAP,
    DOMAIN,
    mode_label,
)
from .controller import AiperDeviceController
from .coordinator import AiperDataUpdateCoordinator
from .profiles import Capability
from .state import DeviceState, state_has_capability

_LOGGER = logging.getLogger(__name__)


def _coerce_int(val: Any) -> int | None:
    if isinstance(val, bool) or val is None:
        return None
    if isinstance(val, int):
        return val
    if isinstance(val, float):
        return int(val)
    if isinstance(val, str) and val.strip().lstrip("-").isdigit():
        return int(val.strip())
    return None


def _device_online(coordinator: AiperDataUpdateCoordinator, sn: str) -> bool | None:
    """Return the normalized online state for control availability."""
    dev = (coordinator.data or {}).get(sn)
    if dev is None:
        return None
    try:
        value = dev["online"].value
    except KeyError:
        return None
    return value if isinstance(value, bool) else None


def _supports_clean_path(dev: DeviceState) -> bool:
    """Return whether the clean-path control should be exposed."""
    return state_has_capability(dev, Capability.CLEAN_PATH)


def _supports_mode_control(dev: DeviceState) -> bool:
    """Return whether mode control has enough evidence to be exposed."""
    return state_has_capability(dev, Capability.CLEANING_MODE_SELECT)


class AiperSelectBase(CoordinatorEntity[AiperDataUpdateCoordinator], SelectEntity):
    """Base class for Aiper select entities."""

    _requires_online: bool = True
    _requires_mqtt: bool = False

    def __init__(
        self,
        coordinator: AiperDataUpdateCoordinator,
        controller: AiperDeviceController,
        sn: str,
        key: str,
        name: str,
        *,
        icon: str | None = None,
        mqtt_required: bool = False,
        enabled_default: bool = True,
    ) -> None:
        super().__init__(coordinator)
        self.controller = controller
        self._sn = sn
        self._key = key
        self._attr_name = name
        self._attr_unique_id = f"{sn}_{key}"
        self._attr_icon = icon
        self._attr_entity_registry_enabled_default = enabled_default
        self._requires_mqtt = mqtt_required

    @property
    def device_info(self) -> DeviceInfo:
        dev = (self.coordinator.data or {})[self._sn]
        device_info = dev["device_info"]
        device_info_attrs = device_info.attributes
        return {
            "identifiers": {(DOMAIN, self._sn)},
            "name": str(device_info.value or self._sn),
            "manufacturer": "Aiper",
            "model": device_info_attrs.get("model"),
            "sw_version": device_info_attrs.get("sw_version"),
        }

    @property
    def available(self) -> bool:
        if not self.coordinator.last_update_success:
            return False

        # If MQTT is required for this control, it is only available when MQTT is connected.
        if self._requires_mqtt and not self.coordinator.api.is_mqtt_connected():
            return False

        if not self._requires_online:
            return True

        online = _device_online(self.coordinator, self._sn)
        return online is not False

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        attrs: dict[str, Any] = {}

        online = _device_online(self.coordinator, self._sn)
        if online is not None:
            attrs["device_online"] = online

        attrs["mqtt_connected"] = self.coordinator.api.is_mqtt_connected()

        return attrs

    def _raise_if_control_blocked(self) -> None:
        online = _device_online(self.coordinator, self._sn)

        if self._requires_mqtt and not self.coordinator.api.is_mqtt_connected():
            raise HomeAssistantError("Aiper MQTT connection is not available; cannot send this command.")

        if self._requires_online and online is False:
            raise HomeAssistantError("Device is offline; controls are disabled.")


class AiperCleaningModeSelect(AiperSelectBase):
    """Select for choosing cleaning mode."""

    def __init__(
        self,
        coordinator: AiperDataUpdateCoordinator,
        controller: AiperDeviceController,
        sn: str,
        name: str,
        supported_mode_ids: list[int],
        mode_map: dict[int, str],
    ) -> None:
        # MQTT is required to change the mode.
        super().__init__(
            coordinator,
            controller,
            sn,
            "mode_selection",
            f"{name} Cleaning mode",
            icon="mdi:robot-vacuum",
            mqtt_required=False,
            enabled_default=True,
        )
        # Build options list from supported IDs.
        self._mode_ids: list[int] = []
        self._mode_map = {}
        for key, value in (mode_map or {}).items():
            try:
                self._mode_map[int(key)] = str(value)
            except Exception:
                continue
        options: list[str] = []
        for mid in supported_mode_ids:
            label = self._mode_map.get(mid) or mode_label(mid)
            if label and label not in options:
                self._mode_ids.append(int(mid))
                options.append(label)
        self._attr_options = options

    def _get_current_mode_id(self) -> int | None:
        dev = (self.coordinator.data or {})[self._sn]
        return _coerce_int(dev["mode"].attributes.get("code"))

    @property
    def current_option(self) -> str | None:
        mid = self._get_current_mode_id()
        if mid is None:
            return None
        return self._mode_map.get(mid) or mode_label(mid)

    async def async_select_option(self, option: str) -> None:
        self._raise_if_control_blocked()

        # Map label -> id
        mode_id = None
        for mid, label in self._mode_map.items():
            if label == option:
                mode_id = int(mid)
                break
        if mode_id is None:
            raise HomeAssistantError(f"Invalid cleaning mode: {option}")

        # No-op if already in that mode.
        cur = self._get_current_mode_id()
        if cur is not None and cur == mode_id:
            return

        result = await self.controller.set_cleaning_mode(self._sn, mode_id)
        if not result.ok:
            if not self.coordinator.api.is_mqtt_connected():
                raise HomeAssistantError("Failed to set cleaning mode: MQTT is not connected.")
            raise HomeAssistantError(f"Failed to set cleaning mode: {result.reason or 'device rejected the command'}")

        # Ask for a shadow refresh and a coordinator refresh.
        with suppress(Exception):
            await self.controller.refresh_shadow(self._sn)

        await self.coordinator.async_request_refresh()


class AiperCleanPathSelect(AiperSelectBase):
    """Select for choosing cleaning path."""

    def __init__(
        self,
        coordinator: AiperDataUpdateCoordinator,
        controller: AiperDeviceController,
        sn: str,
        name: str,
    ) -> None:
        super().__init__(
            coordinator,
            controller,
            sn,
            "clean_path",
            f"{name} Clean path",
            icon="mdi:routes",
            mqtt_required=False,
            enabled_default=True,
        )
        self._attr_options = list(CLEAN_PATH_MAP.values())

    @property
    def current_option(self) -> str | None:
        dev = (self.coordinator.data or {})[self._sn]
        label = dev["clean_path"].value
        if label is not None and label not in CLEAN_PATH_MAP.values():
            try:
                opts = list(self._attr_options or [])
                if label not in opts:
                    opts.append(label)
                    self._attr_options = opts
            except Exception:
                pass
        return str(label) if label is not None else None

    async def async_select_option(self, option: str) -> None:
        self._raise_if_control_blocked()

        # Map label -> id
        path_id = None
        for pid, label in CLEAN_PATH_MAP.items():
            if label == option:
                path_id = int(pid)
                break

        # Allow unexpected IDs that we surfaced as dynamic options (e.g. 'Path 2').
        if path_id is None and isinstance(option, str) and option.lower().startswith("path "):
            try:
                path_id = int(option.split(" ", 1)[1].strip())
            except Exception:
                path_id = None

        if path_id is None:
            raise HomeAssistantError(f"Invalid clean path: {option}")

        dev = (self.coordinator.data or {})[self._sn]
        cur = _coerce_int(dev["clean_path"].attributes.get("code"))
        if cur is not None and cur == path_id:
            return

        result = await self.controller.set_clean_path(self._sn, path_id)
        if not result.ok:
            if not self.coordinator.api.is_mqtt_connected():
                raise HomeAssistantError(
                    "Failed to set clean path: cloud control is unavailable because MQTT is not connected."
                )
            raise HomeAssistantError(f"Failed to set clean path: {result.reason or 'device rejected the command'}")

        # Optimistically cache the selection. Some firmwares never report cleanPath
        # in reported shadow state, so without this the entity can remain Unknown.
        with suppress(Exception):
            self.coordinator.set_clean_path_cache(self._sn, path_id)

        # Ask for a shadow refresh and a coordinator refresh.
        with suppress(Exception):
            await self.controller.refresh_shadow(self._sn)

        await self.coordinator.async_request_refresh()


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry, async_add_entities) -> None:
    """Set up select entities from a config entry."""
    coordinator: AiperDataUpdateCoordinator = hass.data[DOMAIN][entry.entry_id]["coordinator"]
    controller: AiperDeviceController = hass.data[DOMAIN][entry.entry_id]["controller"]

    entities: list[SelectEntity] = []
    if coordinator.data:
        for sn, dev in coordinator.data.items():
            device_info = dev["device_info"]
            name = str(device_info.value or sn)
            mode_options = dev["mode_options"]
            supported = mode_options.value
            if not isinstance(supported, list) or not supported:
                continue
            supported_ids = [int(mode_id) for mode_id in supported]
            mode_map = mode_options.attributes.get("mode_map")
            if not isinstance(mode_map, dict):
                mode_map = {mode_id: mode_label(mode_id) for mode_id in supported_ids}

            if _supports_clean_path(dev):
                entities.append(AiperCleanPathSelect(coordinator, controller, sn, name))
            if _supports_mode_control(dev):
                entities.append(AiperCleaningModeSelect(coordinator, controller, sn, name, supported_ids, mode_map))

    async_add_entities(entities)
