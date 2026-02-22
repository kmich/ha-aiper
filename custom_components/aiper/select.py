
"""Select platform for Aiper integration.

Design goals (community-friendly):
- Device-reported state is authoritative (no optimistic select state).
- Control entities become unavailable when the device is offline, unless the
  user explicitly enables offline queueing (advanced option).
- Robust, explicit error handling to avoid taking the whole integration down
  on a single denied/failed command.
"""

from __future__ import annotations

import logging
from typing import Any

from homeassistant.components.select import SelectEntity
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.exceptions import HomeAssistantError
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from .const import (
    DOMAIN,
    CONF_ENABLE_MQTT,
    CONF_QUEUE_OFFLINE_COMMANDS,
    MODE_MAP,
    CLEAN_PATH_MAP,
)
from .coordinator import AiperDataUpdateCoordinator

_LOGGER = logging.getLogger(__name__)


def _coerce_bool(val: Any) -> bool | None:
    if val is None:
        return None
    if isinstance(val, bool):
        return val
    if isinstance(val, (int, float)):
        return bool(int(val))
    if isinstance(val, str):
        s = val.strip().lower()
        if s in {"true", "on", "yes", "1"}:
            return True
        if s in {"false", "off", "no", "0"}:
            return False
    return None


def _device_online(coordinator: AiperDataUpdateCoordinator, sn: str) -> bool | None:
    """Best-effort online indicator.

    Preference order:
      1) REST-derived authoritative state (_ha_online)
      2) Shadow netstat.online
    """
    try:
        dev = (coordinator.data or {}).get(sn) or {}
        rest = _coerce_bool(dev.get("_ha_online"))
        if rest is not None:
            return rest
    except Exception:
        pass

    try:
        netstat = coordinator.get_netstat(sn) or {}
        mqtt = _coerce_bool(netstat.get("online"))
        return mqtt
    except Exception:
        return None


class AiperSelectBase(CoordinatorEntity[AiperDataUpdateCoordinator], SelectEntity):
    """Base class for Aiper select entities."""

    _requires_online: bool = True
    _requires_mqtt: bool = False

    def __init__(
        self,
        coordinator: AiperDataUpdateCoordinator,
        entry: ConfigEntry,
        sn: str,
        key: str,
        name: str,
        *,
        icon: str | None = None,
        mqtt_required: bool = False,
        enabled_default: bool = True,
    ) -> None:
        super().__init__(coordinator)
        self._config_entry = entry
        self._sn = sn
        self._key = key
        self._attr_name = name
        self._attr_unique_id = f"{sn}_{key}"
        self._attr_icon = icon
        self._attr_entity_registry_enabled_default = enabled_default
        self._requires_mqtt = mqtt_required

    @property
    def device_info(self) -> dict[str, Any]:
        dev = (self.coordinator.data or {}).get(self._sn) or {}
        model = dev.get("model") or dev.get("productName") or "Aiper Pool Cleaner"
        sw = dev.get("_ha_fw_main") or dev.get("firmwareVersion")
        return {
            "identifiers": {(DOMAIN, self._sn)},
            "name": dev.get("name") or dev.get("deviceName") or self._sn,
            "manufacturer": "Aiper",
            "model": model,
            "sw_version": sw,
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

        allow_offline = bool(self._config_entry.options.get(CONF_QUEUE_OFFLINE_COMMANDS, False))
        if allow_offline:
            return True

        online = _device_online(self.coordinator, self._sn)
        return online is not False

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        dev = (self.coordinator.data or {}).get(self._sn) or {}
        attrs: dict[str, Any] = {}

        online = _device_online(self.coordinator, self._sn)
        if online is not None:
            attrs["device_online"] = online

        attrs["mqtt_connected"] = self.coordinator.api.is_mqtt_connected()
        attrs["allow_offline_commands"] = bool(self._config_entry.options.get(CONF_QUEUE_OFFLINE_COMMANDS, False))

        # Diagnostic command tracking
        try:
            cmd = self.coordinator.get_command_state(self._sn)
            if cmd:
                attrs["pending_commands"] = cmd.get("pending")
                attrs["last_commands"] = cmd.get("last")
        except Exception:
            pass

        # Last seen (best-effort)
        last_seen = dev.get("_ha_last_seen")
        if last_seen is not None:
            try:
                attrs["last_seen"] = last_seen.isoformat() if hasattr(last_seen, "isoformat") else str(last_seen)
            except Exception:
                attrs["last_seen"] = str(last_seen)

        return attrs

    def _raise_if_control_blocked(self) -> None:
        allow_offline = bool(self._config_entry.options.get(CONF_QUEUE_OFFLINE_COMMANDS, False))
        online = _device_online(self.coordinator, self._sn)

        if self._requires_mqtt and not self.coordinator.api.is_mqtt_connected():
            raise HomeAssistantError("Aiper MQTT connection is not available; cannot send this command.")

        if self._requires_online and not allow_offline and online is False:
            raise HomeAssistantError(
                "Device is offline; controls are disabled. "
                "Enable 'Queue commands while device is offline' in the integration options to allow scheduling."
            )


class AiperCleaningModeSelect(AiperSelectBase):
    """Select for choosing cleaning mode."""

    def __init__(
        self,
        coordinator: AiperDataUpdateCoordinator,
        entry: ConfigEntry,
        sn: str,
        name: str,
        supported_mode_ids: list[int],
        mqtt_enabled: bool,
    ) -> None:
        # MQTT is required to change the mode.
        super().__init__(
            coordinator,
            entry,
            sn,
            "mode_selection",
            f"{name} Cleaning mode",
            icon="mdi:robot-vacuum",
            mqtt_required=False,
            enabled_default=True,
        )
        # Build options list from supported IDs.
        self._mode_ids: list[int] = []
        options: list[str] = []
        for mid in supported_mode_ids:
            label = MODE_MAP.get(mid)
            if label and label not in options:
                self._mode_ids.append(int(mid))
                options.append(label)
        self._attr_options = options

    def _get_current_mode_id(self) -> int | None:
        # Prefer shadow Machine.mode
        st = self.coordinator.get_machine_state(self._sn) or {}
        m = st.get("mode")
        if isinstance(m, int):
            return m
        if isinstance(m, str) and m.isdigit():
            return int(m)

        # Fallback to REST info if present
        dev = (self.coordinator.data or {}).get(self._sn) or {}
        info = dev.get("info") or {}
        if isinstance(info, dict):
            for k in ("mode", "workMode"):
                if k in info and info.get(k) is not None:
                    try:
                        return int(info.get(k))
                    except Exception:
                        continue
        return None

    @property
    def current_option(self) -> str | None:
        mid = self._get_current_mode_id()
        if mid is None:
            return None
        return MODE_MAP.get(mid)

    async def async_select_option(self, option: str) -> None:
        self._raise_if_control_blocked()

        # Map label -> id
        mode_id = None
        for mid, label in MODE_MAP.items():
            if label == option:
                mode_id = int(mid)
                break
        if mode_id is None:
            raise HomeAssistantError(f"Invalid cleaning mode: {option}")

        # No-op if already in that mode.
        cur = self._get_current_mode_id()
        if cur is not None and cur == mode_id:
            return

        self.coordinator.note_command_sent(self._sn, "mode", mode_id)

        ok = False
        try:
            ok = await self.hass.async_add_executor_job(self.coordinator.api.set_mode, self._sn, mode_id)
        except Exception as err:
            self.coordinator.note_command_failed(self._sn, "mode", mode_id, reason=str(err))
            raise HomeAssistantError(f"Failed to set cleaning mode: {err}") from err
        if not ok:
            self.coordinator.note_command_failed(self._sn, "mode", mode_id, reason="device rejected")
            if not self.coordinator.api.is_mqtt_connected():
                raise HomeAssistantError(
                    "Failed to set cleaning mode: MQTT is not connected. Enable MQTT in the Aiper integration options."
                )
            raise HomeAssistantError("Failed to set cleaning mode: device rejected the command")

        # Ask for a shadow refresh and a coordinator refresh.
        try:
            await self.hass.async_add_executor_job(self.coordinator.api.request_shadow, self._sn)
        except Exception:
            pass

        await self.coordinator.async_request_refresh()
class AiperCleanPathSelect(AiperSelectBase):
    """Select for choosing cleaning path."""

    def __init__(
        self,
        coordinator: AiperDataUpdateCoordinator,
        entry: ConfigEntry,
        sn: str,
        name: str,
    ) -> None:
        super().__init__(
            coordinator,
            entry,
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
        val = self.coordinator.get_clean_path(self._sn)
        if val is None:
            return None
        try:
            iv = int(val)
        except Exception:
            return None

        label = CLEAN_PATH_MAP.get(iv)
        if label is None:
            # If the device reports an unexpected ID, expose it without breaking the UI.
            label = f"Path {iv}"
            try:
                opts = list(self._attr_options or [])
                if label not in opts:
                    opts.append(label)
                    self._attr_options = opts
            except Exception:
                pass
        return label

    @property
    def extra_state_attributes(self):
        attrs = dict(super().extra_state_attributes)
        try:
            shadow = getattr(self.coordinator, "_shadow_data", {}).get(self._sn) or {}
            if isinstance(shadow, dict):
                mach = shadow.get("machine") or {}
                dm = shadow.get("desired_machine") or {}
                attrs["clean_path_reported_raw"] = (mach.get("cleanPath") if isinstance(mach, dict) else None)
                attrs["clean_path_desired_raw"] = (dm.get("cleanPath") if isinstance(dm, dict) else None)
        except Exception:
            pass
        return attrs


    async def async_select_option(self, option: str) -> None:
        self._raise_if_control_blocked()

        # Map label -> id
        path_id = None
        for pid, label in CLEAN_PATH_MAP.items():
            if label == option:
                path_id = int(pid)
                break

        # Allow unexpected IDs that we surfaced as dynamic options (e.g. 'Path 2').
        if path_id is None and isinstance(option, str) and option.lower().startswith('path '):
            try:
                path_id = int(option.split(' ', 1)[1].strip())
            except Exception:
                path_id = None

        if path_id is None:
            raise HomeAssistantError(f"Invalid clean path: {option}")

        cur = self.coordinator.get_clean_path(self._sn)
        if cur is not None and int(cur) == path_id:
            return

        self.coordinator.note_command_sent(self._sn, "clean_path", path_id)

        ok = False
        try:
            ok = await self.hass.async_add_executor_job(
                self.coordinator.api.update_clean_path_setting,
                self._sn,
                path_id,
            )
        except Exception as err:
            self.coordinator.note_command_failed(self._sn, "clean_path", path_id, reason=str(err))
            raise HomeAssistantError(f"Failed to set clean path: {err}") from err
        if not ok:
            self.coordinator.note_command_failed(self._sn, "clean_path", path_id, reason="device rejected")
            if not self.coordinator.api.is_mqtt_connected():
                raise HomeAssistantError(
                    "Failed to set clean path: cloud control is unavailable because MQTT is not connected. Enable MQTT in the Aiper integration options."
                )
            raise HomeAssistantError("Failed to set clean path: device rejected the command")



        # Optimistically cache the selection. Some firmwares never report cleanPath
        # in reported shadow state, so without this the entity can remain Unknown.
        try:
            self.coordinator.set_clean_path_cache(self._sn, path_id)
        except Exception:
            pass

        # Ask for a shadow refresh and a coordinator refresh.
        try:
            await self.hass.async_add_executor_job(self.coordinator.api.request_shadow, self._sn)
        except Exception:
            pass

        await self.coordinator.async_request_refresh()
async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry, async_add_entities) -> None:
    """Set up select entities from a config entry."""
    coordinator: AiperDataUpdateCoordinator = hass.data[DOMAIN][entry.entry_id]["coordinator"]

    # Determine if MQTT is enabled (controls the default enabled-state for mode select).
    mqtt_enabled = bool(entry.options.get(CONF_ENABLE_MQTT)) if CONF_ENABLE_MQTT in entry.options else True

    entities: list[SelectEntity] = []
    if coordinator.data:
        for sn, dev in coordinator.data.items():
            name = dev.get("name") or dev.get("deviceName") or dev.get("productName") or sn
            supported = dev.get("_ha_supported_mode_ids")
            if not isinstance(supported, list) or not supported:
                # fallback to known modes
                supported = sorted(MODE_MAP.keys())

            entities.append(AiperCleanPathSelect(coordinator, entry, sn, name))
            entities.append(AiperCleaningModeSelect(coordinator, entry, sn, name, supported, mqtt_enabled))

    async_add_entities(entities)
