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
from homeassistant.core import HomeAssistant
from homeassistant.exceptions import ServiceValidationError
from homeassistant.helpers.entity_platform import AddEntitiesCallback

from . import AiperConfigEntry
from .const import (
    CLEAN_PATH_MAP,
    DOMAIN,
    mode_label,
)
from .controller import AiperDeviceController
from .coordinator import AiperDataUpdateCoordinator
from .entity import AiperControlEntity, async_setup_dynamic_device_entities, device_online
from .helpers import supports_clean_path, supports_mode_control
from .state import DeviceState
from .state_common import _coerce_int as coerce_int

_LOGGER = logging.getLogger(__name__)

# Commands are serialized per device by the API; don't fan out in parallel.
PARALLEL_UPDATES = 1


class AiperSelectBase(AiperControlEntity, SelectEntity):
    """Base class for Aiper select entities."""

    # Precondition flags churn often and carry no history value.
    _unrecorded_attributes = frozenset({"device_online", "mqtt_connected"})

    def __init__(
        self,
        coordinator: AiperDataUpdateCoordinator,
        controller: AiperDeviceController,
        sn: str,
        key: str,
        *,
        icon: str | None = None,
        mqtt_required: bool = False,
        enabled_default: bool = True,
    ) -> None:
        super().__init__(coordinator, controller, sn, key)
        self._attr_translation_key = key
        self._attr_icon = icon
        self._attr_entity_registry_enabled_default = enabled_default
        self._requires_mqtt = mqtt_required

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        attrs: dict[str, Any] = {}

        online = device_online(self.coordinator, self._sn)
        if online is not None:
            attrs["device_online"] = online

        attrs["mqtt_connected"] = self.coordinator.api.is_mqtt_connected()

        return attrs


class AiperCleaningModeSelect(AiperSelectBase):
    """Select for choosing cleaning mode."""

    def __init__(
        self,
        coordinator: AiperDataUpdateCoordinator,
        controller: AiperDeviceController,
        sn: str,
        supported_mode_ids: list[int],
        mode_map: dict[int, str],
    ) -> None:
        super().__init__(
            coordinator,
            controller,
            sn,
            "mode_selection",
            mqtt_required=False,
            enabled_default=True,
        )
        self._baseline_mode_options = (self.device_data or {}).get("mode_options")
        self._mode_ids, self._mode_map, self._attr_options = self._build_mode_config(supported_mode_ids, mode_map)

    @staticmethod
    def _build_mode_config(
        supported_mode_ids: list[int], mode_map: dict[Any, Any] | None
    ) -> tuple[list[int], dict[int, str], list[str]]:
        clean_map: dict[int, str] = {}
        for key, value in (mode_map or {}).items():
            try:
                clean_map[int(key)] = str(value)
            except Exception:
                continue
        mode_ids: list[int] = []
        options: list[str] = []
        for mid in supported_mode_ids:
            mid_int = int(mid)
            label = clean_map.get(mid_int) or mode_label(mid_int)
            if label and label not in options:
                mode_ids.append(mid_int)
                options.append(label)
        return mode_ids, clean_map, options

    def _current_mode_config(self) -> tuple[list[int], dict[int, str], list[str]]:
        current_mo = (self.device_data or {}).get("mode_options")
        if (
            current_mo is not None
            and current_mo != self._baseline_mode_options
            and isinstance(current_mo.value, list)
            and current_mo.value
        ):
            supported_ids = [int(mid) for mid in current_mo.value]
            mode_map = current_mo.attributes.get("mode_map")
            return self._build_mode_config(supported_ids, mode_map if isinstance(mode_map, dict) else None)
        return self._mode_ids, self._mode_map, list(self._attr_options or [])

    @property
    def options(self) -> list[str]:
        """Return currently supported cleaning mode labels."""
        return self._current_mode_config()[2]

    def _mode_id_for_label(self, label: Any) -> int | None:
        if label is None:
            return None
        label_text = str(label).strip()
        if not label_text:
            return None
        mode_ids, mode_map, _ = self._current_mode_config()
        for mid, known_label in mode_map.items():
            if known_label == label_text:
                return int(mid)
        for mid in mode_ids:
            if mode_label(mid) == label_text:
                return int(mid)
        return None

    def _get_current_mode_id(self) -> int | None:
        dev = self.device_data or {}
        mode_ids, _, _ = self._current_mode_config()
        mode_state = dev.get("mode")
        reported = coerce_int(mode_state.attributes.get("code")) if mode_state is not None else None
        if reported in mode_ids:
            return reported

        mode_options = dev.get("mode_options")
        selected = coerce_int(mode_options.attributes.get("selected_mode")) if mode_options is not None else None
        if selected in mode_ids:
            return selected

        pending = coerce_int(self.coordinator.get_pending_command_target(self._sn, "mode"))
        if pending in mode_ids:
            return pending

        last_mode = dev.get("last_cleaning_mode")
        history_mode = self._mode_id_for_label(last_mode.value if last_mode else None)
        if history_mode in mode_ids:
            return history_mode

        return reported

    @property
    def current_option(self) -> str | None:
        mode_ids, mode_map, _ = self._current_mode_config()
        mid = self._get_current_mode_id()
        if mid is None or mid not in mode_ids:
            return None
        return mode_map.get(mid) or mode_label(mid)

    async def async_select_option(self, option: str) -> None:
        self._raise_if_control_blocked()

        mode_id = self._mode_id_for_label(option)
        if mode_id is None:
            raise ServiceValidationError(
                translation_domain=DOMAIN,
                translation_key="invalid_option",
                translation_placeholders={"option": option},
            )

        # No-op if already in that mode.
        cur = self._get_current_mode_id()
        if cur is not None and cur == mode_id:
            return

        result = await self.controller.set_cleaning_mode(self._sn, mode_id)
        self._raise_for_failed_command(result)

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
    ) -> None:
        super().__init__(
            coordinator,
            controller,
            sn,
            "clean_path",
            mqtt_required=False,
            enabled_default=True,
        )
        self._attr_options = list(CLEAN_PATH_MAP.values())

    @property
    def options(self) -> list[str]:
        """Return clean-path options, including any device-reported non-standard label."""
        opts = list(CLEAN_PATH_MAP.values())
        clean_path = self.entity_state("clean_path")
        label = clean_path.value if clean_path is not None else None
        if isinstance(label, str) and label and label not in opts:
            opts.append(label)
        return opts

    @property
    def current_option(self) -> str | None:
        pending = coerce_int(self.coordinator.get_pending_command_target(self._sn, "clean_path"))
        if pending in CLEAN_PATH_MAP:
            return CLEAN_PATH_MAP[pending]
        clean_path = self.entity_state("clean_path")
        label = clean_path.value if clean_path is not None else None
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
            raise ServiceValidationError(
                translation_domain=DOMAIN,
                translation_key="invalid_option",
                translation_placeholders={"option": option},
            )

        clean_path = self.entity_state("clean_path")
        cur = coerce_int(clean_path.attributes.get("code")) if clean_path is not None else None
        if cur is not None and cur == path_id:
            return

        result = await self.controller.set_clean_path(self._sn, path_id)
        self._raise_for_failed_command(result)

        # Optimistically cache the selection. Some firmwares never report cleanPath
        # in reported shadow state, so without this the entity can remain Unknown.
        with suppress(Exception):
            self.coordinator.set_clean_path_cache(self._sn, path_id)

        # Scuba S1 can acknowledge a write before AT+AUTO? reflects it. Hold
        # the requested option while pending and confirm with bounded backoff,
        # rather than allowing an immediate stale query to flicker the UI back.
        confirmed = False
        with suppress(Exception):
            confirmed = await self.coordinator.async_confirm_clean_path_selection(self._sn, path_id)

        # Ask for a shadow refresh and a coordinator refresh.
        with suppress(Exception):
            await self.controller.refresh_shadow(self._sn)

        # A successful AT+AUTO? confirmation is newer than an immediately
        # following full refresh, which can still return the previous value.
        if not confirmed:
            await self.coordinator.async_request_refresh()


async def async_setup_entry(
    hass: HomeAssistant,
    entry: AiperConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Set up select entities from a config entry."""
    coordinator: AiperDataUpdateCoordinator = entry.runtime_data.coordinator
    controller: AiperDeviceController = entry.runtime_data.controller

    def _create_device_entities(sn: str, dev: DeviceState) -> list[SelectEntity]:
        dev_entities: list[SelectEntity] = []
        if supports_clean_path(dev):
            dev_entities.append(AiperCleanPathSelect(coordinator, controller, sn))

        mode_options = dev.get("mode_options")
        supported = mode_options.value if mode_options is not None else None
        if supports_mode_control(dev) and isinstance(supported, list) and supported:
            supported_ids = [int(mode_id) for mode_id in supported]
            mode_map = mode_options.attributes.get("mode_map") if mode_options is not None else None
            if not isinstance(mode_map, dict):
                mode_map = {mode_id: mode_label(mode_id) for mode_id in supported_ids}
            dev_entities.append(AiperCleaningModeSelect(coordinator, controller, sn, supported_ids, mode_map))
        return dev_entities

    async_setup_dynamic_device_entities(entry, coordinator, async_add_entities, _create_device_entities)
