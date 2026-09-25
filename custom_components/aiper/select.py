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
from .entity import AiperControlEntity, device_online
from .helpers import supports_clean_path, supports_mode_control
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

    def _mode_id_for_label(self, label: Any) -> int | None:
        if label is None:
            return None
        label_text = str(label).strip()
        if not label_text:
            return None
        for mid, known_label in self._mode_map.items():
            if known_label == label_text:
                return int(mid)
        for mid in self._mode_ids:
            if mode_label(mid) == label_text:
                return int(mid)
        return None

    def _get_current_mode_id(self) -> int | None:
        dev = self.device_data or {}
        mode_state = dev.get("mode")
        reported = coerce_int(mode_state.attributes.get("code")) if mode_state is not None else None
        if reported in self._mode_ids:
            return reported

        mode_options = dev.get("mode_options")
        selected = coerce_int(mode_options.attributes.get("selected_mode")) if mode_options is not None else None
        if selected in self._mode_ids:
            return selected

        pending = coerce_int(self.coordinator.get_pending_command_target(self._sn, "mode"))
        if pending in self._mode_ids:
            return pending

        last_mode = dev.get("last_cleaning_mode")
        history_mode = self._mode_id_for_label(last_mode.value if last_mode else None)
        if history_mode in self._mode_ids:
            return history_mode

        return reported

    @property
    def current_option(self) -> str | None:
        mid = self._get_current_mode_id()
        if mid is None or mid not in self._mode_ids:
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
            icon="mdi:routes",
            mqtt_required=False,
            enabled_default=True,
        )
        self._attr_options = list(CLEAN_PATH_MAP.values())

    @property
    def current_option(self) -> str | None:
        pending = coerce_int(self.coordinator.get_pending_command_target(self._sn, "clean_path"))
        if pending in CLEAN_PATH_MAP:
            return CLEAN_PATH_MAP[pending]
        clean_path = self.entity_state("clean_path")
        label = clean_path.value if clean_path is not None else None
        if label is not None and label not in CLEAN_PATH_MAP.values():
            # Surface firmware-specific paths (e.g. "Path 2") as selectable options.
            opts = list(self._attr_options or [])
            if label not in opts:
                self._attr_options = [*opts, label]
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

    entities: list[SelectEntity] = []
    if coordinator.data:
        for sn, dev in coordinator.data.items():
            mode_options = dev["mode_options"]
            supported = mode_options.value
            if not isinstance(supported, list) or not supported:
                continue
            supported_ids = [int(mode_id) for mode_id in supported]
            mode_map = mode_options.attributes.get("mode_map")
            if not isinstance(mode_map, dict):
                mode_map = {mode_id: mode_label(mode_id) for mode_id in supported_ids}

            if supports_clean_path(dev):
                entities.append(AiperCleanPathSelect(coordinator, controller, sn))
            if supports_mode_control(dev):
                entities.append(AiperCleaningModeSelect(coordinator, controller, sn, supported_ids, mode_map))

    async_add_entities(entities)
