"""Switch platform for Aiper integration."""

from __future__ import annotations

from contextlib import suppress

from homeassistant.components.switch import SwitchEntity
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.exceptions import HomeAssistantError
from homeassistant.helpers.device_registry import DeviceInfo
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from .const import DOMAIN
from .controller import AiperDeviceController
from .coordinator import AiperDataUpdateCoordinator
from .profiles import Capability
from .state import DeviceState, state_has_capability


def _device_online(coordinator: AiperDataUpdateCoordinator, sn: str) -> bool | None:
    dev = (coordinator.data or {}).get(sn)
    if dev is None:
        return None
    try:
        value = dev["online"].value
    except KeyError:
        return None
    return value if isinstance(value, bool) else None


def _device_name(dev: DeviceState, sn: str) -> str:
    return str(dev["device_info"].value or sn)


def _supports_running_control(dev: DeviceState) -> bool:
    """Return whether the device supports simple on/off running control."""
    return state_has_capability(dev, Capability.RUNNING_CONTROL)


class AiperRunningSwitch(CoordinatorEntity[AiperDataUpdateCoordinator], SwitchEntity):
    """Switch for simple start/stop control."""

    _attr_icon = "mdi:pool"

    def __init__(
        self,
        coordinator: AiperDataUpdateCoordinator,
        controller: AiperDeviceController,
        sn: str,
        name: str,
    ) -> None:
        super().__init__(coordinator)
        self.controller = controller
        self._sn = sn
        self._attr_name = f"{name} Running"
        self._attr_unique_id = f"{sn}_running"

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
        if not self.coordinator.api.is_mqtt_connected():
            return False

        online = _device_online(self.coordinator, self._sn)
        return online is not False

    @property
    def is_on(self) -> bool | None:
        pending = self.coordinator.get_pending_command_target(self._sn, "running")
        if isinstance(pending, bool):
            return pending
        dev = (self.coordinator.data or {})[self._sn]
        running = dev["running"].value
        return running if isinstance(running, bool) else None

    def _raise_if_control_blocked(self) -> None:
        if not self.coordinator.api.is_mqtt_connected():
            raise HomeAssistantError("Aiper MQTT connection is not available; cannot send this command.")

        online = _device_online(self.coordinator, self._sn)
        if online is False:
            raise HomeAssistantError("Device is offline; controls are disabled.")

    async def _set_running(self, running: bool) -> None:
        self._raise_if_control_blocked()

        result = await self.controller.set_running(self._sn, running)
        if not result.ok:
            raise HomeAssistantError(f"Failed to set running state: {result.reason or 'device rejected the command'}")

        with suppress(Exception):
            await self.controller.refresh_shadow(self._sn)

        await self.coordinator.async_request_refresh()

    async def async_turn_on(self, **kwargs) -> None:
        """Start running."""
        await self._set_running(True)

    async def async_turn_off(self, **kwargs) -> None:
        """Stop running."""
        await self._set_running(False)


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry, async_add_entities) -> None:
    """Set up switch entities from a config entry."""
    coordinator: AiperDataUpdateCoordinator = hass.data[DOMAIN][entry.entry_id]["coordinator"]
    controller: AiperDeviceController = hass.data[DOMAIN][entry.entry_id]["controller"]

    entities: list[SwitchEntity] = []
    if coordinator.data:
        for sn, dev in coordinator.data.items():
            if _supports_running_control(dev):
                entities.append(AiperRunningSwitch(coordinator, controller, sn, _device_name(dev, sn)))

    async_add_entities(entities)
