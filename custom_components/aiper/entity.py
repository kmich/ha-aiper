"""Shared entity base classes for the Aiper integration."""

from __future__ import annotations

from homeassistant.exceptions import HomeAssistantError
from homeassistant.helpers.device_registry import DeviceEntryType, DeviceInfo
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from .const import DOMAIN
from .controller import AiperCommandResult, AiperDeviceController
from .coordinator import AiperDataUpdateCoordinator
from .state import DeviceState, EntityState


def device_info_for(sn: str, device_data: DeviceState | None) -> DeviceInfo:
    """Build the one DeviceInfo shape every Aiper device entity shares."""
    device_info = (device_data or {}).get("device_info")
    attrs = device_info.attributes if device_info is not None else {}
    name = device_info.value if device_info is not None else None
    return DeviceInfo(
        identifiers={(DOMAIN, sn)},
        name=str(name or f"Aiper {sn}"),
        manufacturer="Aiper",
        model=attrs.get("model"),
        serial_number=sn,
        sw_version=attrs.get("sw_version"),
    )


def cloud_connection_device_info(entry_id: str) -> DeviceInfo:
    """DeviceInfo for the per-config-entry Aiper cloud-connection service device.

    The REST/MQTT link is shared by every device on the account, so its health
    entities live on one service device rather than being duplicated per robot.
    """
    return DeviceInfo(
        identifiers={(DOMAIN, f"cloud_{entry_id}")},
        name="Aiper Cloud",
        manufacturer="Aiper",
        model="Cloud Connection",
        entry_type=DeviceEntryType.SERVICE,
    )


def device_online(coordinator: AiperDataUpdateCoordinator, sn: str) -> bool | None:
    """Return the normalized online state for control availability."""
    dev = (coordinator.data or {}).get(sn)
    if dev is None:
        return None
    online = dev.get("online")
    value = online.value if online is not None else None
    return value if isinstance(value, bool) else None


class AiperEntity(CoordinatorEntity[AiperDataUpdateCoordinator]):
    """Base for entities that belong to one Aiper device."""

    _attr_has_entity_name = True

    def __init__(
        self,
        coordinator: AiperDataUpdateCoordinator,
        sn: str,
        key: str,
        device_data: DeviceState | None = None,
    ) -> None:
        """Initialize identity and device registry information."""
        super().__init__(coordinator)
        self._sn = sn
        self._attr_unique_id = f"{sn}_{key}"
        if device_data is None:
            device_data = (coordinator.data or {}).get(sn)
        self._attr_device_info = device_info_for(sn, device_data)

    @property
    def sn(self) -> str:
        """Return the device serial number."""
        return self._sn

    @property
    def device_data(self) -> DeviceState | None:
        """Return the current normalized state for this device, if present."""
        return (self.coordinator.data or {}).get(self._sn)

    def entity_state(self, key: str) -> EntityState | None:
        """Return one normalized state field for this device."""
        data = self.device_data
        return data.get(key) if data is not None else None

    @property
    def available(self) -> bool:
        """Unavailable when the coordinator failed or the device disappeared."""
        return super().available and self.device_data is not None


class AiperControlEntity(AiperEntity):
    """Base for entities that send commands to a device."""

    _requires_mqtt: bool = False
    _requires_online: bool = True

    def __init__(
        self,
        coordinator: AiperDataUpdateCoordinator,
        controller: AiperDeviceController,
        sn: str,
        key: str,
        device_data: DeviceState | None = None,
    ) -> None:
        """Initialize the control entity."""
        super().__init__(coordinator, sn, key, device_data)
        self.controller = controller

    @property
    def available(self) -> bool:
        """Controls also need MQTT (when required) and a device that is not offline."""
        if not super().available:
            return False
        if self._requires_mqtt and not self.coordinator.api.is_mqtt_connected():
            return False
        return not (self._requires_online and device_online(self.coordinator, self._sn) is False)

    def _raise_if_control_blocked(self) -> None:
        """Raise a translated error when a command cannot be sent right now."""
        if self._requires_mqtt and not self.coordinator.api.is_mqtt_connected():
            raise HomeAssistantError(translation_domain=DOMAIN, translation_key="mqtt_unavailable")
        if self._requires_online and device_online(self.coordinator, self._sn) is False:
            raise HomeAssistantError(translation_domain=DOMAIN, translation_key="device_offline")

    def _raise_for_failed_command(self, result: AiperCommandResult) -> None:
        """Raise a translated error for a command the device did not accept."""
        if result.ok:
            return
        if not self.coordinator.api.is_mqtt_connected():
            raise HomeAssistantError(translation_domain=DOMAIN, translation_key="mqtt_unavailable")
        raise HomeAssistantError(
            translation_domain=DOMAIN,
            translation_key="command_failed",
            translation_placeholders={
                "command": result.command,
                "reason": result.reason or "device rejected the command",
            },
        )
