"""Binary sensor platform for Aiper integration."""

from __future__ import annotations

from dataclasses import dataclass

from homeassistant.components.binary_sensor import (
    BinarySensorDeviceClass,
    BinarySensorEntity,
    BinarySensorEntityDescription,
)
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.device_registry import DeviceInfo
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from .const import DOMAIN
from .coordinator import AiperDataUpdateCoordinator
from .profiles import Capability
from .state import DeviceState, state_has_capability


@dataclass(frozen=True, kw_only=True)
class AiperBinarySensorEntityDescription(BinarySensorEntityDescription):
    """Describes Aiper binary sensor entity."""

    enabled_default: bool = True
    capability: Capability | None = None


BINARY_SENSOR_DESCRIPTIONS: tuple[AiperBinarySensorEntityDescription, ...] = (
    AiperBinarySensorEntityDescription(
        key="online",
        name="Online",
        device_class=BinarySensorDeviceClass.CONNECTIVITY,
    ),
    AiperBinarySensorEntityDescription(
        key="in_water",
        name="In Water",
        icon="mdi:water",
        device_class=BinarySensorDeviceClass.MOISTURE,
        enabled_default=True,
        capability=Capability.IN_WATER,
    ),
    AiperBinarySensorEntityDescription(
        key="running",
        name="Running",
        icon="mdi:run",
        device_class=BinarySensorDeviceClass.RUNNING,
    ),
    AiperBinarySensorEntityDescription(
        key="solar_charging",
        name="Solar Charging",
        icon="mdi:solar-power",
        device_class=BinarySensorDeviceClass.BATTERY_CHARGING,
        enabled_default=False,  # MQTT-only
        capability=Capability.SOLAR_CHARGING,
    ),
    AiperBinarySensorEntityDescription(
        key="bluetooth",
        name="Bluetooth",
        icon="mdi:bluetooth",
        device_class=BinarySensorDeviceClass.CONNECTIVITY,
        enabled_default=False,  # MQTT-only
        capability=Capability.BLUETOOTH,
    ),
    AiperBinarySensorEntityDescription(
        key="wifi",
        name="WiFi Connected",
        icon="mdi:wifi",
        device_class=BinarySensorDeviceClass.CONNECTIVITY,
    ),
    AiperBinarySensorEntityDescription(
        key="linked",
        name="Device Linked",
        icon="mdi:link",
        enabled_default=False,  # MQTT-only
        capability=Capability.DEVICE_LINK,
    ),
)


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Set up Aiper binary sensors based on a config entry."""
    coordinator: AiperDataUpdateCoordinator = hass.data[DOMAIN][entry.entry_id]["coordinator"]

    entities: list[AiperBinarySensor] = []

    if coordinator.data:
        for sn, device_data in coordinator.data.items():
            for description in BINARY_SENSOR_DESCRIPTIONS:
                if description.capability and not state_has_capability(device_data, description.capability):
                    continue
                entities.append(
                    AiperBinarySensor(
                        coordinator=coordinator,
                        description=description,
                        sn=sn,
                        device_data=device_data,
                    )
                )

    async_add_entities(entities)


class AiperBinarySensor(CoordinatorEntity[AiperDataUpdateCoordinator], BinarySensorEntity):
    """Representation of an Aiper binary sensor."""

    entity_description: AiperBinarySensorEntityDescription
    _attr_has_entity_name = True

    def __init__(
        self,
        coordinator: AiperDataUpdateCoordinator,
        description: AiperBinarySensorEntityDescription,
        sn: str,
        device_data: DeviceState,
    ) -> None:
        """Initialize the binary sensor."""
        super().__init__(coordinator)
        self.entity_description = description
        self._sn = sn
        self._attr_unique_id = f"{sn}_{description.key}"
        self._attr_entity_registry_enabled_default = description.enabled_default
        device_info = device_data["device_info"]
        device_info_attrs = device_info.attributes

        self._attr_device_info = DeviceInfo(
            identifiers={(DOMAIN, sn)},
            name=str(device_info.value or f"Aiper {sn}"),
            manufacturer="Aiper",
            model=device_info_attrs.get("model"),
            serial_number=sn,
            sw_version=device_info_attrs.get("sw_version"),
        )

    @property
    def is_on(self) -> bool | None:
        """Return true if the binary sensor is on."""
        if self.coordinator.data and self._sn in self.coordinator.data:
            data = self.coordinator.data[self._sn]
            value = data[self.entity_description.key].value
            return value if isinstance(value, bool) else None
        return None

    @property
    def available(self) -> bool:
        """Return True if entity is available."""
        if not super().available:
            return False
        if self.coordinator.data and self._sn in self.coordinator.data:
            data = self.coordinator.data[self._sn]
            return data[self.entity_description.key].value is not None
        return False
