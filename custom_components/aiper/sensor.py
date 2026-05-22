"""Sensor platform for Aiper integration."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from homeassistant.components.sensor import (
    SensorDeviceClass,
    SensorEntity,
    SensorEntityDescription,
    SensorStateClass,
)
from homeassistant.config_entries import ConfigEntry
from homeassistant.const import PERCENTAGE, EntityCategory, UnitOfTemperature
from homeassistant.core import HomeAssistant
from homeassistant.helpers.device_registry import DeviceInfo
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from .const import DOMAIN
from .coordinator import AiperDataUpdateCoordinator
from .profiles import Capability, DeviceFamily
from .state import DeviceState, state_has_capability


def _is_not_surfer(device: DeviceState) -> bool:
    return device["device_family"].value != DeviceFamily.SURFER.value


@dataclass(frozen=True, kw_only=True)
class AiperSensorEntityDescription(SensorEntityDescription):
    """Describes Aiper sensor entity."""

    enabled_default: bool | None = None
    capability: Capability | None = None
    include_fn: Callable[[DeviceState], bool] = lambda _: True

    def __post_init__(self) -> None:
        """Default diagnostics to disabled unless the description overrides it."""
        if self.enabled_default is None:
            object.__setattr__(self, "enabled_default", self.entity_category != EntityCategory.DIAGNOSTIC)


SENSOR_DESCRIPTIONS: tuple[AiperSensorEntityDescription, ...] = (
    AiperSensorEntityDescription(
        key="battery",
        name="Battery",
        native_unit_of_measurement=PERCENTAGE,
        device_class=SensorDeviceClass.BATTERY,
        state_class=SensorStateClass.MEASUREMENT,
    ),
    AiperSensorEntityDescription(
        key="status",
        name="Status",
        icon="mdi:robot-vacuum",
    ),
    AiperSensorEntityDescription(
        key="mode",
        name="Mode",
        icon="mdi:robot-vacuum",
    ),
    AiperSensorEntityDescription(
        key="temperature",
        name="Water Temperature",
        native_unit_of_measurement=UnitOfTemperature.CELSIUS,
        device_class=SensorDeviceClass.TEMPERATURE,
        state_class=SensorStateClass.MEASUREMENT,
        capability=Capability.WATER_TEMPERATURE,
    ),
    AiperSensorEntityDescription(
        key="warning",
        name="Warning",
        icon="mdi:alert-circle",
    ),
    AiperSensorEntityDescription(
        key="wifi_signal",
        name="WiFi Signal",
        icon="mdi:wifi",
        native_unit_of_measurement="dBm",
        device_class=SensorDeviceClass.SIGNAL_STRENGTH,
        state_class=SensorStateClass.MEASUREMENT,
    ),
    AiperSensorEntityDescription(
        key="runtime",
        name="Current Cleaning Time",
        icon="mdi:timer",
        native_unit_of_measurement="h",
        state_class=SensorStateClass.MEASUREMENT,
    ),
    # --- Device info / firmware (REST) ---
    AiperSensorEntityDescription(
        key="device_family",
        name="Device Family",
        entity_category=EntityCategory.DIAGNOSTIC,
    ),
    AiperSensorEntityDescription(
        key="main_version",
        name="Main Version",
        entity_category=EntityCategory.DIAGNOSTIC,
    ),
    AiperSensorEntityDescription(
        key="mcu_version",
        name="MCU Version",
        entity_category=EntityCategory.DIAGNOSTIC,
    ),
    AiperSensorEntityDescription(
        key="ip_address",
        name="IP Address",
        entity_category=EntityCategory.DIAGNOSTIC,
    ),
    AiperSensorEntityDescription(
        key="ap_hotspot",
        name="AP Hotspot",
        entity_category=EntityCategory.DIAGNOSTIC,
    ),
    AiperSensorEntityDescription(
        key="bluetooth_name",
        name="Bluetooth Name",
        entity_category=EntityCategory.DIAGNOSTIC,
    ),
    AiperSensorEntityDescription(
        key="clean_path",
        name="Clean Path Preference",
        entity_category=EntityCategory.DIAGNOSTIC,
        capability=Capability.CLEAN_PATH,
    ),
    AiperSensorEntityDescription(
        key="ota_state",
        name="OTA State",
        entity_category=EntityCategory.DIAGNOSTIC,
    ),
    # --- Consumables (REST) ---
    AiperSensorEntityDescription(
        key="roller_brush",
        name="Roller Brush",
        icon="mdi:percent",
        native_unit_of_measurement=PERCENTAGE,
        entity_category=EntityCategory.DIAGNOSTIC,
        state_class=SensorStateClass.MEASUREMENT,
        include_fn=_is_not_surfer,
    ),
    AiperSensorEntityDescription(
        key="micromesh_filter",
        name="MicroMesh Filter",
        icon="mdi:percent",
        native_unit_of_measurement=PERCENTAGE,
        entity_category=EntityCategory.DIAGNOSTIC,
        state_class=SensorStateClass.MEASUREMENT,
    ),
    AiperSensorEntityDescription(
        key="caterpillar_tread",
        name="Caterpillar Tread",
        icon="mdi:percent",
        native_unit_of_measurement=PERCENTAGE,
        entity_category=EntityCategory.DIAGNOSTIC,
        state_class=SensorStateClass.MEASUREMENT,
        include_fn=_is_not_surfer,
    ),
    AiperSensorEntityDescription(
        key="propeller",
        name="Propeller",
        icon="mdi:percent",
        native_unit_of_measurement=PERCENTAGE,
        entity_category=EntityCategory.DIAGNOSTIC,
        state_class=SensorStateClass.MEASUREMENT,
    ),
)


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Set up Aiper sensors based on a config entry."""
    coordinator: AiperDataUpdateCoordinator = hass.data[DOMAIN][entry.entry_id]["coordinator"]

    entities: list[AiperSensor] = []

    if coordinator.data:
        for sn, device_data in coordinator.data.items():
            for description in SENSOR_DESCRIPTIONS:
                if description.capability and not state_has_capability(device_data, description.capability):
                    continue
                if not description.include_fn(device_data):
                    continue
                entities.append(
                    AiperSensor(
                        coordinator=coordinator,
                        description=description,
                        sn=sn,
                        device_data=device_data,
                    )
                )

    async_add_entities(entities)


class AiperSensor(CoordinatorEntity[AiperDataUpdateCoordinator], SensorEntity):
    """Representation of an Aiper sensor."""

    entity_description: AiperSensorEntityDescription
    _attr_has_entity_name = True

    def __init__(
        self,
        coordinator: AiperDataUpdateCoordinator,
        description: AiperSensorEntityDescription,
        sn: str,
        device_data: DeviceState,
    ) -> None:
        """Initialize the sensor."""
        super().__init__(coordinator)
        self.entity_description = description
        self._sn = sn
        self._attr_unique_id = f"{sn}_{description.key}"
        self._attr_entity_registry_enabled_default = bool(description.enabled_default)
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
    def native_value(self) -> Any:
        """Return the state of the sensor."""
        if self.coordinator.data and self._sn in self.coordinator.data:
            data = self.coordinator.data[self._sn]
            return data[self.entity_description.key].value
        return None

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        """Return additional sensor attributes."""
        if self.coordinator.data and self._sn in self.coordinator.data:
            data = self.coordinator.data[self._sn]
            return dict(data[self.entity_description.key].attributes)
        return {}

    @property
    def entity_picture(self) -> str | None:
        """Return a device model image for the primary status sensor."""
        if self.entity_description.key != "status":
            return None
        if self.coordinator.data and self._sn in self.coordinator.data:
            return self.coordinator.data[self._sn]["entity_picture"].value
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
