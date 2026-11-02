"""Binary sensor platform for Aiper integration."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from homeassistant.components.binary_sensor import (
    BinarySensorDeviceClass,
    BinarySensorEntity,
    BinarySensorEntityDescription,
)
from homeassistant.const import EntityCategory
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from . import AiperConfigEntry
from .coordinator import AiperDataUpdateCoordinator
from .entity import AiperEntity, cloud_connection_device_info
from .helpers import is_not_hydrocomm
from .profiles import Capability
from .state import DeviceState, state_has_capability

# Entities only read coordinator data; no per-entity update calls.
PARALLEL_UPDATES = 0


@dataclass(frozen=True, kw_only=True)
class AiperBinarySensorEntityDescription(BinarySensorEntityDescription):
    """Describes Aiper binary sensor entity."""

    enabled_default: bool = True
    capability: Capability | None = None
    include_fn: Callable[[DeviceState], bool] = lambda _: True
    expose_attributes: bool = False


BINARY_SENSOR_DESCRIPTIONS: tuple[AiperBinarySensorEntityDescription, ...] = (
    AiperBinarySensorEntityDescription(
        key="online",
        translation_key="online",
        device_class=BinarySensorDeviceClass.CONNECTIVITY,
    ),
    AiperBinarySensorEntityDescription(
        key="in_water",
        translation_key="in_water",
        device_class=BinarySensorDeviceClass.MOISTURE,
        enabled_default=True,
        capability=Capability.IN_WATER,
    ),
    AiperBinarySensorEntityDescription(
        key="running",
        translation_key="running",
        device_class=BinarySensorDeviceClass.RUNNING,
        include_fn=is_not_hydrocomm,
    ),
    AiperBinarySensorEntityDescription(
        key="charging",
        translation_key="charging",
        device_class=BinarySensorDeviceClass.BATTERY_CHARGING,
        capability=Capability.CHARGING,
    ),
    AiperBinarySensorEntityDescription(
        key="solar_charging",
        translation_key="solar_charging",
        device_class=BinarySensorDeviceClass.BATTERY_CHARGING,
        enabled_default=False,  # MQTT-only
        capability=Capability.SOLAR_CHARGING,
    ),
    AiperBinarySensorEntityDescription(
        key="bluetooth",
        translation_key="bluetooth",
        device_class=BinarySensorDeviceClass.CONNECTIVITY,
        enabled_default=False,  # MQTT-only
        capability=Capability.BLUETOOTH,
    ),
    AiperBinarySensorEntityDescription(
        key="wifi",
        translation_key="wifi",
        device_class=BinarySensorDeviceClass.CONNECTIVITY,
    ),
    AiperBinarySensorEntityDescription(
        key="linked",
        translation_key="linked",
        enabled_default=False,  # MQTT-only
        capability=Capability.DEVICE_LINK,
    ),
)

# Read-only binary sensors from Scuba V3 Ultra ``*Report`` sections
# (report_sections.py). Debris-basket semantics are not yet physically verified.
REPORT_BINARY_SENSOR_DESCRIPTIONS: tuple[AiperBinarySensorEntityDescription, ...] = (
    AiperBinarySensorEntityDescription(
        key="debris_basket_blocked",
        translation_key="debris_basket_blocked",
        device_class=BinarySensorDeviceClass.PROBLEM,
        capability=Capability.REPORT_SECTIONS,
        expose_attributes=True,
    ),
    AiperBinarySensorEntityDescription(
        key="debris_basket_in_place",
        translation_key="debris_basket_in_place",
        capability=Capability.REPORT_SECTIONS,
        expose_attributes=True,
    ),
    AiperBinarySensorEntityDescription(
        key="camera",
        translation_key="camera",
        entity_category=EntityCategory.DIAGNOSTIC,
        capability=Capability.REPORT_SECTIONS,
    ),
    *(
        AiperBinarySensorEntityDescription(
            key=key,
            translation_key=key,
            entity_category=EntityCategory.DIAGNOSTIC,
            enabled_default=False,
            capability=Capability.REPORT_SECTIONS,
        )
        for key in ("schedule_weather", "schedule_adapt", "schedule_habit")
    ),
)


async def async_setup_entry(
    hass: HomeAssistant,
    entry: AiperConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Set up Aiper binary sensors based on a config entry."""
    coordinator: AiperDataUpdateCoordinator = entry.runtime_data.coordinator
    known_devices: set[str] = set()

    def _create_device_entities(sn: str, device_data: DeviceState) -> list[BinarySensorEntity]:
        dev_entities: list[BinarySensorEntity] = []
        for description in (*BINARY_SENSOR_DESCRIPTIONS, *REPORT_BINARY_SENSOR_DESCRIPTIONS):
            if description.capability and not state_has_capability(device_data, description.capability):
                continue
            if not description.include_fn(device_data):
                continue
            dev_entities.append(
                AiperBinarySensor(
                    coordinator=coordinator,
                    description=description,
                    sn=sn,
                    device_data=device_data,
                )
            )
        return dev_entities

    @callback
    def _async_add_new_devices() -> None:
        if not coordinator.data:
            return
        new_entities: list[BinarySensorEntity] = []
        for sn, device_data in coordinator.data.items():
            if sn not in known_devices:
                known_devices.add(sn)
                new_entities.extend(_create_device_entities(sn, device_data))
        if new_entities:
            async_add_entities(new_entities)

    initial_entities: list[BinarySensorEntity] = []
    if coordinator.data:
        for sn, device_data in coordinator.data.items():
            known_devices.add(sn)
            initial_entities.extend(_create_device_entities(sn, device_data))

    initial_entities.append(AiperCloudConnectedBinarySensor(coordinator, entry.entry_id))
    async_add_entities(initial_entities)
    if hasattr(entry, "async_on_unload"):
        entry.async_on_unload(coordinator.async_add_listener(_async_add_new_devices))


class AiperBinarySensor(AiperEntity, BinarySensorEntity):
    """Representation of an Aiper binary sensor."""

    entity_description: AiperBinarySensorEntityDescription

    def __init__(
        self,
        coordinator: AiperDataUpdateCoordinator,
        description: AiperBinarySensorEntityDescription,
        sn: str,
        device_data: DeviceState,
    ) -> None:
        """Initialize the binary sensor."""
        super().__init__(coordinator, sn, description.key, device_data)
        self.entity_description = description
        self._attr_entity_registry_enabled_default = description.enabled_default

    @property
    def is_on(self) -> bool | None:
        """Return true if the binary sensor is on."""
        state = self.entity_state(self.entity_description.key)
        value = state.value if state is not None else None
        return value if isinstance(value, bool) else None

    @property
    def extra_state_attributes(self) -> dict[str, Any] | None:
        """Return the raw report fields for descriptions that expose them."""
        if not self.entity_description.expose_attributes:
            return None
        state = self.entity_state(self.entity_description.key)
        return dict(state.attributes) if state is not None else None

    @property
    def available(self) -> bool:
        """Return True if entity is available."""
        state = self.entity_state(self.entity_description.key)
        return super().available and state is not None and state.value is not None


class AiperCloudConnectedBinarySensor(CoordinatorEntity[AiperDataUpdateCoordinator], BinarySensorEntity):
    """Whether the integration currently holds a live AWS IoT MQTT connection.

    Lives on the per-entry "Aiper Cloud" service device and reflects the shared
    connection tracker, so an automation can react to the cloud link dropping
    for all devices at once.
    """

    _attr_has_entity_name = True
    _attr_translation_key = "cloud_connected"
    _attr_device_class = BinarySensorDeviceClass.CONNECTIVITY
    _attr_entity_category = EntityCategory.DIAGNOSTIC

    def __init__(self, coordinator: AiperDataUpdateCoordinator, entry_id: str) -> None:
        super().__init__(coordinator)
        self._attr_unique_id = f"{entry_id}_cloud_connected"
        self._attr_device_info = cloud_connection_device_info(entry_id)

    @property
    def is_on(self) -> bool:
        """Return True while the MQTT connection tracker reports CONNECTED."""
        return self.coordinator.api.connection.is_connected

    @property
    def available(self) -> bool:
        """Connection health is always meaningful, even when a poll has failed."""
        return True
