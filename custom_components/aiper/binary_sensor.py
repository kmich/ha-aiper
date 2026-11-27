"""Binary sensor platform for Aiper integration."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from homeassistant.components.binary_sensor import (
    BinarySensorDeviceClass,
    BinarySensorEntity,
    BinarySensorEntityDescription,
)
from homeassistant.const import EntityCategory
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.update_coordinator import CoordinatorEntity
from homeassistant.util import dt as dt_util

from . import AiperConfigEntry
from .coordinator import MQTT_LIVE_STATE_TTL, AiperDataUpdateCoordinator
from .entity import AiperEntity, async_setup_dynamic_device_entities, cloud_connection_device_info, device_online
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
    warning_mask: int | None = None


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
    # Live Scuba S3 alarm catalog, grouped by the Android app's module IDs.
    *(
        AiperBinarySensorEntityDescription(
            key=key,
            translation_key=key,
            device_class=BinarySensorDeviceClass.PROBLEM,
            entity_category=EntityCategory.DIAGNOSTIC,
            enabled_default=False,
            capability=Capability.SCUBA_S3_HEALTH,
            warning_mask=mask,
        )
        for key, mask in (
            ("action_module_problem", 0x2 | 0x4),
            ("cleaning_module_problem", 0x8 | 0x10),
            ("power_module_problem", 0x40 | 0x80 | 0x200 | 0x400),
        )
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

    async_setup_dynamic_device_entities(
        entry,
        coordinator,
        async_add_entities,
        _create_device_entities,
        extra_entities=(AiperCloudConnectedBinarySensor(coordinator, entry.entry_id),),
    )


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
        if (mask := self.entity_description.warning_mask) is not None:
            state = self.entity_state("scuba_s3_warning_code")
            return bool(state.value & mask) if state is not None else None
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
        if self.entity_description.warning_mask is not None:
            warning = self.entity_state("scuba_s3_warning_code")
            observed_at = warning.attributes.get("observed_at") if warning is not None else None
            return (
                super().available
                and device_online(self.coordinator, self._sn) is True
                and isinstance(observed_at, datetime)
                and dt_util.utcnow() - observed_at <= MQTT_LIVE_STATE_TTL
            )
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
