"""Sensor platform for Aiper integration."""

from __future__ import annotations

import math
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any

from homeassistant.components.sensor import RestoreSensor, SensorEntity, SensorEntityDescription
from homeassistant.components.sensor.const import SensorDeviceClass, SensorStateClass
from homeassistant.const import PERCENTAGE, EntityCategory, UnitOfTemperature, UnitOfTime
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.event import async_track_time_interval
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from . import AiperConfigEntry
from .connection import ConnectionState
from .coordinator import AiperDataUpdateCoordinator
from .entity import AiperEntity, cloud_connection_device_info
from .helpers import is_not_hydrocomm
from .profiles import Capability
from .state import DeviceState, state_has_capability

# Entities only read coordinator data; no per-entity update calls.
PARALLEL_UPDATES = 0


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
        translation_key="battery",
        native_unit_of_measurement=PERCENTAGE,
        device_class=SensorDeviceClass.BATTERY,
        state_class=SensorStateClass.MEASUREMENT,
    ),
    AiperSensorEntityDescription(
        key="status",
        translation_key="status",
        icon="mdi:robot-vacuum",
    ),
    AiperSensorEntityDescription(
        key="mode",
        translation_key="mode",
        icon="mdi:robot-vacuum",
        include_fn=is_not_hydrocomm,
    ),
    AiperSensorEntityDescription(
        key="temperature",
        translation_key="temperature",
        native_unit_of_measurement=UnitOfTemperature.CELSIUS,
        device_class=SensorDeviceClass.TEMPERATURE,
        state_class=SensorStateClass.MEASUREMENT,
        capability=Capability.WATER_TEMPERATURE,
    ),
    AiperSensorEntityDescription(
        key="warning",
        translation_key="warning",
        icon="mdi:alert-circle",
    ),
    AiperSensorEntityDescription(
        key="wifi_signal",
        translation_key="wifi_signal",
        icon="mdi:wifi",
        native_unit_of_measurement="dBm",
        device_class=SensorDeviceClass.SIGNAL_STRENGTH,
        state_class=SensorStateClass.MEASUREMENT,
    ),
    AiperSensorEntityDescription(
        key="runtime",
        translation_key="runtime",
        icon="mdi:timer",
        native_unit_of_measurement="h",
        state_class=SensorStateClass.MEASUREMENT,
        include_fn=is_not_hydrocomm,
    ),
    # --- Cleaning history (REST) ---
    AiperSensorEntityDescription(
        key="total_cleanings",
        translation_key="total_cleanings",
        icon="mdi:counter",
        state_class=SensorStateClass.TOTAL_INCREASING,
        enabled_default=False,
        include_fn=is_not_hydrocomm,
    ),
    AiperSensorEntityDescription(
        key="total_cleaning_time",
        translation_key="total_cleaning_time",
        icon="mdi:timer-outline",
        native_unit_of_measurement="h",
        state_class=SensorStateClass.TOTAL_INCREASING,
        enabled_default=False,
        include_fn=is_not_hydrocomm,
    ),
    AiperSensorEntityDescription(
        key="total_cleaning_time_minutes",
        translation_key="total_cleaning_time_minutes",
        icon="mdi:timer-outline",
        native_unit_of_measurement="min",
        state_class=SensorStateClass.TOTAL_INCREASING,
        enabled_default=False,
        include_fn=is_not_hydrocomm,
    ),
    AiperSensorEntityDescription(
        key="last_cleaning_mode",
        translation_key="last_cleaning_mode",
        icon="mdi:map-marker-path",
        enabled_default=False,
        include_fn=is_not_hydrocomm,
    ),
    AiperSensorEntityDescription(
        key="last_cleaning_start",
        translation_key="last_cleaning_start",
        device_class=SensorDeviceClass.TIMESTAMP,
        entity_category=EntityCategory.DIAGNOSTIC,
        enabled_default=False,
        include_fn=is_not_hydrocomm,
    ),
    AiperSensorEntityDescription(
        key="last_cleaning_duration",
        translation_key="last_cleaning_duration",
        icon="mdi:timer",
        native_unit_of_measurement="min",
        state_class=SensorStateClass.MEASUREMENT,
        enabled_default=False,
        include_fn=is_not_hydrocomm,
    ),
    # --- HydroComm / HydroHub water quality (MQTT shadow) ---
    AiperSensorEntityDescription(
        key="ph",
        translation_key="ph",
        icon="mdi:ph",
        state_class=SensorStateClass.MEASUREMENT,
        capability=Capability.WATER_QUALITY,
    ),
    AiperSensorEntityDescription(
        key="orp",
        translation_key="orp",
        icon="mdi:current-dc",
        native_unit_of_measurement="mV",
        state_class=SensorStateClass.MEASUREMENT,
        capability=Capability.WATER_QUALITY,
    ),
    AiperSensorEntityDescription(
        key="ec",
        translation_key="ec",
        icon="mdi:flash",
        native_unit_of_measurement="uS/cm",
        state_class=SensorStateClass.MEASUREMENT,
        capability=Capability.WATER_QUALITY,
    ),
    AiperSensorEntityDescription(
        key="tds",
        translation_key="tds",
        icon="mdi:water-percent",
        native_unit_of_measurement="ppm",
        state_class=SensorStateClass.MEASUREMENT,
        capability=Capability.WATER_QUALITY,
    ),
    AiperSensorEntityDescription(
        key="rcl",
        translation_key="rcl",
        icon="mdi:pool",
        native_unit_of_measurement="mg/L",
        state_class=SensorStateClass.MEASUREMENT,
        capability=Capability.WATER_QUALITY,
    ),
    AiperSensorEntityDescription(
        key="water_quality_score",
        translation_key="water_quality_score",
        icon="mdi:gauge",
        state_class=SensorStateClass.MEASUREMENT,
        capability=Capability.WATER_QUALITY,
    ),
    AiperSensorEntityDescription(
        key="water_quality_result",
        translation_key="water_quality_result",
        icon="mdi:water-check",
        entity_category=EntityCategory.DIAGNOSTIC,
        capability=Capability.WATER_QUALITY,
    ),
    AiperSensorEntityDescription(
        key="wqs_sample_time",
        translation_key="wqs_sample_time",
        icon="mdi:clock-outline",
        device_class=SensorDeviceClass.TIMESTAMP,
        entity_category=EntityCategory.DIAGNOSTIC,
        capability=Capability.WATER_QUALITY,
    ),
    AiperSensorEntityDescription(
        key="charge_type",
        translation_key="charge_type",
        icon="mdi:battery-charging",
        entity_category=EntityCategory.DIAGNOSTIC,
        capability=Capability.CHARGE_TYPE,
    ),
    AiperSensorEntityDescription(
        key="supply_voltage",
        translation_key="supply_voltage",
        icon="mdi:current-dc",
        native_unit_of_measurement="mV",
        entity_category=EntityCategory.DIAGNOSTIC,
        state_class=SensorStateClass.MEASUREMENT,
        capability=Capability.WATER_QUALITY,
    ),
    AiperSensorEntityDescription(
        key="solar_voltage",
        translation_key="solar_voltage",
        icon="mdi:solar-power-variant",
        native_unit_of_measurement="mV",
        entity_category=EntityCategory.DIAGNOSTIC,
        state_class=SensorStateClass.MEASUREMENT,
        capability=Capability.WATER_QUALITY,
    ),
    AiperSensorEntityDescription(
        key="light_level",
        translation_key="light_level",
        icon="mdi:brightness-5",
        native_unit_of_measurement="lx",
        entity_category=EntityCategory.DIAGNOSTIC,
        state_class=SensorStateClass.MEASUREMENT,
        capability=Capability.WATER_QUALITY,
    ),
    AiperSensorEntityDescription(
        key="work_current",
        translation_key="work_current",
        icon="mdi:current-dc",
        native_unit_of_measurement="mA",
        entity_category=EntityCategory.DIAGNOSTIC,
        state_class=SensorStateClass.MEASUREMENT,
        capability=Capability.WATER_QUALITY,
    ),
    AiperSensorEntityDescription(
        key="charge_current",
        translation_key="charge_current",
        icon="mdi:current-dc",
        native_unit_of_measurement="mA",
        entity_category=EntityCategory.DIAGNOSTIC,
        state_class=SensorStateClass.MEASUREMENT,
        capability=Capability.WATER_QUALITY,
    ),
    AiperSensorEntityDescription(
        key="calibration_status",
        translation_key="calibration_status",
        icon="mdi:tune",
        entity_category=EntityCategory.DIAGNOSTIC,
        capability=Capability.PROBE_STATUS,
    ),
    AiperSensorEntityDescription(
        key="probe_1_status",
        translation_key="probe_1_status",
        icon="mdi:water-thermometer",
        entity_category=EntityCategory.DIAGNOSTIC,
        capability=Capability.PROBE_STATUS,
    ),
    AiperSensorEntityDescription(
        key="probe_2_status",
        translation_key="probe_2_status",
        icon="mdi:water-thermometer",
        entity_category=EntityCategory.DIAGNOSTIC,
        capability=Capability.PROBE_STATUS,
    ),
    AiperSensorEntityDescription(
        key="probe_3_status",
        translation_key="probe_3_status",
        icon="mdi:water-thermometer",
        entity_category=EntityCategory.DIAGNOSTIC,
        capability=Capability.PROBE_STATUS,
    ),
    AiperSensorEntityDescription(
        key="ultrasonic_status",
        translation_key="ultrasonic_status",
        icon="mdi:radar",
        entity_category=EntityCategory.DIAGNOSTIC,
        capability=Capability.PROBE_STATUS,
    ),
    # --- Device info / firmware (REST) ---
    AiperSensorEntityDescription(
        key="device_family",
        translation_key="device_family",
        entity_category=EntityCategory.DIAGNOSTIC,
    ),
    AiperSensorEntityDescription(
        key="main_version",
        translation_key="main_version",
        entity_category=EntityCategory.DIAGNOSTIC,
    ),
    AiperSensorEntityDescription(
        key="mcu_version",
        translation_key="mcu_version",
        entity_category=EntityCategory.DIAGNOSTIC,
    ),
    AiperSensorEntityDescription(
        key="ip_address",
        translation_key="ip_address",
        entity_category=EntityCategory.DIAGNOSTIC,
    ),
    AiperSensorEntityDescription(
        key="ap_hotspot",
        translation_key="ap_hotspot",
        entity_category=EntityCategory.DIAGNOSTIC,
    ),
    AiperSensorEntityDescription(
        key="bluetooth_name",
        translation_key="bluetooth_name",
        entity_category=EntityCategory.DIAGNOSTIC,
    ),
    AiperSensorEntityDescription(
        key="clean_path",
        translation_key="clean_path",
        entity_category=EntityCategory.DIAGNOSTIC,
        capability=Capability.CLEAN_PATH,
    ),
    AiperSensorEntityDescription(
        key="ota_state",
        translation_key="ota_state",
        entity_category=EntityCategory.DIAGNOSTIC,
    ),
    # --- Consumables (REST) ---
    AiperSensorEntityDescription(
        key="roller_brush",
        translation_key="roller_brush",
        icon="mdi:percent",
        native_unit_of_measurement=PERCENTAGE,
        entity_category=EntityCategory.DIAGNOSTIC,
        state_class=SensorStateClass.MEASUREMENT,
        capability=Capability.ROLLER_BRUSH,
    ),
    AiperSensorEntityDescription(
        key="micromesh_filter",
        translation_key="micromesh_filter",
        icon="mdi:percent",
        native_unit_of_measurement=PERCENTAGE,
        entity_category=EntityCategory.DIAGNOSTIC,
        state_class=SensorStateClass.MEASUREMENT,
        capability=Capability.MICROMESH_FILTER,
    ),
    AiperSensorEntityDescription(
        key="caterpillar_tread",
        translation_key="caterpillar_tread",
        icon="mdi:percent",
        native_unit_of_measurement=PERCENTAGE,
        entity_category=EntityCategory.DIAGNOSTIC,
        state_class=SensorStateClass.MEASUREMENT,
        capability=Capability.CATERPILLAR_TREAD,
    ),
    AiperSensorEntityDescription(
        key="propeller",
        translation_key="propeller",
        icon="mdi:percent",
        native_unit_of_measurement=PERCENTAGE,
        entity_category=EntityCategory.DIAGNOSTIC,
        state_class=SensorStateClass.MEASUREMENT,
        capability=Capability.PROPELLER,
    ),
)

ESTIMATED_CLEANING_TIME_DESCRIPTION = AiperSensorEntityDescription(
    key="estimated_cleaning_time",
    translation_key="estimated_cleaning_time",
    icon="mdi:timer-sand",
    native_unit_of_measurement=UnitOfTime.MINUTES,
    device_class=SensorDeviceClass.DURATION,
    state_class=SensorStateClass.MEASUREMENT,
    capability=Capability.ESTIMATED_CLEANING_TIME,
)

ESTIMATED_CLEANING_TIME_INTERVAL = timedelta(minutes=1)


async def async_setup_entry(
    hass: HomeAssistant,
    entry: AiperConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Set up Aiper sensors based on a config entry."""
    coordinator: AiperDataUpdateCoordinator = entry.runtime_data.coordinator

    entities: list[SensorEntity] = []

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
            if state_has_capability(device_data, Capability.ESTIMATED_CLEANING_TIME):
                entities.append(
                    AiperEstimatedCleaningTimeSensor(
                        coordinator=coordinator,
                        sn=sn,
                        device_data=device_data,
                    )
                )

    entities.extend(
        (
            AiperConnectionStateSensor(coordinator, entry.entry_id),
            AiperLastCloudUpdateSensor(coordinator, entry.entry_id),
        )
    )

    async_add_entities(entities)


class AiperSensor(AiperEntity, SensorEntity):
    """Representation of an Aiper sensor."""

    entity_description: AiperSensorEntityDescription

    def __init__(
        self,
        coordinator: AiperDataUpdateCoordinator,
        description: AiperSensorEntityDescription,
        sn: str,
        device_data: DeviceState,
    ) -> None:
        """Initialize the sensor."""
        super().__init__(coordinator, sn, description.key, device_data)
        self.entity_description = description
        self._attr_entity_registry_enabled_default = bool(description.enabled_default)

    @property
    def native_value(self) -> Any:
        """Return the state of the sensor."""
        state = self.entity_state(self.entity_description.key)
        return state.value if state is not None else None

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        """Return additional sensor attributes."""
        state = self.entity_state(self.entity_description.key)
        return dict(state.attributes) if state is not None else {}

    @property
    def entity_picture(self) -> str | None:
        """Return a device model image for the primary status sensor."""
        if self.entity_description.key != "status":
            return None
        state = self.entity_state("entity_picture")
        return state.value if state is not None else None

    @property
    def available(self) -> bool:
        """Return True if entity is available."""
        return super().available and self.native_value is not None


class _AiperCloudSensorBase(CoordinatorEntity[AiperDataUpdateCoordinator], SensorEntity):
    """Base for sensors on the per-entry 'Aiper Cloud' service device."""

    _attr_has_entity_name = True
    _attr_entity_category = EntityCategory.DIAGNOSTIC

    def __init__(self, coordinator: AiperDataUpdateCoordinator, entry_id: str, key: str) -> None:
        super().__init__(coordinator)
        self._attr_translation_key = key
        self._attr_unique_id = f"{entry_id}_{key}"
        self._attr_device_info = cloud_connection_device_info(entry_id)

    @property
    def available(self) -> bool:
        """Connection health stays meaningful even when a poll has failed."""
        return True


class AiperConnectionStateSensor(_AiperCloudSensorBase):
    """Current coarse state of the AWS IoT MQTT connection."""

    _attr_device_class = SensorDeviceClass.ENUM
    _attr_options = [str(state) for state in ConnectionState]

    def __init__(self, coordinator: AiperDataUpdateCoordinator, entry_id: str) -> None:
        super().__init__(coordinator, entry_id, "connection_state")

    @property
    def native_value(self) -> str:
        return str(self.coordinator.api.connection.state)

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        conn = self.coordinator.api.connection
        return {
            "reconnect_count": conn.reconnect_count,
            "connect_attempts": conn.connect_attempts,
            "credential_refresh_count": conn.credential_refresh_count,
            "credential_reject_count": conn.credential_reject_count,
            "last_error": conn.last_error,
        }


class AiperLastCloudUpdateSensor(_AiperCloudSensorBase):
    """Timestamp of the last successful coordinator poll."""

    _attr_device_class = SensorDeviceClass.TIMESTAMP

    def __init__(self, coordinator: AiperDataUpdateCoordinator, entry_id: str) -> None:
        super().__init__(coordinator, entry_id, "last_cloud_update")

    @property
    def native_value(self) -> Any:
        return self.coordinator.last_successful_update


class AiperEstimatedCleaningTimeSensor(AiperEntity, RestoreSensor):
    """Estimate active cleaning duration between authoritative cloud samples."""

    entity_description = ESTIMATED_CLEANING_TIME_DESCRIPTION

    def __init__(
        self,
        coordinator: AiperDataUpdateCoordinator,
        sn: str,
        device_data: DeviceState,
    ) -> None:
        """Initialize the estimated cleaning-time sensor."""
        super().__init__(coordinator, sn, ESTIMATED_CLEANING_TIME_DESCRIPTION.key, device_data)
        self._estimated_minutes = 0.0
        self._authoritative_runtime_hours: float | None = None
        self._unsub_tick: Callable[[], None] | None = None
        self._sync_with_coordinator()

    @property
    def native_value(self) -> float:
        """Return the locally advanced duration in minutes."""
        return round(self._estimated_minutes, 2)

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        """Describe the estimate and retain its restore anchor."""
        return {
            "estimated": True,
            "authoritative_source": "Current Cleaning Time",
            "authoritative_runtime_hours": self._authoritative_runtime_hours,
            "estimation_method": "Aiper cloud runtime plus local one-minute ticks while cleaning",
            "backend_lifecycle_caveat": (
                "If Aiper remains latched at Cleaning after the robot stops, this estimate can continue "
                "until a newer authoritative lifecycle report arrives."
            ),
        }

    async def async_added_to_hass(self) -> None:
        """Restore a running estimate and start its minute ticker when appropriate."""
        await super().async_added_to_hass()
        self.async_on_remove(self._stop_ticking)
        await self._async_restore_estimate()
        self._sync_with_coordinator()

    async def _async_restore_estimate(self) -> None:
        """Restore only when current normalized lifecycle still permits estimating."""
        snapshot = self._current_snapshot()
        if snapshot is None or not snapshot[0] or snapshot[1] is None or snapshot[1] < 0:
            return
        last_state = await self.async_get_last_state()
        if last_state is None:
            return
        try:
            restored_minutes = float(last_state.state)
            restored_anchor = float(last_state.attributes["authoritative_runtime_hours"])
        except (KeyError, TypeError, ValueError):
            return
        if not math.isfinite(restored_minutes) or not math.isfinite(restored_anchor):
            return
        if restored_anchor != snapshot[1]:
            return
        self._estimated_minutes = max(0.0, restored_minutes)
        self._authoritative_runtime_hours = max(0.0, restored_anchor)

    @callback
    def _handle_coordinator_update(self) -> None:
        """Apply lifecycle resets or changed authoritative runtime anchors."""
        self._sync_with_coordinator()
        super()._handle_coordinator_update()

    @callback
    def _async_handle_tick(self, _now: datetime) -> None:
        """Advance the estimate by one minute while its lifecycle remains active."""
        if self._advance_estimate_one_minute():
            self.async_write_ha_state()

    def _current_snapshot(self) -> tuple[bool, float | None] | None:
        """Return whether estimation is permitted and the raw runtime in hours."""
        if not self.coordinator.data or self._sn not in self.coordinator.data:
            return None
        data = self.coordinator.data[self._sn]
        running = data.get("running")
        charging = data.get("charging")
        status = data.get("status")
        runtime = data.get("runtime")
        active = bool(
            running is not None
            and running.value is True
            and charging is not None
            and charging.value is False
            and status is not None
            and str(status.value).casefold() == "cleaning"
        )
        try:
            runtime_hours = float(runtime.value) if runtime is not None and runtime.value is not None else None
        except (TypeError, ValueError):
            runtime_hours = None
        if runtime_hours is not None and not math.isfinite(runtime_hours):
            runtime_hours = None
        return active, runtime_hours

    def _sync_with_coordinator(self) -> bool:
        """Synchronize lifecycle and return whether a new raw anchor was applied."""
        snapshot = self._current_snapshot()
        if snapshot is None:
            self._reset_estimate()
            return False
        active, runtime_hours = snapshot
        if not active or runtime_hours is None or runtime_hours < 0:
            self._reset_estimate()
            return False
        if runtime_hours != self._authoritative_runtime_hours:
            self._authoritative_runtime_hours = runtime_hours
            self._estimated_minutes = float(round(runtime_hours * 60))
            self._restart_ticking()
            return True
        self._start_ticking()
        return False

    def _advance_estimate_one_minute(self) -> bool:
        """Advance once without letting an unchanged stale sample re-anchor it."""
        if self._sync_with_coordinator():
            return True
        snapshot = self._current_snapshot()
        if snapshot is None or not snapshot[0] or snapshot[1] is None or snapshot[1] < 0:
            return False
        self._estimated_minutes += 1
        return True

    def _reset_estimate(self) -> None:
        """Reset and stop when the current-cycle lifecycle is no longer active."""
        self._estimated_minutes = 0.0
        self._authoritative_runtime_hours = None
        self._stop_ticking()

    def _start_ticking(self) -> None:
        """Start a single minute ticker while the entity is attached to Home Assistant."""
        if self._unsub_tick is not None or self.hass is None:
            return
        self._unsub_tick = async_track_time_interval(
            self.hass,
            self._async_handle_tick,
            ESTIMATED_CLEANING_TIME_INTERVAL,
            name=f"Aiper estimated cleaning time {self._sn}",
            cancel_on_shutdown=True,
        )

    def _restart_ticking(self) -> None:
        """Restart the minute interval from a changed authoritative sample."""
        self._stop_ticking()
        self._start_ticking()

    @callback
    def _stop_ticking(self) -> None:
        """Cancel the active minute ticker."""
        if self._unsub_tick is None:
            return
        self._unsub_tick()
        self._unsub_tick = None
