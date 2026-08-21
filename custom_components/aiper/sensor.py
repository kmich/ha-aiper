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
from homeassistant.helpers.device_registry import DeviceInfo
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.event import async_track_time_interval
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from . import AiperConfigEntry
from .connection import ConnectionState
from .const import DOMAIN
from .coordinator import AiperDataUpdateCoordinator
from .helpers import cloud_connection_device_info, is_not_hydrocomm
from .profiles import Capability
from .state import DeviceState, state_has_capability


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
        include_fn=is_not_hydrocomm,
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
        include_fn=is_not_hydrocomm,
    ),
    # --- Cleaning history (REST) ---
    AiperSensorEntityDescription(
        key="total_cleanings",
        name="Total Cleanings",
        icon="mdi:counter",
        state_class=SensorStateClass.TOTAL_INCREASING,
        enabled_default=False,
        include_fn=is_not_hydrocomm,
    ),
    AiperSensorEntityDescription(
        key="total_cleaning_time",
        name="Total Cleaning Time",
        icon="mdi:timer-outline",
        native_unit_of_measurement="h",
        state_class=SensorStateClass.TOTAL_INCREASING,
        enabled_default=False,
        include_fn=is_not_hydrocomm,
    ),
    AiperSensorEntityDescription(
        key="total_cleaning_time_minutes",
        name="Total Cleaning Time Minutes",
        icon="mdi:timer-outline",
        native_unit_of_measurement="min",
        state_class=SensorStateClass.TOTAL_INCREASING,
        enabled_default=False,
        include_fn=is_not_hydrocomm,
    ),
    AiperSensorEntityDescription(
        key="last_cleaning_mode",
        name="Last Cleaning Mode",
        icon="mdi:map-marker-path",
        enabled_default=False,
        include_fn=is_not_hydrocomm,
    ),
    AiperSensorEntityDescription(
        key="last_cleaning_start",
        name="Last Cleaning Start",
        device_class=SensorDeviceClass.TIMESTAMP,
        entity_category=EntityCategory.DIAGNOSTIC,
        enabled_default=False,
        include_fn=is_not_hydrocomm,
    ),
    AiperSensorEntityDescription(
        key="last_cleaning_duration",
        name="Last Cleaning Duration",
        icon="mdi:timer",
        native_unit_of_measurement="min",
        state_class=SensorStateClass.MEASUREMENT,
        enabled_default=False,
        include_fn=is_not_hydrocomm,
    ),
    # --- HydroComm / HydroHub water quality (MQTT shadow) ---
    AiperSensorEntityDescription(
        key="ph",
        name="pH",
        icon="mdi:ph",
        state_class=SensorStateClass.MEASUREMENT,
        capability=Capability.WATER_QUALITY,
    ),
    AiperSensorEntityDescription(
        key="orp",
        name="ORP",
        icon="mdi:current-dc",
        native_unit_of_measurement="mV",
        state_class=SensorStateClass.MEASUREMENT,
        capability=Capability.WATER_QUALITY,
    ),
    AiperSensorEntityDescription(
        key="ec",
        name="EC",
        icon="mdi:flash",
        native_unit_of_measurement="uS/cm",
        state_class=SensorStateClass.MEASUREMENT,
        capability=Capability.WATER_QUALITY,
    ),
    AiperSensorEntityDescription(
        key="tds",
        name="TDS",
        icon="mdi:water-percent",
        native_unit_of_measurement="ppm",
        state_class=SensorStateClass.MEASUREMENT,
        capability=Capability.WATER_QUALITY,
    ),
    AiperSensorEntityDescription(
        key="rcl",
        name="Free Chlorine",
        icon="mdi:pool",
        native_unit_of_measurement="mg/L",
        state_class=SensorStateClass.MEASUREMENT,
        capability=Capability.WATER_QUALITY,
    ),
    AiperSensorEntityDescription(
        key="water_quality_score",
        name="Water Quality Score",
        icon="mdi:gauge",
        state_class=SensorStateClass.MEASUREMENT,
        capability=Capability.WATER_QUALITY,
    ),
    AiperSensorEntityDescription(
        key="water_quality_result",
        name="Water Quality Result",
        icon="mdi:water-check",
        entity_category=EntityCategory.DIAGNOSTIC,
        capability=Capability.WATER_QUALITY,
    ),
    AiperSensorEntityDescription(
        key="wqs_sample_time",
        name="Water Sample Time",
        icon="mdi:clock-outline",
        device_class=SensorDeviceClass.TIMESTAMP,
        entity_category=EntityCategory.DIAGNOSTIC,
        capability=Capability.WATER_QUALITY,
    ),
    AiperSensorEntityDescription(
        key="charge_type",
        name="Charge Type",
        icon="mdi:battery-charging",
        entity_category=EntityCategory.DIAGNOSTIC,
        capability=Capability.CHARGE_TYPE,
    ),
    AiperSensorEntityDescription(
        key="supply_voltage",
        name="Supply Voltage",
        icon="mdi:current-dc",
        native_unit_of_measurement="mV",
        entity_category=EntityCategory.DIAGNOSTIC,
        state_class=SensorStateClass.MEASUREMENT,
        capability=Capability.WATER_QUALITY,
    ),
    AiperSensorEntityDescription(
        key="solar_voltage",
        name="Solar Voltage",
        icon="mdi:solar-power-variant",
        native_unit_of_measurement="mV",
        entity_category=EntityCategory.DIAGNOSTIC,
        state_class=SensorStateClass.MEASUREMENT,
        capability=Capability.WATER_QUALITY,
    ),
    AiperSensorEntityDescription(
        key="light_level",
        name="Light Level",
        icon="mdi:brightness-5",
        native_unit_of_measurement="lx",
        entity_category=EntityCategory.DIAGNOSTIC,
        state_class=SensorStateClass.MEASUREMENT,
        capability=Capability.WATER_QUALITY,
    ),
    AiperSensorEntityDescription(
        key="work_current",
        name="Work Current",
        icon="mdi:current-dc",
        native_unit_of_measurement="mA",
        entity_category=EntityCategory.DIAGNOSTIC,
        state_class=SensorStateClass.MEASUREMENT,
        capability=Capability.WATER_QUALITY,
    ),
    AiperSensorEntityDescription(
        key="charge_current",
        name="Charge Current",
        icon="mdi:current-dc",
        native_unit_of_measurement="mA",
        entity_category=EntityCategory.DIAGNOSTIC,
        state_class=SensorStateClass.MEASUREMENT,
        capability=Capability.WATER_QUALITY,
    ),
    AiperSensorEntityDescription(
        key="calibration_status",
        name="Calibration Status",
        icon="mdi:tune",
        entity_category=EntityCategory.DIAGNOSTIC,
        capability=Capability.PROBE_STATUS,
    ),
    AiperSensorEntityDescription(
        key="probe_1_status",
        name="Probe 1 Status",
        icon="mdi:water-thermometer",
        entity_category=EntityCategory.DIAGNOSTIC,
        capability=Capability.PROBE_STATUS,
    ),
    AiperSensorEntityDescription(
        key="probe_2_status",
        name="Probe 2 Status",
        icon="mdi:water-thermometer",
        entity_category=EntityCategory.DIAGNOSTIC,
        capability=Capability.PROBE_STATUS,
    ),
    AiperSensorEntityDescription(
        key="probe_3_status",
        name="Probe 3 Status",
        icon="mdi:water-thermometer",
        entity_category=EntityCategory.DIAGNOSTIC,
        capability=Capability.PROBE_STATUS,
    ),
    AiperSensorEntityDescription(
        key="ultrasonic_status",
        name="Ultrasonic Sensor Status",
        icon="mdi:radar",
        entity_category=EntityCategory.DIAGNOSTIC,
        capability=Capability.PROBE_STATUS,
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
        capability=Capability.ROLLER_BRUSH,
    ),
    AiperSensorEntityDescription(
        key="micromesh_filter",
        name="MicroMesh Filter",
        icon="mdi:percent",
        native_unit_of_measurement=PERCENTAGE,
        entity_category=EntityCategory.DIAGNOSTIC,
        state_class=SensorStateClass.MEASUREMENT,
        capability=Capability.MICROMESH_FILTER,
    ),
    AiperSensorEntityDescription(
        key="caterpillar_tread",
        name="Caterpillar Tread",
        icon="mdi:percent",
        native_unit_of_measurement=PERCENTAGE,
        entity_category=EntityCategory.DIAGNOSTIC,
        state_class=SensorStateClass.MEASUREMENT,
        capability=Capability.CATERPILLAR_TREAD,
    ),
    AiperSensorEntityDescription(
        key="propeller",
        name="Propeller",
        icon="mdi:percent",
        native_unit_of_measurement=PERCENTAGE,
        entity_category=EntityCategory.DIAGNOSTIC,
        state_class=SensorStateClass.MEASUREMENT,
        capability=Capability.PROPELLER,
    ),
)

ESTIMATED_CLEANING_TIME_DESCRIPTION = AiperSensorEntityDescription(
    key="estimated_cleaning_time",
    name="Estimated Cleaning Time",
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
        self._attr_device_info = _device_info(sn, device_data)

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


def _device_info(sn: str, device_data: DeviceState) -> DeviceInfo:
    """Build shared Home Assistant device information."""
    device_info = device_data["device_info"]
    device_info_attrs = device_info.attributes
    return DeviceInfo(
        identifiers={(DOMAIN, sn)},
        name=str(device_info.value or f"Aiper {sn}"),
        manufacturer="Aiper",
        model=device_info_attrs.get("model"),
        serial_number=sn,
        sw_version=device_info_attrs.get("sw_version"),
    )


class AiperEstimatedCleaningTimeSensor(CoordinatorEntity[AiperDataUpdateCoordinator], RestoreSensor):
    """Estimate active cleaning duration between authoritative cloud samples."""

    entity_description = ESTIMATED_CLEANING_TIME_DESCRIPTION
    _attr_has_entity_name = True

    def __init__(
        self,
        coordinator: AiperDataUpdateCoordinator,
        sn: str,
        device_data: DeviceState,
    ) -> None:
        """Initialize the estimated cleaning-time sensor."""
        super().__init__(coordinator)
        self._sn = sn
        self._attr_unique_id = f"{sn}_{self.entity_description.key}"
        self._attr_device_info = _device_info(sn, device_data)
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

    @property
    def available(self) -> bool:
        """Return whether the coordinator still provides this device."""
        return bool(super().available and self.coordinator.data and self._sn in self.coordinator.data)

    async def async_added_to_hass(self) -> None:
        """Restore a running estimate and start its minute ticker when appropriate."""
        await super().async_added_to_hass()
        self.async_on_remove(self._stop_ticking)
        await self._async_restore_estimate()
        self._sync_with_coordinator()

    async def _async_restore_estimate(self) -> None:
        """Restore only when current normalized lifecycle still permits estimating."""
        snapshot = self._current_snapshot()
        if snapshot is None or not snapshot[0] or snapshot[1] is None or snapshot[1] <= 0:
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
        if not active or runtime_hours is None or runtime_hours <= 0:
            self._reset_estimate()
            return False
        if runtime_hours != self._authoritative_runtime_hours:
            self._authoritative_runtime_hours = runtime_hours
            self._estimated_minutes = runtime_hours * 60
            self._restart_ticking()
            return True
        self._start_ticking()
        return False

    def _advance_estimate_one_minute(self) -> bool:
        """Advance once without letting an unchanged stale sample re-anchor it."""
        if self._sync_with_coordinator():
            return True
        snapshot = self._current_snapshot()
        if snapshot is None or not snapshot[0] or snapshot[1] is None or snapshot[1] <= 0:
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
