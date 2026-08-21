"""Tests for the capability-gated estimated cleaning-time sensor."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from typing import cast
from unittest.mock import AsyncMock

import pytest
from homeassistant.components.sensor import RestoreSensor
from homeassistant.components.sensor.const import SensorDeviceClass
from homeassistant.const import UnitOfTime
from homeassistant.core import State

from custom_components.aiper.coordinator import AiperDataUpdateCoordinator
from custom_components.aiper.sensor import ESTIMATED_CLEANING_TIME_INTERVAL, AiperEstimatedCleaningTimeSensor
from custom_components.aiper.state import DeviceState, normalize_device_state


@dataclass
class FakeCoordinator:
    """Minimal coordinator for estimated-duration entity tests."""

    data: dict[str, DeviceState]
    last_update_success: bool = True

    def async_add_listener(self, update_callback, context=None):
        return lambda: None

    async def async_request_refresh(self) -> None:
        return None


def _normalized_device(
    *,
    model: str = "Scuba_S1_2025",
    status: int = 1,
    runtime_minutes: int = 12,
) -> DeviceState:
    return normalize_device_state(
        {
            "sn": "SN123",
            "name": "Pool Robot",
            "model": model,
            "machineStatus": status,
            "runTime": runtime_minutes,
            "online": status == 1,
        }
    )


def _entity(device: DeviceState) -> tuple[AiperEstimatedCleaningTimeSensor, FakeCoordinator]:
    coordinator = FakeCoordinator(data={"SN123": device})
    entity = AiperEstimatedCleaningTimeSensor(
        cast(AiperDataUpdateCoordinator, coordinator),
        "SN123",
        device,
    )
    return entity, coordinator


def test_first_creation_while_running_anchors_without_backfill() -> None:
    """Mid-cycle creation seeds from raw runtime and invents no earlier time."""
    entity, _coordinator = _entity(_normalized_device(runtime_minutes=12))

    assert isinstance(entity, RestoreSensor)
    assert entity._attr_unique_id == "SN123_estimated_cleaning_time"
    assert entity.entity_description.native_unit_of_measurement == UnitOfTime.MINUTES
    assert entity.entity_description.device_class == SensorDeviceClass.DURATION
    assert ESTIMATED_CLEANING_TIME_INTERVAL.total_seconds() == 60
    assert entity.native_value == 12

    assert entity._advance_estimate_one_minute() is True
    assert entity.native_value == 13


def test_estimate_ticks_once_per_minute_while_cleaning() -> None:
    """Each timer callback advances exactly one minute from the raw anchor."""
    entity, _coordinator = _entity(_normalized_device(runtime_minutes=12))

    assert entity._advance_estimate_one_minute() is True
    assert entity._advance_estimate_one_minute() is True

    assert entity.native_value == 14


def test_changed_authoritative_runtime_corrects_and_reanchors() -> None:
    """A changed cloud runtime corrects the estimate immediately."""
    entity, coordinator = _entity(_normalized_device(runtime_minutes=12))
    entity._advance_estimate_one_minute()
    entity._advance_estimate_one_minute()
    assert entity.native_value == 14

    coordinator.data["SN123"] = _normalized_device(runtime_minutes=8)

    assert entity._sync_with_coordinator() is True
    assert entity.native_value == pytest.approx(7.8)
    assert entity._advance_estimate_one_minute() is True
    assert entity.native_value == pytest.approx(8.8)


def test_unchanged_stale_runtime_does_not_reanchor() -> None:
    """A repeated stale REST snapshot must not suppress local progression."""
    entity, coordinator = _entity(_normalized_device(runtime_minutes=12))
    entity._advance_estimate_one_minute()
    assert entity.native_value == 13

    coordinator.data["SN123"] = _normalized_device(runtime_minutes=12)

    assert entity._sync_with_coordinator() is False
    assert entity.native_value == 13
    assert entity._advance_estimate_one_minute() is True
    assert entity.native_value == 14


def test_zero_runtime_resets_and_stops_progression() -> None:
    """An authoritative current-cycle reset returns the estimate to zero."""
    entity, coordinator = _entity(_normalized_device(runtime_minutes=12))
    entity._advance_estimate_one_minute()

    coordinator.data["SN123"] = _normalized_device(runtime_minutes=0)

    assert entity._sync_with_coordinator() is False
    assert entity.native_value == 0
    assert entity._advance_estimate_one_minute() is False
    assert entity.native_value == 0


def test_stopped_lifecycle_resets_and_stops_progression() -> None:
    """A non-running lifecycle resets even if an old raw value was nonzero."""
    entity, coordinator = _entity(_normalized_device(runtime_minutes=12))
    entity._advance_estimate_one_minute()

    coordinator.data["SN123"] = _normalized_device(status=10, runtime_minutes=12)

    assert entity._sync_with_coordinator() is False
    assert entity.native_value == 0
    assert entity._advance_estimate_one_minute() is False


def test_charging_resets_and_never_ticks() -> None:
    """Charging is authoritative and disables the local estimator."""
    entity, coordinator = _entity(_normalized_device(runtime_minutes=12))
    entity._advance_estimate_one_minute()

    coordinator.data["SN123"] = _normalized_device(status=2, runtime_minutes=19)

    assert entity._sync_with_coordinator() is False
    assert entity.native_value == 0
    assert entity._advance_estimate_one_minute() is False
    assert entity.native_value == 0


@pytest.mark.asyncio
async def test_restart_while_already_running_restores_and_resumes() -> None:
    """Restart restoration resumes only from a matching authoritative anchor."""
    entity, _coordinator = _entity(_normalized_device(runtime_minutes=12))
    entity.async_get_last_state = AsyncMock(  # type: ignore[method-assign]
        return_value=State(
            "sensor.scuba_s1_estimated_cleaning_time",
            "15",
            {
                "authoritative_runtime_hours": 0.2,
                "unit_of_measurement": "min",
            },
            last_changed=datetime.now(UTC),
            last_reported=datetime.now(UTC),
            last_updated=datetime.now(UTC),
        )
    )

    await entity._async_restore_estimate()
    assert entity._sync_with_coordinator() is False
    assert entity.native_value == 15

    assert entity._advance_estimate_one_minute() is True
    assert entity.native_value == 16


@pytest.mark.asyncio
async def test_restart_restore_yields_to_changed_authoritative_sample() -> None:
    """A newer raw sample wins over a restored estimate immediately."""
    entity, _coordinator = _entity(_normalized_device(runtime_minutes=18))
    entity.async_get_last_state = AsyncMock(  # type: ignore[method-assign]
        return_value=State(
            "sensor.scuba_s1_estimated_cleaning_time",
            "15",
            {"authoritative_runtime_hours": 0.2},
            last_changed=datetime.now(UTC),
            last_reported=datetime.now(UTC),
            last_updated=datetime.now(UTC),
        )
    )

    await entity._async_restore_estimate()

    assert entity._sync_with_coordinator() is True
    assert entity.native_value == 18
