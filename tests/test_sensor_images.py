"""Tests for sensor entity images."""

from __future__ import annotations

from custom_components.aiper.sensor import SENSOR_DESCRIPTIONS, AiperSensor
from custom_components.aiper.state import normalize_device_state
from tests.coordinator_factory import make_coordinator


def _sensor(key: str) -> AiperSensor:
    description = next(description for description in SENSOR_DESCRIPTIONS if description.key == key)
    coordinator = make_coordinator(
        data={"SN123": normalize_device_state({"deviceModelUrl": "https://static.example.test/surfer-s2.png"})}
    )
    return AiperSensor(coordinator, description, "SN123", coordinator.data["SN123"])


def test_status_sensor_uses_device_model_image_url() -> None:
    """The primary status sensor should carry the device model image."""
    assert _sensor("status").entity_picture == "https://static.example.test/surfer-s2.png"


def test_non_status_sensors_do_not_duplicate_device_model_image_url() -> None:
    """Avoid placing the same picture on every entity for a device."""
    assert _sensor("battery").entity_picture is None
