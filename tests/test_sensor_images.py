"""Tests for sensor entity images."""

from __future__ import annotations

from types import SimpleNamespace
from typing import cast

from custom_components.aiper.coordinator import AiperDataUpdateCoordinator
from custom_components.aiper.sensor import SENSOR_DESCRIPTIONS, AiperSensor
from custom_components.aiper.state import normalize_device_state


def _description(key: str):
    return next(description for description in SENSOR_DESCRIPTIONS if description.key == key)


def test_status_sensor_uses_device_model_image_url() -> None:
    """The primary status sensor should carry the device model image."""
    sensor = AiperSensor.__new__(AiperSensor)
    sensor.entity_description = _description("status")
    sensor._sn = "SN123"
    sensor.coordinator = cast(
        AiperDataUpdateCoordinator,
        SimpleNamespace(
            data={"SN123": normalize_device_state({"deviceModelUrl": "https://static.example.test/surfer-s2.png"})}
        ),
    )

    assert sensor.entity_picture == "https://static.example.test/surfer-s2.png"


def test_non_status_sensors_do_not_duplicate_device_model_image_url() -> None:
    """Avoid placing the same picture on every entity for a device."""
    sensor = AiperSensor.__new__(AiperSensor)
    sensor.entity_description = _description("battery")
    sensor._sn = "SN123"
    sensor.coordinator = cast(
        AiperDataUpdateCoordinator,
        SimpleNamespace(
            data={"SN123": normalize_device_state({"deviceModelUrl": "https://static.example.test/surfer-s2.png"})}
        ),
    )

    assert sensor.entity_picture is None
