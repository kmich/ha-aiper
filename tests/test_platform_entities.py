"""Tests for per-family platform entity publication."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, cast

import pytest
from homeassistant.config_entries import ConfigEntry
from homeassistant.const import EntityCategory
from homeassistant.core import HomeAssistant
from pytest_homeassistant_custom_component.common import MockConfigEntry

from custom_components.aiper import AiperConfigEntry, AiperRuntimeData, binary_sensor, button, select, sensor, switch
from custom_components.aiper.api import AiperApi
from custom_components.aiper.const import DOMAIN
from custom_components.aiper.controller import AiperDeviceController
from custom_components.aiper.coordinator import AiperDataUpdateCoordinator
from custom_components.aiper.profiles import derive_device_profile
from custom_components.aiper.state import normalize_device_state


@dataclass
class FakeApi:
    """Minimal API object needed by entity availability attributes."""

    shadow_requested: list[str] | None = None

    def is_mqtt_connected(self) -> bool:
        return True

    async def request_shadow(self, sn: str) -> bool:
        if self.shadow_requested is None:
            self.shadow_requested = []
        self.shadow_requested.append(sn)
        return True


@dataclass
class FakeCoordinator:
    """Minimal coordinator carrying normalized device data."""

    data: dict[str, dict[str, Any]]
    api: FakeApi
    last_update_success: bool = True
    pending_targets: dict[tuple[str, str], Any] | None = None
    metadata_refreshed: list[str] | None = None
    command_state_cleared: list[str] | None = None

    def get_pending_command_target(self, sn: str, kind: str) -> Any:
        return (self.pending_targets or {}).get((sn, kind))

    async def async_refresh_metadata(self, sn: str) -> None:
        if self.metadata_refreshed is None:
            self.metadata_refreshed = []
        self.metadata_refreshed.append(sn)

    def clear_command_state(self, sn: str) -> None:
        if self.command_state_cleared is None:
            self.command_state_cleared = []
        self.command_state_cleared.append(sn)


def _profiled_device(device: dict[str, Any]) -> dict[str, Any]:
    profile = derive_device_profile(device)
    out = dict(device)
    out["capabilities"] = [cap.value for cap in profile.capabilities]
    out["mode_map"] = profile.mode_map
    return normalize_device_state(out)


def _hass_with_device(hass: HomeAssistant, device: dict[str, Any]) -> tuple[ConfigEntry, FakeCoordinator]:
    coordinator = FakeCoordinator(data={"SN123": _profiled_device(device)}, api=FakeApi())
    entry = MockConfigEntry(domain=DOMAIN, entry_id="entry-1", options={})
    entry.runtime_data = AiperRuntimeData(
        api=cast(AiperApi, coordinator.api),
        controller=cast(
            AiperDeviceController, AiperDeviceController(cast(Any, coordinator.api), cast(Any, coordinator))
        ),
        coordinator=cast(AiperDataUpdateCoordinator, coordinator),
        unsub_keepalive=None,
    )
    return entry, coordinator


async def _setup_platform(platform_module, hass: HomeAssistant, entry: AiperConfigEntry) -> list[Any]:
    entities: list[Any] = []

    def add_entities(new_entities) -> None:
        entities.extend(new_entities)

    await platform_module.async_setup_entry(hass, entry, add_entities)
    return entities


def _keys(entities: list[Any]) -> set[str]:
    return {entity.entity_description.key for entity in entities}


def _select_keys(entities: list[Any]) -> set[str]:
    return {entity._key for entity in entities}


def _unique_ids(entities: list[Any]) -> set[str]:
    return {entity.unique_id for entity in entities}


def _entity_by_key(entities: list[Any], key: str) -> Any:
    return next(entity for entity in entities if entity.entity_description.key == key)


@pytest.mark.asyncio
async def test_surfer_entity_publication_is_verified_and_not_scuba_specific(hass: HomeAssistant) -> None:
    """Surfer publishes verified controls without Scuba-style mode select."""
    entry, _coordinator = _hass_with_device(
        hass,
        {
            "sn": "SN123",
            "name": "Surfer S2",
            "model": "Surfer_S2",
            "battLevel": 80,
            "machineStatus": 129,
            "supported_mode_ids": [1, 2, 3, 4, 5],
            "consumables": [
                {
                    "key": "propeller",
                    "name": "Propeller",
                    "percent_left": 90,
                    "remaining_hours": 100,
                    "last_replacement": "2026-05-01T00:00:00+00:00",
                },
                {"name": "Roller Brush", "remaining_hours": 10, "percent_left": 50},
                {"name": "MicroMesh Filter", "remaining_hours": 20, "percent_left": 75},
                {"name": "Caterpillar Tread", "remaining_hours": 30, "percent_left": 80},
            ],
            "runTime": 1673,
            "mode": 5,
        },
    )

    sensor_entities = await _setup_platform(sensor, hass, entry)
    binary_entities = await _setup_platform(binary_sensor, hass, entry)
    select_entities = await _setup_platform(select, hass, entry)
    switch_entities = await _setup_platform(switch, hass, entry)

    assert {"status", "battery", "mode", "propeller", "micromesh_filter"}.issubset(_keys(sensor_entities))
    assert "roller_brush" not in _keys(sensor_entities)
    assert "caterpillar_tread" not in _keys(sensor_entities)
    propeller = _entity_by_key(sensor_entities, "propeller")
    assert propeller.native_value == 90
    assert propeller.extra_state_attributes == {
        "consumable_key": "propeller",
        "consumable_name": "Propeller",
        "remaining_hours": 100,
        "last_replacement": "2026-05-01T00:00:00+00:00",
    }
    micromesh_filter = _entity_by_key(sensor_entities, "micromesh_filter")
    assert micromesh_filter.native_value == 75
    assert micromesh_filter.extra_state_attributes == {
        "consumable_name": "MicroMesh Filter",
        "remaining_hours": 20,
    }
    runtime = _entity_by_key(sensor_entities, "runtime")
    assert runtime.entity_description.name == "Current Cleaning Time"
    assert runtime.unique_id == "SN123_runtime"
    assert runtime.native_value == 16.73
    assert "running" in _keys(binary_entities)
    assert "solar_charging" in _keys(binary_entities)
    assert _entity_by_key(binary_entities, "running").is_on is True
    assert _entity_by_key(sensor_entities, "status").native_value == "Cleaning"
    assert _entity_by_key(sensor_entities, "mode").native_value == "Scheduled"
    assert select_entities == []
    assert _unique_ids(switch_entities) == {"SN123_running"}
    assert switch_entities[0].name == "Surfer S2 Running"
    assert switch_entities[0].is_on is True

    _coordinator.data["SN123"] = _profiled_device(
        {
            "sn": "SN123",
            "name": "Surfer S2",
            "model": "Surfer_S2",
            "battLevel": 80,
            "machineStatus": 0,
            "supported_mode_ids": [1, 2, 3, 4, 5],
            "runTime": 1673,
            "mode": 5,
        }
    )
    assert _entity_by_key(binary_entities, "running").is_on is False
    assert _entity_by_key(sensor_entities, "status").native_value == "Idle"
    assert _entity_by_key(sensor_entities, "mode").native_value == "Off"
    assert switch_entities[0].is_on is False

    _coordinator.pending_targets = {("SN123", "running"): True}
    assert switch_entities[0].is_on is True

    _coordinator.data["SN123"] = _profiled_device(
        {
            "sn": "SN123",
            "name": "Surfer S2",
            "model": "Surfer_S2",
            "machineStatus": 128,
        }
    )
    _coordinator.pending_targets = {("SN123", "running"): False}
    assert switch_entities[0].is_on is False


@pytest.mark.asyncio
async def test_scuba_entity_publication_uses_scuba_capabilities(hass: HomeAssistant) -> None:
    """Scuba publishes Scuba mode/clean-path and maintenance entities."""
    entry, _coordinator = _hass_with_device(
        hass,
        {
            "sn": "SN123",
            "name": "Scuba X1",
            "model": "Scuba_X1",
            "battLevel": 80,
            "machineStatus": 1,
            "supported_mode_ids": [1, 2, 3, 4, 5],
            "consumables": [
                {"name": "Roller Brush", "remaining_hours": 10, "percent_left": 50},
                {"name": "MicroMesh Filter", "remaining_hours": 20, "percent_left": 75},
                {"name": "Caterpillar Tread", "remaining_hours": 30, "percent_left": 80},
            ],
            "temp": 23,
            "in_water": 1,
            "total_cleanings": 12,
            "total_cleaning_hours": 6.5,
            "last_cleaning_mode": "Floor",
            "last_cleaning_duration_min": 42,
        },
    )

    sensor_entities = await _setup_platform(sensor, hass, entry)
    binary_entities = await _setup_platform(binary_sensor, hass, entry)
    select_entities = await _setup_platform(select, hass, entry)
    switch_entities = await _setup_platform(switch, hass, entry)

    assert {
        "temperature",
        "roller_brush",
        "micromesh_filter",
        "caterpillar_tread",
        "propeller",
        "total_cleanings",
        "total_cleaning_time",
        "last_cleaning_mode",
        "last_cleaning_duration",
    }.issubset(_keys(sensor_entities))
    assert _entity_by_key(sensor_entities, "propeller").available is False
    roller_brush = _entity_by_key(sensor_entities, "roller_brush")
    assert roller_brush.native_value == 50
    assert roller_brush.extra_state_attributes == {
        "consumable_name": "Roller Brush",
        "remaining_hours": 10,
    }
    device_family = _entity_by_key(sensor_entities, "device_family")
    assert device_family.native_value == "scuba"
    assert _entity_by_key(sensor_entities, "total_cleanings").native_value == 12
    assert _entity_by_key(sensor_entities, "total_cleaning_time").native_value == 6.5
    assert _entity_by_key(sensor_entities, "last_cleaning_mode").native_value == "Floor"
    assert _entity_by_key(sensor_entities, "last_cleaning_duration").native_value == 42.0
    diagnostic_entities = [
        entity for entity in sensor_entities if entity.entity_description.entity_category == EntityCategory.DIAGNOSTIC
    ]
    assert diagnostic_entities
    assert all(
        entity._attr_entity_registry_enabled_default is False
        for entity in diagnostic_entities
        if entity.entity_description.key != "last_cleaning_start"
    )
    assert "mode" in _keys(sensor_entities)
    assert _entity_by_key(sensor_entities, "mode").available is False
    assert "in_water" in _keys(binary_entities)
    assert "running" in _keys(binary_entities)
    assert _entity_by_key(binary_entities, "running").is_on is True
    assert _select_keys(select_entities) == {"mode_selection", "clean_path"}
    mode_select = next(entity for entity in select_entities if entity._key == "mode_selection")
    assert mode_select.current_option == "Floor"
    assert switch_entities == []


@pytest.mark.asyncio
async def test_shark_entity_publication_keeps_consumables_unavailable_without_values(hass: HomeAssistant) -> None:
    """Shark publishes applicable consumable entities without inventing values."""
    entry, _coordinator = _hass_with_device(
        hass,
        {
            "sn": "SN123",
            "name": "Shark",
            "model": "Shark_X",
            "battLevel": 80,
            "machineStatus": 1,
        },
    )

    sensor_entities = await _setup_platform(sensor, hass, entry)
    binary_entities = await _setup_platform(binary_sensor, hass, entry)
    select_entities = await _setup_platform(select, hass, entry)
    switch_entities = await _setup_platform(switch, hass, entry)

    assert {"status", "battery", "warning"}.issubset(_keys(sensor_entities))
    assert "temperature" not in _keys(sensor_entities)
    assert {"propeller", "micromesh_filter", "roller_brush", "caterpillar_tread"}.issubset(_keys(sensor_entities))
    assert _entity_by_key(sensor_entities, "propeller").available is False
    assert _entity_by_key(sensor_entities, "micromesh_filter").available is False
    assert _entity_by_key(sensor_entities, "roller_brush").available is False
    assert _entity_by_key(sensor_entities, "caterpillar_tread").available is False
    assert "mode" in _keys(sensor_entities)
    assert _entity_by_key(sensor_entities, "mode").available is False
    assert "in_water" not in _keys(binary_entities)
    assert "running" in _keys(binary_entities)
    assert _entity_by_key(binary_entities, "running").is_on is True
    assert select_entities == []
    assert switch_entities == []


@pytest.mark.asyncio
async def test_button_entities_are_safe_device_actions(hass: HomeAssistant) -> None:
    """Buttons expose safe refresh and local command-state actions."""
    entry, coordinator = _hass_with_device(
        hass,
        {
            "sn": "SN123",
            "name": "Scuba X1",
            "model": "Scuba_X1",
            "battLevel": 80,
            "machineStatus": 1,
        },
    )

    button_entities = await _setup_platform(button, hass, entry)

    assert _keys(button_entities) == {"refresh_shadow", "refresh_metadata", "clear_command_state"}
    assert _unique_ids(button_entities) == {
        "SN123_refresh_shadow",
        "SN123_refresh_metadata",
        "SN123_clear_command_state",
    }
    clear_command_state = _entity_by_key(button_entities, "clear_command_state")
    assert clear_command_state.entity_description.entity_category == EntityCategory.DIAGNOSTIC
    assert clear_command_state._attr_entity_registry_enabled_default is False

    await _entity_by_key(button_entities, "refresh_shadow").async_press()
    await _entity_by_key(button_entities, "refresh_metadata").async_press()
    await clear_command_state.async_press()

    assert coordinator.api.shadow_requested == ["SN123"]
    assert coordinator.metadata_refreshed == ["SN123"]
    assert coordinator.command_state_cleared == ["SN123"]


@pytest.mark.asyncio
async def test_hydrocomm_entity_publication_uses_monitor_capabilities(hass: HomeAssistant) -> None:
    """HydroComm publishes water-quality monitor entities without cleaner controls."""
    entry, _coordinator = _hass_with_device(
        hass,
        {
            "sn": "SN123",
            "name": "HydroComm",
            "model": "HydroComm",
            "deviceType": "4",
            "online": True,
            "battLevel": 80,
            "machineStatus": 2,
            "temp": 27.5,
            "ph": 7.4,
            "orp": 668,
            "ec": 1220,
            "tds": 450,
            "rcl": 1.1,
            "water_quality_score": 91,
            "probe_1_status": "Installed",
        },
    )

    sensor_entities = await _setup_platform(sensor, hass, entry)
    binary_entities = await _setup_platform(binary_sensor, hass, entry)
    select_entities = await _setup_platform(select, hass, entry)
    switch_entities = await _setup_platform(switch, hass, entry)

    sensor_keys = _keys(sensor_entities)
    assert {
        "status",
        "battery",
        "temperature",
        "ph",
        "orp",
        "ec",
        "tds",
        "rcl",
        "water_quality_score",
        "probe_1_status",
    }.issubset(sensor_keys)
    assert "mode" not in sensor_keys
    assert "runtime" not in sensor_keys
    assert "total_cleanings" not in sensor_keys
    assert "roller_brush" not in sensor_keys
    assert _entity_by_key(sensor_entities, "status").native_value == "Charging"
    assert _entity_by_key(sensor_entities, "ph").native_value == 7.4

    assert "online" in _keys(binary_entities)
    assert "charging" in _keys(binary_entities)
    assert "running" not in _keys(binary_entities)
    assert _entity_by_key(binary_entities, "charging").is_on is True
    assert select_entities == []
    assert switch_entities == []
