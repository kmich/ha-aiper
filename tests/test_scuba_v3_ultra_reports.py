"""Scuba V3 Ultra: read-only entities from the other ``*Report`` shadow sections.

``SHADOW`` is the full ``state.reported`` of a captured ``shadow/get/accepted``
from a Scuba V3 Ultra (main firmware V1.1.16.4, Americas region) on its
charger; serials and the Wi-Fi name are replaced.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any
from zoneinfo import ZoneInfo

import pytest
from homeassistant.const import EntityCategory
from homeassistant.core import HomeAssistant
from homeassistant.util import dt as dt_util

from custom_components.aiper import binary_sensor, sensor
from custom_components.aiper.profiles import Capability, derive_device_profile
from custom_components.aiper.report_sections import next_scheduled_clean, report_entity_states
from custom_components.aiper.state import EntityState, normalize_device_state
from tests.coordinator_factory import BaseFakeApi, make_coordinator
from tests.test_platform_entities import _entity_by_key, _hass_with_device, _keys, _setup_platform

SN = "SN1234567890"
PACIFIC = ZoneInfo("America/Los_Angeles")
# Capture time: Sunday 2026-10-25 15:01 PDT.
NOW = datetime(2026, 10, 25, 15, 1, 59, tzinfo=PACIFIC)

SHADOW: dict[str, Any] = {
    "NetStat": {"online": 1, "ble": 2},
    "LogInfoReport": {"logVersion": "release"},
    "GetWorkModeReport": {
        "working": 0,
        "ts": 1792964984824,
        "task": {
            "nameID": "Memory_1032454089",
            "startTime": "14:49:43",
            "taskType": 4,
            "aiType": 0,
            "cleanMode": 0,
            "cleanIntensity": 1,
            "cleanAreas": [{"area": 1, "count": 1}],
        },
    },
    "EntryPointReport": {"type": 0},
    "VoiceBroadcastReport": {"enable": 1, "language": 2, "timbre": 1, "volume": 76},
    "LifeTimeReport": {"battery": 99},
    "SuperEcoReport": {"mode": 2},
    "SpeedReport": {"lineSpeed": 0, "angularSpeed": 45, "pumpSpeedSec": 1000},
    "MotorThresholdReport": {
        "driveMotor": 2.5,
        "pumpMotor": 3.8,
        "turnMotor": 0.9,
        "airMotor": 1.2,
        "pulsatorMotor": 0.45,
    },
    "LittleWaterReport": {"mode": 2},
    "AngoEnableReport": {"mode": 1},
    "AirBagReport": {"inflatableTime": 50, "deflatedTime": 50},
    "MultiBottomReport": {"mode": 1},
    "BottomRunModeReport": {"mode": 2},
    "SurfaceWaterReport": {
        "aiSurfaceTime": 180,
        "aiBottomTime": 90,
        "workTime": 180,
        "distanceSide": 1,
        "circleCount": 0,
        "lineCount": 0,
    },
    "AutoWorkReport": {"mode": 2},
    "WaterGoverReport": {"mode": 2},
    "AutomationTaskSettingReport": {"weather": False, "adapt": False, "habit": False},
    "InspectionSettingReport": {"camera": True},
    "AdjustButtonReport": {"mode": 1},
    "OpInfoReport": {
        "wifiRssi": -78,
        "batCurrent": 4,
        "batVoltage": 23060,
        "batTemperature": 22,
        "batQuantity": 62,
        "status": 2,
        "wifiName": "<redacted>",
    },
    "InwaterReport": {"inWater": 1},
    "GetRubbishBoxStatusReport": {"blockage": 0, "inPlace": 0, "health": 0},
    "WQSReport": {"temp": 25},
    "AirBagStatusReport": {"status": 0},
    "TaskEstimateReport": {
        "cleanTime": [270, 270, 120, 100, 100, 100, 62, 62],
        "cleanArea": [344, 344.5, 1100, 295, 239.5, 239.5, 239.5, 909, 44.5, 60.6],
    },
    "OtaStatusReport": {
        "error": 0,
        "msg": "ota success",
        "progress": 100,
        "sn": "<redacted>",
        "state": 3,
        "version": "V1.1.16.4",
        "ts": "1791932576320",
    },
    "OtaResultReport": {
        "base": {"state": 1, "version": "1.4.41"},
        "cloudver": "V1.1.16.4",
        "computing": {"state": 1, "version": "1.2.12"},
        "controlLogId": 0,
        "error": 0,
        "led": {"state": 1, "version": "1.3.20"},
        "msg": "",
        "power": {"state": 1, "version": "1.4.25"},
        "sn": "<redacted>",
        "socver": {"state": 1, "version": "1.1.16.4"},
        "state": 1,
        "ts": "1791932576371",
    },
    "GetAlarmReport": {"code": [], "ts": "1792965231155"},
    "PoolInfoReport": {"poolArea": 0, "poolVolume": 0},
    "FinishTaskReport": {
        "task": {
            "nameID": "Custom_1792958748713",
            "taskType": 2,
            "aiType": 0,
            "cleanMode": 0,
            "cleanIntensity": 1,
            "cleanAreas": [{"area": 1, "count": 1}],
            "cleanResult": 4,
        },
        "ts": "1792964983406",
    },
    "AutomationTaskReport": {
        "autoTasks": [
            {
                "userSelect": 0,
                "nameID": "automation_2_1021768298",
                "weekday": 2,
                "date": "2026-10-27",
                "startTime": "11:52:00",
                "aiType": 0,
                "cleanMode": 0,
                "cleanIntensity": 2,
                "waterGover": 2,
                "cleanAreas": [{"area": 2, "count": 1}],
            },
            {
                "userSelect": 0,
                "nameID": "automation_3_1021768298",
                "weekday": 4,
                "date": "2026-10-29",
                "startTime": "11:52:00",
                "aiType": 0,
                "cleanMode": 0,
                "cleanIntensity": 2,
                "waterGover": 2,
                "cleanAreas": [{"area": 3, "count": 1}],
            },
            {
                "userSelect": 0,
                "nameID": "automation_4_1025934488",
                "weekday": 6,
                "date": "2026-10-31",
                "startTime": "11:52:00",
                "aiType": 0,
                "cleanMode": 0,
                "cleanIntensity": 2,
                "waterGover": 2,
                "cleanAreas": [{"area": 2, "count": 1}],
            },
        ]
    },
}

REPORT_SENSOR_KEYS = {description.key for description in sensor.REPORT_SENSOR_DESCRIPTIONS}
REPORT_BINARY_KEYS = {description.key for description in binary_sensor.REPORT_BINARY_SENSOR_DESCRIPTIONS}


def _states() -> dict[str, EntityState]:
    return report_entity_states(SHADOW, NOW, PACIFIC)


def test_captured_shadow_maps_every_report_entity() -> None:
    states = _states()

    # Every described entity gets a value from the captured shadow (main_version
    # and ota_state are existing sensors the OtaStatusReport also fills).
    assert set(states) == REPORT_SENSOR_KEYS | REPORT_BINARY_KEYS | {"main_version", "ota_state"}
    values = {key: state.value for key, state in states.items()}
    assert values == {
        "next_scheduled_clean": datetime(2026, 10, 27, 11, 52, tzinfo=PACIFIC),
        "schedule_weather": False,
        "schedule_adapt": False,
        "schedule_habit": False,
        "battery_health": 99,
        "battery_voltage": 23.06,
        "battery_current": 4.0,
        "battery_power": 0.09,
        "battery_temperature": 22.0,
        "debris_basket_blocked": False,
        "debris_basket_in_place": False,
        "debris_basket_health": 0,
        "cleaning_estimates": "270, 270, 120, 100, 100, 100, 62, 62",
        "last_cleaning_result": 4,
        "base_version": "1.4.41",
        "computing_version": "1.2.12",
        "led_version": "1.3.20",
        "power_version": "1.4.25",
        "main_version": "V1.1.16.4",
        "ota_state": "ota success",
        "voice_volume": 76,
        "camera": True,
        "airbag_status": 0,
        "eco_mode": 2,
        "water_gover_mode": 2,
        "bottom_run_mode": 2,
        "little_water_mode": 2,
        "multi_bottom_mode": 1,
        "surface_water_settings": (
            "aiSurfaceTime=180, aiBottomTime=90, workTime=180, distanceSide=1, circleCount=0, lineCount=0"
        ),
        "airbag_settings": "inflatableTime=50, deflatedTime=50",
        "speed_settings": "lineSpeed=0, angularSpeed=45, pumpSpeedSec=1000",
        "motor_thresholds": "driveMotor=2.5, pumpMotor=3.8, turnMotor=0.9, airMotor=1.2, pulsatorMotor=0.45",
    }


def test_captured_shadow_report_attributes() -> None:
    states = _states()

    schedule = states["next_scheduled_clean"].attributes["schedule"]
    assert [(entry["date"], entry["weekday_name"], entry["clean_areas"]) for entry in schedule] == [
        ("2026-10-27", "Tuesday", [{"area": 2, "count": 1}]),
        ("2026-10-29", "Thursday", [{"area": 3, "count": 1}]),
        ("2026-10-31", "Saturday", [{"area": 2, "count": 1}]),
    ]
    assert schedule[0] == {
        "date": "2026-10-27",
        "start_time": "11:52:00",
        "weekday": 2,
        "weekday_name": "Tuesday",
        "clean_mode": 0,
        "clean_intensity": 2,
        "water_gover": 2,
        "clean_areas": [{"area": 2, "count": 1}],
        "user_select": 0,
    }
    assert states["debris_basket_in_place"].attributes == {"blockage": 0, "in_place": 0, "health": 0}
    assert states["cleaning_estimates"].attributes == {
        "clean_time": [270, 270, 120, 100, 100, 100, 62, 62],
        "clean_area": [344, 344.5, 1100, 295, 239.5, 239.5, 239.5, 909, 44.5, 60.6],
    }
    assert states["last_cleaning_result"].attributes == {
        "task_kind": "Custom",
        "task_type": 2,
        "clean_mode": 0,
        "clean_intensity": 1,
        "clean_areas": [{"area": 1, "count": 1}],
    }
    assert states["base_version"].attributes == {"state": 1}
    assert states["ota_state"].attributes == {"state": 3, "progress": 100, "error": 0}
    assert states["voice_volume"].attributes == {"enabled": True, "language": 2, "timbre": 1}
    assert states["motor_thresholds"].attributes == SHADOW["MotorThresholdReport"]


def test_cleaning_op_info_report_power() -> None:
    # shadow/update/accepted while cleaning (14:47 PDT).
    states = report_entity_states(
        {"OpInfoReport": {"batCurrent": 859, "batVoltage": 21900, "batTemperature": 22, "status": 1}},
        NOW,
        PACIFIC,
    )

    assert states["battery_voltage"].value == 21.9
    assert states["battery_current"].value == 859.0
    assert states["battery_power"].value == 18.81


def test_partial_and_malformed_sections_are_skipped() -> None:
    assert report_entity_states({}, NOW, PACIFIC) == {}
    assert (
        report_entity_states(
            {
                "AutomationTaskReport": {"autoTasks": "x"},
                "AutomationTaskSettingReport": {},
                "LifeTimeReport": {},
                "OpInfoReport": {"batVoltage": "bogus"},
                "GetRubbishBoxStatusReport": {},
                "TaskEstimateReport": {"cleanTime": None},
                "FinishTaskReport": {"task": {"nameID": "Custom_1"}},
                "OtaResultReport": {"base": "x", "led": {}},
                "OtaStatusReport": {"msg": " "},
                "VoiceBroadcastReport": {"enable": 1},
                "InspectionSettingReport": {},
                "AirBagStatusReport": {},
                "SuperEcoReport": {},
                "SpeedReport": {"nested": {"a": 1}},
                "WaterGoverReport": "x",
            },
            NOW,
            PACIFIC,
        )
        == {}
    )
    states = report_entity_states(
        {
            "OpInfoReport": {"batCurrent": 5},
            "TaskEstimateReport": {"cleanTime": [], "cleanArea": "x"},
            "FinishTaskReport": {"task": {"cleanResult": 1}},
        },
        NOW,
        PACIFIC,
    )
    assert states == {
        "battery_current": EntityState(5.0),
        "cleaning_estimates": EntityState(None, {"clean_time": [], "clean_area": None}),
        "last_cleaning_result": EntityState(
            1,
            {"task_kind": None, "task_type": None, "clean_mode": None, "clean_intensity": None, "clean_areas": None},
        ),
    }
    empty_schedule = report_entity_states({"AutomationTaskReport": {"autoTasks": [None]}}, NOW, PACIFIC)
    assert empty_schedule == {"next_scheduled_clean": EntityState(None, {"schedule": []})}


def test_next_scheduled_clean_rolls_weekly_and_falls_back_to_weekday() -> None:
    schedule = _states()["next_scheduled_clean"].attributes["schedule"]

    # After Tuesday's start, Thursday is next.
    after_tuesday = datetime(2026, 10, 27, 12, 0, tzinfo=PACIFIC)
    start, entry = next_scheduled_clean(schedule, after_tuesday, PACIFIC)
    assert start == datetime(2026, 10, 29, 11, 52, tzinfo=PACIFIC)
    assert entry is not None and entry["weekday_name"] == "Thursday"

    # Once every reported date has passed, the schedule repeats weekly.
    later = datetime(2026, 11, 1, 9, 0, tzinfo=PACIFIC)
    start, entry = next_scheduled_clean(schedule, later, PACIFIC)
    assert start == datetime(2026, 11, 3, 11, 52, tzinfo=PACIFIC)

    # Without a date, the Sunday-based weekday is used.
    undated = [{"weekday": 0, "start_time": "08:00:00"}, {"weekday": 3, "start_time": "08:00:00"}]
    assert next_scheduled_clean(undated, NOW, PACIFIC)[0] == datetime(2026, 10, 28, 8, 0, tzinfo=PACIFIC)
    assert next_scheduled_clean([{"weekday": 0, "start_time": "16:00"}], NOW, PACIFIC)[0] == datetime(
        2026, 10, 25, 16, 0, tzinfo=PACIFIC
    )

    unusable: list[dict[str, Any]] = [
        {"weekday": 9, "start_time": "08:00"},
        {"weekday": None, "start_time": "08:00"},
        {"start_time": "x"},
    ]
    assert next_scheduled_clean(unusable, NOW, PACIFIC) == (None, None)
    assert next_scheduled_clean([], NOW, PACIFIC) == (None, None)


def _coordinator() -> Any:
    device = {"sn": SN, "name": "Scuba V3 Ultra", "model": "Scuba_V3_Ultra", "online": True}
    coordinator = make_coordinator(BaseFakeApi(), _devices={SN: dict(device)})
    coordinator.data = {SN: normalize_device_state(dict(device))}
    coordinator.async_update_listeners = lambda: None  # type: ignore[method-assign]
    return coordinator


def test_coordinator_applies_report_sections_from_shadow() -> None:
    coordinator = _coordinator()

    coordinator._on_shadow_update(
        SN, {"_topic": f"$aws/things/{SN}/shadow/get/accepted", "state": {"reported": SHADOW}}
    )

    data = coordinator.data[SN]
    assert data["battery_health"].value == 99
    assert data["debris_basket_blocked"].value is False
    assert data["voice_volume"].value == 76
    assert data["ota_state"].value == "ota success"
    assert data["next_scheduled_clean"].attributes["schedule"][1]["date"] == "2026-10-29"


def test_coordinator_ignores_report_sections_for_other_models() -> None:
    device = {"sn": SN, "name": "Scuba V3", "model": "Scuba_V3", "online": True}
    coordinator = make_coordinator(BaseFakeApi(), _devices={SN: dict(device)})
    coordinator.data = {SN: normalize_device_state(dict(device))}
    coordinator.async_update_listeners = lambda: None  # type: ignore[method-assign]

    coordinator._on_shadow_update(SN, {"state": {"reported": {"LifeTimeReport": {"battery": 99}}}})

    assert "battery_health" not in coordinator.data[SN]


def test_report_capability_is_v3_ultra_only() -> None:
    assert Capability.REPORT_SECTIONS in derive_device_profile({"model": "Scuba_V3_Ultra"}).capabilities
    assert Capability.REPORT_SECTIONS not in derive_device_profile({"model": "Scuba_V3"}).capabilities


@pytest.mark.asyncio
async def test_v3_ultra_publishes_report_entities(hass: HomeAssistant, monkeypatch: pytest.MonkeyPatch) -> None:
    entry, coordinator = _hass_with_device(hass, {"sn": "SN123", "name": "Scuba V3 Ultra", "model": "Scuba_V3_Ultra"})
    coordinator.data["SN123"].update(_states())
    monkeypatch.setattr(dt_util, "now", lambda time_zone=None: datetime(2026, 10, 28, 9, 0, tzinfo=PACIFIC))

    sensors = await _setup_platform(sensor, hass, entry)
    binaries = await _setup_platform(binary_sensor, hass, entry)

    assert _keys(sensors) >= REPORT_SENSOR_KEYS
    assert _keys(binaries) >= REPORT_BINARY_KEYS

    next_clean = _entity_by_key(sensors, "next_scheduled_clean")
    assert next_clean.native_value == datetime(2026, 10, 29, 11, 52, tzinfo=PACIFIC)
    attributes = next_clean.extra_state_attributes
    assert attributes["weekday_name"] == "Thursday"
    assert attributes["clean_areas"] == [{"area": 3, "count": 1}]
    assert len(attributes["schedule"]) == 3
    assert next_clean.entity_category is None
    assert next_clean.entity_registry_enabled_default is True

    health = _entity_by_key(sensors, "battery_health")
    assert health.native_value == 99
    assert health.extra_state_attributes == {}
    assert health.entity_category == EntityCategory.DIAGNOSTIC
    assert health.entity_registry_enabled_default is True
    enabled = {
        entity.entity_description.key
        for entity in sensors
        if hasattr(entity, "entity_description") and entity.entity_registry_enabled_default
    }
    assert {"voice_volume", "eco_mode", "battery_temperature", "last_cleaning_result"} <= enabled
    assert {"battery_current", "motor_thresholds", "debris_basket_health"}.isdisjoint(enabled)

    basket = _entity_by_key(binaries, "debris_basket_in_place")
    assert basket.is_on is False
    assert basket.extra_state_attributes == {"blockage": 0, "in_place": 0, "health": 0}
    camera = _entity_by_key(binaries, "camera")
    assert camera.is_on is True
    assert camera.extra_state_attributes is None
    assert _entity_by_key(binaries, "schedule_habit").entity_registry_enabled_default is False

    coordinator.data["SN123"].pop("next_scheduled_clean")
    coordinator.data["SN123"].pop("debris_basket_in_place")
    assert next_clean.native_value is None
    assert next_clean.extra_state_attributes == {}
    assert basket.extra_state_attributes is None

    coordinator.data["SN123"]["next_scheduled_clean"] = EntityState(None, {"schedule": "x"})
    assert next_clean.native_value is None
    assert next_clean.extra_state_attributes == {"schedule": "x"}


@pytest.mark.asyncio
async def test_other_scuba_models_do_not_publish_report_entities(hass: HomeAssistant) -> None:
    entry, _coordinator = _hass_with_device(hass, {"sn": "SN123", "name": "Scuba V3", "model": "Scuba_V3"})

    sensors = await _setup_platform(sensor, hass, entry)
    binaries = await _setup_platform(binary_sensor, hass, entry)

    assert REPORT_SENSOR_KEYS.isdisjoint(_keys(sensors))
    assert REPORT_BINARY_KEYS.isdisjoint(_keys(binaries))
