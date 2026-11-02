"""Scuba V3 Ultra: ``*Report`` shadow sections drive live state.

Payloads are trimmed from captures on a Scuba V3 Ultra (main firmware
V1.1.16.4, Americas region); serials and Wi-Fi names are replaced.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
from zoneinfo import ZoneInfo

from homeassistant.util import dt as dt_util

from custom_components.aiper.coordinator import AiperDataUpdateCoordinator
from custom_components.aiper.coordinator_parsing import _finished_task_summary, _machine_from_reports
from custom_components.aiper.state import normalize_device_state
from tests.coordinator_factory import BaseFakeApi, make_coordinator

SN = "SN1234567890"
ACCEPTED = f"$aws/things/{SN}/shadow/update/accepted"
GET = f"$aws/things/{SN}/shadow/get/accepted"
PACIFIC = ZoneInfo("America/Los_Angeles")

# shadow/update/accepted while cleaning (14:47 PDT).
CLEANING: dict[str, Any] = {
    "OpInfoReport": {
        "wifiRssi": -64,
        "batCurrent": 859,
        "batVoltage": 21900,
        "batTemperature": 22,
        "batQuantity": 47,
        "status": 1,
        "wifiName": "<ssid>",
    }
}
# GetWorkModeReport while the custom task was running.
WORKING: dict[str, Any] = {
    "GetWorkModeReport": {
        "working": 1,
        "ts": 1792964280658,
        "task": {
            "nameID": "Custom_1792958748713",
            "startTime": "13:05:47",
            "taskType": 2,
            "aiType": 0,
            "cleanMode": 0,
            "cleanIntensity": 1,
            "cleanAreas": [{"area": 1, "count": 1}],
        },
    }
}
FINISH: dict[str, Any] = {
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
    }
}
# Full shadow (get/accepted) ~13 min later, on the charger. The InwaterReport is
# the one sent as the run finished; it is not refreshed while charging.
CHARGING_SHADOW: dict[str, Any] = {
    "NetStat": {"online": 1, "ble": 2},
    "GetWorkModeReport": {
        "working": 0,
        "ts": 1792964984824,
        "task": {"nameID": "Memory_1032454089", "startTime": "14:49:43", "taskType": 4},
    },
    "OpInfoReport": {
        "wifiRssi": -78,
        "batCurrent": 4,
        "batVoltage": 23060,
        "batTemperature": 22,
        "batQuantity": 62,
        "status": 2,
        "wifiName": "<ssid>",
    },
    "InwaterReport": {"inWater": 1},
    "GetRubbishBoxStatusReport": {"blockage": 0, "inPlace": 0, "health": 0},
    "WQSReport": {"temp": 25},
    "GetAlarmReport": {"code": [], "ts": "1792965231155"},
    **FINISH,
}


def _coordinator() -> AiperDataUpdateCoordinator:
    device = {"sn": SN, "name": "Scuba V3 Ultra", "model": "Scuba_V3_Ultra", "online": True}
    coordinator = make_coordinator(BaseFakeApi(), _devices={SN: dict(device)})
    coordinator.data = {SN: normalize_device_state(dict(device))}
    coordinator.async_update_listeners = lambda: None  # type: ignore[method-assign]
    return coordinator


def _accepted(reported: dict[str, Any], topic: str = ACCEPTED) -> dict[str, Any]:
    return {"_topic": topic, "state": {"reported": reported}}


def _value(coordinator: AiperDataUpdateCoordinator, key: str) -> Any:
    return coordinator.data[SN][key].value


def test_machine_from_reports_maps_captured_sections() -> None:
    assert _machine_from_reports(CHARGING_SHADOW) == {
        "status": 2,
        "cap": 62,
        "in_water": 1,
        "temp": 25,
        "warn_codes": [],
    }
    assert _machine_from_reports({"VoiceBroadcastReport": {"enable": 1}}) == {}


def test_op_info_report_drives_status_battery_and_wifi() -> None:
    coordinator = _coordinator()

    coordinator._on_shadow_update(SN, _accepted(CLEANING))

    assert _value(coordinator, "status") == "Cleaning"
    assert _value(coordinator, "running") is True
    assert _value(coordinator, "charging") is False
    assert _value(coordinator, "battery") == 47
    assert _value(coordinator, "wifi_signal") == -64


def test_parked_after_finish_stays_in_water() -> None:
    coordinator = _coordinator()

    coordinator._on_shadow_update(
        SN,
        _accepted({"OpInfoReport": {**CLEANING["OpInfoReport"], "status": 7}, "InwaterReport": {"inWater": 1}}),
    )

    assert _value(coordinator, "status") == "Parked"
    assert _value(coordinator, "running") is False
    assert _value(coordinator, "charging") is False
    assert _value(coordinator, "in_water") is True


def test_charging_shadow_reports_dry_charging_and_temperature() -> None:
    coordinator = _coordinator()

    coordinator._on_shadow_update(SN, _accepted(CHARGING_SHADOW, topic=GET))

    assert _value(coordinator, "status") == "Charging"
    assert _value(coordinator, "running") is False
    assert _value(coordinator, "charging") is True
    assert _value(coordinator, "battery") == 62
    # Charging wins over the stale submerged InwaterReport.
    assert _value(coordinator, "in_water") is False
    assert _value(coordinator, "temperature") == 25
    assert _value(coordinator, "warning") == "No active warnings"


def test_finish_task_dates_last_cleaning_from_running_task() -> None:
    coordinator = _coordinator()

    coordinator._on_shadow_update(SN, _accepted(WORKING, topic=GET))
    coordinator._on_shadow_update(SN, _accepted(FINISH))

    assert _value(coordinator, "last_cleaning_mode") == "Custom"
    start = _value(coordinator, "last_cleaning_start")
    assert start.astimezone(dt_util.get_default_time_zone()).strftime("%H:%M:%S") == "13:05:47"
    assert _value(coordinator, "last_cleaning_duration") == round(
        (datetime.fromtimestamp(1792964983.406, UTC) - start).total_seconds() / 60, 1
    )


def test_finish_task_without_running_task_only_sets_mode() -> None:
    coordinator = _coordinator()

    coordinator._on_shadow_update(SN, _accepted(CHARGING_SHADOW, topic=GET))

    assert _value(coordinator, "last_cleaning_mode") == "Custom"
    assert _value(coordinator, "last_cleaning_start") is None
    assert _value(coordinator, "last_cleaning_duration") is None


def test_finished_task_summary_handles_midnight_and_mismatches() -> None:
    finish = FINISH["FinishTaskReport"]
    task = WORKING["GetWorkModeReport"]["task"]

    summary = _finished_task_summary(finish, task, PACIFIC)
    assert summary["last_cleaning_start"] == datetime(2026, 10, 25, 20, 5, 47, tzinfo=UTC)
    assert summary["last_cleaning_duration"] == 103.9

    late = _finished_task_summary(finish, {**task, "startTime": "23:30:00"}, PACIFIC)
    assert late["last_cleaning_start"] == datetime(2026, 10, 25, 6, 30, tzinfo=UTC)

    assert _finished_task_summary(finish, {**task, "nameID": "Custom_other"}, PACIFIC) == {
        "last_cleaning_mode": "Custom"
    }
    assert _finished_task_summary(finish, {**task, "startTime": "bogus"}, PACIFIC) == {"last_cleaning_mode": "Custom"}
    assert _finished_task_summary(finish, {**task, "startTime": None}, PACIFIC) == {"last_cleaning_mode": "Custom"}
    assert _finished_task_summary({"task": "x"}, task, PACIFIC) == {}
    assert _finished_task_summary({"task": {}}, None, PACIFIC) == {}
