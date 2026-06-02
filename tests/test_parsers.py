"""Tests for Aiper payload parser helpers."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import pytest

from custom_components.aiper.coordinator import _clean_path_value, _parse_cleaning_history, _parse_consumables
from custom_components.aiper.state import (
    _centihours_to_hours,
    _collect_warning_codes,
    _hours,
    _normalize_warn_code,
    normalize_device_state,
    normalize_machine_update,
    normalize_w2_alarm_update,
    normalize_w2_info_update,
    normalize_w2_lifetime_update,
    normalize_w2_sensor_status_update,
    normalize_w2_wqs_update,
)


def test_clean_path_value_normalizes_common_variants() -> None:
    """Clean-path payloads vary across REST, shadow, and firmware reports."""
    assert _clean_path_value(-1) == 0
    assert _clean_path_value("0") == 0
    assert _clean_path_value("Adaptive") == 1
    assert _clean_path_value("S-shaped") == 0
    assert _clean_path_value("unknown") is None


def test_warning_code_normalization_and_collection() -> None:
    """Warning codes should be stable for user-facing warning sensors."""
    assert _normalize_warn_code(12) == "e12"
    assert _normalize_warn_code("E-013") == "e13"
    assert _normalize_warn_code(0) is None

    assert _collect_warning_codes(
        {
            "warnCodeList": [12, "e13", 0],
            "errorCode": "14",
        }
    ) == ["e12", "e13", "e14"]


def test_runtime_hours_normalizes_centi_hour_payloads() -> None:
    """Aiper reports REST runTime in centi-hours, not whole hours."""
    device: dict[str, Any] = {"runTime": 1673}
    state = normalize_device_state(device)
    assert state["runtime"].value == 16.73

    device = {"runTime": 1673.0}
    state = normalize_device_state(device)
    assert state["runtime"].value == 16.73

    device = {"runTime": "16.73"}
    state = normalize_device_state(device)
    assert state["runtime"].value is None

    device = {"runTime": None}
    state = normalize_device_state(device)
    assert state["runtime"].value is None


def test_machine_solar_status_uses_observed_integer_payload() -> None:
    """Solar charging comes from MQTT Machine.solar_status as an integer flag."""
    assert normalize_machine_update({"model": "Surfer_S2"}, {"solar_status": 1})["solar_charging"].value is True
    assert normalize_machine_update({"model": "Surfer_S2"}, {"solar_status": 0})["solar_charging"].value is False


def test_machine_solar_status_camel_case_alias() -> None:
    """solarStatus (camelCase) is treated as an alias for solar_status."""
    assert normalize_machine_update({"model": "Surfer_S2"}, {"solarStatus": 1})["solar_charging"].value is True
    assert normalize_machine_update({"model": "Surfer_S2"}, {"solarStatus": 0})["solar_charging"].value is False


def test_machine_status_update_coerces_status_without_losing_operating_status() -> None:
    """MQTT status may arrive as text, but the base status must stay intact."""
    state = normalize_machine_update({"model": "Surfer_S2"}, {"status": "129"})

    assert state["running"].value is True
    assert state["status"].value == "Cleaning"
    assert state["status"].attributes == {"code": 1}


def test_cleaner_returning_status_is_not_charging() -> None:
    """Status 2 (RETURNING) must not be treated as charging for pool cleaners."""
    state = normalize_device_state({"model": "Scuba_X1", "machineStatus": 2})

    assert state["status"].value == "Returning"
    assert state["running"].value is True
    assert state["charging"].value is False


def test_cleaner_charging_status_is_charging() -> None:
    """Status 3 (CHARGING) must be treated as charging for pool cleaners."""
    state = normalize_device_state({"model": "Scuba_X1", "machineStatus": 3})

    assert state["charging"].value is True
    assert state["running"].value is False


def test_hydrocomm_machine_status_uses_station_status_map() -> None:
    """W2/HydroComm status 2/3 are charging states, not cleaner returning."""
    state = normalize_machine_update(
        {"model": "HydroComm", "profile_family": "hydrocomm"},
        {"status": 2},
    )

    assert state["status"].value == "Charging"
    assert state["status"].attributes == {"code": 2}
    assert state["charging"].value is True
    assert "running" not in state


def test_hour_helpers_keep_field_units_explicit() -> None:
    """Known hour and centi-hour fields should not share implicit parsing."""
    assert _hours("16.73") == 16.73
    assert _centihours_to_hours(1673) == 16.73
    assert _centihours_to_hours("16.73") is None


def test_w2_info_update_maps_battery_charging_and_solar_fields() -> None:
    """HydroComm W2Info carries battery, charging type, and station electrical fields."""
    state = normalize_w2_info_update(
        {
            "bal_cal": 76,
            "chargeType": 2,
            "vcvol": 4100,
            "sunvol": 5200,
            "lux": 320,
            "workCur": 12,
            "chargeCur": 150,
            "calStatus": 1,
        }
    )

    assert state["battery"].value == 76
    assert state["charge_type"].value == "Solar charging"
    assert state["charging"].value is True
    assert state["solar_charging"].value is True
    assert state["supply_voltage"].value == 4100
    assert state["solar_voltage"].value == 5200
    assert state["light_level"].value == 320
    assert state["work_current"].value == 12
    assert state["charge_current"].value == 150
    assert state["calibration_status"].value == "In progress"


def test_w2_wqs_update_maps_water_quality_values() -> None:
    """HydroComm W2WQS is the live water-quality sensor payload."""
    state = normalize_w2_wqs_update(
        {
            "time": "2026-05-26T12:00:00Z",
            "temp": 27.4,
            "ph": "7.3",
            "orp": 670,
            "ec": 1234,
            "tds": 456,
            "rcl": 1.2,
            "swpi": 88,
            "result": 0,
        }
    )

    assert state["water_quality_result"].value == "Ready"
    assert state["temperature"].value == 27.4
    assert state["ph"].value == 7.3
    assert state["orp"].value == 670.0
    assert state["ec"].value == 1234.0
    assert state["tds"].value == 456.0
    assert state["rcl"].value == 1.2
    assert state["water_quality_score"].value == 88.0
    assert state["ph"].attributes == {"sample_time": "2026-05-26T12:00:00Z"}
    assert state["wqs_sample_time"].value == datetime(2026, 5, 26, 12, 0, 0, tzinfo=UTC)


def test_w2_probe_status_and_lifetime_merge_attributes() -> None:
    """Probe status is live, while lifetime payloads add serial/calibration attributes."""
    current = normalize_w2_lifetime_update(
        {
            "sn1": "P1",
            "usetime1": "10",
            "ctime1": "1714608000",
        }
    )
    state = normalize_w2_sensor_status_update({"sensor1": 1}, current)

    assert state["probe_1_status"].value == "Installed"
    assert state["probe_1_status"].attributes == {
        "probe_serial": "P1",
        "usage_time": "10",
        "calibration_time": "1714608000",
        "code": 1,
    }


def test_w2_alarm_update_decodes_alarm_bitmask() -> None:
    """HydroComm alarm code is a bitmap of probe/property errors."""
    state = normalize_w2_alarm_update({"time": "now", "Alarm": 256 + 8192})

    assert state["warning"].value == "pH constant value, Battery low"
    assert state["warning"].attributes == {"code": 8448, "codes": [256, 8192], "time": "now"}


def test_parse_cleaning_history_surfer_s2_clean_time_min_keys() -> None:
    """Surfer S2 history records may use cleanTimeMin (minutes) as the duration key."""
    total_count, total_hours, records = _parse_cleaning_history(
        {
            "code": "200",
            "data": {
                "totalCleanCount": 3,
                "list": [
                    {
                        "mode": 1,
                        "cleanDate": "2026-05-24",
                        "cleanTimeMin": 45,
                    },
                    {
                        "mode": 1,
                        "cleanDate": "2026-05-25",
                        "cleanTimeMin": 90,
                    },
                    {
                        "mode": 1,
                        "cleanDate": "2026-05-26",
                        "cleanTimeMin": 60,
                    },
                ],
            },
        }
    )

    assert total_count == 3
    assert records[0]["duration_min"] == 60.0
    assert records[1]["duration_min"] == 90.0
    # total_hours derived from record sum: (45+90+60)/60 = 3.25 h
    assert total_hours == pytest.approx(3.25, rel=0.01)


def test_parse_cleaning_history_restores_totals_and_last_record() -> None:
    """Cleaning history totals and last record should survive regional wrappers."""
    total_count, total_hours, records = _parse_cleaning_history(
        {
            "code": "200",
            "data": {
                "totalCleanings": 2,
                "totalCleaningMinutes": 95,
                "list": [
                    {
                        "modeId": 2,
                        "modeName": "Floor",
                        "startTime": "2026-05-24 09:00:00",
                        "durationTime": "35 min",
                    },
                    {
                        "modeId": 3,
                        "modeName": "Wall",
                        "startTime": "2026-05-25 10:00:00",
                        "durationTime": "3600s",
                    },
                ],
            },
        }
    )

    assert total_count == 2
    assert total_hours == 1.583
    assert records[0]["mode"] == "Wall"
    assert records[0]["start"] == datetime(2026, 5, 25, 10, 0, tzinfo=UTC)
    assert records[0]["duration_min"] == 60.0


def test_parse_consumables_handles_scuba_wrapper_payload() -> None:
    """Scuba consumables use wrapper/list payloads with remaining-hour fields."""
    consumables = _parse_consumables(
        {
            "data": {
                "list": [
                    {
                        "id": "brush",
                        "consumableName": "Roller Brush",
                        "componentReplaceRemainHour": 500,
                        "longestUseTime": 1000,
                        "lastChangeTime": 1_714_608_000_000,
                    }
                ]
            }
        }
    )

    assert consumables[0]["key"] == "brush_roller_brush"
    assert consumables[0]["remaining_hours"] == 500
    assert consumables[0]["percent_left"] == 50.0
    assert consumables[0]["last_replacement"].tzinfo == UTC


def test_parse_consumables_handles_surfer_s2_direct_list_payload() -> None:
    """Surfer S2 consumables use a direct data list keyed by serial number."""
    consumables = _parse_consumables(
        {
            "code": "200",
            "data": [
                {
                    "componentMaintainType": 1,
                    "consumableModel": "S2-Propeller",
                    "consumableName": "Propeller",
                    "consumableType": 1,
                    "dynamicsFields": [
                        {"display": "Consumables Name", "key": "consumable_name", "value": "Propeller"},
                        {"display": "Component maintenance", "key": "component_maintain"},
                    ],
                    "id": 78039,
                    "maintainLastChangeTime": 1_777_544_862_000,
                    "useTime": 0,
                }
            ],
            "message": "Success",
            "successful": True,
        }
    )

    assert consumables == [
        {
            "key": "78039_propeller",
            "name": "Propeller",
            "remaining_hours": None,
            "percent_left": None,
            "last_replacement": consumables[0]["last_replacement"],
            "raw": {
                "componentMaintainType": 1,
                "consumableModel": "S2-Propeller",
                "consumableName": "Propeller",
                "consumableType": 1,
                "dynamicsFields": [
                    {"display": "Consumables Name", "key": "consumable_name", "value": "Propeller"},
                    {"display": "Component maintenance", "key": "component_maintain"},
                ],
                "id": 78039,
                "maintainLastChangeTime": 1_777_544_862_000,
                "useTime": 0,
            },
        }
    ]
    assert consumables[0]["last_replacement"].tzinfo == UTC
