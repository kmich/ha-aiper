"""Tests for Aiper payload parser helpers."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from custom_components.aiper.coordinator import _clean_path_value, _parse_cleaning_history, _parse_consumables
from custom_components.aiper.state import (
    _centihours_to_hours,
    _collect_warning_codes,
    _hours,
    _normalize_warn_code,
    normalize_device_state,
    normalize_machine_update,
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


def test_machine_status_update_coerces_status_without_losing_operating_status() -> None:
    """MQTT status may arrive as text, but the base status must stay intact."""
    state = normalize_machine_update({"model": "Surfer_S2"}, {"status": "129"})

    assert state["running"].value is True
    assert state["status"].value == "Cleaning"
    assert state["status"].attributes == {"code": 1}


def test_hour_helpers_keep_field_units_explicit() -> None:
    """Known hour and centi-hour fields should not share implicit parsing."""
    assert _hours("16.73") == 16.73
    assert _centihours_to_hours(1673) == 16.73
    assert _centihours_to_hours("16.73") is None


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
