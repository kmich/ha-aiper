"""Tests for state normalization helpers and less common payload fields."""

from __future__ import annotations

import pytest

from custom_components.aiper import state
from custom_components.aiper.state import (
    EntityState,
    normalize_clean_path_update,
    normalize_device_state,
    normalize_machine_update,
    normalize_mode_options_update,
    normalize_netstat_update,
    normalize_ota_update,
    normalize_w2_alarm_update,
    normalize_w2_wqs_update,
    supported_mode_ids_from_payload,
)


def test_mode_text_adds_running_control_labels_and_falls_back() -> None:
    surfer = {"model": "Surfer_S2", "capabilities": ["running_control"], "mode_map": {2: "Floor"}}
    assert state._mode_text(surfer, 0) == "Off"
    assert state._mode_text({"model": "Scuba_X1"}, 99) == "Mode 99"
    assert state._mode_text({"model": "Scuba_X1"}, None) is None


def test_clean_path_text() -> None:
    assert state._clean_path_text(None) is None
    assert state._clean_path_text("1") == "Adaptive"
    assert state._clean_path_text(7) == "7"
    assert state._clean_path_text("zigzag") == "zigzag"


@pytest.mark.parametrize(
    ("code", "expected"),
    [
        (None, None),
        ([1], None),
        (0, None),
        (12.0, "e12"),
        (float("nan"), None),
        ("  ", None),
        ("0", None),
        ("015", "e15"),
        ("E-7", "e7"),
        ("E", "e"),
        ("Stuck", "stuck"),
    ],
)
def test_normalize_warn_code(code, expected) -> None:
    assert state._normalize_warn_code(code) == expected


def test_warning_text_variants() -> None:
    assert state._warning_text({"warn": 1}, None) == "Active"
    assert state._warning_text({"warn": 0, "warn_code": 3}, True) == "e3"
    assert state._warning_text({"warn": 1}, False) == "No active warnings"


@pytest.mark.parametrize(
    ("ota", "expected"),
    [
        ({"state": 0}, "Idle"),
        ({"status": 1}, "Downloading"),
        ({"otaState": "2"}, "Installing"),
        ({"ota_status": 3}, "Rebooting"),
        ({"state": "flashing"}, "flashing"),
        ({"state": None}, None),
    ],
)
def test_ota_state_text(ota, expected) -> None:
    assert state._ota_state_text(ota) == expected
    assert normalize_ota_update(ota)["ota_state"].value == expected


@pytest.mark.parametrize(
    ("status", "expected"),
    [
        (None, None),
        (0, "Idle"),
        (1, "Active"),
        (2, "Charging"),
        (4, "Updating"),
        (5, "Sleeping"),
        (7, "Deep Sleep"),
        (9, "Status 9"),
    ],
)
def test_hydrocomm_status_text(status, expected) -> None:
    assert state._hydrocomm_status_text(status) == expected


@pytest.mark.parametrize(
    ("value", "expected"),
    [(None, None), (0, "Not charging"), (1, "Charging"), (2, "Solar charging"), (9, "Charge type 9")],
)
def test_charge_type_text(value, expected) -> None:
    assert state._charge_type_text(value) == expected


def test_charging_value_and_probe_text() -> None:
    assert state._charging_value(None, None) is None
    assert state._charging_value(1, 0) is False
    assert state._charging_value(None, 2) is True
    assert state._probe_status_text(None) is None
    assert state._probe_status_text(0) == "Not installed"
    assert state._probe_status_text(3) == "Status 3"
    assert state._hydrocomm_alarm_codes(-1) == []
    assert state._hydrocomm_warning_text(0) == "No active warnings"


def test_supported_mode_ids_from_mixed_payloads() -> None:
    payload = {"modeList": [1, 2.0, {"mode": "3"}, {"mode": "x"}, {"name": "no mode"}, "4", "bad", 1]}

    assert supported_mode_ids_from_payload(payload) == [1, 2, 3, 4]
    assert supported_mode_ids_from_payload({"modeList": "5"}) == [5]
    assert supported_mode_ids_from_payload({}) == []
    assert normalize_mode_options_update({"mode_map": "bad"}, {"modeList": []}) == {}
    assert normalize_mode_options_update({}, {"modeList": [1]})["mode_options"].attributes == {"mode_map": {}}


def test_machine_update_covers_optional_fields() -> None:
    surfer = {"model": "Surfer_S2", "capabilities": ["running_control"]}
    current = {"online": EntityState(True)}

    updates = normalize_machine_update(
        surfer,
        {"status": 0, "temp": 27.5, "link": 1, "cleanPath": "1", "solarStatus": 1, "warn_code": 0},
        current,
    )

    assert updates["status"].attributes == {"code": 0}
    assert updates["mode"].value == "Off"
    assert updates["temperature"].value == 27.5
    assert updates["linked"].value is True
    assert updates["clean_path"].value == "Adaptive"
    assert updates["solar_charging"].value is True
    assert updates["warning"].value == "No active warnings"

    odd_path = normalize_machine_update({"model": "Scuba_X1"}, {"cleanPath": "zigzag"})
    assert odd_path["clean_path"] == EntityState("zigzag", {})


def test_netstat_and_clean_path_updates() -> None:
    updates = normalize_netstat_update({"online": 1, "sta": 2, "ble": "1", "nearFieldBind": True})
    assert updates["wifi"].value is True
    assert updates["bluetooth"].value is True
    assert updates["linked"].value is True
    assert normalize_clean_path_update({"cleanPath": "x"}) == {}


def test_w2_updates() -> None:
    assert normalize_w2_wqs_update({"result": 2, "ph": 7.1}) == {
        "water_quality_result": EntityState("Result 2", {"code": 2})
    }
    ready = normalize_w2_wqs_update({"result": 0, "ph": "7.2", "manual": 1})
    assert ready["ph"].value == 7.2
    assert ready["water_quality_manual"].value is True

    assert normalize_w2_alarm_update({}) == {}
    alarm = normalize_w2_alarm_update({"Alarm": "x"})
    assert alarm["warning"] == EntityState("No active warnings", {})


def test_find_consumable_ignores_malformed_items() -> None:
    assert state._find_consumable({"consumables": "bad"}, "brush") is None
    assert state._find_consumable({"consumables": ["x", {"name": "Roller Brush"}]}, "brush") == {"name": "Roller Brush"}


def test_normalize_device_state_for_minimal_payload() -> None:
    normalized = normalize_device_state({"sn": "SN1234567890"})

    assert normalized["device_info"].value == "Aiper SN1234567890"
