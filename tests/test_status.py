"""Tests for Aiper status-code normalization."""

from __future__ import annotations

import pytest

from custom_components.aiper.const import status_label, status_running, status_value
from custom_components.aiper.state import normalize_device_state, normalize_machine_update


def test_status_label_uses_lower_status_bits() -> None:
    """Surfer status reports set a high bit while preserving base state."""
    assert status_value(128) == 0
    assert status_value(129) == 1
    assert status_label(128) == "Idle"
    assert status_label(129) == "Cleaning"


def test_status_running_uses_operating_base_status() -> None:
    """Running reflects actual operation, not merely the high status bit."""
    assert status_running(128) is False
    assert status_running(129) is True
    assert status_running(1) is True
    assert status_running(130) is True
    assert status_running(131) is False


def test_surfer_standby_state_is_normalized_at_boundary() -> None:
    """Surfer reports mode 5 while stopped; normalize the exposed mode to off."""
    device = {
        "model": "Surfer_S2",
        "machineStatus": 128,
        "mode": 5,
    }

    state = normalize_device_state(device)

    assert state["running"].value is False
    assert state["mode"].attributes == {"code": 0}
    assert state["mode"].value == "Off"


def test_running_status_is_normalized_to_base_status() -> None:
    """Raw status is interpreted once into base status and running state."""
    device = {
        "model": "Surfer_S2",
        "machineStatus": 129,
        "mode": 1,
    }

    state = normalize_device_state(device)

    assert state["running"].value is True
    assert state["mode"].attributes == {"code": 1}
    assert state["mode"].value == "Manual"


def test_scuba_charging_status_is_reported_from_base_status() -> None:
    """Scuba X1 status 3/131 is charging, not running or returning."""
    state = normalize_device_state({"model": "Scuba_X1", "machineStatus": 131})

    assert state["running"].value is False
    assert state["status"].value == "Charging"
    assert state["status"].attributes == {"code": 3}
    assert state["charging"].value is True


def test_scuba_s3_reports_charging_on_status_2() -> None:
    """Scuba S3 firmware reports status 2 for the whole charge, not "returning"."""
    state = normalize_device_state({"model": "Scuba_S3", "machineStatus": 2})

    assert state["status"].value == "Charging"
    assert state["status"].attributes == {"code": 2}
    assert state["charging"].value is True
    assert state["running"].value is False


def test_scuba_s3_reports_charged_on_status_3() -> None:
    """Scuba S3 switches to status 3 once the battery reaches 100%."""
    state = normalize_device_state({"model": "Scuba_S3", "machineStatus": 3})

    assert state["status"].value == "Charged"
    assert state["status"].attributes == {"code": 3}
    assert state["charging"].value is True
    assert state["running"].value is False


def test_scuba_s3_cleaning_status_is_unchanged() -> None:
    """Only codes 2 and 3 differ on the S3; cleaning stays code 1."""
    state = normalize_device_state({"model": "Scuba_S3", "machineStatus": 1})

    assert state["status"].value == "Cleaning"
    assert state["charging"].value is False
    assert state["running"].value is True


def test_scuba_s3_status_semantics_apply_to_mqtt_updates() -> None:
    """The MQTT shadow path uses the same model-specific mapping as REST."""
    rest = {"model": "Scuba_S3"}

    updates = normalize_machine_update(rest, {"status": 2, "cap": 52, "in_water": 0})

    assert updates["status"].value == "Charging"
    assert updates["charging"].value is True
    assert updates["running"].value is False


def test_scuba_s1_reports_charging_on_status_2() -> None:
    """Scuba S1 V2.0.1 reports status 2 while physically charging."""
    state = normalize_device_state({"model": "Scuba_S1_2025", "machineStatus": 2})

    assert state["status"].value == "Charging"
    assert state["status"].attributes == {"code": 2}
    assert state["charging"].value is True
    assert state["running"].value is False


def test_scuba_s1_active_status_is_visible_while_cloud_marks_offline() -> None:
    """Connectivity must not hide fresh evidence that the cleaner is running."""
    state = normalize_device_state(
        {"model": "Scuba_S1_2025", "machineStatus": 1, "online": False}
    )

    assert state["online"].value is False
    assert state["status"].value == "Cleaning"
    assert state["running"].value is True
    assert state["charging"].value is False


def test_scuba_s1_reports_low_battery_terminal_state_as_parked() -> None:
    """Observed status 10 is parked and non-running after the S1 cycle ends."""
    state = normalize_device_state({"model": "Scuba_S1_2025", "machineStatus": 10})

    assert state["status"].value == "Parked"
    assert state["status"].attributes == {"code": 10}
    assert state["charging"].value is False
    assert state["running"].value is False


def test_scuba_s1_status_semantics_apply_to_mqtt_updates() -> None:
    """The S1 MQTT shadow path uses the same model-specific charging map."""
    updates = normalize_machine_update(
        {"model": "Scuba_S1_2025"},
        {"status": 2, "cap": 15, "run_time": 0, "in_water": 0},
    )

    assert updates["status"].value == "Charging"
    assert updates["charging"].value is True
    assert updates["running"].value is False
    assert updates["in_water"].value is False


@pytest.mark.parametrize("reported_water", [None, 1])
def test_scuba_s1_charging_clears_stale_wet_state(reported_water: int | None) -> None:
    """S1 charging is dry evidence when MQTT omits or repeats stale water."""
    payload = {"status": 2, "cap": 15}
    if reported_water is not None:
        payload["in_water"] = reported_water
    updates = normalize_machine_update(
        {"model": "Scuba_S1_2025"},
        payload,
    )

    assert updates["status"].value == "Charging"
    assert updates["charging"].value is True
    assert updates["running"].value is False
    assert updates["in_water"].value is False


def test_other_models_do_not_infer_water_from_charging_status() -> None:
    """The physically validated dry inference must remain S1-specific."""
    updates = normalize_machine_update(
        {"model": "Scuba_X1"},
        {"status": 3, "cap": 15},
    )

    assert "in_water" not in updates


def test_other_models_keep_explicit_water_value_while_charging() -> None:
    """The S1 override must not alter another model's explicit water field."""
    updates = normalize_machine_update(
        {"model": "Scuba_X1"},
        {"status": 3, "cap": 15, "in_water": 1},
    )

    assert updates["in_water"].value is True


def test_scuba_s3_semantics_resolve_from_device_list_model() -> None:
    """A failed device-info call must not revert the S3 to the default encoding."""
    state = normalize_device_state({"deviceModel": "Scuba_S3", "machineStatus": 2})

    assert state["status"].value == "Charging"
    assert state["charging"].value is True


def test_other_scuba_models_keep_default_status_encoding() -> None:
    """The S3 override must not leak into other Scuba models."""
    state = normalize_device_state({"model": "Scuba_X1", "machineStatus": 2})

    assert state["status"].value == "Returning"
    assert state["charging"].value is False
    assert state["running"].value is True


def test_identity_metadata_is_normalized_at_boundary() -> None:
    """Platform entities should not need model/name/firmware fallback chains."""
    device = {
        "sn": "SN123",
        "name": "Pool Bot",
        "model": "Surfer_S2",
        "fw_main": "V7.1.0",
    }

    state = normalize_device_state(device)

    device_info = state["device_info"]
    assert device_info.value == "Pool Bot"
    assert device_info.attributes["model"] == "Surfer_S2"
    assert device_info.attributes["sw_version"] == "V7.1.0"
    assert state["device_family"].value == "surfer"
