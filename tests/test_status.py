"""Tests for Aiper status-code normalization."""

from __future__ import annotations

from custom_components.aiper.const import status_label, status_running, status_value
from custom_components.aiper.state import normalize_device_state


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
