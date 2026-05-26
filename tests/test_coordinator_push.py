"""Tests for MQTT coordinator behavior."""

from __future__ import annotations

from datetime import timedelta
from typing import Any, cast

import pytest
from homeassistant.core import HomeAssistant
from homeassistant.util import dt as dt_util

from custom_components.aiper.coordinator import AiperDataUpdateCoordinator
from custom_components.aiper.state import normalize_device_state


def _bare_coordinator() -> AiperDataUpdateCoordinator:
    coordinator = AiperDataUpdateCoordinator.__new__(AiperDataUpdateCoordinator)
    coordinator._consumables_cache = {}
    coordinator._history_cache = {}
    coordinator._clean_path_cache = {}
    coordinator._devices = {
        "SN123": {
            "sn": "SN123",
            "battLevel": 10,
            "machineStatus": 128,
            "mode": 1,
            "online": False,
        }
    }
    coordinator._last_online = {"SN123": False}
    coordinator._command_state = {}
    coordinator.data = {"SN123": normalize_device_state(dict(coordinator._devices["SN123"]))}

    def _set_updated_data(data):
        coordinator.data = data

    coordinator.async_set_updated_data = _set_updated_data  # type: ignore[method-assign]
    coordinator.async_update_listeners = lambda: None  # type: ignore[method-assign]
    return coordinator


def test_shadow_update_promotes_live_state() -> None:
    """MQTT reported data should update normalized entity state."""
    coordinator = _bare_coordinator()

    coordinator._on_shadow_update(
        "SN123",
        {
            "state": {
                "reported": {
                    "Machine": {"cap": 70, "status": 129, "mode": 5},
                    "NetStat": {"online": 1, "sta": 2},
                    "OpInfo": {"wifi_name": "Mackay", "wifi_rssi": -79},
                    "OtaStatus": {"version": "V7.1.0", "subver": "V1.0.7.1,V1.0.6.0"},
                }
            }
        },
    )

    device = coordinator.data["SN123"]
    raw_device = coordinator._devices["SN123"]
    assert raw_device["battLevel"] == 10
    assert raw_device["machineStatus"] == 128
    assert device["running"].value is True
    assert device["mode"].attributes == {"code": 5}
    assert device["mode"].value == "Scheduled"
    assert device["online"].value is True
    assert device["battery"].value == 70
    assert device["wifi"].value is True
    assert device["wifi_signal"].value == -79
    assert device["main_version"].value == "V7.1.0"
    assert device["mcu_version"].value == "V1.0.7.1,V1.0.6.0"


def test_shadow_update_promotes_hydrocomm_w2_state() -> None:
    """HydroComm/W2 shadow components should become live HA sensor state."""
    coordinator = _bare_coordinator()
    coordinator._devices["W2SN"] = {
        "sn": "W2SN",
        "name": "HydroComm",
        "model": "HydroComm",
        "deviceType": "4",
        "online": True,
    }
    coordinator._last_online["W2SN"] = True
    coordinator.data["W2SN"] = normalize_device_state(dict(coordinator._devices["W2SN"]))

    coordinator._on_shadow_update(
        "W2SN",
        {
            "state": {
                "reported": {
                    "Machine": {"status": 2},
                    "W2Info": {"bal_cal": 77, "chargeType": 2, "lux": 450},
                    "W2WQS": {"result": 0, "temp": 27.5, "ph": 7.4, "orp": 668, "swpi": 91},
                    "W2LifeTime": {"sn1": "P1", "usetime1": "10", "ctime1": "1714608000"},
                    "W2SensorStatus": {"sensor1": 1, "sensor2": 0, "sensor3": 1, "ulsound": 1},
                    "W2AlarmMessage": {"Alarm": 8192, "time": "2026-05-26T12:00:00Z"},
                }
            }
        },
    )

    device = coordinator.data["W2SN"]
    assert device["status"].value == "Charging"
    assert device["charging"].value is True
    assert device["battery"].value == 77
    assert device["charge_type"].value == "Solar charging"
    assert device["solar_charging"].value is True
    assert device["temperature"].value == 27.5
    assert device["ph"].value == 7.4
    assert device["orp"].value == 668.0
    assert device["water_quality_score"].value == 91.0
    assert device["probe_1_status"].value == "Installed"
    assert device["probe_1_status"].attributes["probe_serial"] == "P1"
    assert device["warning"].value == "Battery low"


@pytest.mark.asyncio
async def test_scheduled_refresh_merges_live_rest_polling(hass: HomeAssistant) -> None:
    """Scheduled refreshes should merge light REST state such as charging."""

    class FakeApi:
        async def get_devices(self):
            return [
                {
                    "sn": "SN123",
                    "name": "Scuba X1",
                    "model": "Scuba_X1",
                    "online": True,
                    "battLevel": 90,
                    "machineStatus": 131,
                }
            ]

        async def get_device_info(self, sn):
            raise AssertionError("metadata info should not be polled before refresh interval")

    now = dt_util.utcnow()
    coordinator = AiperDataUpdateCoordinator.__new__(AiperDataUpdateCoordinator)
    coordinator.hass = hass
    coordinator.api = cast(Any, FakeApi())
    coordinator._devices = {
        "SN123": {
            "sn": "SN123",
            "name": "Scuba X1",
            "model": "Scuba_X1",
            "info": {"mainFirmwareVersion": "old"},
            "online": False,
        }
    }
    coordinator._last_online = {"SN123": False}
    coordinator.update_interval = timedelta(hours=1)
    coordinator._metadata_refresh = timedelta(hours=24)
    coordinator._last_metadata_fetch = {"SN123": now}
    coordinator._history_cache = {}
    coordinator._consumables_cache = {"SN123": []}
    coordinator._clean_path_cache = {}
    coordinator._command_state = {}
    coordinator.data = {
        "SN123": normalize_device_state(
            {
                **coordinator._devices["SN123"],
                "online": True,
                "battLevel": 70,
            }
        )
    }

    data = await coordinator._async_update_data()

    assert coordinator._devices["SN123"]["online"] is True
    assert data["SN123"]["online"].value is True
    assert data["SN123"]["battery"].value == 90
    assert data["SN123"]["status"].value == "Charging"
    assert coordinator._devices["SN123"]["clean_path"] is None


@pytest.mark.asyncio
async def test_rest_refresh_does_not_overwrite_mqtt_live_state(hass: HomeAssistant) -> None:
    """REST slow-refresh must not overwrite authoritative MQTT running/status/charging/mode."""

    class FakeApi:
        async def get_devices(self):
            # REST reports stale Idle/0 for machineStatus while device is actually running
            return [
                {
                    "sn": "SN123",
                    "name": "Scuba X1",
                    "model": "Scuba_X1",
                    "online": True,
                    "battLevel": 85,
                    "machineStatus": 0,  # stale REST value: Idle
                }
            ]

        async def get_device_info(self, sn):
            raise AssertionError("metadata info should not be polled before refresh interval")

    now = dt_util.utcnow()
    coordinator = AiperDataUpdateCoordinator.__new__(AiperDataUpdateCoordinator)
    coordinator.hass = hass
    coordinator.api = cast(Any, FakeApi())
    coordinator._devices = {
        "SN123": {
            "sn": "SN123",
            "name": "Scuba X1",
            "model": "Scuba_X1",
            "online": True,
        }
    }
    coordinator._last_online = {"SN123": True}
    coordinator.update_interval = timedelta(hours=1)
    coordinator._metadata_refresh = timedelta(hours=24)
    coordinator._last_metadata_fetch = {"SN123": now}
    coordinator._history_cache = {}
    coordinator._consumables_cache = {"SN123": []}
    coordinator._clean_path_cache = {}
    coordinator._command_state = {}
    # Simulate live MQTT state: device is actively returning to base
    coordinator.data = {
        "SN123": {
            **normalize_device_state({"sn": "SN123", "model": "Scuba_X1", "online": True}),
            **normalize_device_state({"sn": "SN123", "model": "Scuba_X1", "machineStatus": 2}),
        }
    }

    data = await coordinator._async_update_data()

    # REST updated battery (non-MQTT field) should be applied
    assert data["SN123"]["battery"].value == 85
    # MQTT live state must be preserved despite stale REST machineStatus=0
    assert data["SN123"]["status"].value == "Returning"
    assert data["SN123"]["running"].value is True
    assert data["SN123"]["charging"].value is False


def test_pending_running_intent_confirms_from_reported_status() -> None:
    """Running intent should clear when MQTT reports matching running state."""
    coordinator = _bare_coordinator()
    coordinator.note_command_sent("SN123", "running", True, source="test")

    assert coordinator.get_pending_command_target("SN123", "running") is True

    coordinator._confirm_pending_commands("SN123", {"status": 129})

    assert coordinator.get_pending_command_target("SN123", "running") is None
    assert coordinator.get_command_state("SN123")["last"]["running"]["result"] == "confirmed"


def test_pending_stopped_intent_confirms_from_idle_status() -> None:
    """Stopped intent should clear when MQTT reports an idle base status."""
    coordinator = _bare_coordinator()
    coordinator.note_command_sent("SN123", "running", False, source="test")

    assert coordinator.get_pending_command_target("SN123", "running") is False

    coordinator._confirm_pending_commands("SN123", {"status": 128})

    assert coordinator.get_pending_command_target("SN123", "running") is None
    assert coordinator.get_command_state("SN123")["last"]["running"]["result"] == "confirmed"


def test_pending_mode_intent_confirms_from_reported_mode() -> None:
    """Mode intent should use the same command bucket that the coordinator confirms."""
    coordinator = _bare_coordinator()
    coordinator.note_command_sent("SN123", "mode", 2, source="test")

    assert coordinator.get_pending_command_target("SN123", "mode") == 2

    coordinator._confirm_pending_commands("SN123", {"mode": 2})

    assert coordinator.get_pending_command_target("SN123", "mode") is None
    assert coordinator.get_command_state("SN123")["last"]["mode"]["result"] == "confirmed"


def test_pending_running_intent_expires() -> None:
    """Running intent should not outlive the coordinator pending timeout."""
    coordinator = _bare_coordinator()
    coordinator._command_state = {
        "SN123": {
            "pending": {
                "running": {
                    "target": True,
                    "since": (
                        dt_util.utcnow() - timedelta(seconds=coordinator.PENDING_TIMEOUT_SECONDS + 1)
                    ).isoformat(),
                    "source": "test",
                }
            },
            "last": {},
        }
    }

    assert coordinator.get_pending_command_target("SN123", "running") is None
    assert coordinator.get_command_state("SN123")["last"]["running"]["result"] == "timeout"
