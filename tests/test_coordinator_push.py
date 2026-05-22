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


@pytest.mark.asyncio
async def test_scheduled_refresh_skips_live_rest_polling(hass: HomeAssistant) -> None:
    """Scheduled refreshes should not poll REST live device state."""

    class FakeApi:
        def get_devices(self):
            raise AssertionError("live device list should not be polled")

        def get_device_status(self, sn):
            raise AssertionError("live status should not be polled")

        def get_device_info(self, sn):
            raise AssertionError("live info should not be polled")

    now = dt_util.utcnow()
    coordinator = AiperDataUpdateCoordinator.__new__(AiperDataUpdateCoordinator)
    coordinator.hass = hass
    coordinator.api = cast(Any, FakeApi())
    coordinator._devices = {
        "SN123": {
            "sn": "SN123",
            "name": "Unknown Aiper",
            "model": "Unknown_Model",
            "status_data": {"online": False},
            "info": {"mainFirmwareVersion": "old"},
            "online": False,
        }
    }
    coordinator._last_online = {"SN123": False}
    coordinator.update_interval = timedelta(hours=1)
    coordinator._metadata_refresh = timedelta(hours=24)
    coordinator._last_metadata_fetch = {"SN123": now}
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
    assert data["SN123"]["battery"].value == 70
    assert coordinator._devices["SN123"]["clean_path"] is None


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
