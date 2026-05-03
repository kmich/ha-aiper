"""Tests for MQTT push-primary coordinator behavior."""

from __future__ import annotations

from datetime import timedelta

import pytest
from homeassistant.util import dt as dt_util

from custom_components.aiper.coordinator import AiperDataUpdateCoordinator


def _bare_coordinator() -> AiperDataUpdateCoordinator:
    coordinator = AiperDataUpdateCoordinator.__new__(AiperDataUpdateCoordinator)
    coordinator._shadow_data = {}
    coordinator._consumables_cache = {}
    coordinator._devices = {
        "SN123": {
            "sn": "SN123",
            "battLevel": 10,
            "machineStatus": 128,
            "mode": 1,
            "_ha_online": False,
        }
    }
    coordinator._last_online = {"SN123": False}
    coordinator._push_primary = True
    coordinator.data = {"SN123": dict(coordinator._devices["SN123"])}

    def _set_updated_data(data):
        coordinator.data = data

    coordinator.async_set_updated_data = _set_updated_data
    return coordinator


def test_shadow_update_promotes_live_state_in_push_primary_mode() -> None:
    """MQTT shadow data should become the primary entity state."""
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
    assert device["battLevel"] == 70
    assert device["machineStatus"] == 129
    assert device["mode"] == 5
    assert device["_ha_online"] is True
    assert device["wifiName"] == "Mackay"
    assert device["wifiRssi"] == -79
    assert device["_ha_fw_main"] == "V7.1.0"
    assert device["_ha_fw_mcu"] == "V1.0.7.1,V1.0.6.0"
    assert device["shadow"]["machine"]["cap"] == 70


def test_set_push_primary_switches_update_interval() -> None:
    """Coordinator should switch between push reconciliation and REST fallback polling."""
    coordinator = AiperDataUpdateCoordinator.__new__(AiperDataUpdateCoordinator)
    coordinator._push_reconcile_interval = timedelta(hours=1)
    coordinator._normal_interval = timedelta(seconds=120)
    coordinator._fast_poll_until = "set"
    coordinator.update_interval = None

    coordinator.set_push_primary(True)
    assert coordinator._push_primary is True
    assert coordinator._fast_poll_until is None
    assert coordinator.update_interval == timedelta(hours=1)

    coordinator.set_push_primary(False)
    assert coordinator._push_primary is False
    assert coordinator.update_interval == timedelta(seconds=120)


@pytest.mark.asyncio
async def test_push_primary_refresh_skips_live_rest_polling() -> None:
    """Scheduled push-primary refreshes should not poll live device state."""

    class FakeHass:
        async def async_add_executor_job(self, func, *args):
            return func(*args)

    class FakeApi:
        def get_devices(self):
            raise AssertionError("live device list should not be polled")

        def get_device_status(self, sn):
            raise AssertionError("live status should not be polled")

        def get_device_info(self, sn):
            raise AssertionError("live info should not be polled")

    now = dt_util.utcnow()
    coordinator = AiperDataUpdateCoordinator.__new__(AiperDataUpdateCoordinator)
    coordinator.hass = FakeHass()
    coordinator.api = FakeApi()
    coordinator._push_primary = True
    coordinator._devices = {
        "SN123": {
            "sn": "SN123",
            "name": "Surfer S2",
            "status_data": {"online": False},
            "info": {"mainVersion": "old"},
            "_ha_online": False,
        }
    }
    coordinator._shadow_data = {"SN123": {"netstat": {"online": 1}, "machine": {"cap": 70}}}
    coordinator._last_online = {"SN123": False}
    coordinator._last_fast_trigger = None
    coordinator._fast_poll_until = None
    coordinator.update_interval = timedelta(hours=1)
    coordinator._history_refresh = timedelta(hours=6)
    coordinator._consumables_refresh = timedelta(hours=24)
    coordinator._clean_path_refresh = timedelta(hours=6)
    coordinator._last_history_fetch = {"SN123": now}
    coordinator._last_consumables_fetch = {"SN123": now}
    coordinator._last_clean_path_fetch = {"SN123": now}
    coordinator._history_cache = {"SN123": {"total_count": 1, "total_hours": 2.0, "records": []}}
    coordinator._consumables_cache = {"SN123": []}
    coordinator._clean_path_cache = {}
    coordinator._command_state = {}

    data = await coordinator._async_update_data()

    assert data["SN123"]["_ha_online"] is True
    assert data["SN123"]["shadow"]["machine"]["cap"] == 70
