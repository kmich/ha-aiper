"""Tests for MQTT coordinator behavior."""

from __future__ import annotations

from datetime import datetime, timedelta
from typing import Any, cast
from unittest.mock import AsyncMock

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


def test_apply_device_profile_preserves_surfer_reported_mode_ids() -> None:
    """Non-S1 families keep the device-reported supported_mode_ids untouched.

    Regression test: _apply_device_profile must not unconditionally overwrite
    supported_mode_ids with the family-derived mode map for every model, since
    Surfer's mode-map construction always injects a synthetic mode 0 ("Off")
    even when the hardware never reported it as supported.
    """
    coordinator = _bare_coordinator()
    coordinator._devices["SN123"] = {
        "sn": "SN123",
        "model": "Surfer_S2",
        "supported_mode_ids": [1, 5],
    }

    coordinator._apply_device_profile("SN123")

    assert coordinator._devices["SN123"]["supported_mode_ids"] == [1, 5]


def test_apply_device_profile_reconciles_s1_mode_ids() -> None:
    """Scuba_S1_2025 keeps the derived-profile-is-authoritative behavior,
    stripping an unsupported Waterline id a generic Scuba fallback could
    otherwise leave behind."""
    coordinator = _bare_coordinator()
    coordinator._devices["SN123"] = {
        "sn": "SN123",
        "model": "Scuba_S1_2025",
        "supported_mode_ids": [1, 2, 3, 4, 5],
    }

    coordinator._apply_device_profile("SN123")

    assert coordinator._devices["SN123"]["supported_mode_ids"] == [1, 2, 3, 5]


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
async def test_clean_path_cache_restores_and_persists(hass: HomeAssistant) -> None:
    """The last confirmed path should survive an integration restart."""
    coordinator = _bare_coordinator()

    class FakeStore:
        def __init__(self) -> None:
            self.saved: list[dict[str, int]] = []

        async def async_load(self) -> dict[str, int]:
            return {"SN123": 1, "INVALID": 9}

        async def async_save(self, data: dict[str, int]) -> None:
            self.saved.append(data)

    store = FakeStore()
    coordinator._clean_path_store = cast(Any, store)
    coordinator.hass = hass

    await coordinator.async_restore_clean_path_cache()
    assert coordinator._clean_path_cache == {"SN123": 1}

    coordinator.set_clean_path_cache("SN123", 0)
    await hass.async_block_till_done()
    assert store.saved == [{"SN123": 0}]


@pytest.mark.asyncio
async def test_s1_capability_refresh_is_independent_from_rest_poll() -> None:
    """A direct capability tick should publish path/mode without a REST refresh."""
    coordinator = _bare_coordinator()
    coordinator._devices["SN123"].update({"model": "Scuba_S1_2025", "name": "Scuba S1"})
    coordinator._apply_device_profile("SN123")
    coordinator.data = {"SN123": normalize_device_state(dict(coordinator._devices["SN123"]))}

    class FakeApi:
        def is_mqtt_connected(self) -> bool:
            return True

        async def query_clean_path_setting(self, sn: str) -> int:
            assert sn == "SN123"
            return 1

        async def query_cleaning_mode_setting(self, sn: str) -> int:
            assert sn == "SN123"
            return 2

    coordinator.api = cast(Any, FakeApi())

    await coordinator.async_refresh_s1_capability_settings()

    assert coordinator.data["SN123"]["clean_path"].value == "Adaptive"
    assert coordinator.data["SN123"]["mode_options"].attributes["selected_mode"] == 2


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
    coordinator._live_field_sources = {}
    # Simulate live MQTT state: device is actively returning to base
    coordinator.data = {
        "SN123": {
            **normalize_device_state({"sn": "SN123", "model": "Scuba_X1", "online": True}),
            **normalize_device_state({"sn": "SN123", "model": "Scuba_X1", "machineStatus": 2}),
        }
    }
    # A real MQTT report just set these fields; the source map reflects that,
    # exactly as _on_shadow_update would have recorded it in production.
    coordinator._record_live_field_sources("SN123", "mqtt", ("running", "status", "charging", "mode"), observed_at=now)

    data = await coordinator._async_update_data()

    # REST updated battery (non-MQTT field) should be applied
    assert data["SN123"]["battery"].value == 85
    # MQTT live state must be preserved despite stale REST machineStatus=0
    assert data["SN123"]["status"].value == "Returning"
    assert data["SN123"]["running"].value is True
    assert data["SN123"]["charging"].value is False


@pytest.mark.asyncio
async def test_scuba_s1_fresh_rest_charging_replaces_stale_mqtt_state(hass: HomeAssistant) -> None:
    """S1 REST charging coherently replaces a stale low-battery MQTT report."""

    class FakeApi:
        async def get_devices(self):
            return [
                {
                    "sn": "SN123",
                    "name": "Scuba S1",
                    "model": "Scuba_S1_2025",
                    "online": True,
                    "battLevel": 56,
                    "machineStatus": 2,
                }
            ]

        async def get_device_info(self, sn):
            raise AssertionError("metadata info should not be polled before refresh interval")

        def is_mqtt_connected(self) -> bool:
            return False

    now = dt_util.utcnow()
    coordinator = AiperDataUpdateCoordinator.__new__(AiperDataUpdateCoordinator)
    coordinator.hass = hass
    coordinator.api = cast(Any, FakeApi())
    coordinator._devices = {
        "SN123": {
            "sn": "SN123",
            "name": "Scuba S1",
            "model": "Scuba_S1_2025",
            "online": True,
            "in_water": 1,
            "mode": 1,
            "runTime": 210,
        }
    }
    coordinator._last_online = {"SN123": True}
    coordinator.update_interval = timedelta(hours=1)
    coordinator._metadata_refresh = timedelta(hours=24)
    coordinator._last_metadata_fetch = {"SN123": now}
    coordinator._history_cache = {}
    coordinator._consumables_cache = {"SN123": []}
    coordinator._clean_path_cache = {}
    coordinator._selected_mode_cache = {}
    coordinator._command_state = {}
    coordinator.data = {
        "SN123": normalize_device_state(
            {
                **coordinator._devices["SN123"],
                "battLevel": 9,
                "machineStatus": 1,
            }
        )
    }

    data = await coordinator._async_update_data()

    assert data["SN123"]["battery"].value == 56
    assert data["SN123"]["status"].value == "Charging"
    assert data["SN123"]["status"].attributes == {"code": 2}
    assert data["SN123"]["charging"].value is True
    assert data["SN123"]["running"].value is False
    assert data["SN123"]["in_water"].value is False
    assert data["SN123"]["mode"].attributes == {"code": 0}
    assert data["SN123"]["runtime"].value == 0.0
    assert coordinator._state_reconciliation["SN123"]["trigger"] == "rest_machine_status"
    assert coordinator._state_reconciliation["SN123"]["events"] == [
        {
            key: coordinator._state_reconciliation["SN123"][key]
            for key in ("trigger", "observed_at", "rest_status", "battery_samples", "applied")
        }
    ]


@pytest.mark.asyncio
async def test_scuba_s1_rest_charging_defers_to_recent_mqtt_cleaning_report(hass: HomeAssistant) -> None:
    """A stale REST 'charging' snapshot must not override a fresher MQTT
    report that still shows the device actively cleaning.

    Regression test: unlike the sibling battery_rise_fallback branch, the
    rest_status-in-(2,3) branch originally had no recency check against
    MQTT at all, so a lagging REST poll could silently overwrite a live
    MQTT "Cleaning" state with "Charging".
    """

    class FakeApi:
        async def get_devices(self):
            return [
                {
                    "sn": "SN123",
                    "name": "Scuba S1",
                    "model": "Scuba_S1_2025",
                    "online": True,
                    "battLevel": 56,
                    "machineStatus": 2,  # stale REST snapshot: Charging
                }
            ]

        async def get_device_info(self, sn):
            raise AssertionError("metadata info should not be polled before refresh interval")

        def is_mqtt_connected(self) -> bool:
            return False

    now = dt_util.utcnow()
    coordinator = AiperDataUpdateCoordinator.__new__(AiperDataUpdateCoordinator)
    coordinator.hass = hass
    coordinator.api = cast(Any, FakeApi())
    coordinator._devices = {
        "SN123": {
            "sn": "SN123",
            "name": "Scuba S1",
            "model": "Scuba_S1_2025",
            "online": True,
            "in_water": 1,
            "mode": 1,
            "runTime": 210,
        }
    }
    coordinator._last_online = {"SN123": True}
    coordinator.update_interval = timedelta(hours=1)
    coordinator._metadata_refresh = timedelta(hours=24)
    coordinator._last_metadata_fetch = {"SN123": now}
    coordinator._history_cache = {}
    coordinator._consumables_cache = {"SN123": []}
    coordinator._clean_path_cache = {}
    coordinator._selected_mode_cache = {}
    coordinator._command_state = {}
    # A very recent MQTT report still shows the device actively Cleaning.
    coordinator._last_s1_mqtt_machine_report = {"SN123": {"observed_at": now - timedelta(seconds=5), "status": 1}}
    coordinator.data = {
        "SN123": normalize_device_state(
            {
                **coordinator._devices["SN123"],
                "machineStatus": 1,
            }
        )
    }

    data = await coordinator._async_update_data()

    # The stale REST "Charging" reading must not override the fresher,
    # correct MQTT "Cleaning" state.
    assert data["SN123"]["status"].value == "Cleaning"
    assert data["SN123"]["running"].value is True
    assert data["SN123"]["charging"].value is False


def _live_state_coordinator(hass: HomeAssistant, api: Any, now: datetime) -> AiperDataUpdateCoordinator:
    coordinator = AiperDataUpdateCoordinator.__new__(AiperDataUpdateCoordinator)
    coordinator.hass = hass
    coordinator.api = cast(Any, api)
    coordinator._devices = {
        "SN123": {
            "sn": "SN123",
            "name": "Scuba S1",
            "model": "Scuba_S1_2025",
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
    coordinator._selected_mode_cache = {}
    coordinator._command_state = {}
    coordinator._s1_battery_samples = {}
    coordinator._last_s1_mqtt_machine_report = {}
    coordinator._state_reconciliation = {}
    coordinator._live_field_sources = {}
    return coordinator


@pytest.mark.asyncio
async def test_stale_mqtt_state_yields_to_fresh_rest_after_ttl(hass: HomeAssistant) -> None:
    """Once an MQTT field ages past the TTL, a fresh REST value takes over.

    Regression: a stale MQTT "Idle" shadow could mask a fresh REST
    "Cleaning" status indefinitely.
    """

    class FakeApi:
        async def get_devices(self):
            return [
                {
                    "sn": "SN123",
                    "name": "Scuba S1",
                    "model": "Scuba_S1_2025",
                    "online": True,
                    "battLevel": 80,
                    "machineStatus": 1,  # fresh REST: Cleaning
                    "runTime": 6,
                }
            ]

        async def get_device_info(self, sn):
            raise AssertionError("metadata info should not be polled before refresh interval")

        def is_mqtt_connected(self) -> bool:
            return False

    now = dt_util.utcnow()
    coordinator = _live_state_coordinator(hass, FakeApi(), now)
    coordinator.data = {"SN123": normalize_device_state({"sn": "SN123", "model": "Scuba_S1_2025", "machineStatus": 0})}
    # MQTT last set the live fields well beyond MQTT_LIVE_STATE_TTL ago.
    coordinator._record_live_field_sources(
        "SN123", "mqtt", ("running", "status", "charging", "mode"), observed_at=now - timedelta(minutes=20)
    )
    capability_refresh = AsyncMock()
    coordinator.async_refresh_s1_capability_settings = capability_refresh  # type: ignore[method-assign]

    data = await coordinator._async_update_data()

    capability_refresh.assert_not_awaited()
    assert data["SN123"]["status"].value == "Cleaning"
    assert data["SN123"]["running"].value is True
    assert data["SN123"]["charging"].value is False
    assert coordinator.diagnostic_field_sources["SN123"]["status"]["source"] == "rest"


@pytest.mark.asyncio
async def test_rest_charging_applies_immediately_after_mqtt_dropout(hass: HomeAssistant) -> None:
    """An explicit REST charging correction is not held back by the MQTT TTL.

    If MQTT last reported Cleaning a few minutes ago and then went silent,
    a REST device-list snapshot of Charging (status 2) is a physical-state
    correction and must apply on the next poll, not wait out the full
    MQTT_LIVE_STATE_TTL.
    """

    class FakeApi:
        async def get_devices(self):
            return [
                {
                    "sn": "SN123",
                    "name": "Scuba S1",
                    "model": "Scuba_S1_2025",
                    "online": True,
                    "battLevel": 61,
                    "machineStatus": 2,  # REST now: Charging
                }
            ]

        async def get_device_info(self, sn):
            raise AssertionError("metadata info should not be polled before refresh interval")

        def is_mqtt_connected(self) -> bool:
            return False

    now = dt_util.utcnow()
    coordinator = _live_state_coordinator(hass, FakeApi(), now)
    coordinator._devices["SN123"].update({"in_water": 1, "mode": 1, "runTime": 180})
    coordinator.data = {"SN123": normalize_device_state({**coordinator._devices["SN123"], "machineStatus": 1})}
    # MQTT reported Cleaning 3 minutes ago (inside the TTL) then dropped.
    mqtt_seen = now - timedelta(minutes=3)
    coordinator._last_s1_mqtt_machine_report = {"SN123": {"observed_at": mqtt_seen, "status": 1}}
    coordinator._record_live_field_sources(
        "SN123", "mqtt", ("running", "status", "charging", "mode"), observed_at=mqtt_seen
    )

    data = await coordinator._async_update_data()

    assert data["SN123"]["status"].value == "Charging"
    assert data["SN123"]["charging"].value is True
    assert data["SN123"]["running"].value is False
    assert data["SN123"]["in_water"].value is False
    assert coordinator._state_reconciliation["SN123"]["trigger"] == "rest_machine_status"


@pytest.mark.parametrize(
    ("machine_status", "reported_water", "expected_status"),
    [(1, 0, "Cleaning"), (10, None, "Offline")],
)
@pytest.mark.asyncio
async def test_scuba_s1_rest_cleaning_or_parked_implies_wet(
    hass: HomeAssistant,
    machine_status: int,
    reported_water: int | None,
    expected_status: str,
) -> None:
    """S1 Cleaning overrides stale Dry; Parked stays Wet without a newer report.

    A device physically Cleaning keeps that status even while the cloud
    online flag reads false. Parked (status 10) is not running, so it still
    resolves to Offline when the cloud flag is false.
    """

    class FakeApi:
        async def get_devices(self):
            device = {
                "sn": "SN123",
                "name": "Scuba S1",
                "model": "Scuba_S1_2025",
                "online": False,
                "battLevel": 89,
                "machineStatus": machine_status,
            }
            if reported_water is not None:
                device["in_water"] = reported_water
            return [device]

        async def get_device_info(self, sn):
            raise AssertionError("metadata info should not be polled before refresh interval")

        def is_mqtt_connected(self) -> bool:
            return False

    now = dt_util.utcnow()
    coordinator = AiperDataUpdateCoordinator.__new__(AiperDataUpdateCoordinator)
    coordinator.hass = hass
    coordinator.api = cast(Any, FakeApi())
    coordinator._devices = {
        "SN123": {
            "sn": "SN123",
            "name": "Scuba S1",
            "model": "Scuba_S1_2025",
            "online": False,
            "in_water": 0,
        }
    }
    coordinator._last_online = {"SN123": False}
    coordinator.update_interval = timedelta(hours=1)
    coordinator._metadata_refresh = timedelta(hours=24)
    coordinator._last_metadata_fetch = {"SN123": now}
    coordinator._history_cache = {}
    coordinator._consumables_cache = {"SN123": []}
    coordinator._clean_path_cache = {}
    coordinator._selected_mode_cache = {}
    coordinator._command_state = {}
    coordinator._s1_battery_samples = {}
    coordinator._last_s1_mqtt_machine_report = {}
    coordinator._state_reconciliation = {}
    coordinator.data = {
        "SN123": normalize_device_state(
            {
                **coordinator._devices["SN123"],
                "battLevel": 100,
                "machineStatus": 0,
            }
        )
    }

    data = await coordinator._async_update_data()

    assert data["SN123"]["battery"].value == 89
    assert data["SN123"]["status"].value == expected_status
    assert data["SN123"]["in_water"].value is True
    assert coordinator._devices["SN123"]["in_water"] == 1


@pytest.mark.asyncio
async def test_scuba_s1_sustained_battery_rise_is_conservative_charging_fallback(
    hass: HomeAssistant,
) -> None:
    """S1 may infer charging only from a sustained rise without fresher status."""

    class FakeApi:
        async def get_devices(self):
            return [
                {
                    "sn": "SN123",
                    "name": "Scuba S1",
                    "model": "Scuba_S1_2025",
                    "online": True,
                    "battLevel": 24,
                }
            ]

        async def get_device_info(self, sn):
            raise AssertionError("metadata info should not be polled before refresh interval")

        def is_mqtt_connected(self) -> bool:
            return False

    now = dt_util.utcnow()
    coordinator = AiperDataUpdateCoordinator.__new__(AiperDataUpdateCoordinator)
    coordinator.hass = hass
    coordinator.api = cast(Any, FakeApi())
    coordinator._devices = {
        "SN123": {
            "sn": "SN123",
            "name": "Scuba S1",
            "model": "Scuba_S1_2025",
            "online": True,
            "machineStatus": 1,
            "in_water": 1,
            "mode": 1,
            "runTime": 210,
        }
    }
    coordinator._last_online = {"SN123": True}
    coordinator.update_interval = timedelta(hours=1)
    coordinator._metadata_refresh = timedelta(hours=24)
    coordinator._last_metadata_fetch = {"SN123": now}
    coordinator._history_cache = {}
    coordinator._consumables_cache = {"SN123": []}
    coordinator._clean_path_cache = {}
    coordinator._selected_mode_cache = {}
    coordinator._command_state = {}
    coordinator._s1_battery_samples = {
        "SN123": [
            {"observed_at": now - timedelta(minutes=5), "battery": 20},
            {"observed_at": now - timedelta(minutes=3), "battery": 22},
        ]
    }
    coordinator._last_s1_mqtt_machine_report = {}
    coordinator.data = {
        "SN123": normalize_device_state(
            {
                **coordinator._devices["SN123"],
                "battLevel": 22,
            }
        )
    }

    data = await coordinator._async_update_data()

    assert data["SN123"]["status"].value == "Charging"
    assert data["SN123"]["charging"].value is True
    assert data["SN123"]["running"].value is False
    assert data["SN123"]["in_water"].value is False
    assert coordinator._state_reconciliation["SN123"]["trigger"] == "battery_rise_fallback"


def test_scuba_s1_battery_rise_fallback_rejects_recent_mqtt_report() -> None:
    """A newer MQTT machine report remains authoritative over battery trend."""
    coordinator = _bare_coordinator()
    now = dt_util.utcnow()
    coordinator._s1_battery_samples = {
        "SN123": [
            {"observed_at": now - timedelta(minutes=5), "battery": 20},
            {"observed_at": now - timedelta(minutes=3), "battery": 22},
            {"observed_at": now, "battery": 24},
        ]
    }
    coordinator._last_s1_mqtt_machine_report = {"SN123": {"observed_at": now - timedelta(minutes=1), "status": 1}}

    assert coordinator._s1_battery_rise_indicates_charging("SN123") is False


def test_s1_reconciliation_timeline_deduplicates_repeated_source() -> None:
    """Diagnostics retain source order without flooding on repeated REST polls."""
    coordinator = _bare_coordinator()
    coordinator._state_reconciliation = {}
    coordinator._s1_battery_samples = {}

    coordinator._record_s1_reconciliation("SN123", trigger="mqtt_machine_status")
    coordinator._record_s1_reconciliation("SN123", trigger="rest_machine_status", rest_status=2)
    coordinator._record_s1_reconciliation("SN123", trigger="rest_machine_status", rest_status=2)

    events = coordinator._state_reconciliation["SN123"]["events"]
    assert [(event["trigger"], event["rest_status"]) for event in events] == [
        ("mqtt_machine_status", None),
        ("rest_machine_status", 2),
    ]


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


def test_clean_path_pending_uses_longer_confirmation_window() -> None:
    """S1 clean-path intent survives the normal command timeout."""
    coordinator = _bare_coordinator()
    coordinator._devices["SN123"]["model"] = "Scuba_S1_2025"
    coordinator._command_state = {
        "SN123": {
            "pending": {
                "clean_path": {
                    "target": 0,
                    "since": (
                        dt_util.utcnow() - timedelta(seconds=coordinator.PENDING_TIMEOUT_SECONDS + 1)
                    ).isoformat(),
                    "source": "test",
                }
            },
            "last": {},
        }
    }

    assert coordinator.get_pending_command_target("SN123", "clean_path") == 0


def test_clean_path_pending_window_is_not_extended_for_non_s1_models() -> None:
    """Non-S1 clean-path-capable models (e.g. Scuba S2/S3) keep the standard
    command timeout — the extended window exists only for Scuba_S1_2025's
    slower AT+AUTO? confirmation, not for every clean-path-capable model."""
    coordinator = _bare_coordinator()
    coordinator._devices["SN123"]["model"] = "Scuba_S3"
    coordinator._command_state = {
        "SN123": {
            "pending": {
                "clean_path": {
                    "target": 0,
                    "since": (
                        dt_util.utcnow() - timedelta(seconds=coordinator.PENDING_TIMEOUT_SECONDS + 1)
                    ).isoformat(),
                    "source": "test",
                }
            },
            "last": {},
        }
    }

    assert coordinator.get_pending_command_target("SN123", "clean_path") is None


@pytest.mark.asyncio
async def test_scuba_s1_clean_path_confirmation_ignores_stale_readback() -> None:
    """S1 confirmation retries until AT+AUTO? reports the requested value."""
    coordinator = _bare_coordinator()
    coordinator._devices["SN123"]["model"] = "Scuba_S1_2025"

    class FakeApi:
        def __init__(self) -> None:
            self.responses = iter((1, 0))

        async def query_clean_path_setting(self, sn: str) -> int:
            assert sn == "SN123"
            return next(self.responses)

    coordinator.api = cast(Any, FakeApi())
    coordinator.note_command_sent("SN123", "clean_path", 0, source="test")

    confirmed = await coordinator.async_confirm_clean_path_selection("SN123", 0, retry_delays=(0, 0))

    assert confirmed is True
    assert coordinator._clean_path_cache["SN123"] == 0
    assert coordinator._devices["SN123"]["clean_path"] == 0
    assert coordinator.data["SN123"]["clean_path"].value == "S-shaped"
    assert coordinator.get_pending_command_target("SN123", "clean_path") is None
    assert coordinator.get_command_state("SN123")["last"]["clean_path"]["result"] == "confirmed"
