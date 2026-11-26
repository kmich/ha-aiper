"""Coordinator tests for MQTT payload shapes, command tracking and caches."""

from __future__ import annotations

from datetime import timedelta
from typing import Any
from unittest.mock import MagicMock

import pytest
from homeassistant.core import HomeAssistant
from homeassistant.util import dt as dt_util

from custom_components.aiper.coordinator import AiperDataUpdateCoordinator
from custom_components.aiper.state import normalize_device_state
from tests.coordinator_factory import BaseFakeApi, make_coordinator

SN = "SN1234567890"


def _coordinator(model: str = "Scuba_X1", **raw: Any) -> AiperDataUpdateCoordinator:
    device = {"sn": SN, "name": "Robot", "model": model, "online": True, **raw}
    coordinator = make_coordinator(BaseFakeApi(), _devices={SN: dict(device)})
    coordinator.data = {SN: normalize_device_state(dict(device))}
    coordinator.async_update_listeners = lambda: None  # type: ignore[method-assign]
    return coordinator


def test_delta_topic_only_applies_clean_path() -> None:
    coordinator = _coordinator()

    coordinator._on_shadow_update(
        SN,
        {"_topic": f"$aws/things/{SN}/shadow/update/delta", "state": {"Machine": {"cleanPath": 1, "status": 1}}},
    )

    assert coordinator._clean_path_cache[SN] == 1
    assert coordinator.data[SN]["clean_path"].value == "Adaptive"
    assert coordinator.data[SN]["running"].value is not True


def test_documents_topic_uses_reported_state_and_desired_clean_path() -> None:
    coordinator = _coordinator()

    coordinator._on_shadow_update(
        SN,
        {
            "_topic": f"$aws/things/{SN}/shadow/update/documents",
            "current": {"state": {"desired": {"Machine": {"cleanPath": 0}}, "reported": {"Machine": {"cap": 55}}}},
        },
    )
    assert coordinator.data[SN]["battery"].value == 55
    assert coordinator._clean_path_cache[SN] == 0

    coordinator._on_shadow_update(
        SN,
        {"_topic": f"$aws/things/{SN}/shadow/update/documents", "current": {"state": {"Machine": {"cap": 44}}}},
    )
    assert coordinator.data[SN]["battery"].value == 44


def test_desired_only_state_is_ignored_and_bare_state_is_accepted() -> None:
    coordinator = _coordinator()

    coordinator._on_shadow_update(SN, {"state": {"desired": {"Machine": {"cap": 1, "cleanPath": 1}}}})
    assert coordinator.data[SN]["battery"].value != 1
    assert coordinator._clean_path_cache[SN] == 1

    coordinator._on_shadow_update(SN, {"state": {"Machine": {"cap": 33}}})
    assert coordinator.data[SN]["battery"].value == 33


def test_lowercase_and_typed_component_payloads() -> None:
    coordinator = _coordinator(model="Scuba_S1_2025")

    coordinator._on_shadow_update(SN, {"machine": {"cap": 20}, "netstat": {"online": 1}})
    assert coordinator.data[SN]["battery"].value == 20

    coordinator._on_shadow_update(SN, {"type": "Machine", "data": {"status": 1, "report": "+INFO: 1,2,64,0,12,1,0"}})
    assert coordinator.data[SN]["battery"].value == 64

    coordinator._on_shadow_update(SN, {"type": "OpInfo", "data": {"wifi_rssi": -60}})
    assert coordinator.data[SN]["wifi_signal"].value == -60

    coordinator._on_shadow_update(SN, {"type": "NetStat", "data": {"online": 0}})
    assert coordinator.data[SN]["online"].value is False

    coordinator._on_shadow_update(SN, {"GetWorkMode": {"cleanPath": 1, "modeList": [1, 2]}})
    coordinator._on_shadow_update(SN, {"CycleWork": {"cleanPath": 0}})
    assert coordinator._clean_path_cache[SN] == 0

    coordinator._on_shadow_update(SN, {"type": "W2WQS", "data": {"ph": 7.4}})
    coordinator._apply_shadow_update(SN, 123)  # bare JSON scalar: ignored
    coordinator._apply_shadow_update(SN, {"_topic": "t", "state": {"reported": {"Machine": {"cap": 12}}}})
    assert coordinator.data[SN]["battery"].value == 12


@pytest.mark.parametrize(
    ("report", "expected"),
    [
        (
            "+INFO: 1,2,64,0,12,1,7",
            {"status": 1, "mode": 2, "cap": 64, "warn": 0, "run_time": 12, "in_water": 1, "warn_code": 7},
        ),
        ("+WARN:1,256\n+WORKMODE:3", {"warn": 1, "warn_code": 256, "mode": 3}),
        ("+MODE:x", {}),
        ("+INFO: a,b,c", {}),
        ("\n\n", {}),
    ],
)
def test_parse_machine_report(report: str, expected: dict[str, Any]) -> None:
    assert AiperDataUpdateCoordinator._parse_machine_report(report) == expected


def test_handle_shadow_update_after_loop_close_is_ignored() -> None:
    coordinator = _coordinator()
    coordinator.hass = MagicMock()
    coordinator.hass.loop.call_soon_threadsafe.side_effect = RuntimeError("Event loop is closed")

    coordinator.make_shadow_callback(SN)(SN, {"state": {}})


def test_mqtt_freshness_requires_a_timestamp() -> None:
    coordinator = _coordinator()
    coordinator._live_field_sources = {SN: {"status": {"source": "mqtt", "observed_at": None}}}

    assert coordinator._mqtt_field_is_fresh(SN, "status", dt_util.utcnow()) is False


@pytest.mark.asyncio
async def test_subscribe_all_devices_tolerates_errors() -> None:
    class Api(BaseFakeApi):
        def is_mqtt_connected(self) -> bool:
            return True

        async def subscribe_device(self, sn: str, callback: Any) -> bool:
            raise RuntimeError("denied")

    coordinator = _coordinator()
    coordinator.api = Api()  # type: ignore[assignment]

    await coordinator.async_subscribe_all_devices()


def test_command_state_bookkeeping() -> None:
    coordinator = _coordinator()

    coordinator.note_command_sent(SN, "cleaning_mode", 2)
    assert coordinator.get_pending_command_target(SN, "mode") == 2
    coordinator.note_command_sent(SN, "mode", 3)
    assert coordinator.get_pending_command_target(SN, "cleaning_mode") == 2

    state = coordinator._command_state[SN]
    state["pending"]["bogus"] = "not a dict"
    state["pending"]["undated"] = {"target": 1}
    state["pending"]["badtime"] = {"target": 1, "since": "2024-13-45T00:00:00"}
    coordinator.expire_pending_commands(SN)
    assert {"bogus", "undated", "badtime"} <= set(state["pending"])

    coordinator.clear_command_state(SN)
    assert coordinator.get_command_state(SN) == {"pending": {}, "last": {}}
    coordinator.clear_command_state(SN)
    coordinator.expire_pending_commands("unknown")
    coordinator._confirm_pending_commands("unknown", {})


def test_clean_path_confirmation_from_device_report() -> None:
    coordinator = _coordinator()
    coordinator.note_command_sent(SN, "clean_path", 1)

    coordinator._confirm_pending_commands(SN, {"cleanPath": "Adaptive"})

    assert coordinator.get_command_state(SN)["last"]["clean_path"]["result"] == "confirmed"


@pytest.mark.asyncio
async def test_refresh_metadata_forces_metadata_fetch() -> None:
    coordinator = _coordinator()
    coordinator._last_metadata_fetch[SN] = dt_util.utcnow()
    refreshed: list[None] = []

    async def fake_refresh() -> None:
        refreshed.append(None)

    coordinator.async_request_refresh = fake_refresh  # type: ignore[method-assign]

    await coordinator.async_refresh_metadata(SN)

    assert SN not in coordinator._last_metadata_fetch
    assert refreshed == [None]


@pytest.mark.asyncio
async def test_cache_restores_tolerate_missing_or_broken_stores() -> None:
    coordinator = _coordinator()
    await coordinator.async_restore_clean_path_cache()  # no store without a config entry
    await coordinator.async_restore_learned_routes()

    class BrokenStore:
        async def async_load(self) -> Any:
            raise OSError("corrupt")

    class WrongShape:
        async def async_load(self) -> Any:
            return ["not", "a", "dict"]

    for store in (BrokenStore(), WrongShape()):
        coordinator._clean_path_store = store  # type: ignore[assignment]
        await coordinator.async_restore_clean_path_cache()
    assert coordinator._clean_path_cache == {}

    class Api(BaseFakeApi):
        def __init__(self) -> None:
            self.restored: list[Any] = []
            self.on_learned_routes_changed: Any = None

        def restore_learned_routes(self, routes: Any) -> None:
            self.restored.append(routes)

    coordinator.api = Api()  # type: ignore[assignment]
    coordinator._routes_store = BrokenStore()  # type: ignore[assignment]
    await coordinator.async_restore_learned_routes()
    assert coordinator.api.restored == [None]  # type: ignore[attr-defined]


@pytest.mark.asyncio
async def test_s1_capability_refresh_and_confirmation_tolerate_errors() -> None:
    class Api(BaseFakeApi):
        def is_mqtt_connected(self) -> bool:
            return True

        async def query_clean_path_setting(self, sn: str) -> int:
            raise RuntimeError("no ack")

        async def query_cleaning_mode_setting(self, sn: str) -> int:
            raise RuntimeError("no ack")

    coordinator = _coordinator(model="Scuba_S1_2025", capabilities=["clean_path"])
    coordinator.api = Api()  # type: ignore[assignment]

    await coordinator.async_refresh_s1_capability_settings()
    assert await coordinator.async_confirm_clean_path_selection(SN, 1, retry_delays=(0, 0)) is False

    coordinator._devices[SN]["model"] = "Scuba_X1"
    assert await coordinator.async_confirm_clean_path_selection(SN, 1, retry_delays=(0,)) is False
    assert coordinator.has_scuba_s1_device() is False


@pytest.mark.asyncio
async def test_metadata_refresh_parses_history_and_info(hass: HomeAssistant) -> None:
    class Api(BaseFakeApi):
        async def get_devices(self) -> list[dict[str, Any]]:
            return [{"sn": SN, "name": "Robot", "model": "Scuba_X1", "online": True}]

        async def get_device_info(self, sn: str) -> dict[str, Any]:
            return {"model": "Scuba_X1_Pro", "mainFirmwareVersion": "2.0", "ip": "10.0.0.2"}

        async def get_cleaning_history(self, sn: str) -> dict[str, Any]:
            return {
                "data": {
                    "totalCount": 4,
                    "totalTime": 120,
                    "list": [{"mode": 1, "startTime": "2026-09-01 10:00:00", "duration": 45}],
                }
            }

        async def get_consumables(self, sn: str) -> Any:
            return None

    coordinator = make_coordinator(Api(), hass=hass)
    coordinator.note_command_sent(SN, "running", True)
    coordinator._command_state[SN]["pending"]["running"]["since"] = (
        dt_util.utcnow() - timedelta(minutes=5)
    ).isoformat()

    data = await coordinator._async_update_data()

    raw = coordinator._devices[SN]
    assert raw["model"] == "Scuba_X1_Pro"
    assert raw["fw_main"] == "2.0"
    assert raw["total_cleanings"] == 4
    assert raw["last_cleaning_mode"] is not None
    assert SN in data
    assert coordinator.get_command_state(SN)["last"]["running"]["result"] == "timeout"


@pytest.mark.asyncio
async def test_metadata_refresh_survives_unparseable_history(hass: HomeAssistant, monkeypatch) -> None:
    from custom_components.aiper import coordinator as coordinator_module

    class Api(BaseFakeApi):
        async def get_devices(self) -> list[dict[str, Any]]:
            return [{"sn": SN, "model": "Scuba_X1"}]

        async def get_device_info(self, sn: str) -> dict[str, Any]:
            return {}

        async def get_cleaning_history(self, sn: str) -> dict[str, Any]:
            return {"data": "garbage"}

        async def get_consumables(self, sn: str) -> Any:
            return None

    def explode(raw: Any) -> Any:
        raise ValueError("unexpected history shape")

    monkeypatch.setattr(coordinator_module, "_parse_cleaning_history", explode)
    coordinator = make_coordinator(Api(), hass=hass)

    await coordinator._async_update_data()

    assert coordinator._history_cache[SN]["records"] == []


def test_scuba_s3_charging_status_does_not_confirm_pending_running_command() -> None:
    """Status 2 means Charging on Scuba_S3, so it must not confirm a pending running=True."""
    coordinator = _coordinator(model="Scuba_S3")
    coordinator.note_command_sent(SN, "running", True)

    coordinator._confirm_pending_commands(SN, {"status": 2})

    assert coordinator.get_command_state(SN)["pending"]["running"]["target"] is True


@pytest.mark.asyncio
async def test_mqtt_getworkmode_mode_list_survives_rest_poll_without_modes(hass: HomeAssistant) -> None:
    """Mode IDs learned from MQTT GetWorkMode persist across REST polls lacking modeList."""

    class Api(BaseFakeApi):
        async def get_devices(self) -> list[dict[str, Any]]:
            return [{"sn": SN, "name": "Shark", "model": "Shark_Pro", "online": True}]

        async def get_device_info(self, sn: str) -> dict[str, Any]:
            return {"model": "Shark_Pro"}

    coordinator = make_coordinator(Api(), hass=hass)
    await coordinator._async_update_data()

    coordinator._on_shadow_update(SN, {"GetWorkMode": {"modeList": [1, 5]}})
    assert coordinator.data[SN]["mode_options"].value == [1, 5]

    coordinator._last_metadata_fetch.pop(SN, None)
    data = await coordinator._async_update_data()
    assert data[SN]["mode_options"].value == [1, 5]


@pytest.mark.asyncio
async def test_fresh_mqtt_battery_runtime_temperature_preserved_until_ttl(
    hass: HomeAssistant, caplog: pytest.LogCaptureFixture
) -> None:
    """Fresh MQTT battery/runtime/temperature resist stale REST values until TTL expires."""
    import logging

    class Api(BaseFakeApi):
        async def get_devices(self) -> list[dict[str, Any]]:
            return [
                {
                    "sn": SN,
                    "name": "Robot",
                    "model": "Scuba_X1",
                    "online": True,
                    "battLevel": 40,
                    "runTime": 100,
                    "temp": 18,
                }
            ]

    now = dt_util.utcnow()
    coordinator = make_coordinator(Api(), hass=hass)
    coordinator._devices = {SN: {"sn": SN, "name": "Robot", "model": "Scuba_X1", "online": True}}
    coordinator._last_metadata_fetch = {SN: now}
    coordinator.data = {
        SN: normalize_device_state(
            {"sn": SN, "name": "Robot", "model": "Scuba_X1", "online": True, "battLevel": 82, "runTime": 50, "temp": 25}
        )
    }
    coordinator._record_live_field_sources(
        SN, "mqtt", ("battery", "runtime", "temperature"), observed_at=now - timedelta(minutes=1)
    )

    caplog.set_level(logging.DEBUG, logger="custom_components.aiper.coordinator")
    data = await coordinator._async_update_data()
    assert data[SN]["battery"].value == 82
    assert data[SN]["runtime"].value == 0.5
    assert data[SN]["temperature"].value == 25
    assert SN not in caplog.text

    # After TTL expires, fresh REST values take over.
    coordinator._record_live_field_sources(
        SN, "mqtt", ("battery", "runtime", "temperature"), observed_at=now - timedelta(minutes=20)
    )
    data = await coordinator._async_update_data()
    assert data[SN]["battery"].value == 40
    assert data[SN]["runtime"].value == 1.0
    assert data[SN]["temperature"].value == 18


@pytest.mark.asyncio
async def test_coordinator_watchdog_retries_missing_topic_and_requests_shadow(
    hass: HomeAssistant,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A partial subscribe timeout leaves SN unsubscribed until the watchdog recovers it."""
    from unittest.mock import AsyncMock

    from tests.test_api_mqtt import _connected_api

    api, transport = _connected_api()
    shadow_get_topic = f"$aws/things/{SN}/shadow/get/accepted"
    fail_once = True

    async def subscribe_with_transient_timeout(topic: str, callback: Any, qos: int = 1) -> bool:
        nonlocal fail_once
        if topic == shadow_get_topic and fail_once:
            fail_once = False
            return False
        transport.subscriptions[topic] = callback
        return True

    transport.async_subscribe = subscribe_with_transient_timeout  # type: ignore[method-assign]
    request_shadow = AsyncMock(return_value=True)
    api.request_shadow = request_shadow  # type: ignore[method-assign]

    coordinator = make_coordinator(api, hass=hass, _devices={SN: {"sn": SN, "model": "Scuba_X1"}})
    coordinator.data = {SN: normalize_device_state({"sn": SN, "model": "Scuba_X1"})}
    coordinator.async_update_listeners = lambda: None  # type: ignore[method-assign]

    await coordinator.async_subscribe_all_devices()
    assert SN not in api.subscribed_serials()
    request_shadow.assert_not_awaited()

    # Next watchdog run recovers ONLY the missing topic, requests shadow, and delivers once.
    await coordinator.async_subscribe_all_devices()
    assert SN in api.subscribed_serials()
    request_shadow.assert_awaited_once_with(SN)

    delivered: list[tuple[str, dict[str, Any]]] = []
    monkeypatch.setattr(coordinator, "handle_shadow_update", lambda sn, payload: delivered.append((sn, payload)))
    transport.subscriptions[shadow_get_topic](shadow_get_topic, b'{"state":{"reported":{"Machine":{"cap":77}}}}')
    assert len(delivered) == 1
    assert delivered[0][0] == SN

    # Subsequent watchdog passes skip the now-acknowledged device cleanly.
    request_shadow.reset_mock()
    await coordinator.async_subscribe_all_devices()
    request_shadow.assert_not_awaited()
