"""Tests for clean-path REST and MQTT contracts."""

from __future__ import annotations

from typing import Any, cast

import pytest

from custom_components.aiper.api import AiperApi


def _api() -> AiperApi:
    return AiperApi("user@example.com", "secret", "asia", async_session=cast(Any, object()))


@pytest.mark.asyncio
async def test_scuba_s1_clean_path_query_uses_verified_at_contract(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The S1 should bypass speculative REST and query AT+AUTO directly."""
    api = _api()
    api._devices["SN123"] = {"model": "Scuba_S1_2025"}
    calls: list[tuple[str, str]] = []
    monkeypatch.setattr(api, "is_mqtt_connected", lambda: True)

    async def fake_query(sn: str, name: str) -> int:
        calls.append((sn, name))
        return 1

    monkeypatch.setattr(api, "query_machine_at_int", fake_query)

    assert await api.query_clean_path_setting("SN123") == 1
    assert calls == [("SN123", "AUTO")]


@pytest.mark.asyncio
async def test_scuba_s1_clean_path_update_uses_only_verified_at_contract(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The S1 should send only AT+AUTO with its 0/1 value."""
    api = _api()
    api._devices["SN123"] = {"model": "Scuba_S1_2025"}
    calls: list[tuple[str, str]] = []
    monkeypatch.setattr(api, "is_mqtt_connected", lambda: True)

    async def fake_send(sn: str, command: str) -> bool:
        calls.append((sn, command))
        return True

    monkeypatch.setattr(api, "send_machine_at", fake_send)

    assert await api.update_clean_path_setting("SN123", 0) is True
    assert await api.update_clean_path_setting("SN123", 1) is True
    assert await api.update_clean_path_setting("SN123", 2) is False
    assert calls == [("SN123", "AT+AUTO=0"), ("SN123", "AT+AUTO=1")]


@pytest.mark.asyncio
async def test_scuba_s1_mode_query_and_update_use_verified_at_contract(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The S1 mode surface should use only MODE query/set commands."""
    api = _api()
    api._devices["SN123"] = {"model": "Scuba_S1_2025"}
    calls: list[tuple[str, str]] = []
    monkeypatch.setattr(api, "is_mqtt_connected", lambda: True)

    async def fake_query(sn: str, name: str) -> int:
        calls.append((sn, f"query:{name}"))
        return 1

    async def fake_send(sn: str, command: str) -> bool:
        calls.append((sn, command))
        return True

    monkeypatch.setattr(api, "query_machine_at_int", fake_query)
    monkeypatch.setattr(api, "send_machine_at", fake_send)

    assert await api.query_cleaning_mode_setting("SN123") == 1
    for mode_id in (1, 2, 3, 5):
        assert await api.set_cleaning_mode("SN123", mode_id) is True
    assert await api.set_cleaning_mode("SN123", 4) is False
    assert calls == [
        ("SN123", "query:MODE"),
        ("SN123", "AT+MODE=1"),
        ("SN123", "AT+MODE=2"),
        ("SN123", "AT+MODE=3"),
        ("SN123", "AT+MODE=5"),
    ]


@pytest.mark.asyncio
async def test_surfer_clean_path_query_uses_verified_contract(monkeypatch: pytest.MonkeyPatch) -> None:
    """Surfer query should use the verified encrypted endpoint and sn-only body."""
    api = _api()
    api._devices["SN123"] = {"model": "Surfer_S2"}
    calls: list[tuple[str, Any]] = []

    async def fake_call_with_zoneid(sn: str, fn):
        calls.append(("zone", sn))
        return await fn()

    async def fake_call_encrypted(method: str, path: str, body: dict[str, Any]):
        calls.append(("encrypted", (method, path, body)))
        return {"code": "200", "successful": True, "data": {"cleanPath": 1}}

    monkeypatch.setattr(api, "_call_with_zoneid", fake_call_with_zoneid)
    monkeypatch.setattr(api, "_call_encrypted", fake_call_encrypted)

    assert await api.query_clean_path_setting("SN123") == 1
    assert calls == [
        ("zone", "SN123"),
        (
            "encrypted",
            (
                "POST",
                "/equipmentCleanPathSetting/getCleanPathSetting",
                {"sn": "SN123"},
            ),
        ),
    ]


@pytest.mark.asyncio
async def test_surfer_clean_path_update_uses_verified_contract(monkeypatch: pytest.MonkeyPatch) -> None:
    """Surfer update should persist cleanPath and apply AT+AUTO only."""
    api = _api()
    api._devices["SN123"] = {"model": "Surfer_S2"}
    calls: list[tuple[str, Any]] = []

    async def fake_call_with_zoneid(sn: str, fn):
        calls.append(("zone", sn))
        return await fn()

    async def fake_call_encrypted(method: str, path: str, body: dict[str, Any]):
        calls.append(("encrypted", (method, path, body)))
        return {"code": "200", "successful": True}

    monkeypatch.setattr(api, "_call_with_zoneid", fake_call_with_zoneid)
    monkeypatch.setattr(api, "_call_encrypted", fake_call_encrypted)
    monkeypatch.setattr(api, "is_mqtt_connected", lambda: True)

    async def fake_send_machine_at(sn: str, cmd: str) -> bool:
        calls.append(("at", (sn, cmd)))
        return True

    async def fake_request_shadow(sn: str) -> bool:
        calls.append(("shadow", sn))
        return True

    monkeypatch.setattr(api, "send_machine_at", fake_send_machine_at)
    monkeypatch.setattr(api, "request_shadow", fake_request_shadow)

    assert await api.update_clean_path_setting("SN123", 0) is True
    assert calls == [
        ("zone", "SN123"),
        (
            "encrypted",
            (
                "POST",
                "/equipmentCleanPathSetting/updateCleanPathSetting",
                {"sn": "SN123", "cleanPath": 0},
            ),
        ),
        ("at", ("SN123", "AT+AUTO=0")),
        ("shadow", "SN123"),
    ]


def _scuba_x1_api(monkeypatch: pytest.MonkeyPatch, working: tuple[str, frozenset[str], bool] | None):
    """API for an unverified Scuba model whose backend accepts one REST variant.

    Returns the api and a list recording every (path, body keys, encrypted) call.
    """
    api = _api()
    api._devices["SN123"] = {"model": "Scuba_X1", "equipmentId": 42}
    calls: list[tuple[str, frozenset[str], bool]] = []

    def responder(encrypted: bool):
        async def call(method: str, path: str, body: dict[str, Any]) -> dict[str, Any]:
            key = (path, frozenset(body), encrypted)
            calls.append(key)
            if key == working:
                return {"code": "200", "successful": True, "data": {"cleanPath": 1}}
            return {"code": "500", "successful": False}

        return call

    async def no_zone(sn: str, fn):
        return await fn()

    monkeypatch.setattr(api, "_call_encrypted", responder(True))
    monkeypatch.setattr(api, "_call_plain", responder(False))
    monkeypatch.setattr(api, "_call_with_zoneid", no_zone)
    monkeypatch.setattr(api, "is_mqtt_connected", lambda: False)
    return api, calls


@pytest.mark.asyncio
async def test_unverified_model_sweep_learns_the_working_route(monkeypatch: pytest.MonkeyPatch) -> None:
    """After one discovery sweep, the next update goes straight to the variant that worked."""
    working = ("/network/cleanPathSetting", frozenset({"sn", "cleanPathSetting", "deviceId"}), False)
    api, calls = _scuba_x1_api(monkeypatch, working)
    changes: list[None] = []
    api.on_learned_routes_changed = lambda: changes.append(None)

    assert await api.update_clean_path_setting("SN123", 1) is True
    assert calls[-1] == working
    assert len(calls) > 10
    assert changes == [None]
    assert api.learned_routes == {
        "clean_path_update:scuba_x1": {
            "path": "/network/cleanPathSetting",
            "body_keys": ["cleanPathSetting", "deviceId", "sn"],
            "encrypted": False,
        }
    }

    calls.clear()
    assert await api.update_clean_path_setting("SN123", 0) is True
    assert calls == [working]


@pytest.mark.asyncio
async def test_failed_sweep_is_not_repeated_during_cooldown(monkeypatch: pytest.MonkeyPatch) -> None:
    """A model with no working REST variant must not replay the full sweep on every command."""
    api, calls = _scuba_x1_api(monkeypatch, working=None)

    assert await api.update_clean_path_setting("SN123", 1) is False
    # 6 paths x 12 bodies x 2 envelopes.
    assert len(calls) == 144

    calls.clear()
    assert await api.update_clean_path_setting("SN123", 1) is False
    assert calls == []


@pytest.mark.asyncio
async def test_sweep_stops_on_session_conflict(monkeypatch: pytest.MonkeyPatch) -> None:
    """A session conflict aborts discovery instead of burning through every variant."""
    from custom_components.aiper.api import AiperSessionConflict

    api, calls = _scuba_x1_api(monkeypatch, working=None)

    async def conflict(method: str, path: str, body: dict[str, Any]) -> dict[str, Any]:
        calls.append((path, frozenset(body), True))
        raise AiperSessionConflict("in use")

    monkeypatch.setattr(api, "_call_encrypted", conflict)

    with pytest.raises(AiperSessionConflict):
        await api.update_clean_path_setting("SN123", 1)
    assert len(calls) == 1


@pytest.mark.asyncio
async def test_acknowledged_clean_path_at_variant_is_learned(monkeypatch: pytest.MonkeyPatch) -> None:
    """Once an AT variant gets +OK, later updates send only that variant over MQTT."""
    api, _calls = _scuba_x1_api(monkeypatch, working=None)
    monkeypatch.setattr(api, "is_mqtt_connected", lambda: True)
    sent: list[str] = []

    async def fake_send_command(sn: str, cmd_type: str, data: dict[str, Any]) -> bool:
        sent.append(f"downchan:{data}")
        return True

    async def fake_send_machine_at(sn: str, cmd: str) -> bool | None:
        sent.append(cmd)
        return cmd.startswith("AT+CPATH=")

    async def no_shadow(*args: Any, **kwargs: Any) -> bool:
        return True

    monkeypatch.setattr(api, "send_command", fake_send_command)
    monkeypatch.setattr(api, "send_machine_at", fake_send_machine_at)
    monkeypatch.setattr(api, "publish_shadow_update", no_shadow)
    monkeypatch.setattr(api, "request_shadow", no_shadow)

    assert await api.update_clean_path_setting("SN123", 1) is True
    assert sent[-1] == "AT+CPATH=1"
    assert api.learned_routes["clean_path_at:scuba_x1"] == {"command": "AT+CPATH={value}"}

    sent.clear()
    assert await api.update_clean_path_setting("SN123", 0) is True
    assert sent == ["AT+CPATH=0"]


def test_restore_learned_routes_ignores_malformed_data() -> None:
    """Persisted routes are restored defensively."""
    api = _api()
    api.restore_learned_routes({"ok:Model": {"path": "/x"}, "bad": "nope", 3: {}})
    api.restore_learned_routes(None)

    assert api.learned_routes == {"ok:Model": {"path": "/x"}}
