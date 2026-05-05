"""Tests for clean-path REST and MQTT contracts."""

from __future__ import annotations

from typing import Any, cast

import pytest

from custom_components.aiper.api import AiperApi


def _api() -> AiperApi:
    return AiperApi("user@example.com", "secret", "asia", async_session=cast(Any, object()))


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
