"""Tests for Aiper account session-conflict handling."""

from __future__ import annotations

import json
import time
from typing import Any, cast

import pytest

from custom_components.aiper import api as api_module
from custom_components.aiper.api import AiperApi, AiperSessionConflict


def _api() -> AiperApi:
    return AiperApi("user@example.com", "secret", "asia", async_session=cast(Any, object()))


class FakeEncryption:
    """No-op encrypted envelope for testing API response handling."""

    encrypt_key_header = "test-key"

    def encrypt_request(self, body: dict[str, Any] | None) -> dict[str, Any] | None:
        return body

    def decrypt_response(self, text: str) -> str:
        return text


@pytest.mark.asyncio
async def test_session_conflict_reauthenticates_and_retries_once(monkeypatch: pytest.MonkeyPatch) -> None:
    """A transient 402 should trigger one login and then retry the request."""
    api = _api()
    responses = [
        {"code": "402", "successful": False, "message": "Your account is already being used"},
        {"code": "200", "successful": True, "data": [{"sn": "SN123"}]},
    ]
    request_tokens: list[str | None] = []
    login_calls = 0

    monkeypatch.setattr(api_module, "AiperEncryption", FakeEncryption)

    async def fake_request(method: str, url: str, *, headers: dict, data: Any = None, timeout: int = 30, **kwargs):
        request_tokens.append(headers.get("token"))
        return 200, json.dumps(responses.pop(0))

    async def fake_login() -> bool:
        nonlocal login_calls
        login_calls += 1
        api._token = "fresh-token"
        api._headers["token"] = "fresh-token"
        return True

    monkeypatch.setattr(api, "_request_with_backoff", fake_request)
    monkeypatch.setattr(api, "login", fake_login)

    payload = await api._call_encrypted("POST", "/equipment/getEquipment", {})

    assert payload["successful"] is True
    assert payload["data"] == [{"sn": "SN123"}]
    assert login_calls == 1
    assert request_tokens == ["", "fresh-token"]


@pytest.mark.asyncio
async def test_persistent_session_conflict_enters_cooldown(monkeypatch: pytest.MonkeyPatch) -> None:
    """A repeated 402 should raise and avoid immediate follow-up requests."""
    api = _api()
    responses = [
        {"code": "402", "successful": False, "message": "Your account is already being used"},
        {"code": "402", "successful": False, "message": "Your account is already being used"},
    ]
    request_count = 0

    monkeypatch.setattr(api_module, "AiperEncryption", FakeEncryption)

    async def fake_request(method: str, url: str, *, headers: dict, data: Any = None, timeout: int = 30, **kwargs):
        nonlocal request_count
        request_count += 1
        return 200, json.dumps(responses.pop(0))

    async def fake_login() -> bool:
        api._token = "fresh-token"
        api._headers["token"] = "fresh-token"
        return True

    monkeypatch.setattr(api, "_request_with_backoff", fake_request)
    monkeypatch.setattr(api, "login", fake_login)

    with pytest.raises(AiperSessionConflict):
        await api._call_encrypted("POST", "/equipment/getEquipment", {})

    assert api._session_conflict_until > time.time()

    with pytest.raises(AiperSessionConflict):
        await api._call_encrypted("POST", "/equipment/getEquipment", {})

    assert request_count == 2
