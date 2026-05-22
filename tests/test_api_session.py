"""Tests for Aiper account session-conflict handling."""

from __future__ import annotations

import json
import time
from typing import Any, cast

import aiohttp
import pytest

from custom_components.aiper import api as api_module
from custom_components.aiper.api import AiperApi, AiperConnectionError, AiperResponseError, AiperSessionConflict


def _api() -> AiperApi:
    return AiperApi("user@example.com", "secret", "asia", async_session=cast(Any, object()))


class FakeEncryption:
    """No-op encrypted envelope for testing API response handling."""

    encrypt_key_header = "test-key"

    def encrypt_request(self, body: dict[str, Any] | None) -> dict[str, Any] | None:
        return body

    def decrypt_response(self, text: str) -> str:
        return text


class FakeResponse:
    """Minimal aiohttp response context manager for retry tests."""

    def __init__(self, status: int) -> None:
        self.status = status

    async def __aenter__(self) -> FakeResponse:
        return self

    async def __aexit__(self, exc_type, exc, tb) -> None:
        return None

    async def text(self) -> str:
        return "{}"

    def raise_for_status(self) -> None:
        return None


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


@pytest.mark.asyncio
async def test_request_with_backoff_classifies_retryable_http_failures(monkeypatch: pytest.MonkeyPatch) -> None:
    """Repeated retryable HTTP responses should become a connection error."""
    api = _api()
    api._async_session = type("Session", (), {"request": lambda *args, **kwargs: FakeResponse(503)})()

    async def no_wait() -> None:
        return None

    async def no_sleep(_delay: float) -> None:
        return None

    monkeypatch.setattr(api, "_rest_wait", no_wait)
    monkeypatch.setattr(api_module.asyncio, "sleep", no_sleep)

    with pytest.raises(AiperConnectionError, match="HTTP 503"):
        await api._request_with_backoff("POST", "https://example.invalid", headers={})


@pytest.mark.asyncio
async def test_request_with_backoff_classifies_connection_failures(monkeypatch: pytest.MonkeyPatch) -> None:
    """Repeated aiohttp transport failures should become a connection error."""
    api = _api()

    def fail_request(*args, **kwargs):
        raise aiohttp.ClientConnectionError("network down")

    api._async_session = type("Session", (), {"request": fail_request})()

    async def no_wait() -> None:
        return None

    async def no_sleep(_delay: float) -> None:
        return None

    monkeypatch.setattr(api, "_rest_wait", no_wait)
    monkeypatch.setattr(api_module.asyncio, "sleep", no_sleep)

    with pytest.raises(AiperConnectionError, match="network down"):
        await api._request_with_backoff("POST", "https://example.invalid", headers={})


@pytest.mark.asyncio
async def test_get_devices_rejects_malformed_device_lists(monkeypatch: pytest.MonkeyPatch) -> None:
    """Successful discovery responses still need a device list shape."""
    api = _api()

    async def malformed_devices(*args, **kwargs) -> dict[str, Any]:
        return {"code": "0", "data": "not-a-device-list"}

    monkeypatch.setattr(api, "_call_encrypted", malformed_devices)

    with pytest.raises(AiperResponseError, match="Unexpected device list"):
        await api.get_devices()
