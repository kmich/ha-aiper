"""Tests for Aiper account session-conflict handling."""

from __future__ import annotations

import asyncio
import json
import time
from typing import Any, cast

import aiohttp
import pytest

from custom_components.aiper import api_rest as api_module
from custom_components.aiper.api import (
    AiperApi,
    AiperAuthenticationError,
    AiperConnectionError,
    AiperResponseError,
    AiperSessionConflict,
)


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
async def test_session_conflict_backs_off_then_reauthenticates_after_cooldown(monkeypatch: pytest.MonkeyPatch) -> None:
    """A 402 should enter cooldown without kicking the app, then reauth once cooldown expires."""
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

    with pytest.raises(AiperSessionConflict):
        await api._call_encrypted("POST", "/equipment/getEquipment", {})

    assert login_calls == 0
    assert api._session_conflict_pending_reauth is True
    assert api._session_conflict_until > time.time()

    # During cooldown, requests fail fast without hitting the cloud or logging in.
    with pytest.raises(AiperSessionConflict):
        await api._call_encrypted("POST", "/equipment/getEquipment", {})
    assert len(request_tokens) == 1

    # Once cooldown expires, the next call re-authenticates once and resumes.
    api._session_conflict_until = time.time() - 1
    payload = await api._call_encrypted("POST", "/equipment/getEquipment", {})

    assert payload["successful"] is True
    assert payload["data"] == [{"sn": "SN123"}]
    assert login_calls == 1
    assert api._session_conflict_pending_reauth is False
    assert request_tokens == ["", "fresh-token"]


@pytest.mark.asyncio
async def test_session_conflict_reauth_failure_preserves_pending_flag(monkeypatch: pytest.MonkeyPatch) -> None:
    """A failed post-cooldown reauth keeps the pending flag for the next attempt."""
    api = _api()
    api._session_conflict_pending_reauth = True
    api._session_conflict_until = time.time() - 1

    async def fail_login() -> bool:
        raise AiperConnectionError("offline")

    monkeypatch.setattr(api, "login", fail_login)

    with pytest.raises(AiperConnectionError):
        await api._call_encrypted("POST", "/equipment/getEquipment", {})

    assert api._session_conflict_pending_reauth is True


@pytest.mark.asyncio
async def test_response_errors_do_not_embed_raw_payload_text(monkeypatch: pytest.MonkeyPatch) -> None:
    """Malformed decrypted bodies and tokenless login payloads stay out of exception strings."""
    api = _api()
    monkeypatch.setattr(api_module, "AiperEncryption", FakeEncryption)

    async def bad_json_request(method: str, url: str, **kwargs):
        return 200, "secret-raw-body-leak"

    monkeypatch.setattr(api, "_request_with_backoff", bad_json_request)
    with pytest.raises(AiperResponseError) as err:
        await api._call_encrypted("POST", "/equipment/getEquipment", {})
    assert "secret-raw-body-leak" not in str(err.value)

    async def tokenless_login(method: str, url: str, **kwargs):
        return 200, json.dumps({"code": "200", "successful": True, "data": {"email": "leak@example.com"}})

    monkeypatch.setattr(api, "_request_with_backoff", tokenless_login)
    with pytest.raises(AiperResponseError) as login_err:
        await api.login()
    assert "leak@example.com" not in str(login_err.value)
    assert "keys=['email']" in str(login_err.value)


@pytest.mark.asyncio
async def test_request_with_backoff_classifies_retryable_http_failures(monkeypatch: pytest.MonkeyPatch) -> None:
    """Repeated retryable HTTP responses should become a connection error."""
    api = _api()
    api._async_session = cast(Any, type("Session", (), {"request": lambda *args, **kwargs: FakeResponse(503)})())

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

    api._async_session = cast(Any, type("Session", (), {"request": fail_request})())

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


@pytest.mark.asyncio
async def test_login_rejection_with_401_code_does_not_recurse(monkeypatch: pytest.MonkeyPatch) -> None:
    """A 401/403 body on /login means bad credentials, not an expired token.

    Regression test: the expired-token branch used to call login() again from
    inside login(), recursing until RecursionError while hammering /login.
    """
    api = _api()
    paths: list[str] = []

    monkeypatch.setattr(api_module, "AiperEncryption", FakeEncryption)

    async def fake_request(method: str, url: str, *, headers: dict, data: Any = None, timeout: int = 30, **kwargs):
        paths.append(url.rsplit("/", 1)[-1])
        return 200, json.dumps({"code": "401", "successful": False, "msg": "bad password"})

    monkeypatch.setattr(api, "_request_with_backoff", fake_request)

    with pytest.raises(api_module.AiperAuthenticationError):
        await api.login()

    assert paths == ["login"]


@pytest.mark.asyncio
async def test_openid_fetch_during_login_does_not_reenter_login(monkeypatch: pytest.MonkeyPatch) -> None:
    """A 401/402 on the OpenID fetch that login() makes must not call login() again."""
    api = _api()
    paths: list[str] = []

    monkeypatch.setattr(api_module, "AiperEncryption", FakeEncryption)

    async def fake_request(method: str, url: str, *, headers: dict, data: Any = None, timeout: int = 30, **kwargs):
        path = url.rsplit("/", 1)[-1]
        paths.append(path)
        if path == "login":
            return 200, json.dumps({"code": "200", "successful": True, "data": {"token": "tok"}})
        return 200, json.dumps({"code": "401", "successful": False, "msg": "expired"})

    monkeypatch.setattr(api, "_request_with_backoff", fake_request)

    assert await api.login() is True
    assert paths == ["login", "getOpenIdToken"]


@pytest.mark.asyncio
async def test_concurrent_zone_id_overrides_do_not_leak(monkeypatch: pytest.MonkeyPatch) -> None:
    """Per-device zoneId overrides must stay scoped to their own request.

    Regression test: the override used to mutate the shared header dict, so
    overlapping calls left the session stuck on another device's time zone.
    """
    api = AiperApi("user@example.com", "secret", "eu", async_session=cast(Any, object()), time_zone="Europe/Berlin")
    api._device_zone_id_by_sn = {"SN_A": "America/New_York", "SN_B": "Asia/Tokyo"}
    seen: dict[str, str] = {}

    async def request(sn: str, delay: float) -> None:
        await asyncio.sleep(delay)
        seen[sn] = api._request_headers(None)["zoneId"]
        await asyncio.sleep(delay)

    await asyncio.gather(
        api._call_with_zoneid("SN_A", lambda: request("SN_A", 0.01)),
        api._call_with_zoneid("SN_B", lambda: request("SN_B", 0.02)),
    )

    assert seen == {"SN_A": "America/New_York", "SN_B": "Asia/Tokyo"}
    assert api._headers["zoneId"] == "Europe/Berlin"
    assert api._request_headers(None)["zoneId"] == "Europe/Berlin"


def test_default_zone_id_uses_supplied_time_zone() -> None:
    """The session zoneId comes from Home Assistant, not a hardcoded city."""
    assert AiperApi("u", "p", "eu", async_session=cast(Any, object()), time_zone="Pacific/Auckland")._headers[
        "zoneId"
    ] == ("Pacific/Auckland")
    assert _api()._headers["zoneId"] == api_module.DEFAULT_ZONE_ID


@pytest.mark.asyncio
async def test_device_info_is_not_logged_at_info(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """Device payloads and serials must not be written to INFO logs."""
    api = _api()

    async def fake_call(*args, **kwargs) -> dict[str, Any]:
        return {"code": "0", "data": {"sn": "SERIAL-XYZ-123456", "ip": "10.0.0.5"}}

    monkeypatch.setattr(api, "_call_encrypted", fake_call)
    caplog.set_level("INFO", logger=api_module.__name__)

    await api.get_device_info("SERIAL-XYZ-123456")
    await api.get_device_status("SERIAL-XYZ-123456")

    assert "SERIAL-XYZ-123456" not in caplog.text
    assert "10.0.0.5" not in caplog.text


@pytest.mark.asyncio
async def test_refresh_conflict_propagates_without_calling_login(monkeypatch: pytest.MonkeyPatch) -> None:
    """An equipment 401 followed by refresh 402 enters cooldown without logging in."""
    api = _api()
    api._token = "stale-token"
    monkeypatch.setattr(api_module, "AiperEncryption", FakeEncryption)
    calls: list[str] = []
    responses = [
        {"code": "401", "successful": False, "msg": "expired"},
        {"code": "402", "successful": False, "message": "already logged in elsewhere"},
    ]

    async def fake_request(method: str, url: str, *, headers: dict, data: Any = None, timeout: int = 30, **kwargs):
        calls.append(url.rsplit("/", 1)[-1])
        return 200, json.dumps(responses.pop(0))

    login_calls = 0

    async def fake_login() -> bool:
        nonlocal login_calls
        login_calls += 1
        return True

    monkeypatch.setattr(api, "_request_with_backoff", fake_request)
    monkeypatch.setattr(api, "login", fake_login)

    with pytest.raises(AiperSessionConflict):
        await api._call_encrypted("POST", "/equipment/getEquipment", {})

    assert calls == ["getEquipment", "refresh"]
    assert login_calls == 0
    assert api._session_conflict_pending_reauth is True
    assert api._session_conflict_until > time.time()


@pytest.mark.asyncio
async def test_concurrent_callers_after_cooldown_share_one_login(monkeypatch: pytest.MonkeyPatch) -> None:
    """Two concurrent callers after cooldown expiry share one real login + OpenID fetch."""
    api = _api()
    api._session_conflict_pending_reauth = True
    api._session_conflict_until = time.time() - 1
    monkeypatch.setattr(api_module, "AiperEncryption", FakeEncryption)

    login_count = 0
    openid_count = 0
    equipment_tokens: list[str | None] = []

    async def fake_request(method: str, url: str, *, headers: dict, data: Any = None, timeout: int = 30, **kwargs):
        nonlocal login_count, openid_count
        path = url.rsplit("/", 1)[-1]
        if path == "login":
            login_count += 1
            await asyncio.sleep(0.01)
            return 200, json.dumps({"code": "200", "successful": True, "data": {"token": "recovered-tok"}})
        if path == "getOpenIdToken":
            openid_count += 1
            return 200, json.dumps({"code": "200", "successful": True, "data": {"identityId": "id-1"}})
        equipment_tokens.append(headers.get("token"))
        return 200, json.dumps({"code": "200", "successful": True, "data": []})

    monkeypatch.setattr(api, "_request_with_backoff", fake_request)

    res1, res2 = await asyncio.gather(
        api._call_encrypted("POST", "/equipment/getEquipment", {}),
        api._call_encrypted("POST", "/equipment/getEquipment", {}),
    )

    assert res1["successful"] is True
    assert res2["successful"] is True
    assert login_count == 1
    assert openid_count == 1
    assert equipment_tokens == ["recovered-tok", "recovered-tok"]
    assert api._session_conflict_pending_reauth is False


@pytest.mark.asyncio
async def test_invalid_credentials_during_post_cooldown_recovery_raises_auth_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Bad credentials during post-cooldown recovery surface AiperAuthenticationError."""
    api = _api()
    api._session_conflict_pending_reauth = True
    api._session_conflict_until = time.time() - 1
    monkeypatch.setattr(api_module, "AiperEncryption", FakeEncryption)

    async def fake_request(method: str, url: str, *, headers: dict, data: Any = None, timeout: int = 30, **kwargs):
        return 200, json.dumps({"code": "401", "successful": False, "msg": "bad password"})

    monkeypatch.setattr(api, "_request_with_backoff", fake_request)

    with pytest.raises(AiperAuthenticationError):
        await api._call_encrypted("POST", "/equipment/getEquipment", {})

    assert api._session_conflict_pending_reauth is False


@pytest.mark.asyncio
async def test_concurrent_401_fallback_shares_one_login(monkeypatch: pytest.MonkeyPatch) -> None:
    """Two concurrent callers hitting 401 on the same stale token serialize login recovery."""
    api = _api()
    api._token = "stale-tok"
    monkeypatch.setattr(api_module, "AiperEncryption", FakeEncryption)

    login_calls = 0

    async def fake_request(method: str, url: str, *, headers: dict, data: Any = None, timeout: int = 30, **kwargs):
        nonlocal login_calls
        path = url.rsplit("/", 1)[-1]
        if path == "refresh":
            return 200, json.dumps({"code": "401", "successful": False, "msg": "cannot refresh"})
        if path == "login":
            login_calls += 1
            await asyncio.sleep(0.01)
            return 200, json.dumps({"code": "200", "successful": True, "data": {"token": "new-tok"}})
        if path == "getOpenIdToken":
            return 200, json.dumps({"code": "200", "successful": True, "data": {}})
        if headers.get("token") == "new-tok":
            return 200, json.dumps({"code": "200", "successful": True, "data": [{"sn": "SN1"}]})
        return 200, json.dumps({"code": "401", "successful": False, "msg": "expired"})

    monkeypatch.setattr(api, "_request_with_backoff", fake_request)

    res1, res2 = await asyncio.gather(
        api._call_encrypted("POST", "/equipment/getEquipment", {}),
        api._call_encrypted("POST", "/equipment/getEquipment", {}),
    )

    assert res1["data"] == [{"sn": "SN1"}]
    assert res2["data"] == [{"sn": "SN1"}]
    assert login_calls == 1
