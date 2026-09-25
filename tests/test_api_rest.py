"""Tests for the REST client layer (api_rest.py) without network access."""

from __future__ import annotations

import json
import time
from typing import Any, cast

import aiohttp
import pytest
from multidict import CIMultiDict, CIMultiDictProxy
from yarl import URL

from custom_components.aiper import api_rest
from custom_components.aiper.api import AiperApi
from custom_components.aiper.api_rest import (
    AiperAuthenticationError,
    AiperConnectionError,
    AiperResponseError,
    AiperSessionConflict,
    _load_zone_info,
)

SN = "SN1234567890"


def _api() -> AiperApi:
    return AiperApi("user@example.com", "secret", "eu", async_session=cast(Any, object()))


class NoEncryption:
    encrypt_key_header = "k"

    def encrypt_request(self, body: Any) -> Any:
        return body

    def decrypt_response(self, text: str) -> str:
        return text


def _responder(api: AiperApi, monkeypatch: pytest.MonkeyPatch, responses: dict[str, list[Any]]) -> list[str]:
    """Serve queued response bodies per path suffix from _request_with_backoff."""
    calls: list[str] = []
    monkeypatch.setattr(api_rest, "AiperEncryption", NoEncryption)

    async def fake_request(method: str, url: str, **kwargs: Any) -> tuple[int, str]:
        path = url.rsplit("/", 1)[-1]
        calls.append(path)
        body = responses[path].pop(0)
        if isinstance(body, Exception):
            raise body
        return 200, body if isinstance(body, str) else json.dumps(body)

    monkeypatch.setattr(api, "_request_with_backoff", fake_request)
    return calls


def _response_error(status: int) -> aiohttp.ClientResponseError:
    url = URL("https://api.example.test/x")
    info = aiohttp.RequestInfo(url, "POST", CIMultiDictProxy(CIMultiDict()), url)
    return aiohttp.ClientResponseError(request_info=info, history=(), status=status, message="x")


def test_load_zone_info_tolerates_unknown_zones() -> None:
    assert _load_zone_info("Not/AZone") is None
    assert _load_zone_info("Europe/Berlin") is not None


@pytest.mark.asyncio
async def test_malformed_decrypted_responses_raise_response_error(monkeypatch: pytest.MonkeyPatch) -> None:
    api = _api()
    _responder(api, monkeypatch, {"getEquipment": ["not json", "[1, 2]"]})

    with pytest.raises(AiperResponseError, match="Failed to parse"):
        await api._call_encrypted("POST", "/equipment/getEquipment", {})
    with pytest.raises(AiperResponseError, match="Unexpected decrypted response"):
        await api._call_encrypted("POST", "/equipment/getEquipment", {})


@pytest.mark.asyncio
async def test_session_conflict_relogin_failure_enters_cooldown(monkeypatch: pytest.MonkeyPatch) -> None:
    api = _api()
    _responder(api, monkeypatch, {"getEquipment": [{"code": "402", "msg": "in use"}]})

    async def broken_login() -> bool:
        raise RuntimeError("network")

    monkeypatch.setattr(api, "login", broken_login)

    with pytest.raises(AiperSessionConflict, match="in use"):
        await api._call_encrypted("POST", "/equipment/getEquipment", {})
    assert api._session_conflict_until > time.time()


@pytest.mark.asyncio
async def test_session_conflict_during_relogin_propagates(monkeypatch: pytest.MonkeyPatch) -> None:
    api = _api()
    _responder(api, monkeypatch, {"getEquipment": [{"code": "402"}]})

    async def conflicting_login() -> bool:
        raise AiperSessionConflict("still in use")

    monkeypatch.setattr(api, "login", conflicting_login)

    with pytest.raises(AiperSessionConflict, match="still in use"):
        await api._call_encrypted("POST", "/equipment/getEquipment", {})


@pytest.mark.asyncio
async def test_expired_token_is_refreshed_then_retried(monkeypatch: pytest.MonkeyPatch) -> None:
    api = _api()
    calls = _responder(
        api,
        monkeypatch,
        {
            "getEquipment": [{"code": "401"}, {"code": "0", "data": []}],
            "refresh": [{"code": "0", "data": {"token": "new-token"}}],
        },
    )

    payload = await api._call_encrypted("POST", "/equipment/getEquipment", {})

    assert payload == {"code": "0", "data": []}
    assert calls == ["getEquipment", "refresh", "getEquipment"]
    assert api._token == "new-token"
    assert api._headers["token"] == "new-token"


@pytest.mark.asyncio
async def test_failed_token_refresh_falls_back_to_login(monkeypatch: pytest.MonkeyPatch) -> None:
    api = _api()
    calls = _responder(
        api,
        monkeypatch,
        {
            "getEquipment": [{"code": "403"}, {"code": "0", "data": []}],
            "refresh": [RuntimeError("refresh endpoint down")],
        },
    )
    logins: list[None] = []

    async def fake_login() -> bool:
        logins.append(None)
        return True

    monkeypatch.setattr(api, "login", fake_login)

    assert (await api._call_encrypted("POST", "/equipment/getEquipment", {}))["code"] == "0"
    assert logins == [None]
    assert calls == ["getEquipment", "refresh", "getEquipment"]


@pytest.mark.asyncio
async def test_refresh_token_outcomes(monkeypatch: pytest.MonkeyPatch) -> None:
    api = _api()
    _responder(
        api,
        monkeypatch,
        {"refresh": [{"code": "0", "data": {"token": ""}}, {"code": "500", "msg": "no"}, RuntimeError("down")]},
    )

    assert await api.refresh_token() is False
    assert await api.refresh_token() is False
    assert await api.refresh_token() is False


@pytest.mark.asyncio
async def test_rest_wait_paces_requests(monkeypatch: pytest.MonkeyPatch) -> None:
    api = _api()
    api._rest_min_interval = 5.0
    sleeps: list[float] = []

    async def fake_sleep(delay: float) -> None:
        sleeps.append(delay)

    monkeypatch.setattr(api_rest.asyncio, "sleep", fake_sleep)

    await api._rest_wait()
    await api._rest_wait()

    assert len(sleeps) == 1
    assert 0 < sleeps[0] <= 5.0


class FakeSession:
    """aiohttp-like session returning one canned response per request."""

    def __init__(self, status: int, text: str) -> None:
        self.status = status
        self.body = text
        self.requests: list[dict[str, Any]] = []

    def request(self, method: str, url: str, **kwargs: Any) -> FakeSession:
        self.requests.append({"method": method, "url": url, **kwargs})
        return self

    async def __aenter__(self) -> FakeSession:
        return self

    async def __aexit__(self, *args: Any) -> None:
        return None

    async def text(self) -> str:
        return self.body

    def raise_for_status(self) -> None:
        if self.status >= 400:
            raise _response_error(self.status)


@pytest.mark.asyncio
async def test_request_with_backoff_returns_success_and_raises_client_errors(monkeypatch: pytest.MonkeyPatch) -> None:
    api = _api()

    async def no_wait() -> None:
        return None

    monkeypatch.setattr(api, "_rest_wait", no_wait)
    api._async_session = cast(Any, FakeSession(200, "ok"))
    assert await api._request_with_backoff("GET", "https://x", headers={}) == (200, "ok")

    api._async_session = cast(Any, FakeSession(404, "missing"))
    with pytest.raises(aiohttp.ClientResponseError):
        await api._request_with_backoff("GET", "https://x", headers={})


@pytest.mark.asyncio
async def test_call_plain_parses_json_empty_and_text(monkeypatch: pytest.MonkeyPatch) -> None:
    api = _api()
    bodies = ['{"code": "0"}', "", "<html>oops</html>"]

    async def fake_request(method: str, url: str, **kwargs: Any) -> tuple[int, str]:
        assert kwargs["headers"]["token"] == ""
        assert kwargs["json_body"] == {"sn": SN}
        return 200, bodies.pop(0)

    monkeypatch.setattr(api, "_request_with_backoff", fake_request)

    assert await api._call_plain("POST", "/x", {"sn": SN}) == {"code": "0"}
    assert await api._call_plain("POST", "/x", {"sn": SN}) == {}
    assert await api._call_plain("POST", "/x", {"sn": SN}) == {
        "code": 200,
        "successful": False,
        "message": "<html>oops</html>",
    }


@pytest.mark.asyncio
async def test_login_without_token_or_with_http_error(monkeypatch: pytest.MonkeyPatch) -> None:
    api = _api()
    _responder(api, monkeypatch, {"login": [{"code": "0", "data": {}}]})
    with pytest.raises(AiperResponseError, match="No token"):
        await api.login()

    async def http_error(*args: Any, **kwargs: Any) -> dict[str, Any]:
        raise _response_error(418)

    monkeypatch.setattr(api, "_call_encrypted", http_error)
    with pytest.raises(AiperConnectionError, match="Login request failed"):
        await api.login()


@pytest.mark.asyncio
async def test_login_rejection_raises_authentication_error(monkeypatch: pytest.MonkeyPatch) -> None:
    api = _api()
    _responder(api, monkeypatch, {"login": [{"code": "1001", "msg": "wrong password"}]})

    with pytest.raises(AiperAuthenticationError, match="wrong password"):
        await api.login()


@pytest.mark.asyncio
async def test_login_switches_to_regional_domain_and_loads_openid(monkeypatch: pytest.MonkeyPatch) -> None:
    api = _api()
    _responder(
        api,
        monkeypatch,
        {
            "login": [{"code": "0", "data": {"token": "tok", "domain": ["https://apieu2.aiper.com/"]}}],
            "getOpenIdToken": [
                {
                    "code": "0",
                    "data": {
                        "identityId": "eu-central-1:abc",
                        "token": "openid",
                        "iotEndpoint": "abc.iot.eu-west-1.amazonaws.com",
                        "tokenDuration": 3600,
                    },
                }
            ],
        },
    )

    assert await api.login() is True
    assert api.base_url == "https://apieu2.aiper.com"
    assert api._openid_token == "openid"
    assert api._openid_token_exp is not None
    assert api._resolve_aws_region() == "eu-west-1"


@pytest.mark.asyncio
async def test_openid_failures_are_swallowed(monkeypatch: pytest.MonkeyPatch) -> None:
    api = _api()
    _responder(api, monkeypatch, {"getOpenIdToken": [{"code": "500", "msg": "nope"}, RuntimeError("down")]})

    await api.get_openid_token()
    await api.get_openid_token()

    assert api._openid_token is None
    assert api._resolve_aws_region() == "eu-central-1"


def test_zone_id_fallbacks() -> None:
    api = AiperApi("u", "p", "eu", async_session=cast(Any, object()), time_zone="Europe/Rome")

    assert api._zone_id_for_sn(SN) == "Europe/Rome"
    api._last_timezone_by_sn[SN] = "UTC+2"
    assert api._zone_id_for_sn(SN) == "UTC+2"
    api._device_zone_id_by_sn[SN] = "Europe/Athens"
    assert api._zone_id_for_sn(SN) == "Europe/Athens"
    api._headers["zoneId"] = ""
    assert api._zone_id_for_sn("OTHER") is None


@pytest.mark.asyncio
async def test_aws_credentials_edge_cases(monkeypatch: pytest.MonkeyPatch) -> None:
    api = _api()
    assert await api.get_aws_credentials() is None  # no identity yet

    api._identity_id, api._openid_token = "id", "tok"
    api._openid_token_exp = time.time() + 30  # about to expire
    refreshes: list[None] = []

    async def fake_openid(**kwargs: Any) -> None:
        refreshes.append(None)

    monkeypatch.setattr(api, "get_openid_token", fake_openid)
    responses: list[Any] = [json.dumps({"Unexpected": True})]

    async def exchange() -> tuple[int, str]:
        item = responses.pop(0)
        if isinstance(item, Exception):
            raise item
        return 200, item

    monkeypatch.setattr(api, "_exchange_openid_token", exchange)

    assert await api.get_aws_credentials() is None
    assert refreshes == [None]

    responses.append(_response_error(503))
    with pytest.raises(aiohttp.ClientResponseError):
        await api.get_aws_credentials()


@pytest.mark.asyncio
async def test_aws_credentials_retry_server_error_is_raised(monkeypatch: pytest.MonkeyPatch) -> None:
    api = _api()
    api._identity_id, api._openid_token = "id", "tok"
    responses: list[Any] = [_response_error(400), _response_error(500)]

    async def exchange() -> tuple[int, str]:
        raise responses.pop(0)

    async def new_openid(**kwargs: Any) -> None:
        api._openid_token = "fresh"

    monkeypatch.setattr(api, "_exchange_openid_token", exchange)
    monkeypatch.setattr(api, "get_openid_token", new_openid)

    with pytest.raises(aiohttp.ClientResponseError):
        await api.get_aws_credentials()


@pytest.mark.asyncio
async def test_get_devices_shapes_and_errors(monkeypatch: pytest.MonkeyPatch) -> None:
    api = _api()
    payloads: list[Any] = [
        {"code": "0", "data": {"list": [{"sn": SN, "zoneId": "Europe/Berlin"}]}},
        {"code": "500", "msg": "busy"},
        _response_error(404),
    ]

    async def fake_call(*args: Any, **kwargs: Any) -> dict[str, Any]:
        item = payloads.pop(0)
        if isinstance(item, Exception):
            raise item
        return item

    monkeypatch.setattr(api, "_call_encrypted", fake_call)

    assert await api.get_devices() == [{"sn": SN, "zoneId": "Europe/Berlin"}]
    assert api._device_zone_id_by_sn[SN] == "Europe/Berlin"
    assert api._zone_info_cache["Europe/Berlin"] is not None
    assert api._timezone_string_for_sn(SN) in {"UTC+1", "UTC+2"}
    with pytest.raises(AiperResponseError, match="busy"):
        await api.get_devices()
    with pytest.raises(AiperConnectionError):
        await api.get_devices()


@pytest.mark.asyncio
async def test_device_info_status_and_consumables(monkeypatch: pytest.MonkeyPatch) -> None:
    api = _api()
    payloads: list[Any] = [
        {"code": "0", "data": {"model": "Scuba_X1"}},
        {"code": "0", "data": ["odd"]},
        {"code": "500"},
        _response_error(500),
        {"code": "0", "data": {"online": 1}},
        {"code": "500"},
        _response_error(500),
        {"code": "0", "data": {"list": []}},
        {"code": "500"},
        RuntimeError("down"),
    ]

    async def fake_call(*args: Any, **kwargs: Any) -> dict[str, Any]:
        item = payloads.pop(0)
        if isinstance(item, Exception):
            raise item
        return item

    monkeypatch.setattr(api, "_call_encrypted", fake_call)

    info = await api.get_device_info(SN)
    assert info is not None and info["model"] == "Scuba_X1" and info["payload"]["code"] == "0"
    assert await api.get_device_info(SN) == {"data": ["odd"], "payload": {"code": "0", "data": ["odd"]}}
    assert await api.get_device_info(SN) is None
    assert await api.get_device_info(SN) is None

    assert await api.get_device_status(SN) == {"online": 1}
    assert await api.get_device_status(SN) is None
    assert await api.get_device_status(SN) is None

    assert (await api.get_consumables(SN))["data"] == {"list": []}
    assert await api.get_consumables(SN) is None
    assert await api.get_consumables(SN) is None


@pytest.mark.asyncio
async def test_cleaning_history_tries_body_variants(monkeypatch: pytest.MonkeyPatch) -> None:
    api = _api()
    seen: list[dict[str, Any]] = []
    payloads: list[Any] = [RuntimeError("bad body"), {"code": "500"}, {"code": "0", "data": {"total": 3}}]

    async def fake_call(method: str, path: str, body: dict[str, Any], **kwargs: Any) -> dict[str, Any]:
        seen.append(body)
        item = payloads.pop(0)
        if isinstance(item, Exception):
            raise item
        return item

    monkeypatch.setattr(api, "_call_encrypted", fake_call)

    assert await api.get_cleaning_history(SN) == {"code": "0", "data": {"total": 3}}
    assert [sorted(body) for body in seen] == [["sn"], ["pageNo", "pageSize", "sn"], ["pageNum", "pageSize", "sn"]]

    payloads.extend([{"code": "500"}] * 4)
    assert await api.get_cleaning_history(SN) == {}


@pytest.mark.asyncio
async def test_zone_info_cache_skips_known_zones() -> None:
    api = _api()
    api._zone_info_cache["Europe/Berlin"] = None

    await api._async_cache_zone_info({"Europe/Berlin"})

    assert api._zone_info_cache == {"Europe/Berlin": None}


@pytest.mark.asyncio
async def test_retry_after_refresh_failing_falls_back_to_login(monkeypatch: pytest.MonkeyPatch) -> None:
    """If the request retried with a refreshed token errors, a full login is tried next."""
    api = _api()
    calls = _responder(
        api,
        monkeypatch,
        {
            "getEquipment": [{"code": "401"}, RuntimeError("reset"), {"code": "0", "data": []}],
            "refresh": [{"code": "0", "data": {"token": "new"}}],
        },
    )

    async def fake_login() -> bool:
        return True

    monkeypatch.setattr(api, "login", fake_login)

    assert (await api._call_encrypted("POST", "/equipment/getEquipment", {}))["code"] == "0"
    assert calls == ["getEquipment", "refresh", "getEquipment", "getEquipment"]
