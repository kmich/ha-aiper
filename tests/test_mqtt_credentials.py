"""Tests for AWS IoT MQTT credential refresh and transport signing resolution."""

from __future__ import annotations

import asyncio
import json
import time
from typing import Any, cast

import pytest
from aiohttp import ClientResponseError

from custom_components.aiper.api import (
    AWS_CREDENTIALS_TTL_DEBUG_SECONDS,
    AiperApi,
)
from custom_components.aiper.mqtt import AwsIotCredentials, AwsIotMqttTransport


def _api() -> AiperApi:
    return AiperApi("user@example.com", "secret", "asia", async_session=cast(Any, object()))


def _creds(key: str = "AKIAFIRST") -> AwsIotCredentials:
    return AwsIotCredentials(access_key_id=key, secret_access_key="secret", session_token="token")


@pytest.mark.asyncio
async def test_async_refresh_mqtt_credentials_builds_snapshot_and_handles_missing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """async_refresh_mqtt_credentials() converts Cognito creds and updates metrics."""
    api = _api()
    creds_payloads: list[dict[str, Any] | None] = [
        None,
        {"AccessKeyId": "AKIAFRESH", "SecretKey": "secret", "SessionToken": "token"},
    ]

    async def fake_get_aws_credentials() -> dict[str, Any] | None:
        return creds_payloads.pop(0)

    monkeypatch.setattr(api, "get_aws_credentials", fake_get_aws_credentials)

    assert await api.async_refresh_mqtt_credentials() is None
    assert api.connection.credential_refresh_count == 0

    snapshot = await api.async_refresh_mqtt_credentials()
    assert snapshot == AwsIotCredentials(
        access_key_id="AKIAFRESH",
        secret_access_key="secret",
        session_token="token",
    )
    assert api.connection.credential_refresh_count == 1


@pytest.mark.asyncio
async def test_cognito_4xx_refreshes_openid_without_token_duration(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A rejected OpenID token must refresh once even without an expiry hint."""
    api = _api()
    api._identity_id = "identity-old"
    api._openid_token = "openid-old"
    api._openid_token_exp = None
    exchanges: list[dict[str, Any]] = []

    async def fake_request(*_: Any, **kwargs: Any) -> tuple[int, str]:
        exchanges.append(kwargs["json_body"])
        if len(exchanges) == 1:
            raise ClientResponseError(cast(Any, None), (), status=400, message="expired token")
        return 200, json.dumps(
            {
                "Credentials": {
                    "AccessKeyId": "AKIAREFRESHED",
                    "SecretKey": "secret",
                    "SessionToken": "session",
                }
            }
        )

    async def fake_openid_refresh() -> None:
        api._identity_id = "identity-new"
        api._openid_token = "openid-new"

    monkeypatch.setattr(api, "_request_with_backoff", fake_request)
    monkeypatch.setattr(api, "get_openid_token", fake_openid_refresh)

    credentials = await api.get_aws_credentials()

    assert credentials is not None
    assert credentials["AccessKeyId"] == "AKIAREFRESHED"
    assert exchanges == [
        {
            "IdentityId": "identity-old",
            "Logins": {"cognito-identity.amazonaws.com": "openid-old"},
        },
        {
            "IdentityId": "identity-new",
            "Logins": {"cognito-identity.amazonaws.com": "openid-new"},
        },
    ]
    # The successful retry must actually persist the credentials to the
    # instance cache, not just return them -- otherwise every subsequent
    # call would needlessly re-hit Cognito.
    assert api._aws_credentials is not None
    assert api._aws_credentials["AccessKeyId"] == "AKIAREFRESHED"
    assert api._aws_credentials_exp is not None and api._aws_credentials_exp > time.time()
    assert api._aws_credentials_cooldown_until == 0.0

    # A subsequent call within the cached window must not re-hit Cognito.
    credentials_again = await api.get_aws_credentials()
    assert credentials_again is api._aws_credentials
    assert len(exchanges) == 2


@pytest.mark.asyncio
async def test_cognito_4xx_retry_is_bounded(monkeypatch: pytest.MonkeyPatch) -> None:
    """A persistent Cognito rejection must not create a refresh loop.

    Regression test: the retry's second failure previously escaped
    get_aws_credentials as an uncaught ClientResponseError, breaking its
    dict|None contract. It must now degrade to None and start a cooldown
    instead, so a permanently-broken account doesn't hammer Cognito/Aiper on
    every coordinator poll forever.
    """
    api = _api()
    api._identity_id = "identity"
    api._openid_token = "openid"
    exchanges = 0
    refreshes = 0

    async def fake_request(*_: Any, **__: Any) -> tuple[int, str]:
        nonlocal exchanges
        exchanges += 1
        raise ClientResponseError(cast(Any, None), (), status=400, message="still rejected")

    async def fake_openid_refresh() -> None:
        nonlocal refreshes
        refreshes += 1
        api._openid_token = "openid-refreshed"

    monkeypatch.setattr(api, "_request_with_backoff", fake_request)
    monkeypatch.setattr(api, "get_openid_token", fake_openid_refresh)

    result = await api.get_aws_credentials()

    assert result is None
    assert exchanges == 2
    assert refreshes == 1
    assert api._aws_credentials_cooldown_until > time.time()

    # And while the cooldown is active, a second call must not attempt any
    # further Cognito/OpenID round trips at all.
    result2 = await api.get_aws_credentials()
    assert result2 is None
    assert exchanges == 2
    assert refreshes == 1


@pytest.mark.asyncio
async def test_cognito_4xx_retry_backs_off_when_refresh_does_not_change_credentials(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """If get_openid_token() silently fails to produce new credentials, the
    retry must not resend the identical already-rejected payload -- it
    should back off immediately instead of guaranteeing a second failure.

    Regression test: get_openid_token() swallows its own failures and
    leaves self._identity_id/_openid_token unchanged on error, so the old
    `if not self._identity_id or not self._openid_token` guard never caught
    this case.
    """
    api = _api()
    api._identity_id = "identity"
    api._openid_token = "openid"
    exchanges = 0

    async def fake_request(*_: Any, **__: Any) -> tuple[int, str]:
        nonlocal exchanges
        exchanges += 1
        raise ClientResponseError(cast(Any, None), (), status=400, message="still rejected")

    async def fake_openid_refresh_noop() -> None:
        # Mirrors get_openid_token()'s real behavior on failure: it just
        # returns without touching _identity_id/_openid_token.
        return None

    monkeypatch.setattr(api, "_request_with_backoff", fake_request)
    monkeypatch.setattr(api, "get_openid_token", fake_openid_refresh_noop)

    result = await api.get_aws_credentials()

    assert result is None
    # Only the first exchange should have been attempted -- retrying with
    # byte-identical rejected credentials would be pointless.
    assert exchanges == 1
    assert api._aws_credentials_cooldown_until > time.time()


@pytest.mark.asyncio
async def test_concurrent_credential_fetches_are_serialized(monkeypatch: pytest.MonkeyPatch) -> None:
    """Two concurrent callers must not race on identity/token state or
    duplicate the Cognito exchange.

    Regression test: the coordinator's poll-driven refresh and the MQTT
    signing delegate's CRT-triggered background refresh can both call
    get_aws_credentials() around the same time. Without serialization they
    can interleave awaits inside the function and issue redundant network
    calls.
    """
    api = _api()
    api._identity_id = "identity"
    api._openid_token = "openid"
    exchanges = 0
    release = asyncio.Event()

    async def fake_request(*_: Any, **__: Any) -> tuple[int, str]:
        nonlocal exchanges
        exchanges += 1
        if exchanges == 1:
            # Let the second call start and try to enter the critical
            # section while the first is still "in flight".
            await release.wait()
        return 200, json.dumps({"Credentials": {"AccessKeyId": "AKIAONE", "SecretKey": "s", "SessionToken": "t"}})

    monkeypatch.setattr(api, "_request_with_backoff", fake_request)

    task1 = asyncio.create_task(api.get_aws_credentials())
    await asyncio.sleep(0)  # let task1 acquire the lock and start its request
    task2 = asyncio.create_task(api.get_aws_credentials())
    await asyncio.sleep(0)  # task2 should now be blocked waiting on the lock
    release.set()

    result1 = await task1
    result2 = await task2

    assert result1 is not None and result2 is not None
    # task2 must have waited for task1 to finish and populate the cache,
    # rather than racing it into a second network call.
    assert exchanges == 1
    assert result2 is result1


def test_credential_fetch_uses_whatever_ttl_is_set_at_fetch_time() -> None:
    """get_aws_credentials() must stamp the expiry from the *current* TTL.

    Regression test: __init__.py sets aws_credentials_ttl for debug mode
    before the coordinator's first refresh now (previously it was set
    after), so this locks in the underlying contract that ordering depends
    on -- whichever TTL is on the api object at fetch time is the one used,
    with no separate caching of the "wrong" TTL from construction time.
    """
    api = _api()
    api._identity_id = "identity-1"
    api._openid_token = "token-1"
    api._openid_token_exp = time.time() + 3600

    async def fake_request(*args: Any, **kwargs: Any) -> tuple[int, str]:
        return 200, json.dumps({"Credentials": {"AccessKeyId": "AKIADEBUG", "SecretKey": "s", "SessionToken": "t"}})

    api._request_with_backoff = fake_request  # type: ignore[method-assign]

    api.aws_credentials_ttl = AWS_CREDENTIALS_TTL_DEBUG_SECONDS
    before = time.time()
    creds = asyncio.run(api.get_aws_credentials())

    assert creds is not None
    assert api._aws_credentials_exp is not None
    # Expiry must reflect the debug TTL (300s), not the production one (3300s).
    assert (
        before + AWS_CREDENTIALS_TTL_DEBUG_SECONDS - 5
        <= api._aws_credentials_exp
        <= before + AWS_CREDENTIALS_TTL_DEBUG_SECONDS + 5
    )


def test_resolve_aws_region_prefers_reported_region_then_endpoint_then_default() -> None:
    """The shared region resolver -- used by both get_aws_credentials and
    connect_mqtt -- must apply its fallback chain in the documented order."""
    api = _api()

    # Explicit region wins even if an endpoint is also set.
    api._aws_region = "us-west-2"
    api._iot_endpoint = "abc123.iot.eu-central-1.amazonaws.com"
    assert api._resolve_aws_region() == "us-west-2"

    # No explicit region: parse it out of the endpoint.
    api._aws_region = None
    assert api._resolve_aws_region() == "eu-central-1"

    # Neither available: hardcoded default.
    api._aws_region = None
    api._iot_endpoint = None
    assert api._resolve_aws_region() == "eu-central-1"

    # A malformed endpoint must not raise -- falls back to the default.
    api._iot_endpoint = "not-a-valid-endpoint"
    assert api._resolve_aws_region() == "eu-central-1"


@pytest.mark.asyncio
async def test_transport_asks_the_resolver_on_every_signing() -> None:
    """Each signing must consult the resolver, not a value captured at build time.

    This is what makes the reconnect loop pick up refreshed credentials
    instead of retrying forever with expired ones.
    """
    handed_out = [_creds("AKIAONE"), _creds("AKIATWO")]
    calls: list[int] = []

    def resolver() -> AwsIotCredentials | None:
        calls.append(len(calls))
        return handed_out[min(len(calls) - 1, len(handed_out) - 1)]

    transport = AwsIotMqttTransport(
        endpoint="example.iot.eu-central-1.amazonaws.com",
        region="eu-central-1",
        client_id="client",
        credentials=_creds("AKIAINITIAL"),
        credentials_resolver=resolver,
    )

    first = await transport._resolve_credentials()
    second = await transport._resolve_credentials()

    assert first.access_key_id == "AKIAONE"
    assert second.access_key_id == "AKIATWO"
    assert transport.credential_signing_count == 2
    assert "X-Amz-Credential=AKIATWO" in transport._signed_websocket_url(second)


@pytest.mark.asyncio
async def test_transport_falls_back_to_last_known_credentials() -> None:
    """A resolver returning None or raising must not break signing outright."""
    transport = AwsIotMqttTransport(
        endpoint="example.iot.eu-central-1.amazonaws.com",
        region="eu-central-1",
        client_id="client",
        credentials=_creds("AKIAINITIAL"),
        credentials_resolver=lambda: None,
    )

    signed = await transport._resolve_credentials()
    assert signed.access_key_id == "AKIAINITIAL"

    async def broken_async_resolver() -> AwsIotCredentials | None:
        raise RuntimeError("cognito timeout")

    async_transport = AwsIotMqttTransport(
        endpoint="example.iot.eu-central-1.amazonaws.com",
        region="eu-central-1",
        client_id="client",
        credentials=_creds("AKIAFALLBACK"),
        async_credentials_resolver=broken_async_resolver,
    )
    assert (await async_transport._resolve_credentials()).access_key_id == "AKIAFALLBACK"


@pytest.mark.asyncio
async def test_disconnect_mqtt_drops_the_transport_even_if_it_errors() -> None:
    """A wedged transport must not linger with its own reconnect loop."""
    api = _api()

    class ExplodingTransport:
        async def async_disconnect(self) -> None:
            raise RuntimeError("socket is wedged")

    api._mqtt_client = ExplodingTransport()

    await api.disconnect_mqtt()

    assert api._mqtt_client is None
    assert api.is_mqtt_connected() is False


def test_mqtt_disconnected_seconds_tracks_a_single_outage() -> None:
    """The outage clock must survive the transport being swapped out."""
    api = _api()
    api._mqtt_client = None

    first = api.mqtt_disconnected_seconds()
    assert first is not None and first >= 0

    started_at = api._mqtt_first_disconnected_at

    # Rebuilding the transport must not restart the clock.
    class DisconnectedTransport:
        def is_connected(self) -> bool:
            return False

    api._mqtt_client = DisconnectedTransport()
    assert api.mqtt_disconnected_seconds() is not None
    assert api._mqtt_first_disconnected_at == started_at


def test_reconnecting_clears_the_outage_clock() -> None:
    """Once connected again the outage measurement resets."""
    api = _api()
    assert api.mqtt_disconnected_seconds() is not None

    class ConnectedTransport:
        def is_connected(self) -> bool:
            return True

    api._mqtt_client = ConnectedTransport()

    assert api.is_mqtt_connected() is True
    assert api.mqtt_disconnected_seconds() is None
