"""Tests for AWS IoT MQTT credential refresh and reconnection.

These cover the invariants behind the fix for the connection never coming
back after AWS_ERROR_MQTT_UNEXPECTED_HANGUP (issue #27). The signing
delegate running on the event loop thread is the subtle one: an earlier
attempt at this fix blocked there and deadlocked Home Assistant on startup.
"""

from __future__ import annotations

import asyncio
import json
import threading
import time
from typing import Any, cast

import pytest
from aiohttp import ClientResponseError

from custom_components.aiper.api import (
    AWS_CREDENTIALS_TTL_DEBUG_SECONDS,
    MQTT_CREDENTIALS_REFRESH_MARGIN_SECONDS,
    AiperApi,
)
from custom_components.aiper.mqtt import AwsIotCredentials, AwsIotMqttTransport


def _api() -> AiperApi:
    return AiperApi("user@example.com", "secret", "asia", async_session=cast(Any, object()))


def _creds(key: str = "AKIAFIRST") -> AwsIotCredentials:
    return AwsIotCredentials(access_key_id=key, secret_access_key="secret", session_token="token")


def test_credential_delegate_returns_snapshot_without_blocking() -> None:
    """The signer must answer immediately from the cached snapshot."""
    api = _api()
    api._mqtt_credentials_snapshot = _creds()
    api._aws_credentials_exp = time.time() + 3300

    started = time.monotonic()
    resolved = api._current_mqtt_credentials()
    elapsed = time.monotonic() - started

    assert resolved is not None
    assert resolved.access_key_id == "AKIAFIRST"
    # Anything slow here means we reintroduced blocking work in the delegate.
    assert elapsed < 0.05


def test_credential_delegate_never_blocks_on_the_event_loop() -> None:
    """Regression guard for the deadlock that made v1.2.5 unable to connect.

    The AWS CRT calls the delegate synchronously on the thread driving the
    connection, which during initial connect is the Home Assistant event
    loop. If the delegate waits on a coroutine scheduled onto that same
    loop, that thread -- which IS the loop -- blocks waiting on itself and
    never comes back.

    To actually reproduce that shape, this test runs its own event loop in a
    dedicated thread and calls the delegate directly from inside that loop's
    running coroutine (not via asyncio.to_thread, which would call it from a
    *worker* thread and leave the loop thread free -- that variant would
    pass even with a reintroduced blocking delegate, since the free loop
    thread could still service it). A `Thread.join(timeout=...)` from the
    main test thread gives a hard, OS-level bound: if the delegate really
    deadlocks the loop thread, this test fails cleanly instead of hanging
    the whole suite forever.
    """
    api = _api()
    api._mqtt_credentials_snapshot = _creds()
    # Deliberately stale, so the refresh path is exercised too.
    api._aws_credentials_exp = time.time() + 1

    refreshes: list[str] = []

    async def fake_refresh() -> AwsIotCredentials | None:
        refreshes.append("called")
        return _creds("AKIASECOND")

    api.async_refresh_mqtt_credentials = fake_refresh  # type: ignore[method-assign]

    results: list[AwsIotCredentials | None] = []
    errors: list[BaseException] = []

    def _run_loop_and_call_delegate_on_it() -> None:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        api._async_loop = loop

        async def _drive() -> None:
            # A plain synchronous call executing on the thread currently
            # running this loop -- exactly how the AWS CRT invokes it.
            results.append(api._current_mqtt_credentials())
            # Let the loop run one more iteration so the scheduled refresh
            # task (proof it wasn't awaited inline) gets a chance to run.
            await asyncio.sleep(0)

        try:
            loop.run_until_complete(_drive())
        except BaseException as err:  # noqa: BLE001 - capture anything for the assertion below
            errors.append(err)
        finally:
            loop.close()

    thread = threading.Thread(target=_run_loop_and_call_delegate_on_it, daemon=True)
    thread.start()
    thread.join(timeout=2.0)

    assert not thread.is_alive(), (
        "Calling the credentials delegate on the event loop thread hung -- "
        "it must never block waiting on that same loop."
    )
    assert not errors
    assert results and results[0] is not None
    assert refreshes == ["called"]


def test_stale_credentials_schedule_a_refresh() -> None:
    """A snapshot near expiry should trigger a background renewal."""
    api = _api()
    api._mqtt_credentials_snapshot = _creds()

    api._aws_credentials_exp = time.time() + MQTT_CREDENTIALS_REFRESH_MARGIN_SECONDS - 10
    assert api._mqtt_credentials_due_for_refresh() is True

    api._aws_credentials_exp = time.time() + MQTT_CREDENTIALS_REFRESH_MARGIN_SECONDS + 600
    assert api._mqtt_credentials_due_for_refresh() is False


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


@pytest.mark.asyncio
async def test_cognito_4xx_retry_is_bounded(monkeypatch: pytest.MonkeyPatch) -> None:
    """A persistent Cognito rejection must not create a refresh loop."""
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

    with pytest.raises(ClientResponseError):
        await api.get_aws_credentials()

    assert exchanges == 2
    assert refreshes == 1


def test_refresh_margin_scales_down_for_a_short_ttl() -> None:
    """A debug-mode TTL shorter than the production margin must still
    produce a clean due/not-due cycle instead of being 'due' immediately
    and permanently after every fetch.

    Regression test: MQTT_CREDENTIALS_REFRESH_MARGIN_SECONDS (600) is larger
    than AWS_CREDENTIALS_TTL_DEBUG_SECONDS (300), so an unscaled margin would
    make _mqtt_credentials_due_for_refresh() always True in debug mode.
    """
    api = _api()
    api._mqtt_credentials_snapshot = _creds()
    api.aws_credentials_ttl = AWS_CREDENTIALS_TTL_DEBUG_SECONDS

    # Freshly minted: comfortably not due yet.
    api._aws_credentials_exp = time.time() + AWS_CREDENTIALS_TTL_DEBUG_SECONDS
    assert api._mqtt_credentials_due_for_refresh() is False

    # Past the halfway point of the short TTL: due.
    api._aws_credentials_exp = time.time() + (AWS_CREDENTIALS_TTL_DEBUG_SECONDS // 2) - 1
    assert api._mqtt_credentials_due_for_refresh() is True


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


def test_scheduling_a_refresh_resets_the_flag_if_scheduling_itself_fails() -> None:
    """If call_soon_threadsafe raises, the in-progress flag must not stick.

    Regression test: the flag is set True before the refresh task is
    actually scheduled. If scheduling fails (e.g. the event loop is closing
    during Home Assistant shutdown, racing a live CRT signing callback), the
    scheduled coroutine never runs, so its `finally` never resets the flag --
    permanently disabling the opportunistic background refresh path for the
    rest of that AiperApi instance's life unless the failure path resets it.
    """
    api = _api()
    api._mqtt_credentials_snapshot = _creds()

    class _ClosingLoop:
        def is_running(self) -> bool:
            return True

        def call_soon_threadsafe(self, *args: Any, **kwargs: Any) -> None:
            raise RuntimeError("Event loop is closed")

    api._async_loop = cast(Any, _ClosingLoop())

    api._schedule_mqtt_credentials_refresh()

    assert api._mqtt_credentials_refreshing is False
    # And a subsequent, successful attempt must still be possible -- i.e.
    # the guard doesn't stay tripped from the failed one.
    scheduled: list[str] = []

    class _WorkingLoop:
        def is_running(self) -> bool:
            return True

        def call_soon_threadsafe(self, cb: Any) -> None:
            scheduled.append("scheduled")

    api._async_loop = cast(Any, _WorkingLoop())
    api._schedule_mqtt_credentials_refresh()
    assert scheduled == ["scheduled"]


def test_transport_asks_the_resolver_on_every_signing() -> None:
    """Each signing must consult the resolver, not a value captured at build time.

    This is what makes the SDK's reconnect loop pick up refreshed
    credentials instead of retrying forever with expired ones.
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

    class _FakeAwsCredentials:
        def __init__(self, access_key_id: str, secret_access_key: str, session_token: str | None) -> None:
            self.access_key_id = access_key_id

    import sys
    import types

    fake_auth = types.ModuleType("awscrt.auth")
    fake_auth.AwsCredentials = _FakeAwsCredentials  # type: ignore[attr-defined]
    fake_awscrt = types.ModuleType("awscrt")
    fake_awscrt.auth = fake_auth  # type: ignore[attr-defined]
    sys.modules["awscrt"] = fake_awscrt
    sys.modules["awscrt.auth"] = fake_auth
    try:
        first = transport._sign_with_current_credentials()
        second = transport._sign_with_current_credentials()
    finally:
        sys.modules.pop("awscrt", None)
        sys.modules.pop("awscrt.auth", None)

    assert first.access_key_id == "AKIAONE"
    assert second.access_key_id == "AKIATWO"
    assert transport.credential_signing_count == 2


def test_transport_falls_back_to_last_known_credentials() -> None:
    """A resolver returning None must not break signing outright."""
    transport = AwsIotMqttTransport(
        endpoint="example.iot.eu-central-1.amazonaws.com",
        region="eu-central-1",
        client_id="client",
        credentials=_creds("AKIAINITIAL"),
        credentials_resolver=lambda: None,
    )

    class _FakeAwsCredentials:
        def __init__(self, access_key_id: str, secret_access_key: str, session_token: str | None) -> None:
            self.access_key_id = access_key_id

    import sys
    import types

    fake_auth = types.ModuleType("awscrt.auth")
    fake_auth.AwsCredentials = _FakeAwsCredentials  # type: ignore[attr-defined]
    fake_awscrt = types.ModuleType("awscrt")
    fake_awscrt.auth = fake_auth  # type: ignore[attr-defined]
    sys.modules["awscrt"] = fake_awscrt
    sys.modules["awscrt.auth"] = fake_auth
    try:
        signed = transport._sign_with_current_credentials()
    finally:
        sys.modules.pop("awscrt", None)
        sys.modules.pop("awscrt.auth", None)

    assert signed.access_key_id == "AKIAINITIAL"


@pytest.mark.asyncio
async def test_disconnect_mqtt_drops_the_transport_even_if_it_errors() -> None:
    """A wedged transport must not linger with its own reconnect loop."""
    api = _api()

    class ExplodingTransport:
        async def async_disconnect(self) -> None:
            raise RuntimeError("socket is wedged")

    api._mqtt_client = ExplodingTransport()
    api._mqtt_connected = True

    await api.disconnect_mqtt()

    assert api._mqtt_client is None
    assert api.is_mqtt_connected() is False


def test_mqtt_disconnected_seconds_tracks_a_single_outage() -> None:
    """The outage clock must survive the transport being swapped out."""
    api = _api()
    api._mqtt_connected = False
    api._mqtt_client = None

    first = api.mqtt_disconnected_seconds()
    assert first is not None and first >= 0

    started_at = api._mqtt_first_disconnected_at
    # Rebuilding the transport must not restart the clock.
    api._mqtt_client = object()
    assert api.mqtt_disconnected_seconds() is not None
    assert api._mqtt_first_disconnected_at == started_at


def test_reconnecting_clears_the_outage_clock() -> None:
    """Once connected again the outage measurement resets."""
    api = _api()
    api._mqtt_connected = False
    assert api.mqtt_disconnected_seconds() is not None

    class ConnectedTransport:
        def is_connected(self) -> bool:
            return True

    api._mqtt_client = ConnectedTransport()
    api._mqtt_connected = True

    assert api.is_mqtt_connected() is True
    assert api.mqtt_disconnected_seconds() is None
