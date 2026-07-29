"""Tests for AWS IoT MQTT credential refresh and reconnection.

These cover the invariants behind the fix for the connection never coming
back after AWS_ERROR_MQTT_UNEXPECTED_HANGUP (issue #27). The signing
delegate running on the event loop thread is the subtle one: an earlier
attempt at this fix blocked there and deadlocked Home Assistant on startup.
"""

from __future__ import annotations

import asyncio
import time
from typing import Any, cast

import pytest

from custom_components.aiper.api import (
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
    loop, it waits forever.
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

    async def scenario() -> AwsIotCredentials | None:
        api._async_loop = asyncio.get_running_loop()
        # Call the delegate directly on the loop thread, exactly as the CRT does.
        resolved = await asyncio.wait_for(asyncio.to_thread(api._current_mqtt_credentials), timeout=2)
        await asyncio.sleep(0)  # let the scheduled refresh run
        return resolved

    resolved = asyncio.run(scenario())

    assert resolved is not None
    assert refreshes == ["called"]


def test_stale_credentials_schedule_a_refresh() -> None:
    """A snapshot near expiry should trigger a background renewal."""
    api = _api()
    api._mqtt_credentials_snapshot = _creds()

    api._aws_credentials_exp = time.time() + MQTT_CREDENTIALS_REFRESH_MARGIN_SECONDS - 10
    assert api._mqtt_credentials_due_for_refresh() is True

    api._aws_credentials_exp = time.time() + MQTT_CREDENTIALS_REFRESH_MARGIN_SECONDS + 600
    assert api._mqtt_credentials_due_for_refresh() is False


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
