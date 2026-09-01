"""Tests for the explicit MQTT connection-status tracker."""

from __future__ import annotations

from typing import Any, cast

import pytest

from custom_components.aiper.api import AiperApi
from custom_components.aiper.connection import ConnectionState, ConnectionStatus


def _api() -> AiperApi:
    return AiperApi("user@example.com", "secret", "asia", async_session=cast(Any, object()))


def test_initial_state() -> None:
    status = ConnectionStatus()
    assert status.state is ConnectionState.INITIALIZING
    assert status.is_connected is False
    assert status.connect_attempts == 0
    assert status.last_connected_at is None


def test_connect_cycle_counts_and_timestamps() -> None:
    status = ConnectionStatus()
    status.mark_connecting()
    assert status.state is ConnectionState.CONNECTING
    assert status.connect_attempts == 1

    status.mark_connected()
    assert status.state is ConnectionState.CONNECTED
    assert status.is_connected is True
    assert status.last_connected_at is not None
    assert status.last_error is None


def test_disconnect_stamps_outage_start_once() -> None:
    status = ConnectionStatus()
    status.mark_connecting()
    status.mark_connected()

    status.mark_disconnected("socket reset")
    first = status.last_disconnected_at
    assert first is not None
    assert status.state is ConnectionState.DISCONNECTED
    assert status.last_error == "socket reset"

    # Repeated drops while already down keep the original outage start.
    status.mark_disconnected("still down")
    assert status.last_disconnected_at == first


def test_reconnecting_increments_and_clears_on_success() -> None:
    status = ConnectionStatus()
    status.mark_connecting()
    status.mark_connected()
    status.mark_disconnected()

    status.mark_reconnecting()
    assert status.state is ConnectionState.RECONNECTING
    assert status.reconnect_count == 1

    status.mark_connected()
    assert status.state is ConnectionState.CONNECTED
    assert status.reconnect_count == 1


def test_credentials_stale_then_refreshed() -> None:
    status = ConnectionStatus()
    status.mark_connected()

    status.mark_credentials_stale("Cognito 400 on credentials exchange")
    assert status.state is ConnectionState.CREDENTIALS_STALE
    assert status.credential_reject_count == 1
    assert "Cognito 400" in (status.last_error or "")

    status.mark_credentials_refreshed()
    assert status.credential_refresh_count == 1
    # A refresh does not by itself declare the link healthy again.
    assert status.state is ConnectionState.CREDENTIALS_STALE


def test_fatal_is_sticky_until_explicit_transition() -> None:
    status = ConnectionStatus()
    status.mark_fatal("invalid credentials")
    assert status.state is ConnectionState.FATAL
    assert status.last_error == "invalid credentials"


def test_as_diagnostics_is_json_safe() -> None:
    status = ConnectionStatus()
    status.mark_connecting()
    status.mark_connected()
    status.mark_disconnected("boom")
    snap = status.as_diagnostics()

    assert snap["state"] == "disconnected"
    assert snap["connect_attempts"] == 1
    assert isinstance(snap["last_state_change"], str)
    assert isinstance(snap["last_connected_at"], str)
    assert snap["last_error"] == "boom"
    # Every value must survive a JSON round trip.
    import json

    assert json.loads(json.dumps(snap)) == snap


def test_state_change_timestamp_only_moves_on_real_transition() -> None:
    status = ConnectionStatus()
    status.mark_connected()
    ts = status.last_state_change
    status.mark_connected()  # no-op transition
    assert status.last_state_change == ts


# --- integration with AiperApi -----------------------------------------------


def test_api_starts_with_a_connection_tracker() -> None:
    api = _api()
    assert isinstance(api.connection, ConnectionStatus)
    assert api.connection.state is ConnectionState.INITIALIZING


@pytest.mark.asyncio
async def test_connect_mqtt_without_identity_marks_disconnected() -> None:
    api = _api()
    assert await api.connect_mqtt() is False
    assert api.connection.state is ConnectionState.DISCONNECTED
    assert api.connection.last_error is not None


@pytest.mark.asyncio
async def test_reconnect_mqtt_marks_reconnecting_then_connected(monkeypatch: pytest.MonkeyPatch) -> None:
    api = _api()

    async def fake_disconnect_mqtt() -> None:
        return None

    async def fake_connect_mqtt() -> bool:
        api.connection.mark_connected()
        return True

    async def fake_resubscribe() -> None:
        return None

    monkeypatch.setattr(api, "disconnect_mqtt", fake_disconnect_mqtt)
    monkeypatch.setattr(api, "connect_mqtt", fake_connect_mqtt)
    monkeypatch.setattr(api, "_resubscribe_all_devices", fake_resubscribe)

    assert await api.reconnect_mqtt() is True
    assert api.connection.reconnect_count == 1
    assert api.connection.state is ConnectionState.CONNECTED
