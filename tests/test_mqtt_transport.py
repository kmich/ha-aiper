"""Tests for the AWS IoT MQTT transport wrapper with a fake CRT connection."""

from __future__ import annotations

from concurrent.futures import Future
from typing import Any

import pytest

from custom_components.aiper.mqtt import AwsIotCredentials, AwsIotMqttTransport


def _done(result: Any = None, error: Exception | None = None) -> Future:
    future: Future = Future()
    if error is not None:
        future.set_exception(error)
    else:
        future.set_result(result)
    return future


class FakeConnection:
    """Stand-in for an awscrt MQTT connection; futures resolve immediately."""

    def __init__(self, *, fail: str | None = None) -> None:
        self.fail = fail
        self.subscriptions: dict[str, Any] = {}
        self.published: list[tuple[str, bytes]] = []
        self.disconnected = False

    def _result(self, op: str, value: Any = None) -> Future:
        return _done(error=RuntimeError(f"{op} failed")) if self.fail == op else _done(value)

    def connect(self) -> Future:
        return self._result("connect", {"session_present": False})

    def subscribe(self, *, topic: str, qos: Any, callback: Any) -> tuple[Future, int]:
        self.subscriptions[topic] = callback
        return self._result("subscribe", {"qos": qos}), 1

    def publish(self, *, topic: str, payload: bytes, qos: Any) -> tuple[Future, int]:
        self.published.append((topic, payload))
        return self._result("publish"), 2

    def disconnect(self) -> Future:
        self.disconnected = True
        return self._result("disconnect")


def _transport(connection: FakeConnection, **kwargs: Any) -> AwsIotMqttTransport:
    transport = AwsIotMqttTransport(
        endpoint="example.iot.eu-central-1.amazonaws.com",
        region="eu-central-1",
        client_id="client",
        credentials=AwsIotCredentials(access_key_id="AKIA", secret_access_key="secret"),
        **kwargs,
    )
    transport._build_connection = lambda: connection  # type: ignore[method-assign]
    return transport


@pytest.mark.asyncio
async def test_connect_subscribe_publish_disconnect_round_trip() -> None:
    connection = FakeConnection()
    transport = _transport(connection)
    received: list[tuple[str, bytes]] = []

    assert await transport.async_connect() is True
    assert transport.is_connected() is True
    assert transport.last_connected_at is not None

    assert await transport.async_subscribe("aiper/things/SN1/upChan", lambda t, p: received.append((t, p))) is True
    connection.subscriptions["aiper/things/SN1/upChan"]("aiper/things/SN1/upChan", bytearray(b"hi"), dup=False)
    assert received == [("aiper/things/SN1/upChan", b"hi")]

    assert await transport.async_publish("aiper/things/SN1/downChan", "cmd") is True
    assert connection.published == [("aiper/things/SN1/downChan", b"cmd")]

    await transport.async_disconnect()
    assert connection.disconnected is True
    assert transport.is_connected() is False


@pytest.mark.asyncio
async def test_subscriber_exceptions_are_contained() -> None:
    connection = FakeConnection()
    transport = _transport(connection)
    await transport.async_connect()

    def boom(topic: str, payload: bytes) -> None:
        raise ValueError("bad payload")

    await transport.async_subscribe("t", boom)
    # Must not propagate into the CRT thread.
    connection.subscriptions["t"]("t", b"x")


@pytest.mark.asyncio
@pytest.mark.parametrize("failing_op", ["connect", "subscribe", "publish"])
async def test_operation_failures_return_false_and_record_error(failing_op: str) -> None:
    connection = FakeConnection(fail=failing_op if failing_op != "connect" else None)
    transport = _transport(connection)
    if failing_op == "connect":
        connection.fail = "connect"
        assert await transport.async_connect() is False
        assert transport.is_connected() is False
    else:
        await transport.async_connect()
        if failing_op == "subscribe":
            assert await transport.async_subscribe("t", lambda t, p: None) is False
        else:
            assert await transport.async_publish("t", b"x") is False
    assert transport.last_error is not None
    assert "failed" in transport.last_error


@pytest.mark.asyncio
async def test_operations_without_connection_fail_cleanly() -> None:
    transport = _transport(FakeConnection())

    assert await transport.async_subscribe("t", lambda t, p: None) is False
    assert await transport.async_publish("t", "x") is False
    assert transport.last_error == "MQTT connection is not initialized"
    await transport.async_disconnect()


def test_lifecycle_callbacks_track_state_and_notify_reconnect() -> None:
    reconnects: list[bool] = []
    transport = _transport(FakeConnection(), on_reconnected=reconnects.append)
    transport._connected = True

    transport._on_connection_interrupted(None, RuntimeError("socket reset"))
    assert transport.is_connected() is False
    assert "socket reset" in (transport.last_error or "")

    transport._connection = object()
    transport._on_connection_resumed(None, 0, session_present=False)
    assert transport.is_connected() is True
    assert transport.reconnect_count == 1
    assert reconnects == [False]

    transport._on_connection_failure(None, type("Data", (), {"error": "handshake"})())
    assert transport.is_connected() is False
    assert transport.last_error == "handshake"

    transport._on_connection_closed(None, None)
    assert transport.last_disconnected_at is not None
