"""Tests for the pure-asyncio AWS IoT MQTT-over-WebSockets transport."""

from __future__ import annotations

import asyncio
from collections.abc import Callable
from typing import Any, cast

import aiohttp
import pytest

from custom_components.aiper.mqtt import AwsIotCredentials, AwsIotMqttTransport
from custom_components.aiper.mqtt_codec import (
    PACKET_CONNACK,
    PACKET_CONNECT,
    PACKET_DISCONNECT,
    PACKET_PINGREQ,
    PACKET_PUBLISH,
    PACKET_SUBSCRIBE,
    decode_remaining_length,
    decode_utf8,
    encode_puback,
    encode_publish,
)

_PINGRESP = b"\xd0\x00"


def _connack(*, session_present: bool = False, return_code: int = 0) -> bytes:
    return bytes((PACKET_CONNACK << 4, 2, 1 if session_present else 0, return_code))


def _suback(packet_id: int, *codes: int) -> bytes:
    body = packet_id.to_bytes(2, "big") + bytes(codes)
    return b"\x90" + bytes((len(body),)) + body


class FakeWebSocket:
    """In-memory aiohttp WebSocket double speaking MQTT 3.1.1 frames."""

    def __init__(self, *, on_send: Callable[[FakeWebSocket, bytes], None] | None = None) -> None:
        self.closed = False
        self.sent: list[bytes] = []
        self._incoming: asyncio.Queue[aiohttp.WSMessage] = asyncio.Queue()
        self._on_send = on_send
        self._exc: Exception | None = None

    def push_binary(self, data: bytes) -> None:
        self._incoming.put_nowait(aiohttp.WSMessage(aiohttp.WSMsgType.BINARY, data, None))

    def push_close(self, code: int = 1000) -> None:
        self._incoming.put_nowait(aiohttp.WSMessage(aiohttp.WSMsgType.CLOSE, code, None))

    def push_error(self, exc: Exception) -> None:
        self._exc = exc
        self._incoming.put_nowait(aiohttp.WSMessage(aiohttp.WSMsgType.ERROR, exc, None))

    def exception(self) -> Exception | None:
        return self._exc

    async def send_bytes(self, data: bytes) -> None:
        self.sent.append(data)
        if self._on_send is not None:
            self._on_send(self, data)

    async def receive(self) -> aiohttp.WSMessage:
        return await self._incoming.get()

    async def close(self) -> None:
        if not self.closed:
            self.closed = True
            self._incoming.put_nowait(aiohttp.WSMessage(aiohttp.WSMsgType.CLOSED, None, None))

    def __aiter__(self) -> FakeWebSocket:
        return self

    async def __anext__(self) -> aiohttp.WSMessage:
        msg = await self._incoming.get()
        if msg.type == aiohttp.WSMsgType.CLOSED:
            raise StopAsyncIteration
        return msg


class FakeSession:
    """Fake aiohttp.ClientSession producing scripted FakeWebSocket instances."""

    def __init__(self, sockets: list[FakeWebSocket | Exception]) -> None:
        self._sockets = list(sockets)
        self.urls: list[str] = []

    async def ws_connect(self, url: str, **kwargs: Any) -> FakeWebSocket:
        self.urls.append(url)
        item = self._sockets.pop(0)
        if isinstance(item, Exception):
            raise item
        return item


def _auto_respond(
    ws: FakeWebSocket, data: bytes, *, suback_code: int = 1, puback: bool = True, ping: bool = True
) -> None:
    packet_type = data[0] >> 4
    decoded = decode_remaining_length(data, 1)
    assert decoded is not None
    _rem, pos = decoded
    body = data[pos:]
    if packet_type == PACKET_CONNECT:
        ws.push_binary(_connack())
    elif packet_type == PACKET_SUBSCRIBE:
        pid = int.from_bytes(body[:2], "big")
        ws.push_binary(_suback(pid, suback_code))
    elif packet_type == PACKET_PUBLISH:
        qos = (data[0] >> 1) & 0x03
        if qos > 0 and puback:
            _topic, pid_pos = decode_utf8(body, 0)
            pid = int.from_bytes(body[pid_pos : pid_pos + 2], "big")
            ws.push_binary(encode_puback(pid))
    elif packet_type == PACKET_PINGREQ and ping:
        ws.push_binary(_PINGRESP)


def _transport(session: FakeSession, **kwargs: Any) -> AwsIotMqttTransport:
    return AwsIotMqttTransport(
        endpoint="example.iot.eu-central-1.amazonaws.com",
        region="eu-central-1",
        client_id="client",
        credentials=AwsIotCredentials(access_key_id="AKIA", secret_access_key="secret", session_token="tok"),
        session=cast(Any, session),
        **kwargs,
    )


@pytest.mark.asyncio
async def test_connect_subscribe_publish_incoming_and_disconnect_round_trip() -> None:
    ws = FakeWebSocket(on_send=_auto_respond)
    session = FakeSession([ws])
    transport = _transport(session, keep_alive_secs=10.0)
    received: list[tuple[str, bytes]] = []

    assert await transport.async_connect() is True
    assert transport.is_connected() is True
    assert transport.last_connected_at is not None
    assert "wss://example.iot.eu-central-1.amazonaws.com/mqtt?" in session.urls[0]

    assert await transport.async_subscribe("aiper/things/SN1/upChan", lambda t, p: received.append((t, p))) is True
    # Incoming QoS 1 publish triggers PUBACK and invokes callback; QoS 0 invokes without PUBACK.
    ws.push_binary(encode_publish("aiper/things/SN1/upChan", b"hi", qos=1, packet_id=9))
    ws.push_binary(encode_publish("aiper/things/SN1/upChan", b"q0", qos=0))
    await asyncio.sleep(0.02)
    assert received == [("aiper/things/SN1/upChan", b"hi"), ("aiper/things/SN1/upChan", b"q0")]
    assert encode_puback(9) in ws.sent

    assert await transport.async_publish("aiper/things/SN1/downChan", "cmd", qos=1) is True
    assert await transport.async_publish("aiper/things/SN1/downChan", b"raw", qos=0) is True

    await transport.async_disconnect()
    assert ws.closed is True
    assert ws.sent[-1][0] >> 4 == PACKET_DISCONNECT
    assert transport.is_connected() is False


@pytest.mark.asyncio
async def test_subscriber_exceptions_are_contained() -> None:
    ws = FakeWebSocket(on_send=_auto_respond)
    transport = _transport(FakeSession([ws]))
    await transport.async_connect()

    def boom(topic: str, payload: bytes) -> None:
        raise ValueError("bad payload")

    assert await transport.async_subscribe("t", boom) is True
    ws.push_binary(encode_publish("t", b"x", qos=0))
    await asyncio.sleep(0.02)
    assert transport.is_connected() is True
    await transport.async_disconnect()


@pytest.mark.asyncio
async def test_connect_failures_record_error_and_clean_up() -> None:
    # Missing session
    no_session = AwsIotMqttTransport(
        endpoint="e",
        region="eu-central-1",
        client_id="c",
        credentials=AwsIotCredentials(access_key_id="A", secret_access_key="S"),
    )
    assert await no_session.async_connect() is False
    assert "ClientSession" in (no_session.last_error or "")

    # CONNACK non-zero return code
    bad_connack = FakeWebSocket(on_send=lambda w, d: w.push_binary(_connack(return_code=5)) if d[0] >> 4 == 1 else None)
    t1 = _transport(FakeSession([bad_connack]))
    assert await t1.async_connect() is False
    assert bad_connack.closed is True
    assert "code 5" in (t1.last_error or "")

    # WebSocket closed before CONNACK
    early_close = FakeWebSocket(on_send=lambda w, d: w.push_close() if d[0] >> 4 == 1 else None)
    t2 = _transport(FakeSession([early_close]))
    assert await t2.async_connect() is False
    assert "closed before" in (t2.last_error or "")

    # WebSocket error before CONNACK
    early_err = FakeWebSocket(on_send=lambda w, d: w.push_error(RuntimeError("tls")) if d[0] >> 4 == 1 else None)
    t3 = _transport(FakeSession([early_err]))
    assert await t3.async_connect() is False
    assert "error before" in (t3.last_error or "")


@pytest.mark.asyncio
async def test_subscribe_and_publish_failures_and_timeouts() -> None:
    transport = _transport(FakeSession([]))
    assert await transport.async_subscribe("t", lambda t, p: None) is False
    assert await transport.async_publish("t", "x") is False
    assert transport.last_error == "MQTT connection is not initialized"
    await transport.async_disconnect()

    # SUBACK 0x80 rejection + PUBACK timeout
    ws = FakeWebSocket(
        on_send=lambda w, d: _auto_respond(w, d, suback_code=0x80, puback=False),
    )
    t = _transport(FakeSession([ws]), operation_timeout=0.05)
    assert await t.async_connect() is True
    assert await t.async_subscribe("t", lambda t, p: None) is False
    assert "rejected" in (t.last_error or "")
    assert await t.async_publish("t", "x", qos=1) is False
    assert "TimeoutError" in (t.last_error or "")
    await t.async_disconnect()


@pytest.mark.asyncio
async def test_keepalive_and_auto_reconnect_refresh_credentials() -> None:
    ws1 = FakeWebSocket(on_send=lambda w, d: _auto_respond(w, d, ping=True))
    ws2 = FakeWebSocket(on_send=lambda w, d: w.push_binary(_connack(session_present=True)) if d[0] >> 4 == 1 else None)
    session = FakeSession([ws1, ConnectionError("transient"), ws2])

    reconnected: list[bool] = []
    creds_calls = 0

    async def async_resolver() -> AwsIotCredentials:
        nonlocal creds_calls
        creds_calls += 1
        return AwsIotCredentials(access_key_id=f"AKIA{creds_calls}", secret_access_key="S", session_token="T")

    transport = _transport(
        session,
        keep_alive_secs=0.03,
        ping_timeout=0.2,
        reconnect_min_timeout_secs=0.02,
        reconnect_max_timeout_secs=0.05,
        on_reconnected=reconnected.append,
        async_credentials_resolver=async_resolver,
    )

    assert await transport.async_connect() is True
    # Wait for at least one keepalive PINGREQ/PINGRESP cycle.
    await asyncio.sleep(0.06)
    assert any(frame == b"\xc0\x00" for frame in ws1.sent)

    # Trigger unexpected drop; expect backoff reconnect with refreshed credentials.
    ws1.push_close(1006)
    for _ in range(30):
        if transport.reconnect_count >= 1 and transport.is_connected():
            break
        await asyncio.sleep(0.02)

    assert transport.reconnect_count == 1
    assert transport.is_connected() is True
    assert reconnected == [True]
    assert creds_calls >= 3
    assert "AKIA3" in session.urls[-1]

    await transport.async_disconnect()


@pytest.mark.asyncio
async def test_keepalive_timeout_triggers_reconnect_and_callback_errors_contained() -> None:
    ws1 = FakeWebSocket(on_send=lambda w, d: _auto_respond(w, d, ping=False))
    ws2 = FakeWebSocket(on_send=_auto_respond)
    session = FakeSession([ws1, ws2])

    def bad_reconnected(_session_present: bool) -> None:
        raise RuntimeError("callback bug")

    transport = _transport(
        session,
        keep_alive_secs=0.02,
        ping_timeout=0.02,
        reconnect_min_timeout_secs=0.01,
        reconnect_max_timeout_secs=0.02,
        on_reconnected=bad_reconnected,
    )

    assert await transport.async_connect() is True
    for _ in range(30):
        if transport.reconnect_count >= 1 and transport.is_connected():
            break
        await asyncio.sleep(0.02)

    assert transport.reconnect_count == 1
    assert transport.is_connected() is True
    await transport.async_disconnect()
