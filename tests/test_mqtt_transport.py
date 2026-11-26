"""Tests for the pure-asyncio AWS IoT MQTT-over-WebSockets transport."""

from __future__ import annotations

import asyncio
import logging
import socket
from collections.abc import Callable, Iterator
from typing import Any, cast

import aiohttp
import aiohttp.abc
import pytest
from aiohttp import web

from custom_components.aiper.mqtt import (
    AwsIotCredentials,
    AwsIotMqttTransport,
    format_transport_error,
)
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


@pytest.mark.asyncio
async def test_connect_cancels_previous_lifecycle_and_handles_initial_packets() -> None:
    """Reconnecting replaces any live lifecycle task and dispatches bundled packets."""
    received: list[tuple[str, bytes]] = []
    initial_pub = encode_publish("aiper/things/SN1/upChan", b"bundled", qos=0)

    def _on_send_first(ws: FakeWebSocket, data: bytes) -> None:
        if data[0] >> 4 == PACKET_CONNECT:
            ws.push_binary(_connack() + initial_pub)

    ws1 = FakeWebSocket(on_send=_on_send_first)
    ws2 = FakeWebSocket(on_send=_auto_respond)
    transport = _transport(
        FakeSession([ws1, ws2]),
        credentials_resolver=lambda: (_ for _ in ()).throw(RuntimeError("sync fail")),
    )
    transport._callbacks["aiper/things/SN1/upChan"] = lambda t, p: received.append((t, p))

    assert await transport.async_connect() is True
    await asyncio.sleep(0.02)
    assert received == [("aiper/things/SN1/upChan", b"bundled")]

    # Calling async_connect() again cancels the first lifecycle task cleanly.
    assert await transport.async_connect() is True
    assert ws1.closed is True
    await transport.async_disconnect()


@pytest.mark.asyncio
async def test_ws_error_and_disconnect_fails_pending_and_handles_close_error() -> None:
    """Active WS errors trigger reconnect, fail pending acks, and survive close errors."""
    ws1 = FakeWebSocket(
        on_send=lambda w, d: w.push_binary(_connack()) if d[0] >> 4 == PACKET_CONNECT else None,
    )
    ws2 = FakeWebSocket(on_send=_auto_respond)

    class FailingDisconnectWebSocket(FakeWebSocket):
        async def send_bytes(self, data: bytes) -> None:
            if data[0] >> 4 == PACKET_DISCONNECT:
                raise RuntimeError("disconnect write failed")
            await super().send_bytes(data)

    ws2_bad = FailingDisconnectWebSocket(on_send=_auto_respond)
    transport = _transport(
        FakeSession([ws1, ws2_bad]),
        reconnect_min_timeout_secs=0.01,
        reconnect_max_timeout_secs=0.02,
        operation_timeout=1.0,
    )
    assert await transport.async_connect() is True

    # Start a QoS 1 publish and subscribe that won't receive ACKs before the drop.
    pub_task = asyncio.create_task(transport.async_publish("aiper/things/SN1/downChan", "x", qos=1))
    sub_task = asyncio.create_task(transport.async_subscribe("aiper/things/SN1/upChan", lambda t, p: None))
    await asyncio.sleep(0.01)

    ws1.push_error(RuntimeError("socket reset"))
    assert await pub_task is False
    assert await sub_task is False

    for _ in range(30):
        if transport.reconnect_count >= 1 and transport.is_connected():
            break
        await asyncio.sleep(0.02)
    assert transport.reconnect_count == 1

    # Direct _send_bytes when closed raises ConnectionError cleanly.
    await ws2.close()
    transport._ws = cast(Any, ws2)
    with pytest.raises(ConnectionError):
        await transport._send_bytes(b"\xe0\x00")

    transport._ws = cast(Any, ws2_bad)
    await transport.async_disconnect()
    assert "RuntimeError" in (transport.last_error or "")


def test_format_transport_error_scrubs_urls_and_preserves_context() -> None:
    """Error formatting keeps phase, type and HTTP status while dropping URLs."""
    handshake_err = aiohttp.WSServerHandshakeError(
        cast(Any, SimpleRequestInfo("wss://host.example/mqtt?X-Amz-Signature=deadbeef")),
        (),
        status=403,
        message="Forbidden",
    )
    assert format_transport_error("connect", handshake_err) == "connect: WSServerHandshakeError (HTTP 403)"
    assert format_transport_error("connect", aiohttp.ClientError("bad url")) == "connect: ClientError"
    scrubbed = format_transport_error(
        "read",
        ConnectionError("failed at wss://host.example/mqtt?X-Amz-Signature=deadbeef"),
    )
    assert scrubbed == "read: ConnectionError: failed at <redacted-url>"
    assert "deadbeef" not in scrubbed
    assert format_transport_error("publish", TimeoutError()) == "publish: TimeoutError"


class SimpleRequestInfo:
    """Minimal request_info double for WSServerHandshakeError tests."""

    def __init__(self, real_url: str) -> None:
        self.real_url = real_url


class _LoopbackMqttTransport(AwsIotMqttTransport):
    """Test transport that signs the real AWS URL and targets a loopback peer."""

    def __init__(self, *, port: int, **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self._port = port

    def _signed_websocket_url(self, credentials: AwsIotCredentials) -> str:
        signed = super()._signed_websocket_url(credentials)
        return signed.replace(f"wss://{self.endpoint}", f"ws://127.0.0.1:{self._port}", 1)


def _assert_no_signed_url_leak(text: str) -> None:
    for secret_fragment in (
        "AKIA_SYNTHETIC_KEY",
        "SYNTHETIC_SECRET_KEY",
        "SYNTHETIC_SESSION_TOKEN_VALUE",
        "X-Amz-Credential",
        "X-Amz-Signature",
        "X-Amz-Security-Token",
        "127.0.0.1",
        "ws://",
        "wss://",
    ):
        assert secret_fragment not in text


class _LoopbackResolver(aiohttp.abc.AbstractResolver):
    """In-memory loopback resolver avoiding pycares/DNS worker threads."""

    async def resolve(
        self, host: str, port: int = 0, family: socket.AddressFamily = socket.AF_INET
    ) -> list[aiohttp.abc.ResolveResult]:
        return [
            {
                "hostname": host,
                "host": "127.0.0.1",
                "port": port,
                "family": socket.AF_INET,
                "proto": 0,
                "flags": socket.AI_NUMERICHOST,
            }
        ]

    async def close(self) -> None:
        return None


@pytest.fixture
def loopback_socket() -> Iterator[None]:
    """Allow 127.0.0.1 loopback sockets while keeping external hosts blocked."""
    import pytest_socket

    was_guarded = socket.socket is not pytest_socket._true_socket
    pytest_socket.enable_socket()
    pytest_socket.socket_allow_hosts(["127.0.0.1"])
    try:
        yield
    finally:
        if was_guarded:
            pytest_socket.disable_socket(allow_unix_socket=True)
        else:
            pytest_socket._remove_restrictions()


@pytest.mark.asyncio
async def test_loopback_initial_handshake_rejection_redacts_signed_url(
    caplog: pytest.LogCaptureFixture,
    loopback_socket: None,
) -> None:
    """An HTTP 403 WebSocket upgrade rejection must not leak the signed query string."""
    seen_queries: list[dict[str, str]] = []

    async def handle_mqtt(request: web.Request) -> web.StreamResponse:
        seen_queries.append(dict(request.query))
        return web.Response(status=403, text="Forbidden")

    app = web.Application()
    app.router.add_get("/mqtt", handle_mqtt)
    runner = web.AppRunner(app, access_log=None)
    await runner.setup()
    site = web.TCPSite(runner, "127.0.0.1", 0)
    await site.start()
    port = cast(Any, site._server).sockets[0].getsockname()[1]

    caplog.set_level(logging.DEBUG, logger="custom_components.aiper")
    async with aiohttp.ClientSession(connector=aiohttp.TCPConnector(resolver=_LoopbackResolver())) as session:
        transport = _LoopbackMqttTransport(
            port=port,
            endpoint="example.iot.eu-central-1.amazonaws.com",
            region="eu-central-1",
            client_id="client-1",
            credentials=AwsIotCredentials(
                access_key_id="AKIA_SYNTHETIC_KEY",
                secret_access_key="SYNTHETIC_SECRET_KEY",
                session_token="SYNTHETIC_SESSION_TOKEN_VALUE",
            ),
            session=session,
        )
        try:
            assert await transport.async_connect() is False
            assert transport.last_error == "connect: WSServerHandshakeError (HTTP 403)"
            assert seen_queries and "X-Amz-Signature" in seen_queries[0]
            assert "X-Amz-Security-Token" in seen_queries[0]
            _assert_no_signed_url_leak(transport.last_error)
            aiper_logs = "\n".join(
                record.getMessage() for record in caplog.records if record.name.startswith("custom_components.aiper")
            )
            _assert_no_signed_url_leak(aiper_logs)
            assert "WSServerHandshakeError" in aiper_logs
            assert "HTTP 403" in aiper_logs
        finally:
            await transport.async_disconnect()
            await runner.cleanup()


@pytest.mark.asyncio
async def test_loopback_reconnect_handshake_rejection_redacts_signed_url(
    caplog: pytest.LogCaptureFixture,
    loopback_socket: None,
) -> None:
    """A rejected upgrade during reconnect logs phase and HTTP status without query secrets."""
    attempt = 0

    async def handle_mqtt(request: web.Request) -> web.StreamResponse:
        nonlocal attempt
        attempt += 1
        if attempt == 1:
            ws = web.WebSocketResponse(protocols=("mqtt",))
            await ws.prepare(request)
            msg = await ws.receive()
            if msg.type == aiohttp.WSMsgType.BINARY:
                await ws.send_bytes(_connack())
            await asyncio.sleep(0.02)
            await ws.close(code=1001)
            return ws
        return web.Response(status=403, text="Forbidden")

    app = web.Application()
    app.router.add_get("/mqtt", handle_mqtt)
    runner = web.AppRunner(app, access_log=None)
    await runner.setup()
    site = web.TCPSite(runner, "127.0.0.1", 0)
    await site.start()
    port = cast(Any, site._server).sockets[0].getsockname()[1]

    caplog.set_level(logging.DEBUG, logger="custom_components.aiper")
    async with aiohttp.ClientSession(connector=aiohttp.TCPConnector(resolver=_LoopbackResolver())) as session:
        transport = _LoopbackMqttTransport(
            port=port,
            endpoint="example.iot.eu-central-1.amazonaws.com",
            region="eu-central-1",
            client_id="client-2",
            credentials=AwsIotCredentials(
                access_key_id="AKIA_SYNTHETIC_KEY",
                secret_access_key="SYNTHETIC_SECRET_KEY",
                session_token="SYNTHETIC_SESSION_TOKEN_VALUE",
            ),
            session=session,
            reconnect_min_timeout_secs=0.05,
            reconnect_max_timeout_secs=0.1,
        )
        try:
            assert await transport.async_connect() is True
            for _ in range(60):
                if transport.last_error == "reconnect: WSServerHandshakeError (HTTP 403)":
                    break
                await asyncio.sleep(0.02)

            assert transport.last_error == "reconnect: WSServerHandshakeError (HTTP 403)"
            _assert_no_signed_url_leak(transport.last_error)
            aiper_logs = "\n".join(
                record.getMessage() for record in caplog.records if record.name.startswith("custom_components.aiper")
            )
            _assert_no_signed_url_leak(aiper_logs)
            assert "WSServerHandshakeError" in aiper_logs
            assert "HTTP 403" in aiper_logs
        finally:
            await transport.async_disconnect()
            await runner.cleanup()
