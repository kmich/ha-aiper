"""Pure-asyncio AWS IoT MQTT-over-WebSockets transport for Aiper devices."""

from __future__ import annotations

import asyncio
import logging
import re
from collections.abc import Awaitable, Callable
from contextlib import suppress
from datetime import UTC, datetime

import aiohttp

from .mqtt_codec import (
    AwsIotCredentials as AwsIotCredentials,
)
from .mqtt_codec import (
    ConnAckPacket,
    MqttPacket,
    MqttStreamDecoder,
    PingRespPacket,
    PubAckPacket,
    PublishPacket,
    SubAckPacket,
    encode_connect,
    encode_disconnect,
    encode_pingreq,
    encode_puback,
    encode_publish,
    encode_subscribe,
    topic_matches,
)
from .mqtt_codec import (
    sign_aws_iot_websocket_url as sign_aws_iot_websocket_url,
)
from .redaction import redact_topic

_LOGGER = logging.getLogger(__name__)

MessageCallback = Callable[[str, bytes], None]

_URL_RE = re.compile(r"(?:wss?|https?)://\S+", re.IGNORECASE)
_AMZ_QUERY_PARAM_RE = re.compile(r"X-Amz-[A-Za-z0-9_-]+=\S+", re.IGNORECASE)


def _sanitize_error_detail(text: str) -> str:
    """Scrub URLs and signed AWS query parameters from exception text."""
    sanitized = _URL_RE.sub("<redacted-url>", text)
    return _AMZ_QUERY_PARAM_RE.sub("X-Amz-***", sanitized)


def format_transport_error(phase: str, err: BaseException) -> str:
    """Return a diagnostic-safe transport error summary without URLs or credentials."""
    err_name = type(err).__name__
    if isinstance(err, aiohttp.ClientResponseError):
        return f"{phase}: {err_name} (HTTP {err.status})"
    if isinstance(err, aiohttp.ClientError):
        return f"{phase}: {err_name}"
    detail = _sanitize_error_detail(str(err)).strip()
    return f"{phase}: {err_name}: {detail}" if detail else f"{phase}: {err_name}"


class AwsIotMqttTransport:
    """Pure-asyncio AWS IoT Core MQTT 3.1.1 transport over aiohttp WebSockets."""

    def __init__(
        self,
        *,
        endpoint: str,
        region: str,
        client_id: str,
        credentials: AwsIotCredentials,
        session: aiohttp.ClientSession | None = None,
        connect_timeout: float = 10.0,
        operation_timeout: float = 5.0,
        keep_alive_secs: float = 60.0,
        ping_timeout: float = 5.0,
        reconnect_min_timeout_secs: float = 1.0,
        reconnect_max_timeout_secs: float = 30.0,
        on_reconnected: Callable[[bool], None] | None = None,
        credentials_resolver: Callable[[], AwsIotCredentials | None] | None = None,
        async_credentials_resolver: Callable[[], Awaitable[AwsIotCredentials | None]] | None = None,
    ) -> None:
        self.endpoint = endpoint
        self.region = region
        self.client_id = client_id
        self.credentials = credentials
        self._session = session
        self.connect_timeout = connect_timeout
        self.operation_timeout = operation_timeout
        self.keep_alive_secs = keep_alive_secs
        self.ping_timeout = ping_timeout
        self.reconnect_min_timeout_secs = reconnect_min_timeout_secs
        self.reconnect_max_timeout_secs = reconnect_max_timeout_secs
        self.on_reconnected = on_reconnected
        self._credentials_resolver = credentials_resolver
        self._async_credentials_resolver = async_credentials_resolver

        self._ws: aiohttp.ClientWebSocketResponse | None = None
        self._connected = False
        self._closing = False
        self._lifecycle_task: asyncio.Task[None] | None = None
        self._send_lock = asyncio.Lock()
        self._next_packet_id = 0
        self._callbacks: dict[str, MessageCallback] = {}
        self._pending_pubacks: dict[int, asyncio.Future[None]] = {}
        self._pending_subacks: dict[int, asyncio.Future[SubAckPacket]] = {}
        self._ping_event = asyncio.Event()

        self.last_error: str | None = None
        self.last_connected_at: datetime | None = None
        self.last_disconnected_at: datetime | None = None
        self.reconnect_count = 0
        self.credential_signing_count = 0

    def _allocate_packet_id(self) -> int:
        self._next_packet_id = (self._next_packet_id % 0xFFFF) + 1
        return self._next_packet_id

    async def _resolve_credentials(self) -> AwsIotCredentials:
        """Resolve current AWS credentials, preferring async renewal when available."""
        self.credential_signing_count += 1
        creds: AwsIotCredentials | None = None
        if self._async_credentials_resolver is not None:
            try:
                creds = await self._async_credentials_resolver()
            except Exception as err:
                _LOGGER.debug("Async MQTT credential resolver failed: %s", format_transport_error("credentials", err))
        elif self._credentials_resolver is not None:
            try:
                creds = self._credentials_resolver()
            except Exception as err:
                _LOGGER.debug("Sync MQTT credential resolver failed: %s", format_transport_error("credentials", err))

        if creds is not None:
            self.credentials = creds
        else:
            creds = self.credentials

        _LOGGER.debug(
            "Signing AWS IoT MQTT connection (invocation #%d, access_key_id=%s...)",
            self.credential_signing_count,
            creds.access_key_id[:6],
        )
        return creds

    def _signed_websocket_url(self, credentials: AwsIotCredentials) -> str:
        """Return a SigV4-presigned WebSocket URL for the given credentials."""
        return sign_aws_iot_websocket_url(self.endpoint, self.region, credentials)

    async def _open_session(
        self,
    ) -> tuple[aiohttp.ClientWebSocketResponse, bool, MqttStreamDecoder, list[MqttPacket]]:
        """Open a WebSocket, complete MQTT CONNECT/CONNACK, and return session state."""
        if self._session is None:
            raise ValueError("aiohttp ClientSession is required")

        creds = await self._resolve_credentials()
        url = self._signed_websocket_url(creds)
        ws = await asyncio.wait_for(
            self._session.ws_connect(url, protocols=("mqtt",), heartbeat=None),
            timeout=self.connect_timeout,
        )
        decoder = MqttStreamDecoder()
        try:
            await ws.send_bytes(
                encode_connect(
                    self.client_id,
                    keep_alive=max(1, int(self.keep_alive_secs)),
                    clean_session=False,
                )
            )
            while True:
                msg = await asyncio.wait_for(ws.receive(), timeout=self.connect_timeout)
                if msg.type == aiohttp.WSMsgType.BINARY:
                    packets = decoder.feed(bytes(msg.data))
                    for idx, packet in enumerate(packets):
                        if isinstance(packet, ConnAckPacket):
                            if packet.return_code != 0:
                                raise ConnectionError(f"MQTT CONNACK rejected with code {packet.return_code}")
                            return ws, packet.session_present, decoder, packets[idx + 1 :]
                elif msg.type in (
                    aiohttp.WSMsgType.CLOSE,
                    aiohttp.WSMsgType.CLOSING,
                    aiohttp.WSMsgType.CLOSED,
                ):
                    raise ConnectionError("WebSocket closed before MQTT CONNACK")
                elif msg.type == aiohttp.WSMsgType.ERROR:
                    ws_err = ws.exception()
                    detail = (
                        format_transport_error("handshake", ws_err)
                        if isinstance(ws_err, BaseException)
                        else "handshake: WebSocket error"
                    )
                    raise ConnectionError(f"WebSocket error before MQTT CONNACK ({detail})")
        except BaseException:
            with suppress(Exception):
                await ws.close()
            raise

    async def async_connect(self) -> bool:
        """Connect to AWS IoT Core using SigV4-signed MQTT over WebSockets."""
        if self._lifecycle_task is not None and not self._lifecycle_task.done():
            self._closing = True
            self._lifecycle_task.cancel()
            with suppress(asyncio.CancelledError):
                await self._lifecycle_task

        try:
            self._closing = False
            ws, _session_present, decoder, initial_packets = await self._open_session()
            self._ws = ws
            self._connected = True
            self.last_error = None
            self.last_connected_at = datetime.now(UTC)
            self._lifecycle_task = asyncio.create_task(self._run_lifecycle(decoder, initial_packets))
            _LOGGER.debug("Connected to AWS IoT MQTT")
            return True
        except Exception as err:
            self._ws = None
            self._connected = False
            safe_err = format_transport_error("connect", err)
            self.last_error = safe_err
            _LOGGER.error("AWS IoT MQTT connection failed: %s", safe_err)
            return False

    async def _send_bytes(self, data: bytes) -> None:
        ws = self._ws
        if ws is None or ws.closed:
            raise ConnectionError("MQTT connection is not initialized")
        async with self._send_lock:
            ws = self._ws
            if ws is None or ws.closed:
                raise ConnectionError("MQTT connection is not initialized")
            await ws.send_bytes(data)

    def _fail_pending(self, exc: Exception) -> None:
        for future in self._pending_pubacks.values():
            if not future.done():
                future.set_exception(exc)
        self._pending_pubacks.clear()
        for sub_future in self._pending_subacks.values():
            if not sub_future.done():
                sub_future.set_exception(exc)
        self._pending_subacks.clear()

    def _handle_packet(self, packet: MqttPacket) -> None:
        if isinstance(packet, PublishPacket):
            if packet.qos == 1 and packet.packet_id is not None:
                task = asyncio.create_task(self._send_puback(packet.packet_id))
                task.add_done_callback(lambda t: t.exception() if not t.cancelled() else None)
            for topic_filter, callback in list(self._callbacks.items()):
                if topic_matches(topic_filter, packet.topic):
                    try:
                        callback(packet.topic, packet.payload)
                    except Exception as err:
                        _LOGGER.error("MQTT callback failed for topic %s: %s", redact_topic(packet.topic), err)
        elif isinstance(packet, PubAckPacket):
            pub_future = self._pending_pubacks.pop(packet.packet_id, None)
            if pub_future is not None and not pub_future.done():
                pub_future.set_result(None)
        elif isinstance(packet, SubAckPacket):
            sub_future = self._pending_subacks.pop(packet.packet_id, None)
            if sub_future is not None and not sub_future.done():
                sub_future.set_result(packet)
        elif isinstance(packet, PingRespPacket):
            self._ping_event.set()

    async def _send_puback(self, packet_id: int) -> None:
        with suppress(Exception):
            await self._send_bytes(encode_puback(packet_id))

    async def _read_loop(
        self,
        ws: aiohttp.ClientWebSocketResponse,
        decoder: MqttStreamDecoder,
        initial_packets: list[MqttPacket],
    ) -> None:
        for packet in initial_packets:
            self._handle_packet(packet)

        async for msg in ws:
            if msg.type == aiohttp.WSMsgType.BINARY:
                for packet in decoder.feed(bytes(msg.data)):
                    self._handle_packet(packet)
            elif msg.type in (
                aiohttp.WSMsgType.CLOSE,
                aiohttp.WSMsgType.CLOSING,
                aiohttp.WSMsgType.CLOSED,
            ):
                if not self._closing and self.last_error is None:
                    self.last_error = f"WebSocket closed (code={msg.data})"
                break
            elif msg.type == aiohttp.WSMsgType.ERROR:
                ws_err = ws.exception()
                self.last_error = (
                    format_transport_error("read", ws_err)
                    if isinstance(ws_err, BaseException)
                    else "read: WebSocket error"
                )
                break

    async def _keepalive_loop(self, ws: aiohttp.ClientWebSocketResponse) -> None:
        try:
            while not self._closing and self._ws is ws and not ws.closed:
                await asyncio.sleep(self.keep_alive_secs)
                if self._closing or self._ws is not ws or ws.closed:
                    return
                self._ping_event.clear()
                await self._send_bytes(encode_pingreq())
                await asyncio.wait_for(self._ping_event.wait(), timeout=self.ping_timeout)
        except asyncio.CancelledError:
            raise
        except Exception as err:
            if not self._closing and self._ws is ws:
                self.last_error = format_transport_error("keepalive", err)
                with suppress(Exception):
                    await ws.close()

    async def _run_lifecycle(
        self,
        decoder: MqttStreamDecoder,
        initial_packets: list[MqttPacket],
    ) -> None:
        delay = max(0.05, self.reconnect_min_timeout_secs)
        while not self._closing:
            ws = self._ws
            if ws is not None:
                keepalive = asyncio.create_task(self._keepalive_loop(ws))
                try:
                    await self._read_loop(ws, decoder, initial_packets)
                except asyncio.CancelledError:
                    raise
                except Exception as err:
                    self.last_error = format_transport_error("read", err)
                finally:
                    keepalive.cancel()
                    with suppress(asyncio.CancelledError, Exception):
                        await keepalive
                    if not self._closing:
                        self._connected = False
                        self.last_disconnected_at = datetime.now(UTC)
                        if self.last_error is None:
                            self.last_error = "MQTT connection interrupted"
                        _LOGGER.warning("AWS IoT MQTT connection interrupted: %s", self.last_error)
                    self._fail_pending(ConnectionError("MQTT connection interrupted"))
                    self._ws = None
                    with suppress(Exception):
                        await ws.close()

            if self._closing:
                break

            while not self._closing:
                await asyncio.sleep(delay)
                if self._closing:
                    break
                try:
                    ws, session_present, decoder, initial_packets = await self._open_session()
                except asyncio.CancelledError:
                    raise
                except Exception as err:
                    safe_err = format_transport_error("reconnect", err)
                    self.last_error = safe_err
                    _LOGGER.warning("AWS IoT MQTT reconnect failed: %s", safe_err)
                    delay = min(delay * 2.0, max(delay, self.reconnect_max_timeout_secs))
                    continue

                if self._closing:
                    with suppress(Exception):
                        await ws.close()
                    return

                self._ws = ws
                self._connected = True
                self.last_connected_at = datetime.now(UTC)
                self.last_error = None
                self.reconnect_count += 1
                delay = max(0.05, self.reconnect_min_timeout_secs)
                _LOGGER.info("AWS IoT MQTT connection resumed session_present=%s", session_present)
                if self.on_reconnected is not None:
                    try:
                        self.on_reconnected(session_present)
                    except Exception as err:
                        _LOGGER.debug("on_reconnected callback failed: %s", err)
                break

    async def async_disconnect(self) -> None:
        """Disconnect from AWS IoT Core cleanly without blocking."""
        self._closing = True
        self._connected = False
        self.last_disconnected_at = datetime.now(UTC)

        ws = self._ws
        self._ws = None
        if ws is not None and not ws.closed:
            try:
                await asyncio.wait_for(ws.send_bytes(encode_disconnect()), timeout=self.operation_timeout)
                await asyncio.wait_for(ws.close(), timeout=self.operation_timeout)
            except Exception as err:
                safe_err = format_transport_error("disconnect", err)
                self.last_error = safe_err
                _LOGGER.debug("AWS IoT MQTT disconnect failed: %s", safe_err)

        lifecycle = self._lifecycle_task
        self._lifecycle_task = None
        if lifecycle is not None and not lifecycle.done():
            lifecycle.cancel()
            with suppress(asyncio.CancelledError):
                await lifecycle

        self._fail_pending(ConnectionError("MQTT disconnected"))

    def is_connected(self) -> bool:
        """Return whether the transport considers MQTT connected."""
        return bool(self._connected and self._ws is not None and not self._ws.closed)

    async def async_subscribe(self, topic: str, callback: MessageCallback, qos: int = 1) -> bool:
        """Subscribe to a topic and dispatch incoming payload bytes to callback."""
        if not self.is_connected():
            self.last_error = "MQTT connection is not initialized"
            return False

        self._callbacks[topic] = callback
        packet_id = self._allocate_packet_id()
        loop = asyncio.get_running_loop()
        future: asyncio.Future[SubAckPacket] = loop.create_future()
        self._pending_subacks[packet_id] = future
        try:
            mqtt_qos = 1 if int(qos) == 1 else 0
            await self._send_bytes(encode_subscribe(packet_id, topic, qos=mqtt_qos))
            suback = await asyncio.wait_for(future, timeout=self.operation_timeout)
            if any(code == 0x80 for code in suback.return_codes):
                raise PermissionError(f"MQTT subscribe rejected for {redact_topic(topic)}")
            return True
        except Exception as err:
            self._pending_subacks.pop(packet_id, None)
            safe_err = format_transport_error("subscribe", err)
            self.last_error = safe_err
            _LOGGER.error("AWS IoT MQTT subscribe failed for %s: %s", redact_topic(topic), safe_err)
            return False

    async def async_publish(self, topic: str, payload: str | bytes, qos: int = 1) -> bool:
        """Publish a message to a topic asynchronously."""
        if not self.is_connected():
            self.last_error = "MQTT connection is not initialized"
            return False

        mqtt_qos = 1 if int(qos) == 1 else 0
        payload_bytes = payload.encode("utf-8") if isinstance(payload, str) else bytes(payload)
        packet_id = self._allocate_packet_id() if mqtt_qos > 0 else None
        future: asyncio.Future[None] | None = None
        if packet_id is not None:
            future = asyncio.get_running_loop().create_future()
            self._pending_pubacks[packet_id] = future

        try:
            await self._send_bytes(encode_publish(topic, payload_bytes, qos=mqtt_qos, packet_id=packet_id))
            if future is not None:
                await asyncio.wait_for(future, timeout=self.operation_timeout)
            return True
        except Exception as err:
            if packet_id is not None:
                self._pending_pubacks.pop(packet_id, None)
            safe_err = format_transport_error("publish", err)
            self.last_error = safe_err
            _LOGGER.error("AWS IoT MQTT publish failed for %s: %s", redact_topic(topic), safe_err)
            return False
