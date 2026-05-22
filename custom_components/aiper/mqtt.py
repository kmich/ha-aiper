"""AWS IoT MQTT transport for Aiper devices."""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Callable
from concurrent.futures import Future
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

_LOGGER = logging.getLogger(__name__)

MessageCallback = Callable[[str, bytes], None]


def _wait_crt_operation[T](operation: Future[T] | tuple[Future[T], int], timeout: float) -> T:
    """Wait for an AWS CRT operation result.

    MQTT3 publish/subscribe return `(future, packet_id)` while connect and
    disconnect return a future directly.
    """
    future = operation[0] if isinstance(operation, tuple) else operation
    return future.result(timeout=timeout)


async def _async_wait_crt_operation[T](operation: Future[T] | tuple[Future[T], int], timeout: float) -> T:
    """Wait for an AWS CRT operation result without blocking the event loop."""
    future = operation[0] if isinstance(operation, tuple) else operation
    return await asyncio.wait_for(asyncio.wrap_future(future), timeout=timeout)


@dataclass(frozen=True, kw_only=True)
class AwsIotCredentials:
    """Temporary AWS credentials returned by Cognito."""

    access_key_id: str
    secret_access_key: str
    session_token: str | None = None


class AwsIotMqttTransport:
    """Small wrapper around AWS IoT Device SDK v2 MQTT over WebSockets."""

    def __init__(
        self,
        *,
        endpoint: str,
        region: str,
        client_id: str,
        credentials: AwsIotCredentials,
        connect_timeout: float = 10.0,
        operation_timeout: float = 5.0,
    ) -> None:
        self.endpoint = endpoint
        self.region = region
        self.client_id = client_id
        self.credentials = credentials
        self.connect_timeout = connect_timeout
        self.operation_timeout = operation_timeout

        self._connection: Any = None
        self._connected = False
        self.last_error: str | None = None
        self.last_connected_at: datetime | None = None
        self.last_disconnected_at: datetime | None = None
        self.reconnect_count = 0

    def connect(self) -> bool:
        """Connect to AWS IoT Core using SigV4-signed MQTT over WebSockets."""
        try:
            self._connection = self._build_connection()
            self._connection.connect().result(timeout=self.connect_timeout)
            self._connected = True
            self.last_error = None
            self.last_connected_at = datetime.now(UTC)
            _LOGGER.info("Connected to AWS IoT MQTT endpoint %s", self.endpoint)
            return True
        except Exception as err:
            self._connected = False
            self.last_error = f"{type(err).__name__}: {err}"
            _LOGGER.error("AWS IoT MQTT connection failed: %s", err)
            return False

    async def async_connect(self) -> bool:
        """Connect to AWS IoT Core using SigV4-signed MQTT over WebSockets."""
        try:
            self._connection = self._build_connection()
            await _async_wait_crt_operation(self._connection.connect(), self.connect_timeout)
            self._connected = True
            self.last_error = None
            self.last_connected_at = datetime.now(UTC)
            _LOGGER.info("Connected to AWS IoT MQTT endpoint %s", self.endpoint)
            return True
        except Exception as err:
            self._connected = False
            self.last_error = f"{type(err).__name__}: {err}"
            _LOGGER.error("AWS IoT MQTT connection failed: %s", err)
            return False

    def _build_connection(self) -> Any:
        """Build an AWS IoT MQTT connection object."""
        from awscrt import auth
        from awsiot import mqtt_connection_builder

        credentials_provider = auth.AwsCredentialsProvider.new_static(
            self.credentials.access_key_id,
            self.credentials.secret_access_key,
            self.credentials.session_token,
        )

        return mqtt_connection_builder.websockets_with_default_aws_signing(
            endpoint=self.endpoint,
            region=self.region,
            credentials_provider=credentials_provider,
            client_id=self.client_id,
            clean_session=False,
            keep_alive_secs=60,
            ping_timeout_ms=5000,
            reconnect_min_timeout_secs=1,
            reconnect_max_timeout_secs=30,
            protocol_operation_timeout_ms=int(self.operation_timeout * 1000),
            enable_metrics_collection=False,
            on_connection_interrupted=self._on_connection_interrupted,
            on_connection_resumed=self._on_connection_resumed,
            on_connection_failure=self._on_connection_failure,
            on_connection_closed=self._on_connection_closed,
        )

    def disconnect(self) -> None:
        """Disconnect from AWS IoT Core."""
        connection = self._connection
        self._connected = False
        self.last_disconnected_at = datetime.now(UTC)
        if connection is None:
            return

        try:
            connection.disconnect().result(timeout=self.operation_timeout)
        except Exception as err:
            self.last_error = f"{type(err).__name__}: {err}"
            _LOGGER.debug("AWS IoT MQTT disconnect failed: %s", err)
        finally:
            self._connection = None

    async def async_disconnect(self) -> None:
        """Disconnect from AWS IoT Core without blocking the event loop."""
        connection = self._connection
        self._connected = False
        self.last_disconnected_at = datetime.now(UTC)
        if connection is None:
            return

        try:
            await _async_wait_crt_operation(connection.disconnect(), self.operation_timeout)
        except Exception as err:
            self.last_error = f"{type(err).__name__}: {err}"
            _LOGGER.debug("AWS IoT MQTT disconnect failed: %s", err)
        finally:
            self._connection = None

    def is_connected(self) -> bool:
        """Return whether the transport considers MQTT connected."""
        return bool(self._connected and self._connection is not None)

    def subscribe(self, topic: str, callback: MessageCallback, qos: int = 1) -> bool:
        """Subscribe to a topic and dispatch raw payload bytes to callback."""
        if not self._connection:
            self.last_error = "MQTT connection is not initialized"
            return False

        try:
            from awscrt import mqtt

            mqtt_qos = mqtt.QoS.AT_LEAST_ONCE if int(qos) == 1 else mqtt.QoS.AT_MOST_ONCE

            def _callback(topic: str, payload: bytes, *args: Any, **kwargs: Any) -> None:
                try:
                    callback(topic, bytes(payload))
                except Exception as err:
                    _LOGGER.error("MQTT callback failed for topic %s: %s", topic, err)

            _wait_crt_operation(
                self._connection.subscribe(topic=topic, qos=mqtt_qos, callback=_callback),
                self.operation_timeout,
            )
            return True
        except Exception as err:
            self.last_error = f"{type(err).__name__}: {err}"
            _LOGGER.error("AWS IoT MQTT subscribe failed for %s: %s", topic, err)
            return False

    async def async_subscribe(self, topic: str, callback: MessageCallback, qos: int = 1) -> bool:
        """Subscribe to a topic and dispatch raw payload bytes to callback."""
        if not self._connection:
            self.last_error = "MQTT connection is not initialized"
            return False

        try:
            from awscrt import mqtt

            mqtt_qos = mqtt.QoS.AT_LEAST_ONCE if int(qos) == 1 else mqtt.QoS.AT_MOST_ONCE

            def _callback(topic: str, payload: bytes, *args: Any, **kwargs: Any) -> None:
                try:
                    callback(topic, bytes(payload))
                except Exception as err:
                    _LOGGER.error("MQTT callback failed for topic %s: %s", topic, err)

            await _async_wait_crt_operation(
                self._connection.subscribe(topic=topic, qos=mqtt_qos, callback=_callback),
                self.operation_timeout,
            )
            return True
        except Exception as err:
            self.last_error = f"{type(err).__name__}: {err}"
            _LOGGER.error("AWS IoT MQTT subscribe failed for %s: %s", topic, err)
            return False

    def publish(self, topic: str, payload: str | bytes, qos: int = 1) -> bool:
        """Publish a message to a topic."""
        if not self._connection:
            self.last_error = "MQTT connection is not initialized"
            return False

        try:
            from awscrt import mqtt

            mqtt_qos = mqtt.QoS.AT_LEAST_ONCE if int(qos) == 1 else mqtt.QoS.AT_MOST_ONCE
            payload_bytes = payload.encode("utf-8") if isinstance(payload, str) else bytes(payload)
            _wait_crt_operation(
                self._connection.publish(topic=topic, payload=payload_bytes, qos=mqtt_qos),
                self.operation_timeout,
            )
            return True
        except Exception as err:
            self.last_error = f"{type(err).__name__}: {err}"
            _LOGGER.error("AWS IoT MQTT publish failed for %s: %s", topic, err)
            return False

    async def async_publish(self, topic: str, payload: str | bytes, qos: int = 1) -> bool:
        """Publish a message to a topic without blocking the event loop."""
        if not self._connection:
            self.last_error = "MQTT connection is not initialized"
            return False

        try:
            from awscrt import mqtt

            mqtt_qos = mqtt.QoS.AT_LEAST_ONCE if int(qos) == 1 else mqtt.QoS.AT_MOST_ONCE
            payload_bytes = payload.encode("utf-8") if isinstance(payload, str) else bytes(payload)
            await _async_wait_crt_operation(
                self._connection.publish(topic=topic, payload=payload_bytes, qos=mqtt_qos),
                self.operation_timeout,
            )
            return True
        except Exception as err:
            self.last_error = f"{type(err).__name__}: {err}"
            _LOGGER.error("AWS IoT MQTT publish failed for %s: %s", topic, err)
            return False

    def _on_connection_interrupted(self, connection: Any, error: Exception, **kwargs: Any) -> None:
        self._connected = False
        self.last_error = f"{type(error).__name__}: {error}"
        self.last_disconnected_at = datetime.now(UTC)
        _LOGGER.warning("AWS IoT MQTT connection interrupted: %s", error)

    def _on_connection_resumed(self, connection: Any, return_code: Any, session_present: bool, **kwargs: Any) -> None:
        self._connected = True
        self.last_connected_at = datetime.now(UTC)
        self.reconnect_count += 1
        _LOGGER.info(
            "AWS IoT MQTT connection resumed return_code=%s session_present=%s",
            return_code,
            session_present,
        )

    def _on_connection_failure(self, connection: Any, callback_data: Any, **kwargs: Any) -> None:
        error = getattr(callback_data, "error", None)
        self._connected = False
        self.last_error = str(error or callback_data)
        _LOGGER.warning("AWS IoT MQTT connection attempt failed: %s", self.last_error)

    def _on_connection_closed(self, connection: Any, callback_data: Any, **kwargs: Any) -> None:
        self._connected = False
        self.last_disconnected_at = datetime.now(UTC)
        _LOGGER.info("AWS IoT MQTT connection closed")
