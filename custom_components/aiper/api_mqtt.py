"""Aiper MQTT channel: AWS IoT connection, subscriptions and downChan commands.

Middle layer of the API client stack (see ``api.py``). Builds on the REST
client for Cognito credentials and owns the AWS IoT transport lifecycle,
shadow/report subscriptions, message decoding and AT-command acknowledgement.
"""

from __future__ import annotations

import asyncio
import base64
import json
import logging
import re
import threading
import time
from collections import defaultdict, deque
from collections.abc import Callable
from contextlib import suppress
from datetime import UTC, datetime
from typing import Any

import aiohttp

from .api_rest import AiperRestClient
from .connection import ConnectionState
from .const import X9_SERIES_PREFIXES, XOR_KEY, ApiEndpoint, MqttTopic
from .mqtt import AwsIotCredentials, AwsIotMqttTransport
from .redaction import redact_serial

_LOGGER = logging.getLogger(__name__)

# Refresh the MQTT signing snapshot once the credentials are within this
# window of expiring. Comfortably larger than the coordinator poll interval
# so a refresh is never missed.
MQTT_CREDENTIALS_REFRESH_MARGIN_SECONDS = 600

# MQTT payload callback: called as ``callback(sn, payload)`` from an AWS CRT thread.
ShadowCallback = Callable[[str, dict[str, Any]], None]


class AiperMqttClient(AiperRestClient):
    """AWS IoT MQTT connection and device command channel."""

    def __init__(
        self,
        username: str,
        password: str,
        region: str = ApiEndpoint.eu,
        *,
        async_session: aiohttp.ClientSession,
        time_zone: str | None = None,
    ) -> None:
        """Initialize MQTT state on top of the REST client."""
        super().__init__(username, password, region, async_session=async_session, time_zone=time_zone)
        self._mqtt_client: Any = None
        self._mqtt_first_disconnected_at: datetime | None = None
        self._mqtt_credentials_snapshot: AwsIotCredentials | None = None
        self._mqtt_credentials_refreshing = False
        self._mqtt_last_rebuild_at: float | None = None
        self.mqtt_debug = False
        self._shadow_callbacks: dict[str, list[ShadowCallback]] = {}
        self._lock = threading.Lock()

        # DownChan AT command acknowledgements (received on upChan as "+OK" / "+ERROR").
        # We keep a small per-device FIFO so we can wait for the next ack after a publish.
        self._ack_lock = threading.Lock()
        self._ack_fifo: dict[str, deque[str]] = defaultdict(lambda: deque(maxlen=10))
        self._async_ack_events: dict[str, asyncio.Event] = {}
        self._async_loop: asyncio.AbstractEventLoop | None = None

        # Serialize command sends per device SN so that ack correlation is reliable.
        self._cmd_locks: dict[str, asyncio.Lock] = {}

    def _encrypt(self, data: str) -> str:
        """Encrypt message using XOR + Base64."""
        data_bytes = data.encode("utf-8")
        xored = bytes([b ^ XOR_KEY[i % 4] for i, b in enumerate(data_bytes)])
        return base64.b64encode(xored).decode("utf-8") + "\n"

    def _decrypt(self, data: bytes) -> str:
        """Decrypt message using Base64 + XOR."""
        try:
            decoded = base64.b64decode(data)
            return bytes([b ^ XOR_KEY[i % 4] for i, b in enumerate(decoded)]).decode("utf-8")
        except Exception:
            # May be unencrypted JSON
            return data.decode("utf-8") if isinstance(data, bytes) else data

    async def async_refresh_mqtt_credentials(self) -> AwsIotCredentials | None:
        """Refresh the credential snapshot that the MQTT signer reads.

        `get_aws_credentials` caches until shortly before expiry, so calling
        this from the coordinator on every poll is nearly free and keeps the
        snapshot well ahead of Cognito's ~55 minute lifetime.
        """
        creds = await self.get_aws_credentials()
        if not creds:
            return None
        snapshot = AwsIotCredentials(
            access_key_id=creds["AccessKeyId"],
            secret_access_key=creds["SecretKey"],
            session_token=creds.get("SessionToken", ""),
        )
        self._mqtt_credentials_snapshot = snapshot
        self.connection.mark_credentials_refreshed()
        return snapshot

    def _mqtt_credentials_due_for_refresh(self) -> bool:
        """Whether the cached AWS credentials are close enough to expiry to renew."""
        if self._aws_credentials_exp is None:
            return True
        # Cap the margin at half the configured TTL so a short debug-mode TTL
        # (which can be smaller than the production margin) still produces a
        # clean periodic due/not-due cycle instead of being "due" constantly.
        margin = min(MQTT_CREDENTIALS_REFRESH_MARGIN_SECONDS, self.aws_credentials_ttl // 2)
        return (self._aws_credentials_exp - time.time()) < margin

    def _schedule_mqtt_credentials_refresh(self) -> None:
        """Kick off a credential refresh without waiting for it.

        Safe to call from the AWS CRT's threads: it only hands work to the
        event loop and returns immediately. Never await this from inside the
        signing delegate -- see `_current_mqtt_credentials`.
        """
        loop = self._async_loop
        if loop is None or not loop.is_running():
            return

        # Guard the check-then-set with the same lock used elsewhere for
        # cross-thread state: this can be invoked from multiple AWS CRT
        # threads (not just the event loop thread) per _current_mqtt_credentials's
        # docstring, and an unguarded check-then-set could let two callers
        # both pass the guard and schedule duplicate refreshes.
        with self._lock:
            if self._mqtt_credentials_refreshing:
                return
            self._mqtt_credentials_refreshing = True

        async def _refresh() -> None:
            try:
                await self.async_refresh_mqtt_credentials()
            except Exception as err:
                _LOGGER.debug("Background MQTT credential refresh failed: %s", err)
            finally:
                self._mqtt_credentials_refreshing = False

        try:
            loop.call_soon_threadsafe(lambda: loop.create_task(_refresh()))
        except RuntimeError as err:
            # The loop can be closing/closed if this races with Home
            # Assistant shutdown. If scheduling itself fails, _refresh()
            # never runs, so its `finally` never resets the flag -- reset it
            # here instead, or the opportunistic refresh path stays silently
            # disabled for the rest of this AiperApi instance's life.
            _LOGGER.debug("Could not schedule MQTT credential refresh: %s", err)
            self._mqtt_credentials_refreshing = False

    def _current_mqtt_credentials(self) -> AwsIotCredentials | None:
        """Return the credentials the MQTT transport should sign with.

        Called synchronously by the AWS CRT, sometimes on the Home Assistant
        event loop thread, so this must return immediately. It reads the
        snapshot and, if that snapshot is getting old, schedules a refresh
        for next time rather than waiting for one now.
        """
        if self._mqtt_credentials_due_for_refresh():
            self._schedule_mqtt_credentials_refresh()
        return self._mqtt_credentials_snapshot

    async def connect_mqtt(self) -> bool:
        """Connect to AWS IoT MQTT broker."""
        if not self._identity_id or not self._iot_endpoint:
            _LOGGER.error("No IoT identity/endpoint available")
            self.connection.mark_disconnected("no IoT identity/endpoint available")
            return False

        self.connection.mark_connecting()
        try:
            self._async_loop = asyncio.get_running_loop()
            initial_credentials = await self.async_refresh_mqtt_credentials()
            if initial_credentials is None:
                _LOGGER.error("Unable to obtain AWS credentials for MQTT")
                self.connection.mark_disconnected("unable to obtain AWS credentials for MQTT")
                return False

            client_id = self._identity_id
            region = self._resolve_aws_region()

            self._mqtt_client = AwsIotMqttTransport(
                endpoint=self._iot_endpoint,
                region=region,
                client_id=client_id,
                credentials=initial_credentials,
                connect_timeout=10.0,
                operation_timeout=5.0,
                on_reconnected=self._on_mqtt_reconnected,
                credentials_resolver=self._current_mqtt_credentials,
            )

            if await self._mqtt_client.async_connect():
                self._mqtt_first_disconnected_at = None
                self.connection.mark_connected()
                _LOGGER.debug("Connected to AWS IoT MQTT using AWS IoT Device SDK v2")
                return True

            self.connection.mark_disconnected("MQTT transport did not establish a session")
            return False

        except Exception as err:
            _LOGGER.error("MQTT connection failed: %s", err)
            self.connection.mark_disconnected(err)
            return False

    async def reconnect_mqtt(self) -> bool:
        """Tear down and rebuild the MQTT connection with fresh credentials.

        Backstop for when the SDK's own reconnect loop cannot recover -- a
        wedged socket, or credentials that went stale before the delegate
        was consulted. Rebuilding is heavier than letting the SDK retry, so
        the coordinator only calls this after a long outage.
        """
        _LOGGER.warning("Rebuilding AWS IoT MQTT connection after prolonged disconnect")
        self._mqtt_last_rebuild_at = time.time()
        self.connection.mark_reconnecting()

        with suppress(Exception):
            await self.disconnect_mqtt()

        if not await self.connect_mqtt():
            return False

        await self._resubscribe_all_devices()
        return True

    def seconds_since_mqtt_rebuild(self) -> float | None:
        """Seconds since the last forced MQTT rebuild, or None if never."""
        if self._mqtt_last_rebuild_at is None:
            return None
        return time.time() - self._mqtt_last_rebuild_at

    def is_mqtt_connected(self) -> bool:
        """Return True if the AWS IoT MQTT client is connected.

        Exposed for entity availability and diagnostics. Also records when a
        disconnect began, so `mqtt_disconnected_seconds` keeps measuring the
        same outage across transport objects being rebuilt.
        """
        # The transport is the single source of truth for connectivity; the
        # ConnectionStatus tracker below only records transitions for
        # diagnostics and the connection-state entities.
        client = self._mqtt_client
        connected = bool(client is not None and client.is_connected())
        if connected:
            self._mqtt_first_disconnected_at = None
            if not self.connection.is_connected and self.connection.state is not ConnectionState.RECONNECTING:
                self.connection.mark_connected()
        else:
            if self._mqtt_first_disconnected_at is None:
                self._mqtt_first_disconnected_at = datetime.now(UTC)
            # Sync the tracker when a drop is first observed here (e.g. via a
            # CRT-thread interruption we don't otherwise see), but don't stomp
            # a more specific state like RECONNECTING / CREDENTIALS_STALE.
            if self.connection.state in (ConnectionState.CONNECTED, ConnectionState.CONNECTING):
                self.connection.mark_disconnected()
        return connected

    def mqtt_disconnected_seconds(self) -> float | None:
        """Seconds since MQTT first dropped, or None while connected."""
        self.is_mqtt_connected()  # refreshes _mqtt_first_disconnected_at
        if self._mqtt_first_disconnected_at is None:
            return None
        return (datetime.now(UTC) - self._mqtt_first_disconnected_at).total_seconds()

    def _on_mqtt_reconnected(self, session_present: bool) -> None:
        """Called from the AWS CRT thread when MQTT auto-reconnects.

        When session_present is False the broker has no record of our
        subscriptions, so we must re-subscribe for shadow updates to resume.
        We always re-subscribe to be safe — MQTT re-subscribe is idempotent.
        """
        loop = self._async_loop
        if loop is None or not loop.is_running():
            return
        asyncio.run_coroutine_threadsafe(self._resubscribe_all_devices(), loop)

    async def _resubscribe_all_devices(self) -> None:
        """Re-subscribe to all device topics after an MQTT reconnect."""
        if not self.is_mqtt_connected():
            return
        with self._lock:
            sns = list(self._shadow_callbacks.keys())
        for sn in sns:
            _LOGGER.debug("Re-subscribing MQTT topics for %s after reconnect", redact_serial(sn))

            def on_message(topic: str, payload_bytes: bytes, _sn: str = sn) -> None:
                self._handle_device_message(_sn, topic, payload_bytes)

            async def _subscribe_one(topic: str, _sn: str = sn, _cb: Any = on_message) -> None:
                try:
                    await self._mqtt_client.async_subscribe(topic, _cb, 1)
                except Exception as err:
                    _LOGGER.debug("Re-subscribe failed for %s topic %s: %s", _sn, topic, err)

            # Topics for one device are independent of each other, so
            # subscribe them concurrently instead of paying N sequential
            # round trips per device.
            await asyncio.gather(*(_subscribe_one(topic) for topic in self._subscription_topics_for_sn(sn)))
            with suppress(Exception):
                await self.request_shadow(sn)

    async def request_shadow(self, sn: str) -> bool:
        """Request the current AWS IoT thing shadow."""
        if not self.is_mqtt_connected():
            return False
        try:
            topic = MqttTopic.SHADOW_GET_REQUEST.format(sn=sn)
            if not await self._mqtt_client.async_publish(topic, "", 1):
                return False
            _LOGGER.debug("Published shadow get request to %s", topic)
            return True
        except Exception as err:
            _LOGGER.debug("Failed to request shadow for %s: %s", sn, err)
            return False

    async def publish_shadow_update(self, sn: str, desired: dict[str, Any]) -> bool:
        """Backward-compatible alias for desired-state publishing."""
        return await self.publish_shadow_desired(sn, desired)

    async def publish_shadow_desired(self, sn: str, desired: dict[str, Any]) -> bool:
        """Publish a desired-state update to the AWS IoT device shadow."""
        if not self.is_mqtt_connected():
            return False
        try:
            topic = MqttTopic.SHADOW_UPDATE.format(sn=sn)
            payload = {"state": {"desired": desired}}
            message = json.dumps(payload, separators=(",", ":"))
            if not await self._mqtt_client.async_publish(topic, message, 1):
                return False
            _LOGGER.debug("Published shadow update to %s: %s", topic, message)
            return True
        except Exception as err:
            _LOGGER.debug("Failed to publish shadow update for %s: %s", sn, err)
            return False

    def _register_shadow_callback(self, sn: str, callback: ShadowCallback) -> None:
        """Register a callback for normalized MQTT shadow/report payloads.

        Idempotent: calling this again for the same (sn, callback) pair does
        not append a duplicate, so callers (e.g. a watchdog re-subscribing a
        device that may already be subscribed) can call this safely without
        first checking whether it's already registered.
        """
        with self._lock:
            existing = self._shadow_callbacks.setdefault(sn, [])
            if callback not in existing:
                existing.append(callback)

    def subscribed_serials(self) -> set[str]:
        """Return the serials with at least one registered shadow callback."""
        with self._lock:
            return set(self._shadow_callbacks.keys())

    def _subscription_topics_for_sn(self, sn: str) -> tuple[str, ...]:
        """Return MQTT topics to subscribe for a device."""
        is_x9 = any(sn.upper().startswith(prefix) for prefix in X9_SERIES_PREFIXES)
        report_topic = MqttTopic.SHADOW_REPORT_X9 if is_x9 else MqttTopic.SHADOW_REPORT
        return (
            report_topic.format(sn=sn),
            MqttTopic.READ.format(sn=sn),
            MqttTopic.SHADOW_GET.format(sn=sn),
            MqttTopic.SHADOW_UPDATE_ACCEPTED.format(sn=sn),
            MqttTopic.SHADOW_UPDATE_DELTA.format(sn=sn),
            MqttTopic.SHADOW_UPDATE_DOCUMENTS.format(sn=sn),
            MqttTopic.SHADOW_REPORT_X9.format(sn=sn),
        )

    def _handle_device_message(self, sn: str, topic: str, payload_bytes: bytes) -> None:
        """Normalize one MQTT payload and dispatch it to registered callbacks."""
        try:
            payload = self._decrypt(payload_bytes)
            data = json.loads(payload)

            if (
                isinstance(data, dict)
                and isinstance(data.get("data"), dict)
                and isinstance(data["data"].get("sn"), str)
                and isinstance(data["data"].get("timeZone"), str)
            ):
                self._last_timezone_by_sn[data["data"]["sn"]] = data["data"]["timeZone"]

            if (
                isinstance(data, dict)
                and data.get("type") == "Machine"
                and isinstance(data.get("data"), dict)
                and isinstance(data["data"].get("ack"), str)
            ):
                self._record_ack(sn, data["data"]["ack"])

            if isinstance(data, dict) and "_sn" not in data:
                data["_sn"] = sn

            if isinstance(data, dict) and "_topic" not in data:
                data["_topic"] = topic

            if self.mqtt_debug:
                _LOGGER.debug("MQTT message topic=%s payload=%s", topic, payload[:800])

            with self._lock:
                callbacks = list(self._shadow_callbacks.get(sn, []))
            for cb in callbacks:
                try:
                    cb(sn, data)
                except Exception as err:
                    _LOGGER.error("Callback error: %s", err)

        except Exception as err:
            _LOGGER.error("Failed to process message: %s", err)

    async def subscribe_device(self, sn: str, callback: ShadowCallback) -> bool:
        """Subscribe to device shadow updates."""
        if not self.is_mqtt_connected():
            _LOGGER.warning("MQTT not connected, cannot subscribe")
            return False

        self._async_loop = asyncio.get_running_loop()
        self._register_shadow_callback(sn, callback)

        def on_message(topic: str, payload_bytes: bytes) -> None:
            self._handle_device_message(sn, topic, payload_bytes)

        try:
            # Topics for one device are independent of each other, so
            # subscribe them concurrently instead of paying N sequential
            # round trips per device.
            results = await asyncio.gather(
                *(
                    self._mqtt_client.async_subscribe(topic, on_message, 1)
                    for topic in self._subscription_topics_for_sn(sn)
                )
            )
            return all(results)

        except Exception as err:
            _LOGGER.error("Failed to subscribe to %s: %s", redact_serial(sn), err)
            return False

    def _timezone_string_for_sn(self, sn: str) -> str:
        """Return a timezone string in the device's expected format (e.g. "UTC+3").

        Preference order:
          1) Last value observed from `shadow/report` messages.
          2) Derive from the device's `zoneId` (when available) using zoneinfo.
          3) Fallback to "UTC+0".
        """
        last = self._last_timezone_by_sn.get(sn)
        if isinstance(last, str) and last:
            return last

        zone_id = self._device_zone_id_by_sn.get(sn)
        zone = self._zone_info_cache.get(zone_id) if isinstance(zone_id, str) and zone_id else None
        if zone is not None:
            offset = datetime.now(zone).utcoffset()
            if offset is not None:
                hours = int(offset.total_seconds() / 3600)
                sign = "+" if hours >= 0 else "-"
                return f"UTC{sign}{abs(hours)}"

        return "UTC+0"

    def _record_ack(self, sn: str, ack: str) -> None:
        """Record an AT command acknowledgement received on upChan."""
        with self._ack_lock:
            self._ack_fifo[sn].append(ack)
        if self._async_loop is not None and sn in self._async_ack_events:
            self._async_loop.call_soon_threadsafe(self._async_ack_events[sn].set)

    def _clear_ack_fifo(self, sn: str) -> None:
        with self._ack_lock:
            self._ack_fifo[sn].clear()
        event = self._async_ack_events.get(sn)
        if event is not None:
            event.clear()

    def _async_ack_event(self, sn: str) -> asyncio.Event:
        event = self._async_ack_events.get(sn)
        if event is None:
            event = asyncio.Event()
            self._async_ack_events[sn] = event
        return event

    async def _wait_for_ack(self, sn: str, timeout: float = 4.0) -> str | None:
        """Wait for the next ack for this device SN without blocking."""
        with self._ack_lock:
            if self._ack_fifo[sn]:
                return self._ack_fifo[sn].popleft()

        event = self._async_ack_event(sn)
        try:
            await asyncio.wait_for(event.wait(), timeout=timeout)
        except TimeoutError:
            return None

        with self._ack_lock:
            if not self._ack_fifo[sn]:
                return None
            ack = self._ack_fifo[sn].popleft()
            if not self._ack_fifo[sn]:
                event.clear()
            return ack

    def _cmd_lock(self, sn: str) -> asyncio.Lock:
        lock = self._cmd_locks.get(sn)
        if lock is None:
            lock = asyncio.Lock()
            self._cmd_locks[sn] = lock
        return lock

    async def send_machine_at(self, sn: str, at_cmd: str, timeout: float = 4.0) -> bool | None:
        """Send an AT command via downChan and wait for an upChan ack."""
        self._async_loop = asyncio.get_running_loop()
        tz = self._timezone_string_for_sn(sn)
        payload = {"sn": sn, "timeZone": tz, "cmd": at_cmd}

        async with self._cmd_lock(sn):
            self._async_ack_event(sn)
            self._clear_ack_fifo(sn)
            published = await self.send_command(sn, "Machine", payload)
            if not published:
                return False

            ack = await self._wait_for_ack(sn, timeout=timeout)
            if ack is None:
                return None

            ack_u = ack.upper()
            if "+OK" in ack_u:
                return True
            if "+ERROR" in ack_u:
                return False
            return None

    async def query_machine_at_int(self, sn: str, name: str, timeout: float = 4.0) -> int | None:
        """Query one numeric AT value through downChan.

        Aiper's app emits ``AT+<name>?`` and parses the named response. Keep the
        same command lock used by writes so an unrelated acknowledgement cannot
        be mistaken for the query response.
        """
        self._async_loop = asyncio.get_running_loop()
        command_name = name.strip().upper()
        if not command_name or not re.fullmatch(r"[A-Z0-9_]+", command_name):
            raise ValueError("AT query name contains unsupported characters")

        tz = self._timezone_string_for_sn(sn)
        payload = {"sn": sn, "timeZone": tz, "cmd": f"AT+{command_name}?"}
        pattern = re.compile(rf"(?:\+?{re.escape(command_name)})\s*[:=]\s*(-?\d+)", re.IGNORECASE)

        async with self._cmd_lock(sn):
            self._async_ack_event(sn)
            self._clear_ack_fifo(sn)
            if not await self.send_command(sn, "Machine", payload):
                return None

            deadline = asyncio.get_running_loop().time() + timeout
            while (remaining := deadline - asyncio.get_running_loop().time()) > 0:
                ack = await self._wait_for_ack(sn, timeout=remaining)
                if ack is None:
                    return None
                match = pattern.search(ack)
                if match:
                    return int(match.group(1))
                if "+ERROR" in ack.upper():
                    return None

        return None

    async def send_command(self, sn: str, cmd_type: str, data: dict | None = None) -> bool:
        """Send a command to the device."""
        is_x9 = any(sn.upper().startswith(prefix) for prefix in X9_SERIES_PREFIXES)

        data_obj: dict[str, Any] = dict(data or {})

        if not is_x9:
            cmd_sn = data_obj.get("sn") if isinstance(data_obj.get("sn"), str) else sn
            tz = (
                data_obj.get("timeZone")
                if isinstance(data_obj.get("timeZone"), str)
                else self._timezone_string_for_sn(sn)
            )

            ordered: dict[str, Any] = {
                "sn": cmd_sn,
                "timeZone": tz,
            }

            for k, v in data_obj.items():
                if k in ("sn", "timeZone"):
                    continue
                ordered[k] = v

            data_obj = ordered

        if is_x9:
            payload: dict[str, Any] = {cmd_type: data_obj}
        else:
            payload = {
                "type": cmd_type,
                "data": data_obj,
            }

        if not is_x9:
            payload["res"] = 0

        data_json = json.dumps(data_obj, separators=(",", ":"))
        payload["chksum"] = self._crc16(data_json)

        message = json.dumps(payload, separators=(",", ":"))
        topic = MqttTopic.WRITE.format(sn=sn)

        try:
            if self.is_mqtt_connected():
                if not await self._mqtt_client.async_publish(topic, message, 1):
                    return False
                _LOGGER.debug(
                    "Sent command to %s: %s data=%s",
                    sn,
                    cmd_type,
                    data_json,
                )
                return True
            _LOGGER.warning("MQTT not connected, cannot send command")
            return False
        except Exception as err:
            _LOGGER.error("Failed to send command: %s", err)
            return False

    def _crc16(self, data: str) -> int:
        """Calculate CRC16 checksum."""
        crc = 0x9966
        for byte in data.encode("utf-8"):
            crc ^= byte
            for _ in range(8):
                if crc & 1:
                    crc = (crc >> 1) ^ 0xA001
                else:
                    crc >>= 1
        return crc

    async def disconnect_mqtt(self) -> None:
        """Tear down just the MQTT transport, leaving the REST session alone.

        Always drops the transport reference even if the polite disconnect
        fails, so a wedged connection can't linger with its own reconnect
        loop running alongside its replacement.
        """
        client = self._mqtt_client
        self._mqtt_client = None
        if client is None:
            return
        with suppress(Exception):
            await client.async_disconnect()

    async def disconnect(self) -> None:
        """Disconnect from MQTT and cleanup."""
        await self.disconnect_mqtt()

        _LOGGER.debug("Disconnected from Aiper API")
