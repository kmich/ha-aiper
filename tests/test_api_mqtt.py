"""Tests for the MQTT channel layer (api_mqtt.py) with fake transports."""

from __future__ import annotations

import asyncio
import json
import logging
from typing import Any, cast

import pytest

from custom_components.aiper import api_mqtt
from custom_components.aiper.api import AiperApi
from custom_components.aiper.connection import ConnectionState
from custom_components.aiper.mqtt import AwsIotCredentials

SN = "SN1234567890"


class FakeTransport:
    """Controllable async transport double."""

    def __init__(self, *, connect: bool = True, publish: bool = True, subscribe: bool = True) -> None:
        self.connect_result = connect
        self.publish_result: bool | Exception = publish
        self.subscribe_result: bool | Exception = subscribe
        self.connected = False
        self.published: list[tuple[str, Any]] = []
        self.subscriptions: dict[str, Any] = {}
        self.kwargs: dict[str, Any] = {}

    async def async_connect(self) -> bool:
        self.connected = self.connect_result
        return self.connect_result

    def is_connected(self) -> bool:
        return self.connected

    async def async_publish(self, topic: str, payload: Any, qos: int = 1) -> bool:
        if isinstance(self.publish_result, Exception):
            raise self.publish_result
        self.published.append((topic, payload))
        return self.publish_result

    async def async_subscribe(self, topic: str, callback: Any, qos: int = 1) -> bool:
        if isinstance(self.subscribe_result, Exception):
            raise self.subscribe_result
        self.subscriptions[topic] = callback
        return self.subscribe_result

    async def async_disconnect(self) -> None:
        self.connected = False


def _api() -> AiperApi:
    return AiperApi("user@example.com", "secret", "eu", async_session=cast(Any, object()))


def _connected_api() -> tuple[AiperApi, FakeTransport]:
    api = _api()
    transport = FakeTransport()
    transport.connected = True
    api._mqtt_client = transport
    return api, transport


def _creds() -> dict[str, str]:
    return {"AccessKeyId": "AKIA", "SecretKey": "secret", "SessionToken": "session"}


def test_decrypt_falls_back_to_plain_text() -> None:
    api = _api()

    assert api._decrypt(api._encrypt('{"a": 1}').strip().encode()) == '{"a": 1}'
    assert api._decrypt(b"not base64 at all!") == "not base64 at all!"


@pytest.mark.asyncio
async def test_refresh_mqtt_credentials_builds_snapshot(monkeypatch: pytest.MonkeyPatch) -> None:
    api = _api()
    results: list[Any] = [None, _creds()]

    async def fake_creds() -> Any:
        return results.pop(0)

    monkeypatch.setattr(api, "get_aws_credentials", fake_creds)

    assert await api.async_refresh_mqtt_credentials() is None
    snapshot = await api.async_refresh_mqtt_credentials()
    assert snapshot == AwsIotCredentials(access_key_id="AKIA", secret_access_key="secret", session_token="session")
    assert api.connection.credential_refresh_count == 1


@pytest.mark.asyncio
async def test_connect_mqtt_paths(monkeypatch: pytest.MonkeyPatch) -> None:
    api = _api()
    assert await api.connect_mqtt() is False  # no identity/endpoint yet

    api._identity_id = "eu-central-1:abc"
    api._iot_endpoint = "abc.iot.eu-central-1.amazonaws.com"
    snapshots: list[Any] = [None]

    async def fake_refresh() -> Any:
        return snapshots.pop(0)

    monkeypatch.setattr(api, "async_refresh_mqtt_credentials", fake_refresh)
    assert await api.connect_mqtt() is False
    assert "AWS credentials" in (api.connection.last_error or "")

    transports: list[FakeTransport] = []

    def make_transport(**kwargs: Any) -> FakeTransport:
        transport = FakeTransport(connect=len(transports) > 0)
        transport.kwargs = kwargs
        transports.append(transport)
        return transport

    monkeypatch.setattr(api_mqtt, "AwsIotMqttTransport", make_transport)
    creds = AwsIotCredentials(access_key_id="A", secret_access_key="S")
    snapshots.extend([creds, creds])

    assert await api.connect_mqtt() is False
    assert api.connection.state is ConnectionState.DISCONNECTED
    assert await api.connect_mqtt() is True
    assert api.connection.state is ConnectionState.CONNECTED
    assert transports[-1].kwargs["client_id"] == "eu-central-1:abc"
    assert transports[-1].kwargs["region"] == "eu-central-1"
    assert "credentials_resolver" not in transports[-1].kwargs
    assert transports[-1].kwargs["async_credentials_resolver"] == api.async_refresh_mqtt_credentials

    def exploding(**kwargs: Any) -> Any:
        raise RuntimeError("transport init failed")

    monkeypatch.setattr(api_mqtt, "AwsIotMqttTransport", exploding)
    snapshots.append(creds)
    assert await api.connect_mqtt() is False
    assert "transport init failed" in (api.connection.last_error or "")


@pytest.mark.asyncio
async def test_reconnect_rebuilds_and_resubscribes(monkeypatch: pytest.MonkeyPatch) -> None:
    api, transport = _connected_api()
    received: list[tuple[str, Any]] = []
    api._register_shadow_callback(SN, lambda sn, data: received.append((sn, data)))
    connects: list[bool] = [False, True]

    async def fake_connect() -> bool:
        ok = connects.pop(0)
        if ok:
            api._mqtt_client = transport
            transport.connected = True
        return ok

    monkeypatch.setattr(api, "connect_mqtt", fake_connect)

    assert api.seconds_since_mqtt_rebuild() is None
    assert await api.reconnect_mqtt() is False
    assert api.seconds_since_mqtt_rebuild() is not None
    assert await api.reconnect_mqtt() is True

    upchan = f"aiper/things/{SN}/upChan"
    assert upchan in transport.subscriptions
    assert (f"$aws/things/{SN}/shadow/get", "") in transport.published
    transport.subscriptions[upchan](upchan, json.dumps({"type": "Machine", "data": {"status": 1}}).encode())
    assert received[0][1]["_topic"] == upchan


@pytest.mark.asyncio
async def test_resubscribe_tolerates_subscribe_errors() -> None:
    api, transport = _connected_api()
    api._register_shadow_callback(SN, lambda sn, data: None)
    transport.subscribe_result = RuntimeError("timeout")

    await api._resubscribe_all_devices()

    transport.connected = False
    await api._resubscribe_all_devices()  # disconnected: nothing to do


@pytest.mark.asyncio
async def test_on_reconnected_schedules_resubscribe(monkeypatch: pytest.MonkeyPatch) -> None:
    api, _transport = _connected_api()
    calls: list[None] = []

    async def fake_resubscribe() -> None:
        calls.append(None)

    monkeypatch.setattr(api, "_resubscribe_all_devices", fake_resubscribe)

    api._on_mqtt_reconnected(False)  # no loop captured: ignored
    api._async_loop = asyncio.get_running_loop()
    api._on_mqtt_reconnected(True)
    await asyncio.sleep(0)
    await asyncio.sleep(0)

    assert calls == [None]

    async def failing_resubscribe() -> None:
        raise RuntimeError("boom")

    monkeypatch.setattr(api, "_resubscribe_all_devices", failing_resubscribe)
    api._on_mqtt_reconnected(False)
    await asyncio.sleep(0)
    await asyncio.sleep(0)


@pytest.mark.asyncio
async def test_disconnect_mqtt_cancels_pending_resubscribe_tasks(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    api, transport = _connected_api()
    started = asyncio.Event()
    cancelled = False

    async def slow_resubscribe() -> None:
        nonlocal cancelled
        started.set()
        try:
            await asyncio.sleep(60)
        except asyncio.CancelledError:
            cancelled = True
            raise

    monkeypatch.setattr(api, "_resubscribe_all_devices", slow_resubscribe)
    api._async_loop = asyncio.get_running_loop()
    api._on_mqtt_reconnected(False)
    await started.wait()

    assert len(api._resubscribe_tasks) == 1

    await api.disconnect_mqtt()

    assert cancelled is True
    assert not api._resubscribe_tasks
    assert transport.connected is False


@pytest.mark.asyncio
async def test_resubscribe_all_devices_is_serialized() -> None:
    api, transport = _connected_api()
    api._register_shadow_callback(SN, lambda sn, data: None)
    active = 0
    max_active = 0

    async def slow_subscribe(topic: str, callback: Any, qos: int = 1) -> bool:
        nonlocal active, max_active
        active += 1
        max_active = max(max_active, active)
        await asyncio.sleep(0.01)
        active -= 1
        return True

    transport.async_subscribe = slow_subscribe  # type: ignore[method-assign]
    await asyncio.gather(api._resubscribe_all_devices(), api._resubscribe_all_devices())
    assert max_active <= len(api._subscription_topics_for_sn(SN))


def test_connection_tracker_follows_transport_state() -> None:
    api, transport = _connected_api()
    api.connection.mark_connecting()

    assert api.is_mqtt_connected() is True
    assert api.connection.state is ConnectionState.CONNECTED

    transport.connected = False
    assert api.is_mqtt_connected() is False
    assert api.connection.state is ConnectionState.DISCONNECTED


@pytest.mark.asyncio
async def test_shadow_requests_and_desired_updates() -> None:
    api, transport = _connected_api()

    assert await api.request_shadow(SN) is True
    assert await api.publish_shadow_update(SN, {"Machine": {"cleanPath": 1}}) is True
    assert transport.published[-1] == (
        f"$aws/things/{SN}/shadow/update",
        '{"state":{"desired":{"Machine":{"cleanPath":1}}}}',
    )

    transport.publish_result = False
    assert await api.request_shadow(SN) is False
    assert await api.publish_shadow_desired(SN, {}) is False

    transport.publish_result = RuntimeError("broken pipe")
    assert await api.request_shadow(SN) is False
    assert await api.publish_shadow_desired(SN, {}) is False

    transport.connected = False
    assert await api.request_shadow(SN) is False
    assert await api.publish_shadow_desired(SN, {}) is False


def test_message_handling_redacts_debug_logs_and_contains_errors(caplog: pytest.LogCaptureFixture) -> None:
    api, _transport = _connected_api()
    api.mqtt_debug = True
    seen: list[Any] = []

    def bad_callback(sn: str, data: Any) -> None:
        raise ValueError("callback bug")

    api._register_shadow_callback(SN, bad_callback)
    api._register_shadow_callback(SN, lambda sn, data: seen.append(data))
    caplog.set_level(logging.DEBUG, logger=api_mqtt.__name__)

    payload = {"data": {"sn": SN, "timeZone": "UTC+3"}}
    api._handle_device_message(SN, f"aiper/things/{SN}/shadow/report", json.dumps(payload).encode())
    api._handle_device_message(SN, "t", b"\xff\xfe not json")

    assert seen[0]["data"]["timeZone"] == "UTC+3"
    assert api._last_timezone_by_sn[SN] == "UTC+3"
    assert "Callback error" in caplog.text
    assert "Failed to process message" in caplog.text
    assert SN not in caplog.text


@pytest.mark.asyncio
async def test_subscribe_device_requires_connection_and_reports_errors() -> None:
    api, transport = _connected_api()

    assert await api.subscribe_device(SN, lambda sn, data: None) is True
    assert SN in api.subscribed_serials()

    # An unsubscribed serial reports failure when the transport fails.
    transport.subscribe_result = RuntimeError("denied")
    assert await api.subscribe_device("SN_FAIL", lambda sn, data: None) is False
    assert "SN_FAIL" not in api.subscribed_serials()

    transport.connected = False
    assert await api.subscribe_device("SN_OFFLINE", lambda sn, data: None) is False


@pytest.mark.asyncio
async def test_ack_waiting_timeout_and_late_ack() -> None:
    api, _transport = _connected_api()
    api._async_loop = asyncio.get_running_loop()

    assert await api._wait_for_ack(SN, timeout=0.01) is None

    async def deliver() -> None:
        await asyncio.sleep(0.01)
        api._record_ack(SN, "+OK")

    task = asyncio.create_task(deliver())
    assert await api._wait_for_ack(SN, timeout=1) == "+OK"
    await task

    # An event set with an empty FIFO (e.g. cleared concurrently) yields no ack.
    api._async_ack_event(SN).set()
    assert await api._wait_for_ack(SN, timeout=1) is None


@pytest.mark.asyncio
async def test_send_machine_at_outcomes(monkeypatch: pytest.MonkeyPatch) -> None:
    api, transport = _connected_api()
    acks: list[str | None] = ["+OK", "+ERROR", "garbled", None]

    async def fake_wait(sn: str, timeout: float = 4.0) -> str | None:
        return acks.pop(0)

    monkeypatch.setattr(api, "_wait_for_ack", fake_wait)

    assert await api.send_machine_at(SN, "AT+MODE=1") is True
    assert await api.send_machine_at(SN, "AT+MODE=1") is False
    assert await api.send_machine_at(SN, "AT+MODE=1") is None
    assert await api.send_machine_at(SN, "AT+MODE=1") is None
    transport.publish_result = False
    assert await api.send_machine_at(SN, "AT+MODE=1") is False


@pytest.mark.asyncio
async def test_query_machine_at_int_outcomes(monkeypatch: pytest.MonkeyPatch) -> None:
    api, transport = _connected_api()

    with pytest.raises(ValueError):
        await api.query_machine_at_int(SN, "AUTO;rm")

    acks: list[str | None] = ["+OK", "+AUTO:1", "+ERROR", None]

    async def fake_wait(sn: str, timeout: float = 4.0) -> str | None:
        return acks.pop(0)

    monkeypatch.setattr(api, "_wait_for_ack", fake_wait)

    assert await api.query_machine_at_int(SN, "auto") == 1  # skips the unrelated +OK
    assert await api.query_machine_at_int(SN, "AUTO") is None  # +ERROR
    assert await api.query_machine_at_int(SN, "AUTO") is None  # timeout

    transport.publish_result = False
    assert await api.query_machine_at_int(SN, "AUTO") is None

    transport.publish_result = True
    assert await api.query_machine_at_int(SN, "AUTO", timeout=0) is None


@pytest.mark.asyncio
async def test_send_command_payload_shapes_and_failures(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    api, transport = _connected_api()
    caplog.set_level(logging.DEBUG, logger=api_mqtt.__name__)

    assert await api.send_command(SN, "Machine", {"cmd": "AT+MODE=1", "sn": SN, "timeZone": "UTC+1"}) is True
    topic, message = transport.published[-1]
    body = json.loads(message)
    assert topic == f"aiper/things/{SN}/downChan"
    assert list(body["data"]) == ["sn", "timeZone", "cmd"]
    assert body["res"] == 0 and isinstance(body["chksum"], int)
    assert SN not in caplog.text

    assert await api.send_command("X9ABC123456", "Machine", {"cmd": "x"}) is True
    x9 = json.loads(transport.published[-1][1])
    assert "Machine" in x9 and "res" not in x9

    transport.publish_result = False
    assert await api.send_command(SN, "Machine") is False
    transport.publish_result = RuntimeError("closed")
    assert await api.send_command(SN, "Machine") is False
    transport.connected = False
    assert await api.send_command(SN, "Machine") is False


@pytest.mark.asyncio
async def test_disconnect_without_transport() -> None:
    api = _api()

    await api.disconnect_mqtt()
    await api.disconnect()

    assert api._mqtt_client is None


@pytest.mark.asyncio
async def test_subscription_recovery_retries_only_missing_topics_and_deduplicates_x9() -> None:
    """Partial subscription failure tracks missing topics and recovers without duplicates."""
    api, transport = _connected_api()
    topics = api._subscription_topics_for_sn("X912345")
    assert len(topics) == len(set(topics))

    fail_topic = f"aiper/things/{SN}/upChan"
    subscribe_calls: list[str] = []
    fail_once = True

    async def scripted_subscribe(topic: str, callback: Any, qos: int = 1) -> bool:
        nonlocal fail_once
        subscribe_calls.append(topic)
        if topic == fail_topic and fail_once:
            fail_once = False
            transport.last_error = "publish/subscribe timeout"  # type: ignore[attr-defined]
            return False
        transport.subscriptions[topic] = callback
        return True

    transport.async_subscribe = scripted_subscribe  # type: ignore[method-assign]
    received: list[tuple[str, dict[str, Any]]] = []

    def cb(sn: str, data: dict[str, Any]) -> None:
        received.append((sn, data))

    assert await api.subscribe_device(SN, cb) is False
    assert SN not in api.subscribed_serials()
    initial_calls = len(subscribe_calls)
    assert initial_calls == len(api._subscription_topics_for_sn(SN))

    # Second attempt subscribes ONLY the missing topic, then marks SN subscribed.
    subscribe_calls.clear()
    assert await api.subscribe_device(SN, cb) is True
    assert subscribe_calls == [fail_topic]
    assert SN in api.subscribed_serials()

    transport.subscriptions[fail_topic](fail_topic, b'{"Machine":{"cap":90}}')
    assert len(received) == 1
    assert received[0][1]["Machine"]["cap"] == 90


@pytest.mark.asyncio
async def test_denied_topic_and_backoff_prevent_tight_retry_loops(monkeypatch: pytest.MonkeyPatch) -> None:
    """Denied topics stop retrying on this connection; transient failures back off."""
    api, transport = _connected_api()
    api._subscribe_retry_base_seconds = 30.0
    api._subscribe_retry_max_seconds = 120.0
    api._subscribe_max_retries = 3

    topics = api._subscription_topics_for_sn(SN)
    denied_topic = topics[0]
    flaky_topic = topics[1]
    calls: dict[str, int] = {}

    async def selective_subscribe(topic: str, callback: Any, qos: int = 1) -> bool:
        calls[topic] = calls.get(topic, 0) + 1
        if topic == denied_topic:
            transport.last_error = "subscribe: PermissionError: MQTT subscribe rejected"  # type: ignore[attr-defined]
            return False
        if topic == flaky_topic:
            transport.last_error = "subscribe: TimeoutError"  # type: ignore[attr-defined]
            return False
        transport.subscriptions[topic] = callback
        return True

    transport.async_subscribe = selective_subscribe  # type: ignore[method-assign]

    now = 100.0
    monkeypatch.setattr("time.monotonic", lambda: now)

    assert await api.subscribe_device(SN, lambda sn, data: None) is False
    assert (SN, denied_topic) in api._denied_topics
    assert calls[denied_topic] == 1
    assert calls[flaky_topic] == 1

    # Failure #1 had 0s delay -> immediate second try allowed; denied topic NOT retried.
    assert await api.subscribe_device(SN, lambda sn, data: None) is False
    assert calls[denied_topic] == 1
    assert calls[flaky_topic] == 2

    # Failure #2 scheduled 30s backoff -> blocked at t=110, allowed at t=135.
    now = 110.0
    assert await api.subscribe_device(SN, lambda sn, data: None) is False
    assert calls[flaky_topic] == 2

    now = 135.0
    assert await api.subscribe_device(SN, lambda sn, data: None) is False
    assert calls[flaky_topic] == 3

    # Failure #3 reached max_retries=3 -> no further attempts on this connection.
    now = 9999.0
    assert await api.subscribe_device(SN, lambda sn, data: None) is False
    assert calls[flaky_topic] == 3


@pytest.mark.asyncio
async def test_late_subscription_ack_from_old_connection_is_ignored_and_disconnect_resets() -> None:
    """Late acks from a torn-down connection must not mark the new connection subscribed."""
    api, transport1 = _connected_api()
    gate = asyncio.Event()

    async def slow_subscribe(topic: str, callback: Any, qos: int = 1) -> bool:
        await gate.wait()
        return True

    transport1.async_subscribe = slow_subscribe  # type: ignore[method-assign]
    task = asyncio.create_task(api.subscribe_device(SN, lambda sn, data: None))
    await asyncio.sleep(0.01)

    await api.disconnect_mqtt()
    assert api.subscribed_serials() == set()

    gate.set()
    assert await task is False
    assert api._acked_topics_by_sn == {}
