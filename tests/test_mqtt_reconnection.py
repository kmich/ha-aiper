"""Tests for the coordinator's MQTT reconnect watchdog (_async_maintain_mqtt)
and the api-level reconnect/resubscribe mechanics it drives.

These cover the invariants behind the fix for the connection never coming
back after AWS_ERROR_MQTT_UNEXPECTED_HANGUP (issue #27). Given this exact
feature area has already caused three prior reverts (v1.2.4-v1.2.6), each
test here locks in one specific, previously-unverified behavior rather than
just checking "no exception was raised".
"""

from __future__ import annotations

import asyncio
import time
from typing import Any, cast

import pytest
from homeassistant.core import HomeAssistant

from custom_components.aiper.api import AiperApi
from custom_components.aiper.coordinator import (
    MQTT_REBUILD_MIN_INTERVAL_SECONDS,
    MQTT_RECONNECT_GRACE_SECONDS,
    AiperDataUpdateCoordinator,
)


def _bare_coordinator(api: Any) -> AiperDataUpdateCoordinator:
    coordinator = AiperDataUpdateCoordinator.__new__(AiperDataUpdateCoordinator)
    coordinator.api = api
    coordinator.data = {"SN123": {}}
    coordinator._mqtt_maintenance_task = None
    return coordinator


class _FakeApi:
    """Controllable stand-in for AiperApi's MQTT-maintenance surface."""

    def __init__(
        self,
        *,
        down_seconds: float | None,
        since_rebuild: float | None = None,
        reconnect_result: bool = True,
        connected: bool = False,
    ) -> None:
        self.down_seconds = down_seconds
        self.since_rebuild = since_rebuild
        self.reconnect_result = reconnect_result
        self._connected = connected
        self.refresh_calls = 0
        self.reconnect_calls = 0
        self.subscribed: set[str] = set()
        self.subscribe_calls: list[str] = []
        self.shadow_requests: list[str] = []

    async def async_refresh_mqtt_credentials(self) -> None:
        self.refresh_calls += 1

    def mqtt_disconnected_seconds(self) -> float | None:
        return self.down_seconds

    def seconds_since_mqtt_rebuild(self) -> float | None:
        return self.since_rebuild

    async def reconnect_mqtt(self) -> bool:
        self.reconnect_calls += 1
        if self.reconnect_result:
            self._connected = True
            self.down_seconds = None
        return self.reconnect_result

    def is_mqtt_connected(self) -> bool:
        return self._connected

    def subscribed_serials(self) -> set[str]:
        return set(self.subscribed)

    async def subscribe_device(self, sn: str, callback: Any) -> bool:
        self.subscribe_calls.append(sn)
        self.subscribed.add(sn)
        return True

    async def request_shadow(self, sn: str) -> bool:
        self.shadow_requests.append(sn)
        return True


@pytest.mark.asyncio
async def test_maintain_mqtt_refreshes_credentials_every_call() -> None:
    """The credential snapshot must be refreshed on every watchdog pass,
    regardless of connection state -- this is what lets the AWS CRT's own
    reconnect loop sign with valid credentials."""
    api = _FakeApi(down_seconds=None, connected=True)
    coordinator = _bare_coordinator(api)

    await coordinator._async_maintain_mqtt()

    assert api.refresh_calls == 1


@pytest.mark.asyncio
async def test_maintain_mqtt_does_not_rebuild_within_grace_period() -> None:
    """A short outage must not trigger a forced rebuild -- the SDK's own
    reconnect loop is given a chance to recover first."""
    api = _FakeApi(down_seconds=MQTT_RECONNECT_GRACE_SECONDS - 1)
    coordinator = _bare_coordinator(api)

    await coordinator._async_maintain_mqtt()

    assert api.reconnect_calls == 0


@pytest.mark.asyncio
async def test_maintain_mqtt_rebuilds_after_grace_period() -> None:
    """Once the outage has exceeded the grace period, with no recent rebuild
    on record, the watchdog must force a reconnect."""
    api = _FakeApi(down_seconds=MQTT_RECONNECT_GRACE_SECONDS + 1, since_rebuild=None)
    coordinator = _bare_coordinator(api)

    await coordinator._async_maintain_mqtt()

    assert api.reconnect_calls == 1


@pytest.mark.asyncio
async def test_maintain_mqtt_respects_rebuild_rate_limit() -> None:
    """A rebuild attempted too recently must not be repeated immediately --
    a wedged endpoint would otherwise be hammered every poll."""
    api = _FakeApi(
        down_seconds=MQTT_RECONNECT_GRACE_SECONDS + 1,
        since_rebuild=MQTT_REBUILD_MIN_INTERVAL_SECONDS - 1,
    )
    coordinator = _bare_coordinator(api)

    await coordinator._async_maintain_mqtt()

    assert api.reconnect_calls == 0


@pytest.mark.asyncio
async def test_maintain_mqtt_rebuilds_again_after_rate_limit_window() -> None:
    """Once the rebuild rate-limit window has elapsed, a still-down
    connection must be retried."""
    api = _FakeApi(
        down_seconds=MQTT_RECONNECT_GRACE_SECONDS + 1,
        since_rebuild=MQTT_REBUILD_MIN_INTERVAL_SECONDS + 1,
    )
    coordinator = _bare_coordinator(api)

    await coordinator._async_maintain_mqtt()

    assert api.reconnect_calls == 1


@pytest.mark.asyncio
async def test_maintain_mqtt_subscribes_devices_missing_from_a_prior_failed_setup() -> None:
    """Regression test for the permanent-recovery-failure bug: if a device
    was never subscribed (e.g. the initial connect/subscribe failed at
    setup), simply being 'connected' again must not be treated as fully
    recovered -- the watchdog must notice the gap and subscribe it.
    """
    api = _FakeApi(down_seconds=None, connected=True)
    api.subscribed = set()  # SN123 was never subscribed
    coordinator = _bare_coordinator(api)
    coordinator.data = {"SN123": {}}
    coordinator.make_shadow_callback = lambda sn: lambda data: None  # type: ignore[method-assign]

    await coordinator._async_maintain_mqtt()

    assert api.subscribe_calls == ["SN123"]
    assert api.shadow_requests == ["SN123"]


@pytest.mark.asyncio
async def test_maintain_mqtt_skips_subscribe_for_already_subscribed_devices() -> None:
    """The missing-device subscribe pass must be a no-op once every known
    device already has a subscription -- it should not re-subscribe (and
    thus not duplicate callback registration for) devices every poll."""
    api = _FakeApi(down_seconds=None, connected=True)
    api.subscribed = {"SN123"}
    coordinator = _bare_coordinator(api)
    coordinator.data = {"SN123": {}}
    coordinator.make_shadow_callback = lambda sn: lambda data: None  # type: ignore[method-assign]

    await coordinator._async_maintain_mqtt()

    assert api.subscribe_calls == []


@pytest.mark.asyncio
async def test_maintain_mqtt_resubscribes_missing_devices_after_a_successful_rebuild() -> None:
    """After a forced rebuild succeeds, any device missing from the prior
    session must also get picked up, not just the ones the transport-level
    resubscribe already knew about."""
    api = _FakeApi(down_seconds=MQTT_RECONNECT_GRACE_SECONDS + 1, since_rebuild=None, reconnect_result=True)
    api.subscribed = set()
    coordinator = _bare_coordinator(api)
    coordinator.data = {"SN123": {}}
    coordinator.make_shadow_callback = lambda sn: lambda data: None  # type: ignore[method-assign]

    await coordinator._async_maintain_mqtt()

    assert api.reconnect_calls == 1
    assert api.subscribe_calls == ["SN123"]


@pytest.mark.asyncio
async def test_async_subscribe_all_devices_is_a_noop_when_mqtt_is_disconnected() -> None:
    """Subscribing requires a live MQTT session; calling this while
    disconnected must not attempt (and fail) a subscribe."""
    api = _FakeApi(down_seconds=5.0, connected=False)
    coordinator = _bare_coordinator(api)
    coordinator.data = {"SN123": {}}
    coordinator.make_shadow_callback = lambda sn: lambda data: None  # type: ignore[method-assign]

    await coordinator.async_subscribe_all_devices()

    assert api.subscribe_calls == []


@pytest.mark.asyncio
async def test_reconnect_mqtt_success_stamps_rebuild_time_and_resubscribes(monkeypatch: pytest.MonkeyPatch) -> None:
    """reconnect_mqtt()'s full disconnect -> connect -> resubscribe sequence,
    exercised end to end against the real AiperApi implementation."""
    api = AiperApi("user@example.com", "secret", "asia", async_session=cast(Any, object()))

    disconnect_calls = []
    resubscribe_calls = []

    async def fake_disconnect_mqtt() -> None:
        disconnect_calls.append("called")

    async def fake_connect_mqtt() -> bool:
        return True

    async def fake_resubscribe() -> None:
        resubscribe_calls.append("called")

    monkeypatch.setattr(api, "disconnect_mqtt", fake_disconnect_mqtt)
    monkeypatch.setattr(api, "connect_mqtt", fake_connect_mqtt)
    monkeypatch.setattr(api, "_resubscribe_all_devices", fake_resubscribe)

    before = time.time()
    result = await api.reconnect_mqtt()

    assert result is True
    assert disconnect_calls == ["called"]
    assert resubscribe_calls == ["called"]
    assert api._mqtt_last_rebuild_at is not None and api._mqtt_last_rebuild_at >= before


@pytest.mark.asyncio
async def test_reconnect_mqtt_failure_does_not_resubscribe(monkeypatch: pytest.MonkeyPatch) -> None:
    """If the rebuild's connect attempt fails, resubscribe must not run
    against a dead/absent transport."""
    api = AiperApi("user@example.com", "secret", "asia", async_session=cast(Any, object()))

    resubscribe_calls = []

    async def fake_disconnect_mqtt() -> None:
        return None

    async def fake_connect_mqtt() -> bool:
        return False

    async def fake_resubscribe() -> None:
        resubscribe_calls.append("called")

    monkeypatch.setattr(api, "disconnect_mqtt", fake_disconnect_mqtt)
    monkeypatch.setattr(api, "connect_mqtt", fake_connect_mqtt)
    monkeypatch.setattr(api, "_resubscribe_all_devices", fake_resubscribe)

    result = await api.reconnect_mqtt()

    assert result is False
    assert resubscribe_calls == []


def test_register_shadow_callback_is_idempotent_for_the_same_callback() -> None:
    """Calling subscribe machinery again for an already-subscribed device
    must not duplicate the registered callback -- a duplicate would cause
    every shadow update to be processed twice."""
    api = AiperApi("user@example.com", "secret", "asia", async_session=cast(Any, object()))

    def cb(data: dict) -> None:
        pass

    api._register_shadow_callback("SN123", cb)
    api._register_shadow_callback("SN123", cb)

    assert api._shadow_callbacks["SN123"] == [cb]
    assert api.subscribed_serials() == {"SN123"}


@pytest.mark.asyncio
async def test_start_mqtt_maintenance_does_not_block_the_data_update(hass: HomeAssistant) -> None:
    """Regression test: _async_maintain_mqtt must run as a separate task, not
    be awaited inline ahead of the REST fetch -- otherwise a slow reconnect
    attempt delays the one channel (REST) that's supposed to keep working
    while MQTT is down."""
    slow_event = asyncio.Event()
    maintenance_started = asyncio.Event()

    class _SlowApi(_FakeApi):
        async def async_refresh_mqtt_credentials(self) -> None:
            maintenance_started.set()
            await slow_event.wait()

    api = _SlowApi(down_seconds=None, connected=True)
    coordinator = _bare_coordinator(api)
    coordinator.hass = hass
    coordinator.config_entry = None

    coordinator._start_mqtt_maintenance()

    # The call above must return immediately without waiting for the slow
    # refresh to complete.
    await asyncio.wait_for(maintenance_started.wait(), timeout=1.0)

    # Clean up: let the background task finish so it doesn't leak past the test.
    slow_event.set()
    task = coordinator._mqtt_maintenance_task
    assert task is not None
    await asyncio.wait_for(task, timeout=1.0)
