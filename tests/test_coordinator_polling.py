"""Tests for coordinator polling: auth failures, REST outages and push scheduling."""

from __future__ import annotations

from typing import Any, cast

import pytest
from homeassistant.core import HomeAssistant
from homeassistant.exceptions import ConfigEntryAuthFailed
from homeassistant.helpers.update_coordinator import UpdateFailed

from custom_components.aiper.api import AiperAuthenticationError, AiperConnectionError
from custom_components.aiper.coordinator import AiperDataUpdateCoordinator
from tests.coordinator_factory import BaseFakeApi


class FailingApi(BaseFakeApi):
    """Minimal API double whose device-list call raises a chosen error."""

    def __init__(self, error: Exception) -> None:
        self.error = error

    async def get_devices(self) -> list[dict[str, Any]]:
        raise self.error

    def is_mqtt_connected(self) -> bool:
        return False


@pytest.mark.asyncio
@pytest.mark.parametrize("cached", [False, True])
async def test_auth_error_during_poll_starts_reauth(hass: HomeAssistant, cached: bool) -> None:
    """A rejected password after setup must raise ConfigEntryAuthFailed.

    Even with cached device data (which otherwise masks REST failures), an
    authentication error has to surface so Home Assistant opens reauth.
    """
    coordinator = AiperDataUpdateCoordinator(hass, FailingApi(AiperAuthenticationError("Login failed")))  # type: ignore[arg-type]
    if cached:
        coordinator._devices = {"SN1": {"sn": "SN1"}}

    with pytest.raises(ConfigEntryAuthFailed):
        await coordinator._async_update_data()


@pytest.mark.asyncio
async def test_connection_error_without_cache_is_update_failed(hass: HomeAssistant) -> None:
    """Transport failures stay ordinary UpdateFailed errors."""
    coordinator = AiperDataUpdateCoordinator(hass, FailingApi(AiperConnectionError("down")))  # type: ignore[arg-type]

    with pytest.raises(UpdateFailed):
        await coordinator._async_update_data()


class CachedFailApi(FailingApi):
    """Device-list failures with a configurable MQTT state."""

    def __init__(self, *, mqtt_connected: bool) -> None:
        super().__init__(AiperConnectionError("down"))
        self.mqtt_connected = mqtt_connected

    def is_mqtt_connected(self) -> bool:
        return self.mqtt_connected


@pytest.mark.asyncio
async def test_cached_state_goes_stale_when_rest_and_mqtt_are_both_down(hass: HomeAssistant) -> None:
    """Cached data is served briefly, then the coordinator reports failure."""
    from custom_components.aiper.coordinator import MAX_CACHED_REST_FAILURES

    coordinator = AiperDataUpdateCoordinator(hass, CachedFailApi(mqtt_connected=False))  # type: ignore[arg-type]
    coordinator._devices = {"SN1": {"sn": "SN1"}}

    for _ in range(MAX_CACHED_REST_FAILURES - 1):
        assert "SN1" in await coordinator._async_update_data()
    assert coordinator.last_successful_update is None

    with pytest.raises(UpdateFailed):
        await coordinator._async_update_data()


@pytest.mark.asyncio
async def test_cached_state_kept_while_mqtt_is_live(hass: HomeAssistant) -> None:
    """With MQTT still delivering live state, REST outages don't mark entities unavailable."""
    from custom_components.aiper.coordinator import MAX_CACHED_REST_FAILURES

    coordinator = AiperDataUpdateCoordinator(hass, CachedFailApi(mqtt_connected=True))  # type: ignore[arg-type]
    coordinator._devices = {"SN1": {"sn": "SN1"}}

    for _ in range(MAX_CACHED_REST_FAILURES + 1):
        assert "SN1" in await coordinator._async_update_data()


@pytest.mark.asyncio
async def test_push_updates_do_not_reschedule_rest_poll(hass: HomeAssistant) -> None:
    """MQTT pushes must not keep postponing the scheduled REST poll.

    Regression test: push updates used async_set_updated_data(), which restarts
    the refresh timer on every call.
    """
    coordinator = AiperDataUpdateCoordinator(hass, CachedFailApi(mqtt_connected=True))  # type: ignore[arg-type]
    coordinator.data = {}
    calls: list[None] = []
    unsub = coordinator.async_add_listener(lambda: calls.append(None))
    scheduled = coordinator._unsub_refresh
    assert scheduled is not None

    coordinator.async_set_push_data({"SN1": {}})

    assert coordinator._unsub_refresh is scheduled
    assert coordinator.data == {"SN1": {}}
    assert calls == [None]
    unsub()


@pytest.mark.asyncio
async def test_learned_routes_are_restored_and_persisted(hass: HomeAssistant) -> None:
    """Learned command routes survive restarts via the coordinator's Store."""
    from custom_components.aiper.api import AiperApi

    api = AiperApi("u@example.com", "p", "eu", async_session=cast(Any, object()))
    coordinator = AiperDataUpdateCoordinator(hass, api)

    class FakeStore:
        def __init__(self) -> None:
            self.saved: list[Any] = []

        async def async_load(self) -> dict[str, Any]:
            return {"clean_path_at:scuba_x1": {"command": "AT+CPATH={value}"}}

        def async_delay_save(self, data_func: Any, delay: float = 0) -> None:
            self.saved.append(data_func())

    store = FakeStore()
    coordinator._routes_store = cast(Any, store)

    await coordinator.async_restore_learned_routes()
    assert api.learned_routes == {"clean_path_at:scuba_x1": {"command": "AT+CPATH={value}"}}

    api._learn_route("clean_path_update:scuba_x1", {"path": "/p", "body_keys": ["sn"], "encrypted": True})
    assert store.saved[-1]["clean_path_update:scuba_x1"]["path"] == "/p"
