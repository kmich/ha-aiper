"""Tests for coordinator handling of credential failures after setup."""

from __future__ import annotations

from typing import Any

import pytest
from homeassistant.core import HomeAssistant
from homeassistant.exceptions import ConfigEntryAuthFailed
from homeassistant.helpers.update_coordinator import UpdateFailed

from custom_components.aiper.api import AiperAuthenticationError, AiperConnectionError
from custom_components.aiper.coordinator import AiperDataUpdateCoordinator


class FailingApi:
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
