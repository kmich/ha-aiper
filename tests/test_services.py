"""Tests for Aiper Home Assistant services."""

from __future__ import annotations

import pytest
from homeassistant.core import HomeAssistant

from custom_components.aiper import async_setup
from custom_components.aiper.const import DOMAIN


@pytest.mark.asyncio
async def test_async_setup_does_not_register_raw_at_service(hass: HomeAssistant) -> None:
    """Discovery-only raw AT commands are not exposed as Home Assistant services."""
    assert await async_setup(hass, {}) is True

    assert not hass.services.has_service(DOMAIN, "send_at_command")
