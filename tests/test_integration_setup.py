"""Tests for integration setup and unload wiring."""

from __future__ import annotations

from dataclasses import dataclass, field
from types import SimpleNamespace
from typing import Any, cast

import pytest
from homeassistant.config_entries import ConfigEntry, ConfigEntryState
from homeassistant.const import Platform
from homeassistant.core import HomeAssistant
from homeassistant.helpers import device_registry as dr
from homeassistant.helpers import entity_registry as er
from pytest_homeassistant_custom_component.common import MockConfigEntry

from custom_components import aiper
from custom_components.aiper.const import DOMAIN
from custom_components.aiper.coordinator import AiperDataUpdateCoordinator


@dataclass
class FakeApi:
    """Fake Aiper API used by setup/unload tests."""

    username: str
    password: str
    region: str
    async_session: object | None = None
    login_called: bool = False
    connect_called: bool = False
    disconnected: bool = False
    subscribed: list[str] = field(default_factory=list)
    shadow_requested: list[str] = field(default_factory=list)

    async def login(self) -> bool:
        self.login_called = True
        return True

    async def get_devices(self) -> list[dict[str, Any]]:
        return [{"sn": "SN123", "model": "Shark_X", "name": "Pool Robot", "battLevel": 80, "machineStatus": 1}]

    async def get_device_info(self, sn: str) -> dict[str, Any]:
        return {"mainFirmwareVersion": "1.0.0"}

    async def get_consumables(self, sn: str) -> dict[str, Any]:
        return {"data": []}

    async def connect_mqtt(self) -> bool:
        self.connect_called = True
        return True

    async def subscribe_device(self, sn: str, callback: Any) -> bool:
        self.subscribed.append(sn)
        return True

    async def request_shadow(self, sn: str) -> bool:
        self.shadow_requested.append(sn)
        return True

    async def disconnect(self) -> None:
        self.disconnected = True


@pytest.mark.asyncio
async def test_setup_entry_stores_runtime_data_and_unload_disconnects(
    hass: HomeAssistant,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Setup should create API/coordinator state and unload should clean it up."""

    forwarded: list[tuple[ConfigEntry, list[Platform]]] = []
    unloaded: list[tuple[ConfigEntry, list[Platform]]] = []

    async def fake_forward_entry_setups(entry: ConfigEntry, platforms: list[Platform]) -> None:
        forwarded.append((entry, platforms))

    async def fake_unload_platforms(entry: ConfigEntry, platforms: list[Platform]) -> bool:
        unloaded.append((entry, platforms))
        return True

    monkeypatch.setattr(aiper, "AiperApi", FakeApi)
    monkeypatch.setattr(aiper, "async_get_clientsession", lambda hass: "session")
    monkeypatch.setattr(hass.config_entries, "async_forward_entry_setups", fake_forward_entry_setups)
    monkeypatch.setattr(hass.config_entries, "async_unload_platforms", fake_unload_platforms)

    entry = MockConfigEntry(
        domain=DOMAIN,
        entry_id="entry-1",
        data={
            "username": "user@example.com",
            "password": "secret",
            "region": "asia",
        },
        state=ConfigEntryState.SETUP_IN_PROGRESS,
    )
    entry.add_to_hass(hass)

    assert await aiper.async_setup_entry(hass, cast(ConfigEntry, entry)) is True

    runtime = hass.data[DOMAIN][entry.entry_id]
    api = cast(FakeApi, runtime["api"])
    coordinator = cast(AiperDataUpdateCoordinator, runtime["coordinator"])

    assert api.login_called is True
    assert api.connect_called is True
    assert api.async_session == "session"
    assert coordinator.data is not None
    assert coordinator.data["SN123"]["device_info"].value == "Pool Robot"
    assert coordinator.data["SN123"]["device_family"].value == "shark"
    assert coordinator.update_interval is not None
    assert forwarded == [(cast(ConfigEntry, entry), aiper.PLATFORMS)]

    assert await aiper.async_unload_entry(hass, cast(ConfigEntry, entry)) is True

    assert unloaded == [(cast(ConfigEntry, entry), aiper.PLATFORMS)]
    assert api.disconnected is True
    assert entry.entry_id not in hass.data[DOMAIN]


@pytest.mark.asyncio
async def test_remove_config_entry_device_rejects_active_device(hass: HomeAssistant) -> None:
    """HA should not delete a device that is still returned by Aiper."""
    entry = MockConfigEntry(domain=DOMAIN, entry_id="entry-1")
    entry.add_to_hass(hass)
    hass.data.setdefault(DOMAIN, {})[entry.entry_id] = {
        "coordinator": SimpleNamespace(data={"SN123": {}}),
    }

    dev_reg = dr.async_get(hass)
    device = dev_reg.async_get_or_create(
        config_entry_id=entry.entry_id,
        identifiers={(DOMAIN, "SN123")},
        manufacturer="Aiper",
        name="Pool Robot",
    )

    assert await aiper.async_remove_config_entry_device(hass, cast(ConfigEntry, entry), device) is False


@pytest.mark.asyncio
async def test_remove_config_entry_device_allows_stale_device(hass: HomeAssistant) -> None:
    """HA should be allowed to delete stale device-registry entries."""
    entry = MockConfigEntry(domain=DOMAIN, entry_id="entry-1")
    entry.add_to_hass(hass)
    hass.data.setdefault(DOMAIN, {})[entry.entry_id] = {
        "coordinator": SimpleNamespace(data={"SN123": {}}),
    }

    dev_reg = dr.async_get(hass)
    device = dev_reg.async_get_or_create(
        config_entry_id=entry.entry_id,
        identifiers={(DOMAIN, "SN999")},
        manufacturer="Aiper",
        name="Old Pool Robot",
    )
    ent_reg = er.async_get(hass)
    ent_reg.async_get_or_create(
        "sensor",
        DOMAIN,
        "SN999_status",
        config_entry=cast(ConfigEntry, entry),
        device_id=device.id,
    )

    assert await aiper.async_remove_config_entry_device(hass, cast(ConfigEntry, entry), device) is True
