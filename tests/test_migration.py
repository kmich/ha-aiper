"""Tests for config-entry migration (1.1 -> 1.2)."""

from __future__ import annotations

import pytest
from homeassistant.core import HomeAssistant
from homeassistant.helpers import device_registry as dr
from homeassistant.helpers import entity_registry as er
from pytest_homeassistant_custom_component.common import MockConfigEntry

from custom_components.aiper import async_migrate_entry
from custom_components.aiper.const import DOMAIN


def _entry(unique_id: str, username: str, entry_id: str = "entry-1") -> MockConfigEntry:
    return MockConfigEntry(
        domain=DOMAIN,
        entry_id=entry_id,
        unique_id=unique_id,
        version=1,
        minor_version=1,
        data={"username": username, "password": "secret", "region": "eu"},
    )


@pytest.mark.asyncio
async def test_migration_normalizes_unique_id_and_cleans_registry_once(hass: HomeAssistant) -> None:
    """1.1 entries get a lower-cased unique ID and one-time legacy cleanup."""
    entry = _entry("User@Example.com", "User@Example.com")
    entry.add_to_hass(hass)
    dev_reg = dr.async_get(hass)
    device = dev_reg.async_get_or_create(config_entry_id=entry.entry_id, identifiers={(DOMAIN, "SN123456")})
    ent_reg = er.async_get(hass)
    legacy = ent_reg.async_get_or_create(
        "sensor", DOMAIN, "SN123456_cleaning_mode", config_entry=entry, device_id=device.id
    )
    kept = ent_reg.async_get_or_create("sensor", DOMAIN, "SN123456_battery", config_entry=entry, device_id=device.id)
    legacy_select = ent_reg.async_get_or_create(
        "select", DOMAIN, "SN123456_mode_select", config_entry=entry, device_id=device.id
    )

    assert await async_migrate_entry(hass, entry) is True

    assert entry.unique_id == "user@example.com"
    assert entry.minor_version == 2
    assert ent_reg.async_get(legacy.entity_id) is None
    assert ent_reg.async_get(kept.entity_id) is not None
    migrated = ent_reg.async_get(legacy_select.entity_id)
    assert migrated is not None
    assert migrated.unique_id == "SN123456_mode_selection"


@pytest.mark.asyncio
async def test_migration_keeps_unique_id_when_normalized_one_is_taken(hass: HomeAssistant) -> None:
    """Two legacy entries differing only by case must not end up sharing a unique ID."""
    _entry("user@example.com", "user@example.com", entry_id="entry-a").add_to_hass(hass)
    entry = _entry("USER@example.com", "USER@example.com", entry_id="entry-b")
    entry.add_to_hass(hass)

    assert await async_migrate_entry(hass, entry) is True

    assert entry.unique_id == "USER@example.com"
    assert entry.minor_version == 2


@pytest.mark.asyncio
async def test_migration_refuses_future_major_version(hass: HomeAssistant) -> None:
    """A downgrade from an unknown major version must not load."""
    entry = MockConfigEntry(domain=DOMAIN, version=2, data={})
    entry.add_to_hass(hass)

    assert await async_migrate_entry(hass, entry) is False
