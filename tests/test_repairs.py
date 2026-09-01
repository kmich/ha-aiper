"""Tests for repair issues: unknown model + auth failure."""

from __future__ import annotations

from typing import Any, cast

import pytest
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.exceptions import ConfigEntryAuthFailed
from homeassistant.helpers import issue_registry as ir
from pytest_homeassistant_custom_component.common import MockConfigEntry

from custom_components import aiper
from custom_components.aiper.api import AiperAuthenticationError
from custom_components.aiper.const import DOMAIN
from custom_components.aiper.repairs import (
    async_update_unknown_model_issues,
    unknown_model_issue_id,
)


def test_unknown_model_issue_raised_and_cleared(hass: HomeAssistant) -> None:
    """An unidentifiable device raises an issue; a recognized one clears it."""
    reg = ir.async_get(hass)

    async_update_unknown_model_issues(hass, {"SNX": {"deviceModel": "Totally New Bot 9000"}})
    issue = reg.async_get_issue(DOMAIN, unknown_model_issue_id("SNX"))
    assert issue is not None
    assert issue.translation_key == "unknown_model"
    assert issue.translation_placeholders is not None
    assert issue.translation_placeholders["serial"] == "SNX"
    assert issue.severity is ir.IssueSeverity.WARNING

    # Device is now recognized -> issue goes away.
    async_update_unknown_model_issues(hass, {"SNX": {"deviceModel": "Scuba X1"}})
    assert reg.async_get_issue(DOMAIN, unknown_model_issue_id("SNX")) is None


def test_unknown_model_issue_is_per_device(hass: HomeAssistant) -> None:
    reg = ir.async_get(hass)
    async_update_unknown_model_issues(
        hass,
        {
            "SN_KNOWN": {"deviceModel": "Surfer S2"},
            "SN_WEIRD": {"deviceModel": "??? prototype"},
        },
    )
    assert reg.async_get_issue(DOMAIN, unknown_model_issue_id("SN_KNOWN")) is None
    assert reg.async_get_issue(DOMAIN, unknown_model_issue_id("SN_WEIRD")) is not None


@pytest.mark.asyncio
async def test_setup_raises_auth_failed_on_bad_credentials(
    hass: HomeAssistant, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A rejected login must surface reauth, not an endless ConfigEntryNotReady."""

    async def fake_login(self: Any) -> bool:
        raise AiperAuthenticationError("Login failed: bad password")

    monkeypatch.setattr(aiper.AiperApi, "login", fake_login)
    monkeypatch.setattr(aiper, "async_get_clientsession", lambda hass: "session")

    entry = MockConfigEntry(
        domain=DOMAIN,
        data={"username": "u@example.com", "password": "wrong", "region": "eu"},
    )
    entry.add_to_hass(hass)

    with pytest.raises(ConfigEntryAuthFailed):
        await aiper.async_setup_entry(hass, cast(ConfigEntry, entry))
