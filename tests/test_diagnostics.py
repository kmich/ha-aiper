"""Tests for diagnostics redaction."""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any, cast

import pytest
from homeassistant.core import HomeAssistant
from pytest_homeassistant_custom_component.common import MockConfigEntry

from custom_components.aiper.api import AiperApi
from custom_components.aiper.const import DOMAIN
from custom_components.aiper.coordinator import AiperDataUpdateCoordinator
from custom_components.aiper.diagnostics import async_get_config_entry_diagnostics
from custom_components.aiper.state import normalize_device_state


@pytest.mark.asyncio
async def test_diagnostics_redacts_sensitive_runtime_data(hass: HomeAssistant) -> None:
    """Diagnostics should not expose credentials, tokens, or AWS secrets."""
    entry = MockConfigEntry(
        domain=DOMAIN,
        entry_id="entry-1",
        title="Aiper (person@example.com)",
        data={
            "username": "person@example.com",
            "password": "top-secret",
            "region": "eu",
        },
        options={},
    )
    api = AiperApi("person@example.com", "top-secret", "eu", async_session=cast(Any, object()))
    api._iot_endpoint = "abcdefghijk.iot.eu-central-1.amazonaws.com"
    api._identity_id = "eu-central-1:1234567890"
    api._aws_region = "eu-central-1"
    api._token = "runtime-token"
    api._aws_credentials = {"SecretKey": "aws-secret"}

    class ConnectedTransport:
        last_error = None
        reconnect_count = 1

        def is_connected(self) -> bool:
            return True

    api._mqtt_client = ConnectedTransport()

    coordinator = AiperDataUpdateCoordinator(hass, api)
    coordinator.data = {
        "SN1234567890": normalize_device_state(
            {
                "name": "Pool Robot",
                "deviceModelUrl": "https://static.example.test/surfer-s2.png",
                "token": "runtime-token",
                "nested": {"SecretKey": "aws-secret"},
            }
        )
    }
    coordinator._command_state = {
        "SN1234567890": {
            "pending": {
                "mode": {
                    "accessKeyId": "AKIA...",
                    "value": 1,
                }
            }
        }
    }
    coordinator._state_reconciliation = {
        "SN1234567890": {
            "trigger": "rest_machine_status",
            "rest_status": 2,
            "applied": {"charging": True},
        }
    }
    entry.runtime_data = SimpleNamespace(api=api, coordinator=coordinator)

    diagnostics = await async_get_config_entry_diagnostics(hass, entry)

    assert diagnostics["entry"]["data"] == {
        "region": "eu",
        "username": "per...com",
    }
    assert "token" not in diagnostics["devices"]["SN1...890"]
    assert "nested" not in diagnostics["devices"]["SN1...890"]
    assert "runtime-token" not in str(diagnostics)
    assert "aws-secret" not in str(diagnostics)
    assert diagnostics["device_model_images"] == {"SN1...890": "https://static.example.test/surfer-s2.png"}
    assert diagnostics["command_state"]["SN1...890"]["pending"]["mode"]["accessKeyId"] == "***"
    assert diagnostics["command_state"]["SN1...890"]["pending"]["mode"]["value"] == 1
    assert diagnostics["api"]["mqtt_client"] == "ConnectedTransport"
    assert diagnostics["api"]["mqtt_reconnect_count"] == 1
    assert diagnostics["api"]["mqtt_connected"] is True
    assert diagnostics["state_reconciliation"]["SN1...890"]["trigger"] == "rest_machine_status"
    # The account email is embedded in the entry title and serials appear as
    # keys; neither may leak in full.
    assert diagnostics["entry"]["title"] == "Aiper (per...com)"
    assert "person@example.com" not in str(diagnostics)
    assert "top-secret" not in str(diagnostics)
    assert diagnostics["api"]["identity_id"] == "***"
    assert diagnostics["api"]["iot_endpoint"] == "abc...com"
    assert "SN1234567890" not in str(diagnostics)


@pytest.mark.asyncio
async def test_diagnostics_degrades_gracefully_before_runtime_data_is_set(hass: HomeAssistant) -> None:
    """Diagnostics must not raise if requested before setup assigns runtime_data.

    Regression test: a config entry stuck retrying setup (e.g. login failing,
    or the first coordinator refresh failing) never gets `entry.runtime_data`
    assigned. A user attaching diagnostics from that state must get a
    degraded-but-valid payload, not an unhandled AttributeError.
    """
    entry = MockConfigEntry(domain=DOMAIN, entry_id="entry-not-ready", data={}, options={})
    # Note: entry.runtime_data is deliberately left unset.

    diagnostics = await async_get_config_entry_diagnostics(hass, entry)

    assert diagnostics["api"] == {"base_url": None, "region": None, "mqtt_connected": False}
    assert diagnostics["entry"]["data"] == {}
    assert "coordinator" not in diagnostics
    assert "devices" not in diagnostics
