"""Tests for diagnostics redaction."""

from __future__ import annotations

from types import SimpleNamespace

import pytest
from homeassistant.core import HomeAssistant
from pytest_homeassistant_custom_component.common import MockConfigEntry

from custom_components.aiper.const import DOMAIN
from custom_components.aiper.diagnostics import async_get_config_entry_diagnostics
from custom_components.aiper.state import normalize_device_state


@pytest.mark.asyncio
async def test_diagnostics_redacts_sensitive_runtime_data(hass: HomeAssistant) -> None:
    """Diagnostics should not expose credentials, tokens, or AWS secrets."""
    entry = MockConfigEntry(
        domain=DOMAIN,
        entry_id="entry-1",
        title="Aiper",
        data={
            "username": "person@example.com",
            "password": "top-secret",
            "region": "eu",
        },
        options={},
    )
    api = SimpleNamespace(
        base_url="https://apieurope.aiper.com",
        region="eu",
        _iot_endpoint="abcdefghijk.iot.eu-central-1.amazonaws.com",
        _identity_id="eu-central-1:1234567890",
        _aws_region="eu-central-1",
        _mqtt_client=SimpleNamespace(last_error=None, reconnect_count=1),
        is_mqtt_connected=lambda: True,
    )
    coordinator = SimpleNamespace(
        last_update_success=True,
        update_interval=None,
        data={
            "SN123": normalize_device_state(
                {
                    "name": "Pool Robot",
                    "deviceModelUrl": "https://static.example.test/surfer-s2.png",
                    "token": "runtime-token",
                    "nested": {"SecretKey": "aws-secret"},
                }
            )
        },
        _command_state={
            "SN123": {
                "pending": {
                    "mode": {
                        "accessKeyId": "AKIA...",
                        "value": 1,
                    }
                }
            }
        },
    )
    hass.data.setdefault(DOMAIN, {})[entry.entry_id] = {"api": api, "coordinator": coordinator}

    diagnostics = await async_get_config_entry_diagnostics(hass, entry)

    assert diagnostics["entry"]["data"] == {
        "region": "eu",
        "username": "per...com",
    }
    assert "token" not in diagnostics["devices"]["SN123"]
    assert "nested" not in diagnostics["devices"]["SN123"]
    assert "runtime-token" not in str(diagnostics)
    assert "aws-secret" not in str(diagnostics)
    assert diagnostics["device_model_images"] == {"SN123": "https://static.example.test/surfer-s2.png"}
    assert diagnostics["command_state"]["SN123"]["pending"]["mode"]["accessKeyId"] == "***"
    assert diagnostics["command_state"]["SN123"]["pending"]["mode"]["value"] == 1
    assert diagnostics["api"]["mqtt_client"] == "SimpleNamespace"
    assert diagnostics["api"]["mqtt_reconnect_count"] == 1
