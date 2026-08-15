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
        diagnostic_field_sources={
            "SN123": {
                "status": {
                    "source": "rest",
                    "observed_at": "2026-08-15T09:41:45+00:00",
                    "age_seconds": 30,
                }
            }
        },
        _state_reconciliation={
            "SN123": {
                "trigger": "rest_machine_status",
                "rest_status": 2,
                "applied": {"charging": True},
            }
        },
    )
    entry.runtime_data = SimpleNamespace(api=api, coordinator=coordinator)

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
    assert diagnostics["api"]["mqtt_connected"] is True
    assert diagnostics["field_sources"]["SN123"]["status"]["source"] == "rest"
    assert diagnostics["state_reconciliation"]["SN123"]["trigger"] == "rest_machine_status"


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
    assert "coordinator" not in diagnostics
    assert "devices" not in diagnostics
