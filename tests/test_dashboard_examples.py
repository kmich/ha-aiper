"""Verify the templates provided with the built-in dashboard example."""

from __future__ import annotations

from datetime import timedelta
from pathlib import Path

import yaml
from homeassistant.core import HomeAssistant
from homeassistant.helpers.template import Template
from homeassistant.util import dt as dt_util


async def test_dashboard_uses_device_and_sample_timestamps(hass: HomeAssistant) -> None:
    config = yaml.safe_load((Path(__file__).parents[1] / "lovelace/example-dashboard.yaml").read_text(encoding="utf-8"))
    cleaner, monitor = config["views"][0]["sections"]
    cleaner_template = Template(next(card["content"] for card in cleaner["cards"] if card["type"] == "markdown"), hass)
    monitor_template = Template(next(card["content"] for card in monitor["cards"] if card["type"] == "markdown"), hass)

    hass.states.async_set("sensor.pool_cleaner_status", "Offline")
    hass.states.async_set(
        "sensor.pool_cleaner_last_device_report",
        (dt_util.utcnow() - timedelta(hours=7, minutes=15)).isoformat(),
    )
    hass.states.async_set(
        "sensor.pool_monitor_water_sample_time",
        (dt_util.utcnow() - timedelta(days=2, hours=1)).isoformat(),
    )
    output = cleaner_template.async_render()
    assert "7 hours ago" in output
    assert "No active run reported" in output
    assert "Next scheduled run" not in output
    assert "2 days ago" in monitor_template.async_render()

    hass.states.async_set("sensor.pool_cleaner_status", "Cleaning")
    hass.states.async_set("sensor.pool_cleaner_current_cleaning_time", "0.5")
    hass.states.async_set(
        "event.pool_cleaner_cleaning_finished",
        dt_util.utcnow().isoformat(),
        {"finished_at": (dt_util.utcnow() - timedelta(hours=1, minutes=10)).isoformat()},
    )
    output = cleaner_template.async_render()
    assert "**Current run:** 30 min" in output
    assert "1 hour ago" in output
