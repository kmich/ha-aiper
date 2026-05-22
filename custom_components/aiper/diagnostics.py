"""Diagnostics support for the Aiper integration.

The diagnostics output is intended to be safe to attach to GitHub issues.
We therefore aggressively redact credentials, tokens, and other sensitive
fields.
"""

from __future__ import annotations

from typing import Any

from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant

from .const import DOMAIN
from .redaction import redact, redact_str


async def async_get_config_entry_diagnostics(hass: HomeAssistant, entry: ConfigEntry) -> dict[str, Any]:
    """Return diagnostics for a config entry."""

    data = hass.data.get(DOMAIN, {}).get(entry.entry_id) or {}
    api = data.get("api")
    coordinator = data.get("coordinator")

    # Config entry data: never expose credentials.
    entry_data = {
        "region": entry.data.get("region"),
        "username": redact_str(str(entry.data.get("username", ""))) if entry.data.get("username") else None,
    }

    diag: dict[str, Any] = {
        "entry": {
            "title": entry.title,
            "data": entry_data,
            "options": dict(entry.options),
        },
        "api": {
            "base_url": getattr(api, "base_url", None),
            "region": getattr(api, "region", None),
            "mqtt_connected": getattr(api, "is_mqtt_connected", lambda: False)(),
        },
    }

    if api is not None:
        # Best-effort: include non-sensitive runtime details.
        mqtt_client = getattr(api, "_mqtt_client", None)
        diag["api"].update(
            {
                "iot_endpoint": redact_str(str(getattr(api, "_iot_endpoint", "")))
                if getattr(api, "_iot_endpoint", None)
                else None,
                "identity_id": redact_str(str(getattr(api, "_identity_id", "")))
                if getattr(api, "_identity_id", None)
                else None,
                "aws_region": getattr(api, "_aws_region", None),
                "mqtt_client": type(mqtt_client).__name__ if mqtt_client is not None else None,
                "mqtt_last_error": getattr(mqtt_client, "last_error", None) if mqtt_client is not None else None,
                "mqtt_last_connected_at": getattr(mqtt_client, "last_connected_at", None)
                if mqtt_client is not None
                else None,
                "mqtt_last_disconnected_at": getattr(mqtt_client, "last_disconnected_at", None)
                if mqtt_client is not None
                else None,
                "mqtt_reconnect_count": getattr(mqtt_client, "reconnect_count", None)
                if mqtt_client is not None
                else None,
            }
        )

    if coordinator is not None:
        diag["coordinator"] = {
            "last_update_success": getattr(coordinator, "last_update_success", None),
            "update_interval_seconds": int(
                getattr(getattr(coordinator, "update_interval", None), "total_seconds", lambda: 0)()
            ),
        }

        # Device snapshot (already reasonably bounded). Redact any sensitive keys.
        try:
            diag["devices"] = redact(coordinator.data or {})
            image_urls = {}
            for sn, device in (coordinator.data or {}).items():
                if not isinstance(device, dict):
                    continue
                try:
                    image_url = device["entity_picture"].value
                except KeyError:
                    image_url = None
                if image_url:
                    image_urls[sn] = image_url
            diag["device_model_images"] = image_urls
        except Exception:
            diag["devices"] = "<unavailable>"

        # Command tracker (useful for debugging select behavior).
        try:
            if hasattr(coordinator, "_command_state"):
                diag["command_state"] = redact(getattr(coordinator, "_command_state", {}))
        except Exception:
            pass

    return redact(diag)
