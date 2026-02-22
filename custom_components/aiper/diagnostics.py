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


SENSITIVE_KEY_FRAGMENTS = (
    "password",
    "passwd",
    "token",
    "secret",
    "authorization",
    "openid",
    "identity",
    "accesskey",
    "secretkey",
    "sessiontoken",
    "credential",
    "jwt",
)


def _is_sensitive_key(key: str) -> bool:
    k = key.lower().replace("_", "")
    return any(frag in k for frag in SENSITIVE_KEY_FRAGMENTS)


def _redact_str(value: str) -> str:
    if not value:
        return ""
    if len(value) <= 6:
        return "***"
    return value[:3] + "…" + value[-3:]


def _redact(obj: Any) -> Any:
    """Recursively redact sensitive values from an arbitrary structure."""
    if isinstance(obj, dict):
        out: dict[str, Any] = {}
        for k, v in obj.items():
            if isinstance(k, str) and _is_sensitive_key(k):
                out[k] = "***"
            else:
                out[k] = _redact(v)
        return out
    if isinstance(obj, list):
        return [_redact(v) for v in obj]
    if isinstance(obj, tuple):
        return tuple(_redact(v) for v in obj)
    if isinstance(obj, str):
        # Avoid dumping very long strings (which may include payloads)
        if len(obj) > 512:
            return obj[:256] + "…" + obj[-64:]
        return obj
    return obj


async def async_get_config_entry_diagnostics(
    hass: HomeAssistant, entry: ConfigEntry
) -> dict[str, Any]:
    """Return diagnostics for a config entry."""

    data = hass.data.get(DOMAIN, {}).get(entry.entry_id) or {}
    api = data.get("api")
    coordinator = data.get("coordinator")

    # Config entry data: never expose credentials.
    entry_data = {
        "region": entry.data.get("region"),
        "username": _redact_str(str(entry.data.get("username", ""))) if entry.data.get("username") else None,
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
        diag["api"].update(
            {
                "iot_endpoint": _redact_str(str(getattr(api, "_iot_endpoint", ""))) if getattr(api, "_iot_endpoint", None) else None,
                "identity_id": _redact_str(str(getattr(api, "_identity_id", ""))) if getattr(api, "_identity_id", None) else None,
                "aws_region": getattr(api, "_aws_region", None),
            }
        )

    if coordinator is not None:
        diag["coordinator"] = {
            "last_update_success": getattr(coordinator, "last_update_success", None),
            "update_interval_seconds": int(getattr(getattr(coordinator, "update_interval", None), "total_seconds", lambda: 0)()),
        }

        # Device snapshot (already reasonably bounded). Redact any sensitive keys.
        try:
            diag["devices"] = _redact(coordinator.data or {})
        except Exception:
            diag["devices"] = "<unavailable>"

        # Command tracker (useful for debugging select behavior).
        try:
            if hasattr(coordinator, "_command_state"):
                diag["command_state"] = _redact(getattr(coordinator, "_command_state", {}))
        except Exception:
            pass

    return _redact(diag)
