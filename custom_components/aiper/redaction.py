"""Shared redaction helpers for diagnostics and discovery output."""

from __future__ import annotations

from typing import Any

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


def is_sensitive_key(key: str) -> bool:
    """Return True if a key name appears to contain sensitive data."""
    normalized = key.lower().replace("_", "").replace("-", "")
    return any(fragment in normalized for fragment in SENSITIVE_KEY_FRAGMENTS)


def redact_str(value: str) -> str:
    """Partially redact a human-useful identifier."""
    if not value:
        return ""
    if len(value) <= 6:
        return "***"
    return value[:3] + "..." + value[-3:]


def redact(obj: Any, *, truncate_strings: bool = True) -> Any:
    """Recursively redact sensitive values from an arbitrary structure.

    Serial numbers are intentionally not redacted. They are needed to correlate
    device data, MQTT topics, and support reports.
    """
    if isinstance(obj, dict):
        out: dict[Any, Any] = {}
        for key, value in obj.items():
            if isinstance(key, str) and is_sensitive_key(key):
                out[key] = "***"
            else:
                out[key] = redact(value, truncate_strings=truncate_strings)
        return out
    if isinstance(obj, list):
        return [redact(value, truncate_strings=truncate_strings) for value in obj]
    if isinstance(obj, tuple):
        return tuple(redact(value, truncate_strings=truncate_strings) for value in obj)
    if isinstance(obj, set):
        return {redact(value, truncate_strings=truncate_strings) for value in obj}
    if isinstance(obj, frozenset):
        return frozenset(redact(value, truncate_strings=truncate_strings) for value in obj)
    if isinstance(obj, str) and truncate_strings and len(obj) > 512:
        return obj[:256] + "..." + obj[-64:]
    return obj
