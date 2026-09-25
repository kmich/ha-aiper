"""Shared redaction helpers for diagnostics and discovery output."""

from __future__ import annotations

import dataclasses
from collections.abc import Iterable
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


def redact_serial(serial: object) -> str:
    """Return a log-safe form of a device serial number.

    Keeps enough of the serial to tell devices apart in multi-device logs
    without writing the full identifier to INFO/WARNING/ERROR log lines.
    """
    return redact_str(str(serial)) if serial else ""


def redact_topic(topic: object) -> str:
    """Redact the serial-number segment of an Aiper/AWS IoT thing topic."""
    if not isinstance(topic, str):
        return str(topic)
    parts = topic.split("/")
    for index, part in enumerate(parts[:-1]):
        if part == "things":
            parts[index + 1] = redact_serial(parts[index + 1])
            break
    return "/".join(parts)


def redact(obj: Any, *, truncate_strings: bool = True) -> Any:
    """Recursively redact sensitive values from an arbitrary structure.

    Serial numbers are not recognizable by key name alone, so callers that
    share output (diagnostics, probe bundles and run files) pseudonymize the
    serials they know about with ``redact_known_values`` afterwards. Dataclass
    instances (e.g. normalized ``EntityState`` values) are walked as dicts.
    """
    if dataclasses.is_dataclass(obj) and not isinstance(obj, type):
        obj = {field.name: getattr(obj, field.name) for field in dataclasses.fields(obj)}
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


def redact_known_values(obj: Any, values: Iterable[str]) -> Any:
    """Partially redact every occurrence of known identifiers in a structure.

    Used to pseudonymize device serial numbers (and similar account-linked
    identifiers) in dict keys and string values, while keeping enough of each
    value (`abc...xyz`) to correlate entries within one report.
    """
    replacements = {value: redact_str(value) for value in values if isinstance(value, str) and value}
    if not replacements:
        return obj
    # Longest first so a value that contains another is replaced whole.
    ordered = sorted(replacements, key=len, reverse=True)

    def _redact_text(text: str) -> str:
        for value in ordered:
            if value in text:
                text = text.replace(value, replacements[value])
        return text

    def _walk(item: Any) -> Any:
        if dataclasses.is_dataclass(item) and not isinstance(item, type):
            item = {field.name: getattr(item, field.name) for field in dataclasses.fields(item)}
        if isinstance(item, dict):
            return {(_redact_text(k) if isinstance(k, str) else k): _walk(v) for k, v in item.items()}
        if isinstance(item, list):
            return [_walk(v) for v in item]
        if isinstance(item, tuple):
            return tuple(_walk(v) for v in item)
        if isinstance(item, str):
            return _redact_text(item)
        return item

    return _walk(obj)
