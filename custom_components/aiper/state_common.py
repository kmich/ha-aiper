"""Pure value-coercion helpers shared across state normalization.

No dependency on other integration modules — safe to import from anywhere.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

__all__ = [
    "EntityState",
    "RawDeviceData",
    "DeviceState",
    "DevicesState",
    "_coerce_bool",
    "_coerce_int",
    "_coerce_float",
    "_centihours_to_hours",
    "_round_number",
    "_hours",
    "_state_value",
    "_state_attrs",
]


@dataclass(frozen=True)
class EntityState:
    """Normalized state value plus Home Assistant entity attributes."""

    value: Any
    attributes: dict[str, Any] = field(default_factory=dict)


# Raw REST/cache payload assembled by the coordinator before translation.
RawDeviceData = dict[str, Any]
# Normalized Home Assistant-facing entity states for one device, keyed by entity key.
DeviceState = dict[str, EntityState]
# Data exposed by AiperDataUpdateCoordinator.data, keyed first by device serial number.
DevicesState = dict[str, DeviceState]


def _state_value(state: DeviceState | None, key: str) -> Any:
    if not state:
        return None
    entity = state.get(key)
    return entity.value if entity else None


def _state_attrs(state: DeviceState | None, key: str) -> dict[str, Any]:
    if not state:
        return {}
    entity = state.get(key)
    return dict(entity.attributes) if entity else {}


def _coerce_bool(value: Any) -> bool | None:
    """Coerce common Aiper 0/1/bool/string values into a boolean."""
    if value is None:
        return None
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        if value == 1:
            return True
        if value == 0:
            return False
        return bool(value)
    if isinstance(value, str):
        text = value.strip().lower()
        if text in ("1", "true", "on", "online", "connected"):
            return True
        if text in ("0", "false", "off", "offline", "disconnected"):
            return False
        try:
            return bool(int(text))
        except ValueError:
            return None
    return bool(value)


def _coerce_int(value: Any) -> int | None:
    """Coerce common numeric payload values into an int."""
    if isinstance(value, bool) or value is None:
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        return int(value)
    if isinstance(value, str) and value.strip().lstrip("-").isdigit():
        return int(value.strip())
    return None


def _coerce_float(value: Any) -> float | None:
    """Coerce common numeric payload values into a float."""
    if isinstance(value, bool) or value is None:
        return None
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, str):
        try:
            return float(value.strip())
        except ValueError:
            return None
    return None


def _centihours_to_hours(value: Any) -> float | None:
    if isinstance(value, bool) or value is None:
        return None
    if isinstance(value, int):
        return round(value / 100.0, 2)
    if isinstance(value, float) and value.is_integer():
        return round(value / 100.0, 2)
    if isinstance(value, str):
        stripped = value.strip()
        if stripped.lstrip("-").isdigit():
            return round(int(stripped) / 100.0, 2)
    return None


def _round_number(value: Any) -> float | None:
    """Coerce a numeric payload value and round it to two decimal places."""
    if isinstance(value, bool) or value is None:
        return None
    if isinstance(value, (int, float)):
        return round(float(value), 2)
    if isinstance(value, str):
        try:
            return round(float(value.strip()), 2)
        except ValueError:
            return None
    return None


_hours = _round_number
