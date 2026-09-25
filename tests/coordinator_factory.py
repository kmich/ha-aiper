"""Build real coordinators for tests.

Tests used to bypass ``__init__`` with ``AiperDataUpdateCoordinator.__new__``
and hand-set private attributes, which forced the coordinator to guard every
attribute access with ``getattr(self, ..., default)``. Constructing through
``__init__`` keeps tests honest about the coordinator's real initial state.
"""

from __future__ import annotations

from typing import Any, cast
from unittest.mock import MagicMock

from custom_components.aiper.coordinator import AiperDataUpdateCoordinator


def make_coordinator(api: Any = None, *, hass: Any = None, **attrs: Any) -> AiperDataUpdateCoordinator:
    """Return a coordinator built via ``__init__`` with optional attribute overrides.

    ``hass`` may be omitted for synchronous tests that never touch the event
    loop; a MagicMock stands in for it.
    """
    coordinator = AiperDataUpdateCoordinator(hass if hass is not None else MagicMock(), cast(Any, api))
    for name, value in attrs.items():
        setattr(coordinator, name, value)
    return coordinator


class BaseFakeApi:
    """No-op implementation of the API surface the coordinator's MQTT upkeep uses.

    Test doubles inherit from this and override only what a test exercises.
    """

    def is_mqtt_connected(self) -> bool:
        return False

    async def async_refresh_mqtt_credentials(self) -> None:
        return None

    def mqtt_disconnected_seconds(self) -> float | None:
        return None

    def seconds_since_mqtt_rebuild(self) -> float | None:
        return None

    async def reconnect_mqtt(self) -> bool:
        return False

    def subscribed_serials(self) -> set[str]:
        return set()
