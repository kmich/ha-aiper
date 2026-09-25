"""Switch platform for Aiper integration."""

from __future__ import annotations

from contextlib import suppress
from typing import Any

from homeassistant.components.switch import SwitchEntity
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity_platform import AddEntitiesCallback

from . import AiperConfigEntry
from .controller import AiperDeviceController
from .coordinator import AiperDataUpdateCoordinator
from .entity import AiperControlEntity
from .helpers import supports_running_control

# Commands are serialized per device by the API; don't fan out in parallel.
PARALLEL_UPDATES = 1


class AiperRunningSwitch(AiperControlEntity, SwitchEntity):
    """Switch for simple start/stop control."""

    _attr_icon = "mdi:pool"
    _attr_translation_key = "running"
    # Start/stop is an AT command over the MQTT downChan.
    _requires_mqtt = True

    def __init__(
        self,
        coordinator: AiperDataUpdateCoordinator,
        controller: AiperDeviceController,
        sn: str,
    ) -> None:
        """Initialize the running switch."""
        super().__init__(coordinator, controller, sn, "running")

    @property
    def is_on(self) -> bool | None:
        """Return the pending target while a command is in flight, else the reported state."""
        pending = self.coordinator.get_pending_command_target(self._sn, "running")
        if isinstance(pending, bool):
            return pending
        state = self.entity_state("running")
        running = state.value if state is not None else None
        return running if isinstance(running, bool) else None

    async def _set_running(self, running: bool) -> None:
        self._raise_if_control_blocked()

        result = await self.controller.set_running(self._sn, running)
        self._raise_for_failed_command(result)

        with suppress(Exception):
            await self.controller.refresh_shadow(self._sn)

        await self.coordinator.async_request_refresh()

    async def async_turn_on(self, **kwargs: Any) -> None:
        """Start running."""
        await self._set_running(True)

    async def async_turn_off(self, **kwargs: Any) -> None:
        """Stop running."""
        await self._set_running(False)


async def async_setup_entry(
    hass: HomeAssistant,
    entry: AiperConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Set up switch entities from a config entry."""
    coordinator = entry.runtime_data.coordinator
    controller = entry.runtime_data.controller

    async_add_entities(
        AiperRunningSwitch(coordinator, controller, sn)
        for sn, dev in (coordinator.data or {}).items()
        if supports_running_control(dev)
    )
