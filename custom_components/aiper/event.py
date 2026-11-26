"""Event platform: confirmed cleaning completions for Home Assistant automations."""

from __future__ import annotations

from typing import Any

from homeassistant.components.event import EventEntity
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers.entity_platform import AddEntitiesCallback

from . import AiperConfigEntry
from .cleaning_sessions import CleaningSession
from .coordinator import AiperDataUpdateCoordinator
from .entity import AiperEntity, async_setup_dynamic_device_entities
from .profiles import Capability
from .state import DeviceState, state_has_capability

# Entities only read coordinator data; no per-entity update calls.
PARALLEL_UPDATES = 0

EVENT_CLEANING_FINISHED = "cleaning_finished"


def completion_event_attributes(session: CleaningSession) -> dict[str, Any]:
    """Return the public attributes of a completion event, omitting unknown values."""
    attributes: dict[str, Any] = {"session_id": session.session_id, "sources": sorted(session.sources)}
    if session.finish is not None:
        attributes["finished_at"] = session.finish.isoformat()
    if session.duration_min is not None:
        attributes["duration_min"] = session.duration_min
    if session.mode is not None:
        attributes["mode"] = session.mode
    if session.result is not None:
        attributes["result"] = session.result
    return attributes


async def async_setup_entry(
    hass: HomeAssistant,
    entry: AiperConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Set up Aiper event entities based on a config entry."""
    coordinator: AiperDataUpdateCoordinator = entry.runtime_data.coordinator

    def _create_device_entities(sn: str, device_data: DeviceState) -> list[AiperCleaningFinishedEvent]:
        if not state_has_capability(device_data, Capability.CLEANING_COMPLETION):
            return []
        return [AiperCleaningFinishedEvent(coordinator, sn, device_data)]

    async_setup_dynamic_device_entities(entry, coordinator, async_add_entities, _create_device_entities)


class AiperCleaningFinishedEvent(AiperEntity, EventEntity):
    """Fires once for each newly confirmed cleaning completion."""

    _attr_translation_key = EVENT_CLEANING_FINISHED
    _attr_event_types = [EVENT_CLEANING_FINISHED]

    def __init__(self, coordinator: AiperDataUpdateCoordinator, sn: str, device_data: DeviceState) -> None:
        """Initialize the event entity."""
        super().__init__(coordinator, sn, EVENT_CLEANING_FINISHED, device_data)

    @property
    def available(self) -> bool:
        """A confirmed MQTT completion can arrive during a failed REST poll."""
        return self.device_data is not None

    async def async_added_to_hass(self) -> None:
        """Announce a completion that was confirmed before this entity existed."""
        await super().async_added_to_hass()
        self._announce_pending()

    @callback
    def _handle_coordinator_update(self) -> None:
        """Announce completions confirmed by the latest update."""
        if not self._announce_pending():
            super()._handle_coordinator_update()

    @callback
    def _announce_pending(self) -> bool:
        """Publish each completion separately before acknowledging it."""
        if not self.available:
            return False
        announced = False
        for sn, session in self.coordinator.pending_completions():
            if sn != self._sn:
                continue
            self._trigger_event(EVENT_CLEANING_FINISHED, completion_event_attributes(session))
            self.async_write_ha_state()
            self.coordinator.mark_completion_announced(sn, session.session_id)
            announced = True
        return announced
