"""Typed command surface for Aiper devices."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from custom_components.aiper.const import CleaningMode

from .api import AiperApi
from .profiles import Capability
from .state import state_has_capability

if TYPE_CHECKING:
    from .coordinator import AiperDataUpdateCoordinator


@dataclass(frozen=True, kw_only=True)
class AiperCommandResult:
    """Result from a typed Aiper command."""

    ok: bool
    command: str
    target: Any = None
    reason: str | None = None


class AiperDeviceController:
    """Home Assistant-facing command wrapper for Aiper devices.

    This layer exposes device intent rather than protocol details. The underlying
    API still owns REST/MQTT/AT transport choices because those are cloud and
    model-specific implementation details.
    """

    def __init__(self, api: AiperApi, coordinator: AiperDataUpdateCoordinator) -> None:
        self.api = api
        self.coordinator = coordinator

    def _device(self, sn: str) -> dict[str, Any]:
        return (self.coordinator.data or {}).get(sn) or {}

    def _unsupported(self, command: str, target: Any, capability: Capability) -> AiperCommandResult:
        return AiperCommandResult(
            ok=False,
            command=command,
            target=target,
            reason=f"device does not advertise {capability.value}",
        )

    async def set_cleaning_mode(self, sn: str, mode: int | CleaningMode) -> AiperCommandResult:
        """Set a selectable cleaning mode."""
        if not state_has_capability(self._device(sn), Capability.CLEANING_MODE_SELECT):
            return self._unsupported("cleaning_mode", mode, Capability.CLEANING_MODE_SELECT)

        self.coordinator.note_command_sent(sn, "cleaning_mode", mode, source="controller")
        try:
            ok = await self.api.set_cleaning_mode(sn, mode)
        except Exception as err:
            reason = str(err)
            self.coordinator.note_command_failed(sn, "cleaning_mode", mode, reason=reason, source="controller")
            return AiperCommandResult(ok=False, command="cleaning_mode", target=mode, reason=reason)

        if not ok:
            reason = "device rejected"
            self.coordinator.note_command_failed(sn, "cleaning_mode", mode, reason=reason, source="controller")
            return AiperCommandResult(ok=False, command="cleaning_mode", target=mode, reason=reason)

        return AiperCommandResult(ok=True, command="cleaning_mode", target=mode)

    async def set_running(self, sn: str, running: bool) -> AiperCommandResult:
        """Start or stop device operation."""
        if not state_has_capability(self._device(sn), Capability.RUNNING_CONTROL):
            return self._unsupported("running", running, Capability.RUNNING_CONTROL)

        self.coordinator.note_command_sent(sn, "running", running, source="controller")
        try:
            ok = await self.api.set_running(sn, running)
        except Exception as err:
            reason = str(err)
            self.coordinator.note_command_failed(sn, "running", running, reason=reason, source="controller")
            return AiperCommandResult(ok=False, command="running", target=running, reason=reason)

        if not ok:
            reason = "device rejected"
            self.coordinator.note_command_failed(sn, "running", running, reason=reason, source="controller")
            return AiperCommandResult(ok=False, command="running", target=running, reason=reason)

        return AiperCommandResult(ok=True, command="running", target=running)

    async def set_clean_path(self, sn: str, clean_path: int) -> AiperCommandResult:
        """Set a device clean-path preference."""
        if not state_has_capability(self._device(sn), Capability.CLEAN_PATH):
            return self._unsupported("clean_path", clean_path, Capability.CLEAN_PATH)

        self.coordinator.note_command_sent(sn, "clean_path", clean_path, source="controller")
        try:
            ok = await self.api.update_clean_path_setting(sn, clean_path)
        except Exception as err:
            reason = str(err)
            self.coordinator.note_command_failed(sn, "clean_path", clean_path, reason=reason, source="controller")
            return AiperCommandResult(ok=False, command="clean_path", target=clean_path, reason=reason)

        if not ok:
            reason = "device rejected"
            self.coordinator.note_command_failed(sn, "clean_path", clean_path, reason=reason, source="controller")
            return AiperCommandResult(ok=False, command="clean_path", target=clean_path, reason=reason)

        return AiperCommandResult(ok=True, command="clean_path", target=clean_path)

    async def refresh_shadow(self, sn: str) -> bool:
        """Request an MQTT shadow refresh for a device."""
        return await self.api.request_shadow(sn)
