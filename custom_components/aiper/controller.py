"""Typed command surface for Aiper devices."""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from .api import AiperApi
from .const import CleaningMode
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

    async def _run(
        self,
        sn: str,
        *,
        command: str,
        kind: str,
        target: Any,
        capability: Capability,
        send: Callable[[], Awaitable[bool]],
    ) -> AiperCommandResult:
        """Gate on capability, track the pending command, send it, and report the outcome.

        ``command`` names the user-facing command; ``kind`` is the key the
        coordinator's pending-command tracker confirms against device reports.
        """
        if not state_has_capability(self._device(sn), capability):
            return AiperCommandResult(
                ok=False,
                command=command,
                target=target,
                reason=f"device does not advertise {capability.value}",
            )

        self.coordinator.note_command_sent(sn, kind, target, source="controller")
        try:
            ok = await send()
        except Exception as err:
            reason = str(err)
        else:
            if ok:
                return AiperCommandResult(ok=True, command=command, target=target)
            reason = "device rejected"

        self.coordinator.note_command_failed(sn, kind, target, reason=reason, source="controller")
        return AiperCommandResult(ok=False, command=command, target=target, reason=reason)

    async def set_cleaning_mode(self, sn: str, mode: int | CleaningMode) -> AiperCommandResult:
        """Set a selectable cleaning mode."""
        return await self._run(
            sn,
            command="cleaning_mode",
            kind="mode",
            target=mode,
            capability=Capability.CLEANING_MODE_SELECT,
            send=lambda: self.api.set_cleaning_mode(sn, mode),
        )

    async def set_running(self, sn: str, running: bool) -> AiperCommandResult:
        """Start or stop device operation."""
        return await self._run(
            sn,
            command="running",
            kind="running",
            target=running,
            capability=Capability.RUNNING_CONTROL,
            send=lambda: self.api.set_running(sn, running),
        )

    async def set_clean_path(self, sn: str, clean_path: int) -> AiperCommandResult:
        """Set a device clean-path preference."""
        return await self._run(
            sn,
            command="clean_path",
            kind="clean_path",
            target=clean_path,
            capability=Capability.CLEAN_PATH,
            send=lambda: self.api.update_clean_path_setting(sn, clean_path),
        )

    async def refresh_shadow(self, sn: str) -> bool:
        """Request an MQTT shadow refresh for a device."""
        return await self.api.request_shadow(sn)
