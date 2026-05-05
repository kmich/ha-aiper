"""Tests for the typed Aiper command controller."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, cast

import pytest

from custom_components.aiper.const import CleaningMode
from custom_components.aiper.controller import AiperDeviceController
from custom_components.aiper.profiles import Capability
from custom_components.aiper.state import normalize_device_state


@dataclass
class FakeApi:
    """Fake low-level API used by controller tests."""

    mode_result: bool = True
    clean_path_result: bool = True
    modes: list[tuple[str, int]] = field(default_factory=list)
    running_states: list[tuple[str, bool]] = field(default_factory=list)
    clean_paths: list[tuple[str, int]] = field(default_factory=list)

    async def set_cleaning_mode(self, sn: str, mode: int | CleaningMode) -> bool:
        self.modes.append((sn, int(mode)))
        return self.mode_result

    async def set_running(self, sn: str, running: bool) -> bool:
        self.running_states.append((sn, running))
        return self.mode_result

    async def update_clean_path_setting(self, sn: str, clean_path: int) -> bool:
        self.clean_paths.append((sn, clean_path))
        return self.clean_path_result


@dataclass
class FakeCoordinator:
    """Fake coordinator carrying device capabilities and command state calls."""

    data: dict[str, dict[str, Any]]
    sent: list[tuple[str, str, Any, str]] = field(default_factory=list)
    failed: list[tuple[str, str, Any, str, str]] = field(default_factory=list)

    def note_command_sent(self, sn: str, kind: str, target: Any, *, source: str = "select") -> None:
        self.sent.append((sn, kind, target, source))

    def note_command_failed(
        self,
        sn: str,
        kind: str,
        target: Any,
        *,
        reason: str,
        source: str = "select",
    ) -> None:
        self.failed.append((sn, kind, target, reason, source))


def _controller(api: FakeApi, coordinator: FakeCoordinator) -> AiperDeviceController:
    return AiperDeviceController(cast(Any, api), cast(Any, coordinator))


def _device_with_capabilities(*capabilities: Capability) -> dict[str, Any]:
    return normalize_device_state({"capabilities": [capability.value for capability in capabilities]})


@pytest.mark.asyncio
async def test_set_cleaning_mode_uses_typed_controller_and_records_command_state() -> None:
    """Cleaning mode changes use device intent rather than raw AT commands."""
    api = FakeApi()
    coordinator = FakeCoordinator({"SN123": _device_with_capabilities(Capability.CLEANING_MODE_SELECT)})

    result = await _controller(api, coordinator).set_cleaning_mode("SN123", CleaningMode.FLOOR)

    assert result.ok is True
    assert result.command == "cleaning_mode"
    assert api.modes == [("SN123", 2)]
    assert coordinator.sent == [("SN123", "cleaning_mode", CleaningMode.FLOOR, "controller")]
    assert coordinator.failed == []


@pytest.mark.asyncio
async def test_clean_path_rejects_devices_without_capability() -> None:
    """Unsupported device families should not receive clean-path commands."""
    api = FakeApi()
    coordinator = FakeCoordinator({"SN123": _device_with_capabilities()})

    result = await _controller(api, coordinator).set_clean_path("SN123", 1)

    assert result.ok is False
    assert result.reason == "device does not advertise clean_path"
    assert api.clean_paths == []
    assert coordinator.sent == []


@pytest.mark.asyncio
async def test_set_cleaning_mode_records_device_rejection() -> None:
    """Rejected low-level commands are surfaced as structured command results."""
    api = FakeApi(mode_result=False)
    coordinator = FakeCoordinator({"SN123": _device_with_capabilities(Capability.CLEANING_MODE_SELECT)})

    result = await _controller(api, coordinator).set_cleaning_mode("SN123", CleaningMode.SCHEDULED)

    assert result.ok is False
    assert result.reason == "device rejected"
    assert coordinator.failed == [("SN123", "cleaning_mode", CleaningMode.SCHEDULED, "device rejected", "controller")]


@pytest.mark.asyncio
async def test_set_cleaning_mode_accepts_explicit_device_reported_ids() -> None:
    """Cleaning modes are device-reported integers, not only known enum values."""
    api = FakeApi()
    coordinator = FakeCoordinator({"SN123": _device_with_capabilities(Capability.CLEANING_MODE_SELECT)})

    result = await _controller(api, coordinator).set_cleaning_mode("SN123", 7)

    assert result.ok is True
    assert api.modes == [("SN123", 7)]


@pytest.mark.asyncio
async def test_set_running_uses_surfer_mode_commands() -> None:
    """Surfer running control maps on/off intent to the verified AT mode IDs."""
    api = FakeApi()
    coordinator = FakeCoordinator({"SN123": _device_with_capabilities(Capability.RUNNING_CONTROL)})
    controller = _controller(api, coordinator)

    on_result = await controller.set_running("SN123", True)
    off_result = await controller.set_running("SN123", False)

    assert on_result.ok is True
    assert off_result.ok is True
    assert api.running_states == [("SN123", True), ("SN123", False)]
    assert coordinator.sent == [
        ("SN123", "running", True, "controller"),
        ("SN123", "running", False, "controller"),
    ]


@pytest.mark.asyncio
async def test_set_running_rejects_devices_without_capability() -> None:
    """Devices without verified simple running control should not receive commands."""
    api = FakeApi()
    coordinator = FakeCoordinator({"SN123": _device_with_capabilities()})

    result = await _controller(api, coordinator).set_running("SN123", True)

    assert result.ok is False
    assert result.reason == "device does not advertise running_control"
    assert api.modes == []
    assert coordinator.sent == []
