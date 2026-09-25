"""Behavior tests for Aiper control entities (switch/select) and their base class."""

from __future__ import annotations

from typing import Any, cast

import pytest
from homeassistant.core import HomeAssistant
from homeassistant.exceptions import HomeAssistantError, ServiceValidationError

from custom_components.aiper.const import DOMAIN
from custom_components.aiper.controller import AiperDeviceController
from custom_components.aiper.coordinator import AiperDataUpdateCoordinator
from custom_components.aiper.entity import device_info_for, device_online
from custom_components.aiper.profiles import Capability, derive_device_profile
from custom_components.aiper.select import AiperCleaningModeSelect, AiperCleanPathSelect
from custom_components.aiper.state import EntityState, normalize_device_state
from custom_components.aiper.switch import AiperRunningSwitch
from tests.coordinator_factory import BaseFakeApi, make_coordinator

SN = "SN1234567890"


class CommandApi(BaseFakeApi):
    """API double recording device commands."""

    def __init__(self, *, mqtt: bool = True, accept: bool = True, error: Exception | None = None) -> None:
        self.mqtt = mqtt
        self.accept = accept
        self.error = error
        self.commands: list[tuple[str, Any]] = []

    def is_mqtt_connected(self) -> bool:
        return self.mqtt

    async def _command(self, name: str, value: Any) -> bool:
        self.commands.append((name, value))
        if self.error is not None:
            raise self.error
        return self.accept

    async def set_running(self, sn: str, running: bool) -> bool:
        return await self._command("running", running)

    async def set_cleaning_mode(self, sn: str, mode: int) -> bool:
        return await self._command("mode", mode)

    async def update_clean_path_setting(self, sn: str, value: int) -> bool:
        return await self._command("clean_path", value)

    async def request_shadow(self, sn: str) -> bool:
        self.commands.append(("shadow", sn))
        return True

    async def get_devices(self) -> list[dict[str, Any]]:
        return []


def _device(*, online: bool = True, **extra: Any) -> dict[str, Any]:
    raw = {"sn": SN, "name": "Pool Robot", "model": "Scuba_X1", "online": online, "fw_main": "1.2.3", **extra}
    profile = derive_device_profile(raw)
    raw["capabilities"] = [
        cap.value
        for cap in profile.capabilities
        | {Capability.RUNNING_CONTROL, Capability.CLEAN_PATH, Capability.CLEANING_MODE_SELECT}
    ]
    raw["mode_map"] = profile.mode_map
    raw["supported_mode_ids"] = list(profile.mode_map)
    return normalize_device_state(raw)


def _setup(
    hass: HomeAssistant, api: CommandApi, **device: Any
) -> tuple[AiperDataUpdateCoordinator, AiperDeviceController]:
    coordinator = make_coordinator(api, hass=hass, data={SN: _device(**device)})
    refreshes: list[None] = []

    async def record_refresh() -> None:
        refreshes.append(None)

    # Entities request a REST refresh after commands; record it instead of polling.
    coordinator.async_request_refresh = record_refresh  # type: ignore[method-assign]
    coordinator.refreshes = refreshes  # type: ignore[attr-defined]
    return coordinator, AiperDeviceController(cast(Any, api), coordinator)


def _mode_select(coordinator: AiperDataUpdateCoordinator, controller: AiperDeviceController) -> AiperCleaningModeSelect:
    options = coordinator.data[SN]["mode_options"]
    return AiperCleaningModeSelect(
        coordinator, controller, SN, list(options.value), dict(options.attributes["mode_map"])
    )


def test_device_info_is_shared_and_tolerates_missing_data() -> None:
    """Every entity gets the same device registry shape, even before data arrives."""
    info = device_info_for(SN, _device())
    assert info["identifiers"] == {(DOMAIN, SN)}
    assert info["serial_number"] == SN
    assert info["name"] == "Pool Robot"
    assert info["sw_version"] == "1.2.3"

    assert device_info_for(SN, None)["name"] == f"Aiper {SN}"


@pytest.mark.asyncio
async def test_running_switch_sends_command_and_refreshes(hass: HomeAssistant) -> None:
    api = CommandApi()
    coordinator, controller = _setup(hass, api)
    switch = AiperRunningSwitch(coordinator, controller, SN)

    assert switch.available is True
    await switch.async_turn_on()
    await switch.async_turn_off()

    assert ("running", True) in api.commands
    assert ("running", False) in api.commands
    assert ("shadow", SN) in api.commands
    assert len(coordinator.refreshes) == 2  # type: ignore[attr-defined]


@pytest.mark.asyncio
async def test_running_switch_requires_mqtt(hass: HomeAssistant) -> None:
    coordinator, controller = _setup(hass, CommandApi(mqtt=False))
    switch = AiperRunningSwitch(coordinator, controller, SN)

    assert switch.available is False
    with pytest.raises(HomeAssistantError) as err:
        await switch.async_turn_on()
    assert err.value.translation_key == "mqtt_unavailable"


@pytest.mark.asyncio
async def test_controls_block_when_device_offline(hass: HomeAssistant) -> None:
    coordinator, controller = _setup(hass, CommandApi(), online=False)
    switch = AiperRunningSwitch(coordinator, controller, SN)

    assert device_online(coordinator, SN) is False
    assert switch.available is False
    with pytest.raises(HomeAssistantError) as err:
        await switch.async_turn_on()
    assert err.value.translation_key == "device_offline"


@pytest.mark.asyncio
async def test_rejected_command_raises_translated_error(hass: HomeAssistant) -> None:
    api = CommandApi(accept=False)
    coordinator, controller = _setup(hass, api)
    switch = AiperRunningSwitch(coordinator, controller, SN)

    with pytest.raises(HomeAssistantError) as err:
        await switch.async_turn_on()

    assert err.value.translation_key == "command_failed"
    assert err.value.translation_placeholders == {"command": "running", "reason": "device rejected"}
    assert coordinator.get_command_state(SN)["last"]["running"]["result"] == "failed"


@pytest.mark.asyncio
async def test_command_exception_is_reported_not_raised_raw(hass: HomeAssistant) -> None:
    api = CommandApi(error=RuntimeError("socket closed"))
    coordinator, controller = _setup(hass, api)

    result = await controller.set_running(SN, True)

    assert result.ok is False
    assert result.reason == "socket closed"


@pytest.mark.asyncio
async def test_entities_become_unavailable_when_device_disappears(hass: HomeAssistant) -> None:
    coordinator, controller = _setup(hass, CommandApi())
    switch = AiperRunningSwitch(coordinator, controller, SN)
    path_select = AiperCleanPathSelect(coordinator, controller, SN)

    coordinator.data = {}

    assert switch.available is False
    assert switch.is_on is None
    assert path_select.available is False
    assert path_select.current_option is None


@pytest.mark.asyncio
async def test_mode_select_sets_mode_by_label(hass: HomeAssistant) -> None:
    api = CommandApi()
    coordinator, controller = _setup(hass, api)
    select = _mode_select(coordinator, controller)
    assert select.translation_key == "mode_selection"
    target_label = select.options[-1]

    await select.async_select_option(target_label)

    assert api.commands[0][0] == "mode"
    assert select.extra_state_attributes == {"device_online": True, "mqtt_connected": True}


@pytest.mark.asyncio
async def test_mode_select_rejects_unknown_option(hass: HomeAssistant) -> None:
    coordinator, controller = _setup(hass, CommandApi())
    select = _mode_select(coordinator, controller)

    with pytest.raises(ServiceValidationError) as err:
        await select.async_select_option("Turbo")
    assert err.value.translation_key == "invalid_option"


@pytest.mark.asyncio
async def test_clean_path_select_caches_and_confirms(hass: HomeAssistant) -> None:
    api = CommandApi()
    coordinator, controller = _setup(hass, api)
    select = AiperCleanPathSelect(coordinator, controller, SN)

    await select.async_select_option("Adaptive")

    assert ("clean_path", 1) in api.commands
    assert coordinator._clean_path_cache[SN] == 1
    assert select.current_option == "Adaptive"
    with pytest.raises(ServiceValidationError):
        await select.async_select_option("Zigzag")


@pytest.mark.asyncio
async def test_failed_command_while_mqtt_drops_reports_mqtt_unavailable(hass: HomeAssistant) -> None:
    """If MQTT dropped mid-command, the error says so instead of a generic rejection."""
    api = CommandApi(accept=False)
    coordinator, controller = _setup(hass, api)
    select = AiperCleanPathSelect(coordinator, controller, SN)

    async def reject_and_drop(sn: str, value: int) -> bool:
        api.mqtt = False
        return False

    api.update_clean_path_setting = reject_and_drop  # type: ignore[method-assign]

    with pytest.raises(HomeAssistantError) as err:
        await select.async_select_option("Adaptive")
    assert err.value.translation_key == "mqtt_unavailable"


def test_device_online_is_none_for_unknown_device() -> None:
    assert device_online(make_coordinator(data={}), SN) is None


@pytest.mark.asyncio
async def test_buttons_and_binary_sensors(hass: HomeAssistant) -> None:
    from custom_components.aiper.binary_sensor import (
        BINARY_SENSOR_DESCRIPTIONS,
        AiperBinarySensor,
        AiperCloudConnectedBinarySensor,
    )
    from custom_components.aiper.button import BUTTON_DESCRIPTIONS, AiperButton

    api = CommandApi()
    coordinator, controller = _setup(hass, api)
    refresh = next(d for d in BUTTON_DESCRIPTIONS if d.key == "refresh_shadow")
    button = AiperButton(coordinator, controller, refresh, SN, coordinator.data[SN])

    assert button.available is True
    await button.async_press()
    assert ("shadow", SN) in api.commands

    async def no_shadow(sn: str) -> bool:
        return False

    api.request_shadow = no_shadow  # type: ignore[method-assign]
    with pytest.raises(HomeAssistantError) as err:
        await button.async_press()
    assert err.value.translation_key == "shadow_refresh_failed"

    api.mqtt = False
    assert button.available is False
    coordinator.last_update_success = False
    assert button.available is False

    online = next(d for d in BINARY_SENSOR_DESCRIPTIONS if d.key == "online")
    binary = AiperBinarySensor(coordinator, online, SN, coordinator.data[SN])
    coordinator.last_update_success = True
    assert binary.available is True
    assert binary.is_on is True

    class Api:
        connection = type("C", (), {"is_connected": True})()

    cloud = AiperCloudConnectedBinarySensor(make_coordinator(Api()), "entry")
    assert cloud.is_on is True
    assert cloud.available is True


@pytest.mark.asyncio
async def test_mode_select_label_resolution_and_current_mode_sources(hass: HomeAssistant) -> None:
    coordinator, controller = _setup(hass, CommandApi())
    select = AiperCleaningModeSelect(
        coordinator, controller, SN, [1, 2, 9], cast(Any, {"1": "Smart", "x": "Bad", 2: "Floor"})
    )

    assert select.options == ["Smart", "Floor", "Mode 9"]
    assert select._mode_id_for_label(None) is None
    assert select._mode_id_for_label("  ") is None
    assert select._mode_id_for_label("Floor") == 2
    assert select._mode_id_for_label("Mode 9") == 9
    assert select._mode_id_for_label("Turbo") is None

    data = dict(coordinator.data[SN])
    data["mode"] = EntityState("x", {"code": 42})
    data["mode_options"] = EntityState([1, 2, 9], {"selected_mode": 9})
    coordinator.data = {SN: data}
    assert select.current_option == "Mode 9"

    data["mode_options"] = EntityState([1, 2, 9], {})
    coordinator.note_command_sent(SN, "mode", 2)
    assert select.current_option == "Floor"

    coordinator.clear_command_state(SN)
    data["last_cleaning_mode"] = EntityState("Smart")
    assert select.current_option == "Smart"

    data.pop("last_cleaning_mode")
    assert select.current_option is None

    # Selecting the mode the device already reports is a no-op.
    data["mode"] = EntityState("Floor", {"code": 2})
    await select.async_select_option("Floor")
    assert controller.api.commands == []  # type: ignore[attr-defined]


@pytest.mark.asyncio
async def test_clean_path_select_dynamic_paths(hass: HomeAssistant) -> None:
    api = CommandApi()
    coordinator, controller = _setup(hass, api)
    select = AiperCleanPathSelect(coordinator, controller, SN)

    data = dict(coordinator.data[SN])
    data["clean_path"] = EntityState("Path 2", {"code": 2})
    coordinator.data = {SN: data}
    assert select.current_option == "Path 2"
    assert "Path 2" in select.options

    await select.async_select_option("Path 2")  # already reported: no-op
    assert api.commands == []

    await select.async_select_option("Path 3")
    assert ("clean_path", 3) in api.commands

    with pytest.raises(ServiceValidationError):
        await select.async_select_option("Path x")


@pytest.mark.asyncio
async def test_select_platform_builds_default_mode_map(hass: HomeAssistant) -> None:
    from types import SimpleNamespace

    from custom_components.aiper import select as select_platform

    coordinator, controller = _setup(hass, CommandApi())
    data = dict(coordinator.data[SN])
    data["mode_options"] = EntityState([1, 2], {})
    coordinator.data = {SN: data, "EMPTY": {**data, "mode_options": EntityState([], {})}}
    added: list[Any] = []
    entry = SimpleNamespace(runtime_data=SimpleNamespace(coordinator=coordinator, controller=controller))

    await select_platform.async_setup_entry(hass, entry, lambda entities: added.extend(entities))  # type: ignore[arg-type]

    mode_select = next(entity for entity in added if isinstance(entity, AiperCleaningModeSelect))
    assert mode_select.options == ["Smart", "Floor"]
    assert len(added) == 2


def test_cloud_sensors_report_connection_health() -> None:
    from datetime import UTC, datetime

    from custom_components.aiper.connection import ConnectionStatus
    from custom_components.aiper.sensor import AiperConnectionStateSensor, AiperLastCloudUpdateSensor

    class Api:
        connection = ConnectionStatus()

    coordinator = make_coordinator(Api())
    coordinator.last_successful_update = datetime(2026, 9, 1, tzinfo=UTC)
    Api.connection.mark_connecting()

    state_sensor = AiperConnectionStateSensor(coordinator, "entry")
    updated_sensor = AiperLastCloudUpdateSensor(coordinator, "entry")

    assert state_sensor.native_value == "connecting"
    assert state_sensor.extra_state_attributes["connect_attempts"] == 1
    assert state_sensor.available is True
    assert updated_sensor.native_value == datetime(2026, 9, 1, tzinfo=UTC)
