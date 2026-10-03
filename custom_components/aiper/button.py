"""Button platform for Aiper integration."""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from dataclasses import dataclass

from homeassistant.components.button import ButtonEntity, ButtonEntityDescription
from homeassistant.const import EntityCategory
from homeassistant.core import HomeAssistant, callback
from homeassistant.exceptions import HomeAssistantError
from homeassistant.helpers.entity_platform import AddEntitiesCallback

from . import AiperConfigEntry
from .const import DOMAIN
from .controller import AiperDeviceController
from .coordinator import AiperDataUpdateCoordinator
from .entity import AiperEntity
from .state import DeviceState


async def _noop_press(entity: AiperButton) -> None:
    """Default button press handler."""


# Button presses hit the cloud; don't fan out in parallel.
PARALLEL_UPDATES = 1


@dataclass(frozen=True, kw_only=True)
class AiperButtonEntityDescription(ButtonEntityDescription):
    """Describes an Aiper button entity."""

    press_fn: Callable[[AiperButton], Awaitable[None]] = _noop_press
    enabled_default: bool = True
    requires_mqtt: bool = False


async def _press_refresh_shadow(entity: AiperButton) -> None:
    if not await entity.controller.refresh_shadow(entity.sn):
        raise HomeAssistantError(translation_domain=DOMAIN, translation_key="shadow_refresh_failed")


async def _press_refresh_metadata(entity: AiperButton) -> None:
    await entity.coordinator.async_refresh_metadata(entity.sn)


async def _press_clear_command_state(entity: AiperButton) -> None:
    entity.coordinator.clear_command_state(entity.sn)


BUTTON_DESCRIPTIONS: tuple[AiperButtonEntityDescription, ...] = (
    AiperButtonEntityDescription(
        key="refresh_shadow",
        translation_key="refresh_shadow",
        press_fn=_press_refresh_shadow,
        requires_mqtt=True,
    ),
    AiperButtonEntityDescription(
        key="refresh_metadata",
        translation_key="refresh_metadata",
        press_fn=_press_refresh_metadata,
    ),
    AiperButtonEntityDescription(
        key="clear_command_state",
        translation_key="clear_command_state",
        entity_category=EntityCategory.DIAGNOSTIC,
        enabled_default=False,
        press_fn=_press_clear_command_state,
    ),
)


async def async_setup_entry(
    hass: HomeAssistant,
    entry: AiperConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Set up Aiper buttons based on a config entry."""
    coordinator: AiperDataUpdateCoordinator = entry.runtime_data.coordinator
    controller: AiperDeviceController = entry.runtime_data.controller
    known_devices: set[str] = set()

    def _create_device_entities(sn: str, device_data: DeviceState) -> list[ButtonEntity]:
        return [
            AiperButton(
                coordinator=coordinator,
                controller=controller,
                description=description,
                sn=sn,
                device_data=device_data,
            )
            for description in BUTTON_DESCRIPTIONS
        ]

    @callback
    def _async_add_new_devices() -> None:
        if not coordinator.data:
            return
        new_entities: list[ButtonEntity] = []
        for sn, dev in coordinator.data.items():
            if sn not in known_devices:
                known_devices.add(sn)
                new_entities.extend(_create_device_entities(sn, dev))
        if new_entities:
            async_add_entities(new_entities)

    initial_entities: list[ButtonEntity] = []
    if coordinator.data:
        for sn, dev in coordinator.data.items():
            known_devices.add(sn)
            initial_entities.extend(_create_device_entities(sn, dev))

    async_add_entities(initial_entities)
    if hasattr(entry, "async_on_unload"):
        entry.async_on_unload(coordinator.async_add_listener(_async_add_new_devices))


class AiperButton(AiperEntity, ButtonEntity):
    """Representation of an Aiper button."""

    entity_description: AiperButtonEntityDescription

    def __init__(
        self,
        coordinator: AiperDataUpdateCoordinator,
        controller: AiperDeviceController,
        description: AiperButtonEntityDescription,
        sn: str,
        device_data: DeviceState,
    ) -> None:
        """Initialize the button."""
        super().__init__(coordinator, sn, description.key, device_data)
        self.controller = controller
        self.entity_description = description
        self._attr_entity_registry_enabled_default = description.enabled_default

    @property
    def available(self) -> bool:
        """Return True if the button can be pressed."""
        if not super().available:
            return False
        return not (self.entity_description.requires_mqtt and not self.coordinator.api.is_mqtt_connected())

    async def async_press(self) -> None:
        """Handle the button press."""
        await self.entity_description.press_fn(self)
