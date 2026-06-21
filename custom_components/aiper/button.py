"""Button platform for Aiper integration."""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from dataclasses import dataclass

from homeassistant.components.button import ButtonEntity, ButtonEntityDescription
from homeassistant.config_entries import ConfigEntry
from homeassistant.const import EntityCategory
from homeassistant.core import HomeAssistant
from homeassistant.exceptions import HomeAssistantError
from homeassistant.helpers.device_registry import DeviceInfo
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from .const import DOMAIN
from .controller import AiperDeviceController
from .coordinator import AiperDataUpdateCoordinator
from .state import DeviceState


async def _noop_press(entity: AiperButton) -> None:
    """Default button press handler."""


@dataclass(frozen=True, kw_only=True)
class AiperButtonEntityDescription(ButtonEntityDescription):
    """Describes an Aiper button entity."""

    press_fn: Callable[[AiperButton], Awaitable[None]] = _noop_press
    enabled_default: bool = True
    requires_mqtt: bool = False


async def _press_refresh_shadow(entity: AiperButton) -> None:
    if not await entity.controller.refresh_shadow(entity.sn):
        raise HomeAssistantError("Failed to request Aiper shadow refresh.")


async def _press_refresh_metadata(entity: AiperButton) -> None:
    await entity.coordinator.async_refresh_metadata(entity.sn)


async def _press_clear_command_state(entity: AiperButton) -> None:
    entity.coordinator.clear_command_state(entity.sn)


BUTTON_DESCRIPTIONS: tuple[AiperButtonEntityDescription, ...] = (
    AiperButtonEntityDescription(
        key="refresh_shadow",
        name="Refresh Shadow",
        icon="mdi:cloud-refresh",
        press_fn=_press_refresh_shadow,
        requires_mqtt=True,
    ),
    AiperButtonEntityDescription(
        key="refresh_metadata",
        name="Refresh Metadata",
        icon="mdi:database-refresh",
        press_fn=_press_refresh_metadata,
    ),
    AiperButtonEntityDescription(
        key="clear_command_state",
        name="Clear Command State",
        icon="mdi:playlist-remove",
        entity_category=EntityCategory.DIAGNOSTIC,
        enabled_default=False,
        press_fn=_press_clear_command_state,
    ),
)


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Set up Aiper buttons based on a config entry."""
    coordinator: AiperDataUpdateCoordinator = hass.data[DOMAIN][entry.entry_id]["coordinator"]
    controller: AiperDeviceController = hass.data[DOMAIN][entry.entry_id]["controller"]

    entities: list[ButtonEntity] = []
    if coordinator.data:
        for sn, dev in coordinator.data.items():
            entities.extend(
                AiperButton(
                    coordinator=coordinator,
                    controller=controller,
                    description=description,
                    sn=sn,
                    device_data=dev,
                )
                for description in BUTTON_DESCRIPTIONS
            )

    async_add_entities(entities)


class AiperButton(CoordinatorEntity[AiperDataUpdateCoordinator], ButtonEntity):
    """Representation of an Aiper button."""

    entity_description: AiperButtonEntityDescription
    _attr_has_entity_name = True

    def __init__(
        self,
        coordinator: AiperDataUpdateCoordinator,
        controller: AiperDeviceController,
        description: AiperButtonEntityDescription,
        sn: str,
        device_data: DeviceState,
    ) -> None:
        """Initialize the button."""
        super().__init__(coordinator)
        self.controller = controller
        self.entity_description = description
        self.sn = sn
        self._attr_unique_id = f"{sn}_{description.key}"
        self._attr_entity_registry_enabled_default = description.enabled_default
        device_info = device_data["device_info"]
        device_info_attrs = device_info.attributes

        self._attr_device_info = DeviceInfo(
            identifiers={(DOMAIN, sn)},
            name=str(device_info.value or f"Aiper {sn}"),
            manufacturer="Aiper",
            model=device_info_attrs.get("model"),
            serial_number=sn,
            sw_version=device_info_attrs.get("sw_version"),
        )

    @property
    def available(self) -> bool:
        """Return True if the button can be pressed."""
        if not super().available:
            return False
        if self.entity_description.requires_mqtt and not self.coordinator.api.is_mqtt_connected():
            return False
        return self.coordinator.data is not None and self.sn in self.coordinator.data

    async def async_press(self) -> None:
        """Handle the button press."""
        await self.entity_description.press_fn(self)
