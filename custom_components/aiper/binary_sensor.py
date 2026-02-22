"""Binary sensor platform for Aiper integration."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable

from homeassistant.components.binary_sensor import (
    BinarySensorDeviceClass,
    BinarySensorEntity,
    BinarySensorEntityDescription,
)
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity import DeviceInfo
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from .const import DOMAIN
from .coordinator import AiperDataUpdateCoordinator


@dataclass(frozen=True, kw_only=True)
class AiperBinarySensorEntityDescription(BinarySensorEntityDescription):
    """Describes Aiper binary sensor entity."""

    value_fn: Callable[[dict], bool | None]
    available_fn: Callable[[dict], bool] = lambda x: True
    enabled_default: bool = True



def _coerce_bool(val: Any) -> bool | None:
    """Coerce common Aiper 0/1/bool/string values into a boolean."""
    if val is None:
        return None
    if isinstance(val, bool):
        return val
    if isinstance(val, (int, float)):
        if val == 1:
            return True
        if val == 0:
            return False
        return bool(val)
    if isinstance(val, str):
        v = val.strip().lower()
        if v in ("1", "true", "on", "online", "connected"):
            return True
        if v in ("0", "false", "off", "offline", "disconnected"):
            return False
        try:
            iv = int(v)
            if iv == 1:
                return True
            if iv == 0:
                return False
            return bool(iv)
        except Exception:
            return None
    return bool(val)


def _is_online(data: dict) -> bool | None:
    """Check if device is online.

    Preference order:
      1) status_data.online (explicit endpoint)
      2) coordinator-computed _ha_online (if set)
      3) device.online (from device list)
      4) shadow.netstat.online (MQTT / inferred)
    """
    # 1) Explicit status endpoint
    status_data = data.get("status_data") or {}
    if isinstance(status_data, dict) and "online" in status_data:
        out = _coerce_bool(status_data.get("online"))
        if out is not None:
            return out

    # 2) Coordinator-computed online (if present)
    if "_ha_online" in data:
        out = _coerce_bool(data.get("_ha_online"))
        if out is not None:
            return out

    # 3) Device list payload
    if "online" in data:
        out = _coerce_bool(data.get("online"))
        if out is not None:
            return out

    # 4) Shadow netstat
    shadow_online = (data.get("shadow") or {}).get("netstat", {}).get("online")
    out = _coerce_bool(shadow_online)
    return out


def _is_in_water(data: dict) -> bool | None:
    """Check if device is in water."""
    # Check device data
    if "inWater" in data:
        return bool(data.get("inWater"))
    # Shadow data
    shadow_val = data.get("shadow", {}).get("machine", {}).get("in_water")
    if shadow_val is not None:
        return shadow_val == 1
    return None


def _is_wifi_connected(data: dict) -> bool | None:
    """Check if WiFi is connected."""
    if _is_online(data) is False:
        return False
    # REST API has wifiName when connected
    if "wifiName" in data and data.get("wifiName"):
        return True
    if "wifiRssi" in data and data.get("wifiRssi"):
        return True
    # Shadow data
    sta = data.get("shadow", {}).get("netstat", {}).get("sta")
    # Observed values include 2 for connected.
    return sta in (1, 2, "1", "2")


BINARY_SENSOR_DESCRIPTIONS: tuple[AiperBinarySensorEntityDescription, ...] = (
    AiperBinarySensorEntityDescription(
        key="online",
        name="Online",
        device_class=BinarySensorDeviceClass.CONNECTIVITY,
        value_fn=_is_online,
    ),
    AiperBinarySensorEntityDescription(
        key="in_water",
        name="In Water",
        icon="mdi:water",
        device_class=BinarySensorDeviceClass.MOISTURE,
        value_fn=_is_in_water,
        enabled_default=True,
    ),
    AiperBinarySensorEntityDescription(
        key="solar_charging",
        name="Solar Charging",
        icon="mdi:solar-power",
        device_class=BinarySensorDeviceClass.BATTERY_CHARGING,
        value_fn=lambda data: data.get("shadow", {}).get("machine", {}).get("solar_status") == 1,
        available_fn=lambda data: data.get("shadow", {}).get("machine", {}).get("solar_status") is not None,
        enabled_default=False,  # MQTT-only
    ),
    AiperBinarySensorEntityDescription(
        key="bluetooth",
        name="Bluetooth",
        icon="mdi:bluetooth",
        device_class=BinarySensorDeviceClass.CONNECTIVITY,
        value_fn=lambda data: False if _is_online(data) is False else data.get("shadow", {}).get("netstat", {}).get("ble") == 1,
        enabled_default=False,  # MQTT-only
    ),
    AiperBinarySensorEntityDescription(
        key="wifi",
        name="WiFi Connected",
        icon="mdi:wifi",
        device_class=BinarySensorDeviceClass.CONNECTIVITY,
        value_fn=_is_wifi_connected,
    ),
    AiperBinarySensorEntityDescription(
        key="linked",
        name="Device Linked",
        icon="mdi:link",
        value_fn=lambda data: False if _is_online(data) is False else (
            data.get("shadow", {}).get("netstat", {}).get("nearFieldBind") == 1
            or data.get("shadow", {}).get("machine", {}).get("link") == 1
        ),
        available_fn=lambda data: (
            data.get("shadow", {}).get("netstat", {}).get("nearFieldBind") is not None
            or data.get("shadow", {}).get("machine", {}).get("link") is not None
        ),
        enabled_default=False,  # MQTT-only
    ),
)


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Set up Aiper binary sensors based on a config entry."""
    coordinator: AiperDataUpdateCoordinator = hass.data[DOMAIN][entry.entry_id]["coordinator"]

    entities: list[AiperBinarySensor] = []

    if coordinator.data:
        for sn, device_data in coordinator.data.items():
            for description in BINARY_SENSOR_DESCRIPTIONS:
                entities.append(
                    AiperBinarySensor(
                        coordinator=coordinator,
                        description=description,
                        sn=sn,
                        device_data=device_data,
                    )
                )

    async_add_entities(entities)


class AiperBinarySensor(CoordinatorEntity[AiperDataUpdateCoordinator], BinarySensorEntity):
    """Representation of an Aiper binary sensor."""

    entity_description: AiperBinarySensorEntityDescription
    _attr_has_entity_name = True

    def __init__(
        self,
        coordinator: AiperDataUpdateCoordinator,
        description: AiperBinarySensorEntityDescription,
        sn: str,
        device_data: dict,
    ) -> None:
        """Initialize the binary sensor."""
        super().__init__(coordinator)
        self.entity_description = description
        self._sn = sn
        self._attr_unique_id = f"{sn}_{description.key}"
        self._attr_entity_registry_enabled_default = description.enabled_default

        # Device info
        model = device_data.get("model", device_data.get("modelName", "Aiper Pool Cleaner"))
        self._attr_device_info = DeviceInfo(
            identifiers={(DOMAIN, sn)},
            name=device_data.get("name", f"Aiper {sn}"),
            manufacturer="Aiper",
            model=model,
            serial_number=sn,
            sw_version=device_data.get("firmwareVersion"),
        )

    @property
    def is_on(self) -> bool | None:
        """Return true if the binary sensor is on."""
        if self.coordinator.data and self._sn in self.coordinator.data:
            return self.entity_description.value_fn(self.coordinator.data[self._sn])
        return None

    @property
    def available(self) -> bool:
        """Return True if entity is available."""
        if not super().available:
            return False
        if self.coordinator.data and self._sn in self.coordinator.data:
            return self.entity_description.available_fn(self.coordinator.data[self._sn])
        return False
