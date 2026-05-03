"""Device-family profiles and capability discovery for Aiper devices."""
from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Any

from .const import MODE_MAP, SCUBA_MODEL_MARKERS


class DeviceFamily(StrEnum):
    """Known broad Aiper device families."""

    SCUBA = "scuba"
    SURFER = "surfer"
    SHARK = "shark"
    UNKNOWN = "unknown"


class Capability(StrEnum):
    """Feature flags used to gate entities and controls."""

    BATTERY = "battery"
    ONLINE = "online"
    STATUS = "status"
    WARNING = "warning"
    WIFI = "wifi"
    HISTORY = "history"
    FIRMWARE = "firmware"
    MQTT_SHADOW = "mqtt_shadow"
    MODE_SELECT = "mode_select"
    CLEAN_PATH = "clean_path"
    WATER_TEMPERATURE = "water_temperature"
    IN_WATER = "in_water"
    SOLAR_CHARGING = "solar_charging"
    BLUETOOTH = "bluetooth"
    DEVICE_LINK = "device_link"
    ROLLER_BRUSH = "roller_brush"
    MICROMESH_FILTER = "micromesh_filter"
    CATERPILLAR_TREAD = "caterpillar_tread"
    PROPELLER_MAINTENANCE = "propeller_maintenance"


SURFER_MODEL_MARKERS = ("surfer",)
SHARK_MODEL_MARKERS = ("shark",)

COMMON_CAPABILITIES = frozenset(
    {
        Capability.BATTERY,
        Capability.ONLINE,
        Capability.STATUS,
        Capability.WARNING,
        Capability.WIFI,
        Capability.HISTORY,
        Capability.FIRMWARE,
        Capability.MQTT_SHADOW,
        Capability.BLUETOOTH,
        Capability.DEVICE_LINK,
    }
)

SCUBA_CAPABILITIES = COMMON_CAPABILITIES | frozenset(
    {
        Capability.MODE_SELECT,
        Capability.CLEAN_PATH,
        Capability.WATER_TEMPERATURE,
        Capability.IN_WATER,
        Capability.ROLLER_BRUSH,
        Capability.MICROMESH_FILTER,
        Capability.CATERPILLAR_TREAD,
    }
)

SURFER_CAPABILITIES = COMMON_CAPABILITIES | frozenset(
    {
        Capability.PROPELLER_MAINTENANCE,
        Capability.SOLAR_CHARGING,
    }
)

SHARK_CAPABILITIES = COMMON_CAPABILITIES


@dataclass(frozen=True, kw_only=True)
class DeviceProfile:
    """Derived model profile used to gate entities and commands."""

    family: DeviceFamily
    capabilities: frozenset[Capability]
    mode_map: dict[int, str]


def device_model_string(device: dict[str, Any]) -> str:
    """Return the most specific model string available from a device payload."""
    return str(
        device.get("model")
        or device.get("deviceModel")
        or device.get("modelName")
        or device.get("productName")
        or ""
    )


def device_family(device: dict[str, Any]) -> DeviceFamily:
    """Infer the broad device family from model payload fields."""
    model = device_model_string(device).lower()
    if any(marker in model for marker in SCUBA_MODEL_MARKERS):
        return DeviceFamily.SCUBA
    if any(marker in model for marker in SURFER_MODEL_MARKERS):
        return DeviceFamily.SURFER
    if any(marker in model for marker in SHARK_MODEL_MARKERS):
        return DeviceFamily.SHARK
    return DeviceFamily.UNKNOWN


def _mode_map_for_ids(family: DeviceFamily, mode_ids: list[int]) -> dict[int, str]:
    if family == DeviceFamily.SCUBA:
        return {mode_id: MODE_MAP.get(mode_id, f"Mode {mode_id}") for mode_id in mode_ids}
    return {mode_id: f"Mode {mode_id}" for mode_id in mode_ids}


def _has_consumable(device: dict[str, Any], *terms: str) -> bool:
    wanted = tuple(term.lower() for term in terms)
    for item in device.get("_ha_consumables") or []:
        if not isinstance(item, dict):
            continue
        haystack = " ".join(
            str(item.get(key, ""))
            for key in ("name", "key", "raw_name", "type", "model")
            if item.get(key) is not None
        ).lower()
        if all(term in haystack for term in wanted):
            return True
    return False


def derive_device_profile(device: dict[str, Any]) -> DeviceProfile:
    """Derive a device profile from identity fields and discovered payload evidence."""
    family = device_family(device)
    if family == DeviceFamily.SCUBA:
        capabilities = set(SCUBA_CAPABILITIES)
    elif family == DeviceFamily.SURFER:
        capabilities = set(SURFER_CAPABILITIES)
    elif family == DeviceFamily.SHARK:
        capabilities = set(SHARK_CAPABILITIES)
    else:
        capabilities = set(COMMON_CAPABILITIES)

    if bool(device.get("_ha_supported_modes_explicit")):
        capabilities.add(Capability.MODE_SELECT)

    shadow = device.get("shadow") or {}
    machine = shadow.get("machine") or {}
    if isinstance(machine, dict):
        if machine.get("temp") is not None:
            capabilities.add(Capability.WATER_TEMPERATURE)
        if machine.get("in_water") is not None:
            capabilities.add(Capability.IN_WATER)
        if machine.get("solar_status") is not None:
            capabilities.add(Capability.SOLAR_CHARGING)

    if _has_consumable(device, "propeller"):
        capabilities.add(Capability.PROPELLER_MAINTENANCE)
    if _has_consumable(device, "roller", "brush"):
        capabilities.add(Capability.ROLLER_BRUSH)
    if _has_consumable(device, "micromesh"):
        capabilities.add(Capability.MICROMESH_FILTER)
    if _has_consumable(device, "caterpillar"):
        capabilities.add(Capability.CATERPILLAR_TREAD)

    supported = device.get("_ha_supported_mode_ids")
    mode_ids = [int(mode_id) for mode_id in supported] if isinstance(supported, list) else []
    mode_map = _mode_map_for_ids(family, mode_ids)

    return DeviceProfile(
        family=family,
        capabilities=frozenset(capabilities),
        mode_map=mode_map,
    )


def has_capability(device: dict[str, Any], capability: Capability | str) -> bool:
    """Return whether a normalized device payload has a capability."""
    caps = device.get("_ha_capabilities") or []
    value = capability.value if isinstance(capability, Capability) else str(capability)
    return value in caps
