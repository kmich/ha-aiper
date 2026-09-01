"""Shared helper functions for Aiper entities."""

from __future__ import annotations

from typing import Any

from homeassistant.helpers.device_registry import DeviceEntryType, DeviceInfo

from .const import DOMAIN
from .coordinator import AiperDataUpdateCoordinator
from .state import Capability, DeviceState, state_has_capability


def cloud_connection_device_info(entry_id: str) -> DeviceInfo:
    """DeviceInfo for the per-config-entry Aiper cloud-connection service device.

    The REST/MQTT link is shared by every device on the account, so its health
    entities live on one service device rather than being duplicated per robot.
    """
    return DeviceInfo(
        identifiers={(DOMAIN, f"cloud_{entry_id}")},
        name="Aiper Cloud",
        manufacturer="Aiper",
        model="Cloud Connection",
        entry_type=DeviceEntryType.SERVICE,
    )


def device_online(coordinator: AiperDataUpdateCoordinator, sn: str) -> bool | None:
    """Return the normalized online state for control availability."""
    dev = (coordinator.data or {}).get(sn)
    if dev is None:
        return None
    try:
        value = dev["online"].value
    except KeyError:
        return None
    return value if isinstance(value, bool) else None


def device_name(dev: DeviceState, sn: str) -> str:
    """Return the preferred display name for a device."""
    name = str(getattr(dev.get("device_info"), "value", ""))
    return name if name else f"Aiper {sn}"


def supports_running_control(dev: DeviceState) -> bool:
    """Return whether the running/pause control should be exposed."""
    return state_has_capability(dev, Capability.RUNNING_CONTROL)


def supports_clean_path(dev: DeviceState) -> bool:
    """Return whether the clean-path control should be exposed."""
    return state_has_capability(dev, Capability.CLEAN_PATH)


def supports_mode_control(dev: DeviceState) -> bool:
    """Return whether mode control has enough evidence to be exposed."""
    return state_has_capability(dev, Capability.CLEANING_MODE_SELECT)


def is_not_surfer(device: DeviceState) -> bool:
    family = str(getattr(device.get("device_family"), "value", "")).lower()
    return family != "surfer"


def is_not_hydrocomm(device: DeviceState) -> bool:
    family = str(getattr(device.get("device_family"), "value", "")).lower()
    return family != "hydrocomm"


def is_not_surfer_or_hydrocomm(device: DeviceState) -> bool:
    return is_not_surfer(device) and is_not_hydrocomm(device)


def coerce_int(val: Any) -> int | None:
    if isinstance(val, bool) or val is None:
        return None
    if isinstance(val, int):
        return val
    if isinstance(val, float):
        return int(val)
    if isinstance(val, str) and val.strip().lstrip("-").isdigit():
        return int(val.strip())
    return None
