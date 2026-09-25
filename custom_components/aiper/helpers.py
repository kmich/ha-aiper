"""Shared capability and device-family predicates for Aiper entities."""

from __future__ import annotations

from .profiles import DeviceFamily
from .state import Capability, DeviceState, state_has_capability


def supports_running_control(dev: DeviceState) -> bool:
    """Return whether the running/pause control should be exposed."""
    return state_has_capability(dev, Capability.RUNNING_CONTROL)


def supports_clean_path(dev: DeviceState) -> bool:
    """Return whether the clean-path control should be exposed."""
    return state_has_capability(dev, Capability.CLEAN_PATH)


def supports_mode_control(dev: DeviceState) -> bool:
    """Return whether mode control has enough evidence to be exposed."""
    return state_has_capability(dev, Capability.CLEANING_MODE_SELECT)


def is_not_hydrocomm(device: DeviceState) -> bool:
    """Return True unless the device is a HydroComm water-quality station."""
    family = str(getattr(device.get("device_family"), "value", "")).lower()
    return family != DeviceFamily.HYDROCOMM.value
