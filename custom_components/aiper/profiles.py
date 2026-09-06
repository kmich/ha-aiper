"""Device-family profiles and capability discovery for Aiper devices.

Profiles answer three separate questions:

- Which Home Assistant surfaces should this device expose?
- How should raw device-reported numeric mode IDs be labelled?
- What do this firmware's `Machine.status` codes actually mean?

Do not treat every reported `Machine.mode` ID as a commandable cleaning mode.
Surfer devices report mode as read-only cleaning context, while Scuba exposes
known selectable cleaning modes. Shark/unknown devices only expose a cleaning
mode select when the cloud explicitly reports supported mode IDs.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from enum import StrEnum
from typing import Any

from .const import CleaningMode, DeviceFamily, Status, mode_label


class Capability(StrEnum):
    """Feature flags used to gate entities and controls."""

    BATTERY = "battery"
    ONLINE = "online"
    STATUS = "status"
    WARNING = "warning"
    WIFI = "wifi"
    FIRMWARE = "firmware"
    MQTT_SHADOW = "mqtt_shadow"
    CHARGING = "charging"
    CLEANING_MODE_SELECT = "mode_select"
    RUNNING_CONTROL = "running_control"
    CLEAN_PATH = "clean_path"
    WATER_TEMPERATURE = "water_temperature"
    WATER_QUALITY = "water_quality"
    PROBE_STATUS = "probe_status"
    IN_WATER = "in_water"
    SOLAR_CHARGING = "solar_charging"
    BLUETOOTH = "bluetooth"
    DEVICE_LINK = "device_link"
    CHARGE_TYPE = "charge_type"
    ROLLER_BRUSH = "roller_brush"
    MICROMESH_FILTER = "micromesh_filter"
    CATERPILLAR_TREAD = "caterpillar_tread"
    PROPELLER = "propeller"


SURFER_MODEL_MARKERS = (DeviceFamily.SURFER.value,)
SHARK_MODEL_MARKERS = (DeviceFamily.SHARK.value,)
SCUBA_S1_2025_MODEL = "scuba_s1_2025"
SCUBA_P1_PRO_MODEL = "scuba_p1_pro"

COMMON_CAPABILITIES = frozenset(
    {
        Capability.BATTERY,
        Capability.ONLINE,
        Capability.STATUS,
        Capability.WARNING,
        Capability.WIFI,
        Capability.FIRMWARE,
        Capability.MQTT_SHADOW,
        Capability.CHARGING,
        Capability.BLUETOOTH,
        Capability.DEVICE_LINK,
        Capability.CHARGE_TYPE,
        Capability.ROLLER_BRUSH,
        Capability.MICROMESH_FILTER,
        Capability.CATERPILLAR_TREAD,
        Capability.PROPELLER,
    }
)

SCUBA_CAPABILITIES = COMMON_CAPABILITIES | frozenset(
    {
        Capability.CLEANING_MODE_SELECT,
        Capability.CLEAN_PATH,
        Capability.WATER_TEMPERATURE,
        Capability.IN_WATER,
    }
)

# The 2026 retail Scuba S1 identifies itself to Aiper's backend as
# ``Scuba_S1_2025``. Captured REST, MQTT, and device-shadow payloads do not
# expose water temperature, charge type, roller brush, caterpillar tread, or
# propeller data. Clean-path and MicroMesh support are verified separately, so
# those capabilities remain enabled for this model.
SCUBA_S1_2025_CAPABILITIES = SCUBA_CAPABILITIES - frozenset(
    {
        Capability.WATER_TEMPERATURE,
        Capability.CHARGE_TYPE,
        Capability.ROLLER_BRUSH,
        Capability.CATERPILLAR_TREAD,
        Capability.PROPELLER,
    }
)

# The Scuba P1 Pro identifies itself as ``Scuba_P1_Pro`` (X6 Pro hardware
# family). Its onboarding bundle (issue #45, integration 1.4.0) shows an MQTT
# Machine shadow with no ``temp`` field, and a consumables list of exactly a
# Roller Brush and a MicroMesh Filter. Charge-type, caterpillar-tread, and
# propeller data are absent, so those entities stay off; roller-brush
# maintenance is kept because the device reports that consumable.
SCUBA_P1_PRO_CAPABILITIES = SCUBA_CAPABILITIES - frozenset(
    {
        Capability.WATER_TEMPERATURE,
        Capability.CHARGE_TYPE,
        Capability.CATERPILLAR_TREAD,
        Capability.PROPELLER,
    }
)

SURFER_CAPABILITIES = (
    COMMON_CAPABILITIES - frozenset({Capability.ROLLER_BRUSH, Capability.CATERPILLAR_TREAD})
) | frozenset(
    {
        Capability.RUNNING_CONTROL,
        Capability.SOLAR_CHARGING,
    }
)

SHARK_CAPABILITIES = COMMON_CAPABILITIES

# HydroComm is a water quality monitor, not a pool cleaner.
# Cleaning-specific capabilities (status, warning, mode select, run control,
# clean path, in_water) are intentionally excluded.
HYDROCOMM_CAPABILITIES = frozenset(
    {
        Capability.BATTERY,
        Capability.ONLINE,
        Capability.STATUS,
        Capability.WARNING,
        Capability.WIFI,
        Capability.FIRMWARE,
        Capability.BLUETOOTH,
        Capability.MQTT_SHADOW,
        Capability.CHARGING,
        Capability.CHARGE_TYPE,
        Capability.SOLAR_CHARGING,
        Capability.WATER_TEMPERATURE,
        Capability.WATER_QUALITY,
        Capability.PROBE_STATUS,
    }
)

SCUBA_DEFAULT_MODE_IDS = [
    int(CleaningMode.SMART),
    int(CleaningMode.FLOOR),
    int(CleaningMode.WALL),
    int(CleaningMode.WATERLINE),
    int(CleaningMode.SCHEDULED),
]
SCUBA_S1_2025_MODE_MAP = {
    int(CleaningMode.SMART): "Auto",
    int(CleaningMode.FLOOR): "Floor",
    int(CleaningMode.WALL): "Wall",
    int(CleaningMode.SCHEDULED): "Scheduled",
}
SURFER_DEFAULT_MODE_IDS = [0, int(CleaningMode.SMART), int(CleaningMode.SCHEDULED)]


@dataclass(frozen=True, kw_only=True)
class DeviceProfile:
    """Derived model profile used to gate entities and commands."""

    family: DeviceFamily
    capabilities: frozenset[Capability]
    mode_map: dict[int, str]


@dataclass(frozen=True, kw_only=True)
class StatusSemantics:
    """Model-specific meaning of `Machine.status` codes.

    The shared `Status` enum holds the encoding used by most firmwares. Where a
    model is known to deviate, an entry here overrides the label and the
    charging/running interpretation for that model only.
    """

    labels: Mapping[int, str]
    charging: frozenset[int]
    running: frozenset[int]


# Scuba S3 (main firmware V3.0.0) reports `2` for the whole charge and switches
# to `3` at the moment the battery reaches 100%, where the shared enum reads
# those as "Returning" and "Charging". Confirmed against MQTT shadow and REST
# payloads over four full charge cycles, cross-checked against the Aiper app
# showing "Charging" for the same `status: 2` payload.
#
# This is deliberately scoped to the S3: the Scuba X1 is covered by
# test_scuba_charging_status_is_reported_from_base_status, which asserts the
# default encoding (3 = charging).
SCUBA_S3_STATUS_SEMANTICS = StatusSemantics(
    labels={
        int(Status.RETURNING): "Charging",
        int(Status.CHARGING): "Charged",
    },
    charging=frozenset({int(Status.RETURNING), int(Status.CHARGING)}),
    running=frozenset({int(Status.CLEANING)}),
)

# Captured on Scuba_S1_2025 main firmware V2.0.1:
# - status 1 while physically cleaning
# - status 10 after low-battery parking (not running)
# - status 2 while physically connected to the charger
SCUBA_S1_2025_STATUS_SEMANTICS = StatusSemantics(
    labels={
        int(Status.RETURNING): "Charging",
        10: "Parked",
    },
    charging=frozenset({int(Status.RETURNING), int(Status.CHARGING)}),
    running=frozenset({int(Status.CLEANING)}),
)

MODEL_STATUS_SEMANTICS: dict[str, StatusSemantics] = {
    SCUBA_S1_2025_MODEL: SCUBA_S1_2025_STATUS_SEMANTICS,
    "scuba_s3": SCUBA_S3_STATUS_SEMANTICS,
}


def device_model_string(device: dict[str, Any]) -> str:
    """Return the canonical model string from a device payload."""
    return str(device.get("model") or "")


def model_key(device: dict[str, Any]) -> str:
    """Return the normalized model key used to key model-specific behavior.

    `model` is only populated once the device-info call succeeds; fall back to
    the model carried by the device list (`deviceModel`) so a failed/pending
    info call cannot silently revert the device to default/unknown handling.
    This is the single source of truth for model normalization — every other
    module should import and call this instead of re-deriving it.
    """
    raw_model = device_model_string(device) or str(device.get("deviceModel") or "")
    return raw_model.strip().lower().replace("-", "_").replace(" ", "_")


def status_semantics(device: dict[str, Any]) -> StatusSemantics | None:
    """Return model-specific status-code semantics, or None for the default."""
    return MODEL_STATUS_SEMANTICS.get(model_key(device))


def device_family(device: dict[str, Any]) -> DeviceFamily:
    """Infer the broad device family from model payload fields."""
    # deviceType "4" is the API-level discriminator for HydroComm monitors.
    # Pool cleaners (Scuba, Surfer, Shark) are deviceType "3".
    # Check this first as it is more reliable than model name matching.
    if str(device.get("deviceType") or "") == "4":
        return DeviceFamily.HYDROCOMM

    # Fall back to `deviceModel` (as status_semantics()/model_key() already do)
    # so a device known only by `deviceModel` — e.g. before the first
    # successful info call populates `model` — isn't misclassified as UNKNOWN
    # while model_key()-keyed logic elsewhere still recognizes it correctly.
    # Deliberately not using model_key() here: that also collapses spaces to
    # underscores, which would break the exact-match candidates below (e.g.
    # "hydrocomm pro").
    model = (device_model_string(device) or str(device.get("deviceModel") or "")).lower()
    if DeviceFamily.SCUBA.value in model:
        return DeviceFamily.SCUBA
    if DeviceFamily.SURFER.value in model:
        return DeviceFamily.SURFER
    if DeviceFamily.SHARK.value in model:
        return DeviceFamily.SHARK

    # HydroComm may not always have a clean model string. The APK groups
    # HydroComm, HydroComm Pro/Pure, HydroHub, HydroHub Pro, and bare W2 under
    # the same W2 model family.
    candidate_fields = [
        model,
        str(device.get("name") or "").lower(),
        str(device.get("btName") or "").lower(),
        str(device.get("modelName") or "").lower(),
        str(device.get("bluetooth_name") or "").lower(),
    ]
    if any(
        DeviceFamily.HYDROCOMM.value in f
        or "hydrohub" in f
        or f in {"w2", "hydrocomm pro", "hydrocomm pure", "hydrohub pro"}
        for f in candidate_fields
    ):
        return DeviceFamily.HYDROCOMM

    return DeviceFamily.UNKNOWN


def _mode_map_for_ids(family: DeviceFamily, mode_ids: list[int]) -> dict[int, str]:
    if family == DeviceFamily.SCUBA:
        return {mode_id: mode_label(mode_id) for mode_id in mode_ids}
    if family == DeviceFamily.SURFER:
        mode_map = {0: "Off", 1: "Manual", 5: "Scheduled"}
        return {mode_id: mode_map.get(mode_id, f"Mode {mode_id}") for mode_id in sorted({0, *mode_ids})}
    return {mode_id: f"Mode {mode_id}" for mode_id in mode_ids}


def derive_device_profile(device: dict[str, Any]) -> DeviceProfile:
    """Derive a device profile from identity fields and discovered payload evidence."""
    family = device_family(device)
    supported = device.get("supported_mode_ids")
    mode_ids = [int(mode_id) for mode_id in supported] if isinstance(supported, list) else []
    if not mode_ids:
        if family == DeviceFamily.SCUBA:
            mode_ids = list(SCUBA_DEFAULT_MODE_IDS)
        elif family == DeviceFamily.SURFER:
            mode_ids = list(SURFER_DEFAULT_MODE_IDS)

    key = model_key(device)

    if key == SCUBA_S1_2025_MODEL:
        # Aiper Android 3.5.0's X5ProMax profile exposes Auto, Floor, Wall,
        # and Eco/Scheduled with command IDs 1, 2, 3, and 5. Waterline is not
        # supported by this hardware even though it is a generic Scuba default.
        mode_ids = list(SCUBA_S1_2025_MODE_MAP)

    if family == DeviceFamily.SCUBA:
        if key == SCUBA_S1_2025_MODEL:
            capabilities = set(SCUBA_S1_2025_CAPABILITIES)
        elif key == SCUBA_P1_PRO_MODEL:
            capabilities = set(SCUBA_P1_PRO_CAPABILITIES)
        else:
            capabilities = set(SCUBA_CAPABILITIES)
    elif family == DeviceFamily.SURFER:
        capabilities = set(SURFER_CAPABILITIES)
    elif family == DeviceFamily.SHARK:
        capabilities = set(SHARK_CAPABILITIES)
        if bool(device.get("supported_modes_explicit")) and mode_ids:
            capabilities.add(Capability.CLEANING_MODE_SELECT)
    elif family == DeviceFamily.HYDROCOMM:
        # HydroComm is a monitor, not a cleaner. Use a fixed minimal set
        # and skip the dynamic capability additions below.
        return DeviceProfile(
            family=family,
            capabilities=HYDROCOMM_CAPABILITIES,
            mode_map={},
        )
    else:
        capabilities = set(COMMON_CAPABILITIES)

    if device.get("temp") is not None and key not in (SCUBA_S1_2025_MODEL, SCUBA_P1_PRO_MODEL):
        capabilities.add(Capability.WATER_TEMPERATURE)
    if device.get("in_water") is not None:
        capabilities.add(Capability.IN_WATER)
    mode_map = dict(SCUBA_S1_2025_MODE_MAP) if key == SCUBA_S1_2025_MODEL else _mode_map_for_ids(family, mode_ids)

    return DeviceProfile(
        family=family,
        capabilities=frozenset(capabilities),
        mode_map=mode_map,
    )


def has_capability(device: dict[str, Any], capability: Capability | str) -> bool:
    """Return whether a normalized device payload has a capability."""
    caps = device.get("capabilities") or []
    value = capability.value if isinstance(capability, Capability) else str(capability)
    return value in caps
