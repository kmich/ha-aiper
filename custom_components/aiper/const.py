"""Constants for the Aiper integration."""

from __future__ import annotations

from enum import IntEnum, StrEnum

DOMAIN = "aiper"

# Options
CONF_MQTT_DEBUG = "mqtt_debug"

# Slower-changing cloud metadata refresh options (hours)
CONF_METADATA_REFRESH_HOURS = "metadata_refresh_hours"

DEFAULT_METADATA_REFRESH_HOURS = 24


class ApiEndpoint(StrEnum):
    """Aiper cloud API endpoints by broad region."""

    us = "https://apiamerica.aiper.com"
    eu = "https://apieurope.aiper.com"
    asia = "https://apiasia.aiper.com"


class MqttTopic(StrEnum):
    """MQTT topic templates with an `{sn}` serial-number placeholder."""

    READ = "aiper/things/{sn}/upChan"
    WRITE = "aiper/things/{sn}/downChan"
    SHADOW_GET = "$aws/things/{sn}/shadow/get/accepted"
    SHADOW_GET_REQUEST = "$aws/things/{sn}/shadow/get"
    SHADOW_UPDATE = "$aws/things/{sn}/shadow/update"
    SHADOW_UPDATE_ACCEPTED = "$aws/things/{sn}/shadow/update/accepted"
    SHADOW_UPDATE_DELTA = "$aws/things/{sn}/shadow/update/delta"
    SHADOW_UPDATE_DOCUMENTS = "$aws/things/{sn}/shadow/update/documents"
    SHADOW_REPORT = "aiper/things/{sn}/shadow/report"
    SHADOW_REPORT_X9 = "aiper/things/{sn}/app/report"


# XOR Key for message encryption
XOR_KEY = bytes([0x12, 0x34, 0x56, 0x78])

STATUS_BASE_MASK = 0x7F
# Meaning unknown; observed in both scheduled-idle and manual-cleaning states.
STATUS_HIGH_BIT = 0x80


class Status(IntEnum):
    """Known Aiper device status values carried in the lower status bits."""

    IDLE = 0
    CLEANING = 1
    RETURNING = 2
    CHARGING = 3
    CHARGED = 4
    ERROR = 5
    SLEEPING = 6


def status_value(status: int | Status | None) -> int | None:
    """Return the lower-bit status value from a raw status code."""
    if status is None:
        return None
    try:
        return int(status) & STATUS_BASE_MASK
    except (TypeError, ValueError):
        return None


def status_running(status: int | Status | None) -> bool:
    """Return whether the device is running."""
    value = status_value(status)
    if value is None:
        return False
    return value in (Status.CLEANING, Status.RETURNING)


def status_label(status: int | Status | None) -> str:
    """Return a display label for a known status code."""
    value = status_value(status)
    if value is None:
        return f"Status {status}"
    try:
        return Status(value).name.replace("_", " ").title()
    except ValueError:
        return f"Status {status}"


class CleaningMode(IntEnum):
    """Known labels for device-reported cleaning-mode IDs.

    Cleaning mode IDs are device-specific. This enum is intentionally only the
    known common label set; runtime control paths must still accept explicit
    integer IDs reported by the device.
    """

    SMART = 1
    FLOOR = 2
    WALL = 3
    WATERLINE = 4
    SCHEDULED = 5


class DeviceFamily(StrEnum):
    """Model-name markers used for broad device-family detection."""

    SCUBA = "scuba"
    SURFER = "surfer"
    SHARK = "shark"
    HYDROCOMM = "hydrocomm"
    UNKNOWN = "unknown"


# Cleaning modes
#
# IMPORTANT: These numeric codes are device-specific. For Scuba X1 we have observed
# that the device reports a numeric `Machine.mode` that maps to app modes. Current mapping (based on testing): 1=Smart, 2=Floor, 3=Wall, 4=Waterline.
#
# Other modes are inferred and should be validated with the probe tooling before
# being exposed as stable Home Assistant controls.

MODE_MAP: dict[int, str] = {
    # NOTE: Mode IDs are device-specific and not documented publicly.
    # For Scuba X1 (tested): Machine.mode=1=Smart, 2=Floor, 3=Wall, 4=Waterline.
    # If your device reports different IDs, validate them with the probe tooling before exposing them.
    int(CleaningMode.SCHEDULED): "Scheduled",
    int(CleaningMode.SMART): "Smart",
    int(CleaningMode.FLOOR): "Floor",
    int(CleaningMode.WALL): "Wall",
    int(CleaningMode.WATERLINE): "Waterline",
}


def mode_label(mode_id: int | CleaningMode) -> str:
    """Return a conservative label for a protocol mode ID."""
    mode_value = int(mode_id)
    return MODE_MAP.get(mode_value, f"Mode {mode_value}")


# Warning codes (partial list, expand as discovered)
WARN_CODES = {
    0: "No Warning",
    1: "Stuck",
    2: "Lifted",
    3: "Filter Full",
    4: "Low Battery",
    5: "Out of Water",
    # Add more as discovered from logs
}

# X9 Series device prefixes (use different topic pattern)
X9_SERIES_PREFIXES = ["X9", "SE", "SL"]

# Connection timeout
CONNECT_TIMEOUT = 10

# Clean path preference (Scuba X-series)
# Two observed values: 0=S-shaped (default), 1=Adaptive.
# Server responses may sometimes return -1; treat as default (0).
CLEAN_PATH_S_SHAPED = 0
CLEAN_PATH_ADAPTIVE = 1

CLEAN_PATH_MAP: dict[int, str] = {
    CLEAN_PATH_S_SHAPED: "S-shaped",
    CLEAN_PATH_ADAPTIVE: "Adaptive",
}

CLEAN_PATH_LABEL_TO_VALUE: dict[str, int] = {v: k for k, v in CLEAN_PATH_MAP.items()}
