"""Constants for the Aiper integration."""
from __future__ import annotations

DOMAIN = "aiper"

# Options
CONF_ENABLE_MQTT = "enable_mqtt"
CONF_MQTT_DEBUG = "mqtt_debug"

# Control semantics
CONF_QUEUE_OFFLINE_COMMANDS = "queue_offline_commands"
CONF_POLL_INTERVAL = "poll_interval"

# Slower-changing data refresh options (hours)
CONF_HISTORY_REFRESH_HOURS = "history_refresh_hours"
CONF_CONSUMABLES_REFRESH_HOURS = "consumables_refresh_hours"
CONF_CLEAN_PATH_REFRESH_HOURS = "clean_path_refresh_hours"

DEFAULT_HISTORY_REFRESH_HOURS = 6
DEFAULT_CONSUMABLES_REFRESH_HOURS = 24
DEFAULT_CLEAN_PATH_REFRESH_HOURS = 6

# API Endpoints by region
API_ENDPOINTS = {
    "us": "https://apiamerica.aiper.com",
    "eu": "https://apieurope.aiper.com",
    "asia": "https://apiasia.aiper.com",
}

# AWS IoT Configuration
AWS_IOT_ENDPOINT = "iot.aiper.com"  # Will be retrieved from API
AWS_REGION = "us-east-1"  # Default, may vary by user region

# MQTT Topics (templates with {sn} placeholder)
TOPIC_READ = "aiper/things/{sn}/upChan"
TOPIC_WRITE = "aiper/things/{sn}/downChan"
TOPIC_SHADOW_GET = "$aws/things/{sn}/shadow/get/accepted"
TOPIC_SHADOW_GET_REQUEST = "$aws/things/{sn}/shadow/get"
TOPIC_SHADOW_UPDATE = "$aws/things/{sn}/shadow/update"
TOPIC_SHADOW_UPDATE_ACCEPTED = "$aws/things/{sn}/shadow/update/accepted"
TOPIC_SHADOW_UPDATE_DELTA = "$aws/things/{sn}/shadow/update/delta"
TOPIC_SHADOW_UPDATE_DOCUMENTS = "$aws/things/{sn}/shadow/update/documents"
TOPIC_SHADOW_REPORT = "aiper/things/{sn}/shadow/report"
TOPIC_SHADOW_REPORT_X9 = "aiper/things/{sn}/app/report"

# XOR Key for message encryption
XOR_KEY = bytes([0x12, 0x34, 0x56, 0x78])

# Device status codes
STATUS_IDLE = 0
STATUS_CLEANING = 1
STATUS_RETURNING = 2
STATUS_CHARGING = 3
STATUS_CHARGED = 4
STATUS_ERROR = 5
STATUS_SLEEPING = 6

STATUS_MAP = {
    STATUS_IDLE: "Idle",
    STATUS_CLEANING: "Cleaning",
    STATUS_RETURNING: "Returning",
    STATUS_CHARGING: "Charging",
    STATUS_CHARGED: "Charged",
    STATUS_ERROR: "Error",
    STATUS_SLEEPING: "Sleeping",
}

# Cleaning modes
#
# IMPORTANT: These numeric codes are device-specific. For Scuba X1 we have observed
# that the device reports a numeric `Machine.mode` that maps to app modes. Current mapping (based on testing): 1=Smart, 2=Floor, 3=Wall, 4=Waterline.
#
# The other modes are inferred and should be validated against the official app or by
# experimenting with `AT+MODE=<n>` via the `aiper.send_at_command` service.

# "Scheduled" mode: the device performs an ~50 minute run, powers down, and will
# attempt to run again ~48 hours later if battery is sufficient (as per app behavior).
# Empirically, this appears to be a distinct MODE value, not an "AT+PLAN" command.
MODE_SCHEDULED = 5
MODE_FLOOR = 2
MODE_SMART = 1
MODE_WALL = 3
MODE_WATERLINE = 4

MODE_MAP = {
    # NOTE: Mode IDs are device-specific and not documented publicly.
    # For Scuba X1 (tested): Machine.mode=1=Smart, 2=Floor, 3=Wall, 4=Waterline.
    # If your device reports different IDs, use the `aiper.send_at_command` service to experiment with `AT+MODE=<n>`.
    MODE_SCHEDULED: "Scheduled",
    MODE_SMART: "Smart",
    MODE_FLOOR: "Floor",
    MODE_WALL: "Wall",
    MODE_WATERLINE: "Waterline",
}

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

# Scan interval (seconds)
DEFAULT_SCAN_INTERVAL = 120

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
