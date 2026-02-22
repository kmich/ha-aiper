"""Sensor platform for Aiper integration."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable

from homeassistant.components.sensor import (
    SensorDeviceClass,
    SensorEntity,
    SensorEntityDescription,
    SensorStateClass,
)
from homeassistant.config_entries import ConfigEntry
from homeassistant.const import PERCENTAGE, UnitOfTemperature
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity import DeviceInfo
from homeassistant.helpers.entity import EntityCategory
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from .const import DOMAIN, STATUS_MAP, MODE_MAP, CLEAN_PATH_MAP
from .coordinator import AiperDataUpdateCoordinator


@dataclass(frozen=True, kw_only=True)
class AiperSensorEntityDescription(SensorEntityDescription):
    """Describes Aiper sensor entity."""

    value_fn: Callable[[dict], Any]
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
    """Best-effort online evaluation."""
    status_data = data.get("status_data") or {}
    if isinstance(status_data, dict) and "online" in status_data:
        out = _coerce_bool(status_data.get("online"))
        if out is not None:
            return out
    if "_ha_online" in data:
        out = _coerce_bool(data.get("_ha_online"))
        if out is not None:
            return out
    if "online" in data:
        out = _coerce_bool(data.get("online"))
        if out is not None:
            return out
    shadow_online = (data.get("shadow") or {}).get("netstat", {}).get("online")
    return _coerce_bool(shadow_online)


def _is_wifi_connected(data: dict) -> bool:
    """Return True if Wi-Fi appears connected (best effort)."""
    if _is_online(data) is False:
        return False
    if data.get("wifiName"):
        return True
    if data.get("wifiRssi") is not None:
        return True
    sta = (data.get("shadow") or {}).get("netstat", {}).get("sta")
    return sta in (1, 2, "1", "2")


def _get_battery(data: dict) -> int | None:
    """Get battery from device data."""
    # REST API uses 'battLevel' directly on device
    if "battLevel" in data:
        return data.get("battLevel")
    # Fallback to shadow data (from MQTT)
    shadow_cap = data.get("shadow", {}).get("machine", {}).get("cap")
    if shadow_cap is not None:
        return shadow_cap
    # Other possible field names
    return data.get("battery") or data.get("cap") or data.get("electricity")


def _get_status(data: dict) -> str:
    """Get status from device data."""
    if _is_online(data) is False:
        return "Offline"

    # REST API uses 'machineStatus' directly on device
    if "machineStatus" in data and data.get("machineStatus") is not None:
        status = data.get("machineStatus")
        return STATUS_MAP.get(status, f"Status {status}")

    # Fallback to shadow data (from MQTT)
    shadow_status = (data.get("shadow") or {}).get("machine", {}).get("status")
    if shadow_status is not None:
        return STATUS_MAP.get(shadow_status, f"Status {shadow_status}")

    # If we are online but have no status code, present as Idle (per UX requirement)
    return "Idle"


def _get_mode(data: dict) -> str:
    """Get cleaning mode from device data."""
    # Check for mode in device data
    if "cleanMode" in data:
        return MODE_MAP.get(data.get("cleanMode"), f"Mode {data.get('cleanMode')}")
    if "mode" in data:
        return MODE_MAP.get(data.get("mode"), f"Mode {data.get('mode')}")
    # Fallback to shadow data (from MQTT)
    shadow_mode = data.get("shadow", {}).get("machine", {}).get("mode")
    if shadow_mode is not None:
        return MODE_MAP.get(shadow_mode, f"Mode {shadow_mode}")
    return "Unknown"


def _get_clean_path(data: dict) -> str | None:
    """Best-effort clean path preference.

    Prefer the REST-derived value (stored by the coordinator) when available,
    then fall back to any values found in shadow/info.
    """

    val = data.get("_ha_clean_path")
    if isinstance(val, int):
        return CLEAN_PATH_MAP.get(val, str(val))

    shadow = data.get("shadow") or {}
    cw = shadow.get("cyclework") or {}
    if isinstance(cw, dict):
        for k in ("path", "clean_path", "cleanPath", "route", "pattern"):
            if cw.get(k) is not None:
                return str(cw.get(k))
    info = data.get("info") or {}
    if isinstance(info, dict):
        for k in ("cleanPath", "clean_path", "pathPreference", "path"):
            if info.get(k) is not None:
                return str(info.get(k))
    return None


def _normalize_warn_code(code: Any) -> str | None:
    """Normalize warning codes to the format users expect (e.g., e12)."""
    if code is None:
        return None

    # Lists/tuples are handled by the collector.
    if isinstance(code, (list, tuple, set)):
        return None

    try:
        if isinstance(code, (int, float)):
            ci = int(code)
            if ci <= 0:
                return None
            return f"e{ci}".lower()

        s = str(code).strip()
        if not s:
            return None

        # If it's a pure number, normalize to e<n>
        if s.isdigit():
            ci = int(s)
            if ci <= 0:
                return None
            return f"e{ci}".lower()

        # If it already has an E/e prefix, normalize the prefix and casing.
        if s[0] in ("e", "E") and len(s) > 1 and s[1:].strip(" ").replace("_", "").replace("-", "").isdigit():
            # Preserve the numeric portion only.
            num = "".join(ch for ch in s[1:] if ch.isdigit())
            if num:
                return f"e{int(num)}".lower()

        # Otherwise keep the raw code but normalize whitespace/casing.
        return s.lower()
    except Exception:
        return None


def _collect_warning_codes(shadow_machine: dict) -> list[str]:
    """Collect all warning codes present in the shadow state."""
    codes: list[str] = []

    # Candidate fields that may contain a single code.
    single_keys = (
        "warn_code",
        "warnCode",
        "warning_code",
        "warningCode",
        "error_code",
        "errorCode",
    )

    # Candidate fields that may contain lists.
    list_keys = (
        "warn_codes",
        "warnCodeList",
        "warning_codes",
        "warningCodes",
        "error_codes",
        "errorCodes",
    )

    for k in list_keys:
        val = shadow_machine.get(k)
        if isinstance(val, (list, tuple, set)):
            for item in val:
                c = _normalize_warn_code(item)
                if c and c not in codes:
                    codes.append(c)

    for k in single_keys:
        c = _normalize_warn_code(shadow_machine.get(k))
        if c and c not in codes:
            codes.append(c)

    return codes


def _get_warning_text(data: dict) -> str:
    """Return the warning state as a single string.

    Requirements:
      - If no warnings are active: "No active warnings"
      - If one or more warnings are active: comma-separated codes (e.g., "e12, e13")
    """
    if _is_online(data) is False:
        return "No active warnings"

    shadow_machine = (data.get("shadow") or {}).get("machine") or {}
    warn = _coerce_bool(shadow_machine.get("warn"))
    codes = _collect_warning_codes(shadow_machine)

    # If explicitly no warnings, return the stable text.
    if warn is False:
        return "No active warnings"

    # If warnings appear active, present the codes (or fallback).
    if warn is True:
        return ", ".join(codes) if codes else "Active"

    # If we cannot determine the flag, but we have codes, show them.
    if codes:
        return ", ".join(codes)

    return "No active warnings"


def _find_consumable(data: dict, *keywords: str) -> dict | None:
    """Find a consumable entry by name keywords."""
    items = data.get("_ha_consumables") or []
    if not isinstance(items, list):
        return None
    kw = [k.strip().lower() for k in keywords if k]
    for it in items:
        if not isinstance(it, dict):
            continue
        name = str(it.get("name") or "").lower()
        if all(k in name for k in kw):
            return it
    return None


def _get_ota_state(data: dict) -> str | None:
    shadow = data.get("shadow") or {}
    ota = shadow.get("otastatus") or {}
    if not isinstance(ota, dict):
        return None
    # Common keys: status/state + progress
    for k in ("state", "status", "otaState", "ota_status"):
        if k in ota and ota.get(k) is not None:
            v = ota.get(k)
            # Normalize common numeric states.
            try:
                iv = int(v)
                if iv == 0:
                    return "Idle"
                if iv == 1:
                    return "Downloading"
                if iv == 2:
                    return "Installing"
                if iv == 3:
                    return "Rebooting"
            except Exception:
                pass
            return str(v)
    return None


SENSOR_DESCRIPTIONS: tuple[AiperSensorEntityDescription, ...] = (
    AiperSensorEntityDescription(
        key="battery",
        name="Battery",
        native_unit_of_measurement=PERCENTAGE,
        device_class=SensorDeviceClass.BATTERY,
        state_class=SensorStateClass.MEASUREMENT,
        value_fn=_get_battery,
    ),
    AiperSensorEntityDescription(
        key="status",
        name="Status",
        icon="mdi:robot-vacuum",
        value_fn=_get_status,
    ),
    # Note: "mode" sensor is handled separately by AiperCleaningModeSensor
    AiperSensorEntityDescription(
        key="mode_code",
        name="Cleaning Mode Code",
        icon="mdi:numeric",
        entity_category=EntityCategory.DIAGNOSTIC,
        value_fn=lambda data: (
            data.get("shadow", {}).get("machine", {}).get("mode")
            if data.get("shadow", {}).get("machine", {}).get("mode") is not None
            else data.get("mode", data.get("cleanMode"))
        ),
        available_fn=lambda data: (
            data.get("shadow", {}).get("machine", {}).get("mode") is not None
            or data.get("mode") is not None
            or data.get("cleanMode") is not None
        ),
        enabled_default=False,
    ),
    AiperSensorEntityDescription(
        key="temperature",
        name="Water Temperature",
        native_unit_of_measurement=UnitOfTemperature.CELSIUS,
        device_class=SensorDeviceClass.TEMPERATURE,
        state_class=SensorStateClass.MEASUREMENT,
        value_fn=lambda data: data.get("shadow", {}).get("machine", {}).get("temp"),
        available_fn=lambda data: data.get("shadow", {}).get("machine", {}).get("temp") is not None,
        enabled_default=False,  # MQTT-only until proven via REST
    ),
    AiperSensorEntityDescription(
        key="warning",
        name="Warning",
        icon="mdi:alert-circle",
        value_fn=_get_warning_text,
        # Keep this sensor available even when there is no active warning.
        available_fn=lambda data: True,
        enabled_default=True,
    ),
    AiperSensorEntityDescription(
        key="wifi_signal",
        name="WiFi Signal",
        icon="mdi:wifi",
        native_unit_of_measurement="dBm",
        device_class=SensorDeviceClass.SIGNAL_STRENGTH,
        state_class=SensorStateClass.MEASUREMENT,
        value_fn=lambda data: (
            None
            if (_is_online(data) is False or not _is_wifi_connected(data))
            else (
                data.get("wifiRssi")
                if data.get("wifiRssi") is not None
                else (data.get("shadow") or {}).get("opinfo", {}).get("wifi_rssi")
            )
        ),
        available_fn=lambda data: (
            _is_online(data) is not False
            and _is_wifi_connected(data)
            and (
                data.get("wifiRssi") is not None
                or (data.get("shadow") or {}).get("opinfo", {}).get("wifi_rssi") is not None
            )
        ),
    ),
    AiperSensorEntityDescription(
        key="runtime",
        name="Total Run Time",
        icon="mdi:timer",
        native_unit_of_measurement="h",
        state_class=SensorStateClass.TOTAL_INCREASING,
        value_fn=lambda data: (
            data.get("runTime")
            if data.get("runTime") is not None
            else data.get("shadow", {}).get("machine", {}).get("run_time")
        ),
        available_fn=lambda data: (
            data.get("runTime") is not None
            or data.get("shadow", {}).get("machine", {}).get("run_time") is not None
        ),
    ),

    # --- Cleaning history (REST) ---
    AiperSensorEntityDescription(
        key="total_cleanings",
        name="Total Cleanings",
        icon="mdi:counter",
        state_class=SensorStateClass.TOTAL_INCREASING,
        value_fn=lambda data: data.get("_ha_total_cleanings"),
        available_fn=lambda data: data.get("_ha_total_cleanings") is not None,
        enabled_default=True,
    ),
    AiperSensorEntityDescription(
        key="total_cleaning_time",
        name="Total Cleaning Time",
        icon="mdi:timer-outline",
        native_unit_of_measurement="h",
        state_class=SensorStateClass.TOTAL_INCREASING,
        value_fn=lambda data: data.get("_ha_total_cleaning_hours"),
        available_fn=lambda data: data.get("_ha_total_cleaning_hours") is not None,
        enabled_default=True,
    ),

    AiperSensorEntityDescription(
        key="total_cleaning_time_minutes",
        name="Total Cleaning Time Minutes",
        icon="mdi:timer-outline",
        native_unit_of_measurement="min",
        state_class=SensorStateClass.TOTAL_INCREASING,
        value_fn=lambda data: data.get("_ha_total_cleaning_minutes"),
        available_fn=lambda data: data.get("_ha_total_cleaning_minutes") is not None,
        enabled_default=False,
    ),
    AiperSensorEntityDescription(
        key="last_cleaning_mode",
        name="Last Cleaning Mode",
        icon="mdi:map-marker-path",
        value_fn=lambda data: data.get("_ha_last_cleaning_mode"),
        available_fn=lambda data: data.get("_ha_last_cleaning_mode") is not None,
        enabled_default=True,
    ),
    AiperSensorEntityDescription(
        key="last_cleaning_start",
        name="Last Cleaning Start",
        device_class=SensorDeviceClass.TIMESTAMP,
        entity_category=EntityCategory.DIAGNOSTIC,
        value_fn=lambda data: data.get("_ha_last_cleaning_start"),
        available_fn=lambda data: data.get("_ha_last_cleaning_start") is not None,
        enabled_default=True,
    ),
    AiperSensorEntityDescription(
        key="last_cleaning_duration",
        name="Last Cleaning Duration",
        icon="mdi:timer",
        native_unit_of_measurement="min",
        state_class=SensorStateClass.MEASUREMENT,
        value_fn=lambda data: data.get("_ha_last_cleaning_duration_min"),
        available_fn=lambda data: data.get("_ha_last_cleaning_duration_min") is not None,
        enabled_default=True,
    ),

    # --- Device info / firmware (REST) ---
    AiperSensorEntityDescription(
        key="main_version",
        name="Main Version",
        entity_category=EntityCategory.DIAGNOSTIC,
        value_fn=lambda data: data.get("_ha_fw_main") or (data.get("info") or {}).get("mainVersion") or (data.get("info") or {}).get("mainVer"),
        available_fn=lambda data: (data.get("_ha_fw_main") or (data.get("info") or {}).get("mainVersion") or (data.get("info") or {}).get("mainVer")) is not None,
        enabled_default=True,
    ),
    AiperSensorEntityDescription(
        key="mcu_version",
        name="MCU Version",
        entity_category=EntityCategory.DIAGNOSTIC,
        value_fn=lambda data: data.get("_ha_fw_mcu") or (data.get("info") or {}).get("mcuVersion") or (data.get("info") or {}).get("mcuVer"),
        available_fn=lambda data: (data.get("_ha_fw_mcu") or (data.get("info") or {}).get("mcuVersion") or (data.get("info") or {}).get("mcuVer")) is not None,
        enabled_default=True,
    ),
    AiperSensorEntityDescription(
        key="ip_address",
        name="IP Address",
        entity_category=EntityCategory.DIAGNOSTIC,
        value_fn=lambda data: data.get("_ha_ip_address") or (data.get("info") or {}).get("ipAddress") or (data.get("info") or {}).get("ip"),
        available_fn=lambda data: (data.get("_ha_ip_address") or (data.get("info") or {}).get("ipAddress") or (data.get("info") or {}).get("ip")) is not None,
        enabled_default=True,
    ),
    AiperSensorEntityDescription(
        key="ap_hotspot",
        name="AP Hotspot",
        entity_category=EntityCategory.DIAGNOSTIC,
        value_fn=lambda data: data.get("_ha_ap_hotspot") or (data.get("info") or {}).get("apHotspot") or (data.get("info") or {}).get("ap"),
        available_fn=lambda data: (data.get("_ha_ap_hotspot") or (data.get("info") or {}).get("apHotspot") or (data.get("info") or {}).get("ap")) is not None,
        enabled_default=True,
    ),
    AiperSensorEntityDescription(
        key="bluetooth_name",
        name="Bluetooth Name",
        entity_category=EntityCategory.DIAGNOSTIC,
        value_fn=lambda data: data.get("_ha_bluetooth_name") or (data.get("info") or {}).get("bluetoothName") or (data.get("info") or {}).get("btName"),
        available_fn=lambda data: (data.get("_ha_bluetooth_name") or (data.get("info") or {}).get("bluetoothName") or (data.get("info") or {}).get("btName")) is not None,
        enabled_default=True,
    ),
    AiperSensorEntityDescription(
        key="clean_path",
        name="Clean Path Preference",
        entity_category=EntityCategory.DIAGNOSTIC,
        value_fn=_get_clean_path,
        available_fn=lambda data: _get_clean_path(data) is not None,
        enabled_default=False,
    ),
    AiperSensorEntityDescription(
        key="ota_state",
        name="OTA State",
        entity_category=EntityCategory.DIAGNOSTIC,
        value_fn=_get_ota_state,
        available_fn=lambda data: _get_ota_state(data) is not None,
        enabled_default=False,
    ),

    # --- Consumables (REST) ---
    AiperSensorEntityDescription(
        key="roller_brush_remaining",
        name="Roller Brush Remaining",
        icon="mdi:timer-sand",
        native_unit_of_measurement="h",
        entity_category=EntityCategory.DIAGNOSTIC,
        value_fn=lambda data: (c := _find_consumable(data, "roller", "brush")) and c.get("remaining_hours"),
        available_fn=lambda data: (c := _find_consumable(data, "roller", "brush")) is not None and c.get("remaining_hours") is not None,
        enabled_default=True,
    ),
    AiperSensorEntityDescription(
        key="roller_brush_percent",
        name="Roller Brush Remaining %",
        icon="mdi:percent",
        native_unit_of_measurement=PERCENTAGE,
        entity_category=EntityCategory.DIAGNOSTIC,
        state_class=SensorStateClass.MEASUREMENT,
        value_fn=lambda data: (c := _find_consumable(data, "roller", "brush")) and c.get("percent_left"),
        available_fn=lambda data: (c := _find_consumable(data, "roller", "brush")) is not None and c.get("percent_left") is not None,
        enabled_default=True,
    ),
    AiperSensorEntityDescription(
        key="roller_brush_last_replacement",
        name="Roller Brush Last Replacement",
        device_class=SensorDeviceClass.TIMESTAMP,
        entity_category=EntityCategory.DIAGNOSTIC,
        value_fn=lambda data: (c := _find_consumable(data, "roller", "brush")) and c.get("last_replacement"),
        available_fn=lambda data: (c := _find_consumable(data, "roller", "brush")) is not None and c.get("last_replacement") is not None,
        enabled_default=False,
    ),
    AiperSensorEntityDescription(
        key="micromesh_remaining",
        name="MicroMesh Filter Remaining",
        icon="mdi:timer-sand",
        native_unit_of_measurement="h",
        entity_category=EntityCategory.DIAGNOSTIC,
        value_fn=lambda data: (c := _find_consumable(data, "micromesh")) and c.get("remaining_hours"),
        available_fn=lambda data: (c := _find_consumable(data, "micromesh")) is not None and c.get("remaining_hours") is not None,
        enabled_default=True,
    ),
    AiperSensorEntityDescription(
        key="micromesh_percent",
        name="MicroMesh Filter Remaining %",
        icon="mdi:percent",
        native_unit_of_measurement=PERCENTAGE,
        entity_category=EntityCategory.DIAGNOSTIC,
        state_class=SensorStateClass.MEASUREMENT,
        value_fn=lambda data: (c := _find_consumable(data, "micromesh")) and c.get("percent_left"),
        available_fn=lambda data: (c := _find_consumable(data, "micromesh")) is not None and c.get("percent_left") is not None,
        enabled_default=True,
    ),
    AiperSensorEntityDescription(
        key="micromesh_last_replacement",
        name="MicroMesh Filter Last Replacement",
        device_class=SensorDeviceClass.TIMESTAMP,
        entity_category=EntityCategory.DIAGNOSTIC,
        value_fn=lambda data: (c := _find_consumable(data, "micromesh")) and c.get("last_replacement"),
        available_fn=lambda data: (c := _find_consumable(data, "micromesh")) is not None and c.get("last_replacement") is not None,
        enabled_default=False,
    ),
    AiperSensorEntityDescription(
        key="tread_remaining",
        name="Caterpillar Tread Remaining",
        icon="mdi:timer-sand",
        native_unit_of_measurement="h",
        entity_category=EntityCategory.DIAGNOSTIC,
        value_fn=lambda data: (c := _find_consumable(data, "caterpillar")) and c.get("remaining_hours"),
        available_fn=lambda data: (c := _find_consumable(data, "caterpillar")) is not None and c.get("remaining_hours") is not None,
        enabled_default=True,
    ),
    AiperSensorEntityDescription(
        key="tread_percent",
        name="Caterpillar Tread Remaining %",
        icon="mdi:percent",
        native_unit_of_measurement=PERCENTAGE,
        entity_category=EntityCategory.DIAGNOSTIC,
        state_class=SensorStateClass.MEASUREMENT,
        value_fn=lambda data: (c := _find_consumable(data, "caterpillar")) and c.get("percent_left"),
        available_fn=lambda data: (c := _find_consumable(data, "caterpillar")) is not None and c.get("percent_left") is not None,
        enabled_default=True,
    ),
    AiperSensorEntityDescription(
        key="tread_last_replacement",
        name="Caterpillar Tread Last Replacement",
        device_class=SensorDeviceClass.TIMESTAMP,
        entity_category=EntityCategory.DIAGNOSTIC,
        value_fn=lambda data: (c := _find_consumable(data, "caterpillar")) and c.get("last_replacement"),
        available_fn=lambda data: (c := _find_consumable(data, "caterpillar")) is not None and c.get("last_replacement") is not None,
        enabled_default=False,
    ),
)


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Set up Aiper sensors based on a config entry."""
    coordinator: AiperDataUpdateCoordinator = hass.data[DOMAIN][entry.entry_id]["coordinator"]

    entities: list[AiperSensor] = []

    if coordinator.data:
        for sn, device_data in coordinator.data.items():
            for description in SENSOR_DESCRIPTIONS:
                entities.append(
                    AiperSensor(
                        coordinator=coordinator,
                        description=description,
                        sn=sn,
                        device_data=device_data,
                    )
                )

    async_add_entities(entities)


class AiperSensor(CoordinatorEntity[AiperDataUpdateCoordinator], SensorEntity):
    """Representation of an Aiper sensor."""

    entity_description: AiperSensorEntityDescription
    _attr_has_entity_name = True

    def __init__(
        self,
        coordinator: AiperDataUpdateCoordinator,
        description: AiperSensorEntityDescription,
        sn: str,
        device_data: dict,
    ) -> None:
        """Initialize the sensor."""
        super().__init__(coordinator)
        self.entity_description = description
        self._sn = sn
        self._attr_unique_id = f"{sn}_{description.key}"
        self._attr_entity_registry_enabled_default = description.enabled_default
        self._attr_entity_registry_enabled_default = bool(description.enabled_default)
        
        # Device info
        model = device_data.get("model", device_data.get("modelName", "Aiper Pool Cleaner"))
        self._attr_device_info = DeviceInfo(
            identifiers={(DOMAIN, sn)},
            name=device_data.get("name", f"Aiper {sn}"),
            manufacturer="Aiper",
            model=model,
            serial_number=sn,
            sw_version=(
                device_data.get("_ha_fw_main")
                or device_data.get("firmwareVersion")
                or (device_data.get("info") or {}).get("mainVersion")
            ),
        )

    @property
    def native_value(self) -> Any:
        """Return the state of the sensor."""
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
