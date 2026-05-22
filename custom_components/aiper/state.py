"""Device-state normalization helpers for Aiper payloads."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .const import CLEAN_PATH_MAP, Status, mode_label, status_label, status_running, status_value
from .device_images import device_model_image_url
from .profiles import Capability, derive_device_profile


@dataclass(frozen=True)
class EntityState:
    """Normalized state value plus Home Assistant entity attributes."""

    value: Any
    attributes: dict[str, Any] = field(default_factory=dict)


# Raw REST/cache payload assembled by the coordinator before translation.
RawDeviceData = dict[str, Any]
# Normalized Home Assistant-facing entity states for one device, keyed by entity key.
DeviceState = dict[str, EntityState]
# Data exposed by AiperDataUpdateCoordinator.data, keyed first by device serial number.
DevicesState = dict[str, DeviceState]


def _coerce_bool(value: Any) -> bool | None:
    """Coerce common Aiper 0/1/bool/string values into a boolean."""
    if value is None:
        return None
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        if value == 1:
            return True
        if value == 0:
            return False
        return bool(value)
    if isinstance(value, str):
        text = value.strip().lower()
        if text in ("1", "true", "on", "online", "connected"):
            return True
        if text in ("0", "false", "off", "offline", "disconnected"):
            return False
        try:
            return bool(int(text))
        except ValueError:
            return None
    return bool(value)


def _coerce_int(value: Any) -> int | None:
    """Coerce common numeric payload values into an int."""
    if isinstance(value, bool) or value is None:
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        return int(value)
    if isinstance(value, str) and value.strip().lstrip("-").isdigit():
        return int(value.strip())
    return None


def _centihours_to_hours(value: Any) -> float | None:
    if isinstance(value, bool) or value is None:
        return None
    if isinstance(value, int):
        return round(value / 100.0, 2)
    if isinstance(value, float) and value.is_integer():
        return round(value / 100.0, 2)
    if isinstance(value, str):
        stripped = value.strip()
        if stripped.lstrip("-").isdigit():
            return round(int(stripped) / 100.0, 2)
    return None


def _hours(value: Any) -> float | None:
    if isinstance(value, bool) or value is None:
        return None
    if isinstance(value, (int, float)):
        return round(float(value), 2)
    if isinstance(value, str):
        try:
            return round(float(value.strip()), 2)
        except ValueError:
            return None
    return None


def _mode_text(device: dict[str, Any], mode: int | None) -> str | None:
    if mode is None:
        return None
    raw_mode_map = device.get("mode_map")
    mode_map: dict[Any, Any] = raw_mode_map if isinstance(raw_mode_map, dict) else {}
    if not mode_map:
        mode_map = derive_device_profile(device).mode_map
    if mode not in mode_map and _has_running_control(device):
        mode_map = {**{0: "Off", 1: "Manual", 5: "Scheduled"}, **mode_map}
    return str(mode_map.get(mode) or mode_label(mode))


def _clean_path_text(value: Any) -> str | None:
    if value is None:
        return None
    value_id = _coerce_int(value)
    if value_id is not None:
        return CLEAN_PATH_MAP.get(value_id, str(value_id))
    return str(value)


def _state_value(state: DeviceState | None, key: str) -> Any:
    if not state:
        return None
    entity = state.get(key)
    return entity.value if entity else None


def merge_device_state(current: DeviceState | None, updates: DeviceState, *, ignore_none: bool = False) -> DeviceState:
    """Merge normalized entity updates into existing device state."""
    merged = dict(current or {})
    for key, value in updates.items():
        if ignore_none and value.value is None and not value.attributes:
            continue
        merged[key] = value
    return merged


def _normalize_warn_code(code: Any) -> str | None:
    if code is None or isinstance(code, (list, tuple, set)):
        return None
    try:
        if isinstance(code, (int, float)):
            code_id = int(code)
            return f"e{code_id}".lower() if code_id > 0 else None

        text = str(code).strip()
        if not text:
            return None
        if text.isdigit():
            code_id = int(text)
            return f"e{code_id}".lower() if code_id > 0 else None
        if text[0] in ("e", "E") and len(text) > 1:
            number = "".join(ch for ch in text[1:] if ch.isdigit())
            if number:
                return f"e{int(number)}".lower()
        return text.lower()
    except Exception:
        return None


def _collect_warning_codes(machine: dict[str, Any]) -> list[str]:
    codes: list[str] = []
    for key in (
        "warn_codes",
        "warnCodeList",
        "warning_codes",
        "warningCodes",
        "error_codes",
        "errorCodes",
    ):
        value = machine.get(key)
        if isinstance(value, (list, tuple, set)):
            for item in value:
                code = _normalize_warn_code(item)
                if code and code not in codes:
                    codes.append(code)
    for key in (
        "warn_code",
        "warnCode",
        "warning_code",
        "warningCode",
        "error_code",
        "errorCode",
    ):
        code = _normalize_warn_code(machine.get(key))
        if code and code not in codes:
            codes.append(code)
    return codes


def _warning_text(machine: dict[str, Any], online: bool | None) -> str:
    if online is False:
        return "No active warnings"
    warn = _coerce_bool(machine.get("warn"))
    codes = _collect_warning_codes(machine)
    if warn is True:
        return ", ".join(codes) if codes else "Active"
    if codes:
        return ", ".join(codes)
    return "No active warnings"


def _online_value(current: DeviceState | None) -> bool | None:
    online = _state_value(current, "online")
    return online if isinstance(online, bool) else None


def _ota_state_text(ota: dict[str, Any]) -> str | None:
    for key in ("state", "status", "otaState", "ota_status"):
        value = ota.get(key)
        if value is None:
            continue
        state_id = _coerce_int(value)
        if state_id == 0:
            return "Idle"
        if state_id == 1:
            return "Downloading"
        if state_id == 2:
            return "Installing"
        if state_id == 3:
            return "Rebooting"
        return str(value)
    return None


def supported_mode_ids_from_payload(payload: dict[str, Any]) -> list[int]:
    """Return deduplicated mode IDs from a typed mode-list payload."""
    supported_ids: list[int] = []
    mode_list = payload.get("modeList")
    if mode_list is None:
        return []

    values = mode_list if isinstance(mode_list, list) else (mode_list,)
    for value in values:
        if isinstance(value, (int, float)):
            supported_ids.append(int(value))
        elif isinstance(value, dict):
            mode_value = value.get("mode")
            if mode_value is not None:
                coerced = _coerce_int(mode_value)
                if coerced is not None:
                    supported_ids.append(coerced)
        else:
            coerced = _coerce_int(value)
            if coerced is not None:
                supported_ids.append(coerced)

    seen: set[int] = set()
    deduped: list[int] = []
    for mode_id in supported_ids:
        if mode_id in seen:
            continue
        seen.add(mode_id)
        deduped.append(mode_id)
    return deduped


def normalize_machine_update(
    rest: RawDeviceData, mqtt: dict[str, Any], current: DeviceState | None = None
) -> DeviceState:
    """Translate one MQTT Machine payload into normalized entity updates."""
    updates: DeviceState = {}
    running_control = _has_running_control(rest)
    online = _online_value(current)

    raw_status = _coerce_int(mqtt.get("status"))
    running = None
    if raw_status is not None:
        running = status_running(raw_status)
        status_code = status_value(raw_status)
        if running_control and not running:
            status_code = int(Status.IDLE)
        updates["running"] = EntityState(running)
        updates["status"] = EntityState(status_label(status_code), {"code": status_code})

    if mqtt.get("mode") is not None or (running_control and running is False):
        mode_code = _coerce_int(mqtt.get("mode"))
        if running_control and running is False:
            mode_code = 0
        updates["mode"] = EntityState(
            _mode_text(rest, mode_code),
            {"code": mode_code} if mode_code is not None else {},
        )

    if mqtt.get("cap") is not None:
        updates["battery"] = EntityState(mqtt.get("cap"))
    if mqtt.get("temp") is not None:
        updates["temperature"] = EntityState(mqtt.get("temp"))
    if mqtt.get("run_time") is not None:
        updates["runtime"] = EntityState(_centihours_to_hours(mqtt.get("run_time")))
    if mqtt.get("in_water") is not None:
        updates["in_water"] = EntityState(bool(mqtt.get("in_water")))
    if mqtt.get("solar_status") is not None:
        updates["solar_charging"] = EntityState(mqtt.get("solar_status") == 1)
    if mqtt.get("link") is not None:
        updates["linked"] = EntityState(online and mqtt.get("link") == 1)
    if mqtt.get("cleanPath") is not None:
        clean_path = mqtt.get("cleanPath")
        clean_path_code = _coerce_int(clean_path)
        updates["clean_path"] = EntityState(
            _clean_path_text(clean_path),
            {"code": clean_path_code} if clean_path_code is not None else {},
        )
    if any(key in mqtt for key in ("warn", "warn_code", "warnCode", "warn_codes", "warnCodeList")):
        updates["warning"] = EntityState(_warning_text(mqtt, online))

    return updates


def normalize_netstat_update(netstat: dict[str, Any]) -> DeviceState:
    """Translate one MQTT NetStat payload into normalized entity updates."""
    updates: DeviceState = {}
    online = _coerce_bool(netstat.get("online")) if "online" in netstat else None
    if online is not None:
        updates["online"] = EntityState(online)

    if online is False:
        updates["wifi"] = EntityState(False)
        updates["bluetooth"] = EntityState(False)
        updates["linked"] = EntityState(False)
        updates["wifi_signal"] = EntityState(None)
        return updates

    if netstat.get("sta") is not None:
        updates["wifi"] = EntityState(netstat.get("sta") in (1, 2, "1", "2"))
    if netstat.get("ble") is not None:
        updates["bluetooth"] = EntityState(netstat.get("ble") in (1, "1", True))
    if netstat.get("nearFieldBind") is not None:
        updates["linked"] = EntityState(netstat.get("nearFieldBind") in (1, "1", True))
    return updates


def normalize_opinfo_update(opinfo: dict[str, Any], current: DeviceState | None = None) -> DeviceState:
    """Translate one MQTT OpInfo payload into normalized entity updates."""
    updates: DeviceState = {}
    online = _online_value(current)
    if online is False:
        return updates
    if opinfo.get("wifi_name") or opinfo.get("wifi_rssi") is not None:
        updates["wifi"] = EntityState(True)
    if opinfo.get("wifi_rssi") is not None:
        updates["wifi_signal"] = EntityState(opinfo.get("wifi_rssi"))
    return updates


def normalize_ota_update(ota: dict[str, Any]) -> DeviceState:
    """Translate one MQTT OtaStatus payload into normalized entity updates."""
    updates: DeviceState = {}
    if ota.get("version") is not None:
        updates["main_version"] = EntityState(ota.get("version"))
    if ota.get("subver") is not None:
        updates["mcu_version"] = EntityState(ota.get("subver"))
    if any(key in ota for key in ("state", "status", "otaState", "ota_status")):
        updates["ota_state"] = EntityState(_ota_state_text(ota))
    return updates


def normalize_mode_options_update(raw: RawDeviceData, payload: dict[str, Any]) -> DeviceState:
    """Translate one mode-options payload into normalized entity updates."""
    supported_ids = supported_mode_ids_from_payload(payload)
    if not supported_ids:
        return {}
    mode_map = raw.get("mode_map") if isinstance(raw.get("mode_map"), dict) else {}
    return {"mode_options": EntityState(supported_ids, {"mode_map": mode_map})}


def normalize_clean_path_update(payload: dict[str, Any]) -> DeviceState:
    """Translate a clean-path-bearing payload into normalized entity updates."""
    clean_path = payload.get("cleanPath")
    clean_path_code = _coerce_int(clean_path)
    if clean_path_code is None:
        return {}
    return {
        "clean_path": EntityState(
            _clean_path_text(clean_path),
            {"code": clean_path_code},
        )
    }


def _find_consumable(device: dict[str, Any], *keywords: str) -> dict[str, Any] | None:
    items = device.get("consumables") or []
    if not isinstance(items, list):
        return None
    wanted = [keyword.strip().lower() for keyword in keywords if keyword]
    for item in items:
        if not isinstance(item, dict):
            continue
        name = str(item.get("name") or item.get("key") or "").lower()
        if all(keyword in name for keyword in wanted):
            return item
    return None


def _consumable_attrs(consumable: dict[str, Any] | None) -> dict[str, Any]:
    if not consumable:
        return {}
    attrs: dict[str, Any] = {}
    if consumable.get("key") is not None:
        attrs["consumable_key"] = consumable.get("key")
    if consumable.get("name") is not None:
        attrs["consumable_name"] = consumable.get("name")
    if consumable.get("remaining_hours") is not None:
        attrs["remaining_hours"] = consumable.get("remaining_hours")
    if consumable.get("last_replacement") is not None:
        attrs["last_replacement"] = consumable.get("last_replacement")
    return attrs


def _normalize_consumable(states: DeviceState, device: RawDeviceData, key: str, *keywords: str) -> None:
    consumable = _find_consumable(device, *keywords)
    states[key] = EntityState(
        consumable.get("percent_left") if consumable else None,
        _consumable_attrs(consumable),
    )


def _normalize_identity(states: DeviceState, device: RawDeviceData) -> None:
    sn = device.get("sn")
    fallback_name = f"Aiper {sn}" if sn else "Aiper Pool Cleaner"
    profile_family = device.get("profile_family")
    if profile_family is None:
        profile_family = derive_device_profile(device).family.value
    model = str(device.get("model") or "Aiper Pool Cleaner")
    name = str(device.get("name") or fallback_name)
    sw_version = device.get("fw_main")
    capabilities = list(device.get("capabilities") or [])
    mode_map = device.get("mode_map") if isinstance(device.get("mode_map"), dict) else {}
    supported_mode_ids = device.get("supported_mode_ids")
    if not isinstance(supported_mode_ids, list):
        supported_mode_ids = []

    states["device_info"] = EntityState(
        name,
        {
            "name": name,
            "model": model,
            "sw_version": sw_version,
            "entity_picture": device_model_image_url(device),
        },
    )
    states["device_family"] = EntityState(profile_family, {"capabilities": capabilities})
    states["capabilities"] = EntityState(capabilities)
    states["mode_options"] = EntityState(supported_mode_ids, {"mode_map": mode_map})
    states["entity_picture"] = EntityState(device_model_image_url(device))


def _has_running_control(device: RawDeviceData) -> bool:
    if "capabilities" in device:
        return Capability.RUNNING_CONTROL.value in (device.get("capabilities") or [])
    return Capability.RUNNING_CONTROL in derive_device_profile(device).capabilities


def state_has_capability(device: DeviceState, capability: Capability | str) -> bool:
    """Return whether a normalized entity-state map advertises a capability."""
    value = capability.value if isinstance(capability, Capability) else str(capability)
    capabilities_state = device.get("capabilities")
    capabilities = capabilities_state.value if capabilities_state else None
    return isinstance(capabilities, list) and value in capabilities


def normalize_device_state(raw: RawDeviceData) -> DeviceState:
    """Translate raw REST/cache payloads into Home Assistant-facing entity states.

    Aiper's Machine.status carries the operational status in the lower 7 bits.
    Some Surfer payloads keep the high bit set after stopping, so running is
    derived from the base status rather than from the high bit alone.
    """
    state: DeviceState = {}
    _normalize_identity(state, raw)
    running_control = _has_running_control(raw)

    online = _coerce_bool(raw.get("online"))
    state["online"] = EntityState(online)

    raw_status = _coerce_int(raw.get("machineStatus"))

    if raw_status is not None:
        running = status_running(raw_status)
        status_code = status_value(raw_status)
        if running_control and not running:
            status_code = int(Status.IDLE)
    else:
        running = None
        status_code = None
    state["running"] = EntityState(running)

    if online is False:
        status_text = "Offline"
    elif status_code is not None:
        status_text = status_label(status_code)
    else:
        status_text = "Idle"
    state["status"] = EntityState(
        status_text,
        {"code": status_code} if status_code is not None else {},
    )

    mode_code = _coerce_int(raw.get("mode"))

    if running_control and running is False:
        mode_code = 0

    state["mode"] = EntityState(
        _mode_text(raw, mode_code),
        {"code": mode_code} if mode_code is not None else {},
    )

    state["battery"] = EntityState(raw.get("battLevel"))
    state["temperature"] = EntityState(raw.get("temp"))
    runtime = _centihours_to_hours(raw.get("runTime"))
    state["runtime"] = EntityState(runtime)

    state["in_water"] = EntityState(_coerce_bool(raw.get("in_water")))

    state["solar_charging"] = EntityState(None)

    wifi: bool | None
    bluetooth: bool | None
    linked: bool | None
    if online is False:
        wifi = False
        bluetooth = False
        linked = False
    else:
        wifi_connected = (
            bool(raw.get("wifiName")) or raw.get("wifiRssi") is not None or raw.get("sta") in (1, 2, "1", "2")
        )
        wifi = wifi_connected if wifi_connected or raw.get("sta") is not None else None
        ble = raw.get("ble")
        bluetooth = (ble in (1, "1", True)) if ble is not None else None
        near_field_bind = raw.get("nearFieldBind")
        linked = (near_field_bind in (1, "1", True)) if near_field_bind is not None else None
    state["wifi"] = EntityState(wifi)
    state["bluetooth"] = EntityState(bluetooth)
    state["linked"] = EntityState(linked)

    wifi_signal = raw.get("wifiRssi") if online and wifi else None
    state["wifi_signal"] = EntityState(wifi_signal)

    state["warning"] = EntityState(_warning_text(raw, online))

    state["main_version"] = EntityState(raw.get("fw_main"))
    state["mcu_version"] = EntityState(raw.get("fw_mcu"))
    state["ip_address"] = EntityState(raw.get("ip_address"))
    state["ap_hotspot"] = EntityState(raw.get("ap_hotspot"))
    state["bluetooth_name"] = EntityState(raw.get("bluetooth_name"))

    clean_path = raw.get("clean_path")
    state["clean_path"] = EntityState(
        _clean_path_text(clean_path),
        {"code": clean_path},
    )

    state["ota_state"] = EntityState(_ota_state_text(raw))

    _normalize_consumable(state, raw, "roller_brush", "roller", "brush")
    _normalize_consumable(state, raw, "micromesh_filter", "micromesh")
    _normalize_consumable(state, raw, "caterpillar_tread", "caterpillar")
    _normalize_consumable(state, raw, "propeller", "propeller")
    return state
