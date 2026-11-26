"""HydroComm / W2 water-quality monitor state normalization helpers."""

from __future__ import annotations

import contextlib
from datetime import datetime
from typing import Any

from .state_common import (
    DeviceState,
    EntityState,
    _coerce_float,
    _coerce_int,
    _state_attrs,
    _state_value,
)

HYDROCOMM_ALARM_MESSAGES = {
    1: "All probes uninstalled",
    2: "Probe repeat install",
    4: "Probe installed but no data",
    8: "Probe not fully installed",
    16: "Sensor 1 damaged",
    32: "Sensor 2 damaged",
    64: "Sensor 3 damaged",
    128: "Temperature constant value",
    256: "pH constant value",
    512: "ORP constant value",
    1024: "EC constant value",
    2048: "Chlorine constant value",
    4096: "Temperature out of range",
    8192: "Battery low",
}


def _hydrocomm_status_text(status: int | None) -> str | None:
    """Return a W2/HydroComm station status label from APK-observed states."""
    if status is None:
        return None
    if status == 0:
        return "Idle"
    if status == 1:
        return "Active"
    if status in (2, 3):
        return "Charging"
    if status == 4:
        return "Updating"
    if status == 5:
        return "Sleeping"
    if status == 7:
        return "Deep Sleep"
    return f"Status {status}"


def _charge_type_text(value: Any) -> str | None:
    """Return human-readable label for a HydroComm charge-type code."""
    charge_type = _coerce_int(value)
    if charge_type is None:
        return None
    if charge_type == 0:
        return "Not charging"
    if charge_type == 1:
        return "Charging"
    if charge_type == 2:
        return "Solar charging"
    return f"Charge type {charge_type}"


def _charging_value(status: int | None, charge_type: Any = None) -> bool | None:
    """Return normalized charging flag for HydroComm stations."""
    ctype = _coerce_int(charge_type)
    if status in (2, 3) or ctype in (1, 2):
        return True
    if status is not None or ctype is not None:
        return False
    return None


def _hydrocomm_alarm_codes(value: Any) -> list[int]:
    """Decode bitmask alarm flags from a W2AlarmMessage payload."""
    alarm = _coerce_int(value)
    if alarm is None or alarm <= 0:
        return []
    return [code for code in HYDROCOMM_ALARM_MESSAGES if alarm & code]


def _hydrocomm_warning_text(value: Any) -> str:
    """Format active W2/HydroComm alarms into a single summary string."""
    codes = _hydrocomm_alarm_codes(value)
    if not codes:
        return "No active warnings"
    return ", ".join(HYDROCOMM_ALARM_MESSAGES.get(code, f"Alarm {code}") for code in codes)


def _probe_status_text(value: Any) -> str | None:
    """Return probe installation status text for HydroComm sensors."""
    status = _coerce_int(value)
    if status is None:
        return None
    if status == 1:
        return "Installed"
    if status == 0:
        return "Not installed"
    return f"Status {status}"


def normalize_w2_info_update(w2_info: dict[str, Any]) -> DeviceState:
    """Translate one HydroComm W2Info payload into normalized entity updates."""
    updates: DeviceState = {}
    if w2_info.get("bal_cal") is not None:
        updates["battery"] = EntityState(_coerce_int(w2_info.get("bal_cal")))

    charge_type = w2_info.get("chargeType")
    if charge_type is not None:
        updates["charge_type"] = EntityState(
            _charge_type_text(charge_type),
            {"code": _coerce_int(charge_type)} if _coerce_int(charge_type) is not None else {},
        )
        updates["charging"] = EntityState(_charging_value(None, charge_type))
        updates["solar_charging"] = EntityState(_coerce_int(charge_type) == 2)

    for raw_key, state_key in (
        ("vcvol", "supply_voltage"),
        ("sunvol", "solar_voltage"),
        ("lux", "light_level"),
        ("workCur", "work_current"),
        ("chargeCur", "charge_current"),
    ):
        if w2_info.get(raw_key) is not None:
            updates[state_key] = EntityState(_coerce_int(w2_info.get(raw_key)))

    if w2_info.get("calStatus") is not None:
        status = _coerce_int(w2_info.get("calStatus"))
        updates["calibration_status"] = EntityState(
            "In progress" if status == 1 else "Idle",
            {"code": status} if status is not None else {},
        )

    return updates


def normalize_w2_wqs_update(w2_wqs: dict[str, Any]) -> DeviceState:
    """Translate one HydroComm W2WQS water-quality payload into sensor updates."""
    updates: DeviceState = {}
    if w2_wqs.get("result") is not None:
        result = _coerce_int(w2_wqs.get("result"))
        updates["water_quality_result"] = EntityState(
            "Ready" if result == 0 else f"Result {result}",
            {"code": result} if result is not None else {},
        )
        if result is not None and result != 0:
            return updates

    for raw_key, state_key in (
        ("temp", "temperature"),
        ("ph", "ph"),
        ("orp", "orp"),
        ("ec", "ec"),
        ("tds", "tds"),
        ("rcl", "rcl"),
        ("swpi", "water_quality_score"),
    ):
        if w2_wqs.get(raw_key) is not None:
            updates[state_key] = EntityState(_coerce_float(w2_wqs.get(raw_key)))

    if w2_wqs.get("manual") is not None:
        updates["water_quality_manual"] = EntityState(_coerce_int(w2_wqs.get("manual")) == 1)

    sampled_at = w2_wqs.get("time")
    if sampled_at is not None:
        for key in ("temperature", "ph", "orp", "ec", "tds", "rcl", "water_quality_score"):
            if key in updates:
                updates[key] = EntityState(updates[key].value, {"sample_time": sampled_at})
        sample_dt: datetime | None = None
        with contextlib.suppress(TypeError, ValueError):
            sample_dt = datetime.fromisoformat(sampled_at.replace("Z", "+00:00"))
        updates["wqs_sample_time"] = EntityState(sample_dt)

    return updates


def normalize_w2_sensor_status_update(
    sensor_status: dict[str, Any],
    current: DeviceState | None = None,
) -> DeviceState:
    """Translate one HydroComm W2SensorStatus payload into probe status updates."""
    updates: DeviceState = {}
    for raw_key, state_key in (
        ("sensor1", "probe_1_status"),
        ("sensor2", "probe_2_status"),
        ("sensor3", "probe_3_status"),
        ("ulsound", "ultrasonic_status"),
    ):
        if sensor_status.get(raw_key) is None:
            continue
        code = _coerce_int(sensor_status.get(raw_key))
        updates[state_key] = EntityState(
            _probe_status_text(code),
            {**_state_attrs(current, state_key), **({"code": code} if code is not None else {})},
        )
    return updates


def normalize_w2_lifetime_update(
    lifetime: dict[str, Any],
    current: DeviceState | None = None,
) -> DeviceState:
    """Translate one HydroComm W2LifeTime payload into probe attributes."""
    updates: DeviceState = {}
    for idx in (1, 2, 3):
        state_key = f"probe_{idx}_status"
        attrs = _state_attrs(current, state_key)
        for raw_key, attr_key in (
            (f"sn{idx}", "probe_serial"),
            (f"usetime{idx}", "usage_time"),
            (f"ctime{idx}", "calibration_time"),
        ):
            if lifetime.get(raw_key) is not None:
                attrs[attr_key] = lifetime.get(raw_key)
        if attrs:
            updates[state_key] = EntityState(_state_value(current, state_key), attrs)
    return updates


def normalize_w2_alarm_update(alarm: dict[str, Any]) -> DeviceState:
    """Translate one HydroComm W2AlarmMessage payload into warning state."""
    if alarm.get("Alarm") is None:
        return {}
    code = _coerce_int(alarm.get("Alarm"))
    attrs: dict[str, Any] = {}
    if code is not None:
        attrs["code"] = code
        attrs["codes"] = _hydrocomm_alarm_codes(code)
    if alarm.get("time") is not None:
        attrs["time"] = alarm.get("time")
    return {"warning": EntityState(_hydrocomm_warning_text(code), attrs)}
