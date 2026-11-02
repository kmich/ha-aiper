"""Read-only entity states from Scuba V3 Ultra ``*Report`` shadow sections.

The Scuba V3 Ultra (main firmware V1.1.16.4) reports its settings and
telemetry as ``*Report`` sections in its AWS IoT shadow. The live machine
fields (status, battery, in-water, temperature, alarms) are mapped by
``coordinator_parsing._machine_from_reports``; this module maps the remaining
sections onto their own entity keys. Field shapes come from captured
payloads. Where the meaning of a raw code is not known, the raw value is
exposed unchanged rather than guessed.
"""

from __future__ import annotations

from datetime import date, datetime, time, timedelta, tzinfo
from typing import Any

from .state import EntityState
from .state_common import _coerce_bool, _coerce_float, _coerce_int

__all__ = [
    "next_scheduled_clean",
    "report_entity_states",
]

# ``AutomationTaskReport.autoTasks[].weekday`` counts from Sunday: captured
# tasks dated 2026-10-27 (a Tuesday), 2026-10-29 and 2026-10-31 carry
# weekday 2, 4 and 6.
_WEEKDAY_NAMES = ("Sunday", "Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday")

# Single-value ``{"mode": n}`` sections exposed as raw codes.
_MODE_SECTIONS = {
    "SuperEcoReport": "eco_mode",
    "WaterGoverReport": "water_gover_mode",
    "BottomRunModeReport": "bottom_run_mode",
    "LittleWaterReport": "little_water_mode",
    "MultiBottomReport": "multi_bottom_mode",
}

# Multi-field settings sections: the state is a compact "key=value" summary
# and every field is an attribute.
_SETTINGS_SECTIONS = {
    "SurfaceWaterReport": "surface_water_settings",
    "AirBagReport": "airbag_settings",
    "SpeedReport": "speed_settings",
    "MotorThresholdReport": "motor_thresholds",
}

# ``OtaResultReport`` sub-board firmware components.
_FIRMWARE_COMPONENTS = ("base", "computing", "led", "power")

# ``AutomationTaskSettingReport`` flags.
_SCHEDULE_FLAGS = {"weather": "schedule_weather", "adapt": "schedule_adapt", "habit": "schedule_habit"}


def _section(payload: dict[str, Any], key: str) -> dict[str, Any] | None:
    value = payload.get(key)
    return value if isinstance(value, dict) else None


def _summary(section: dict[str, Any]) -> str | None:
    parts = [f"{key}={value}" for key, value in section.items() if not isinstance(value, (dict, list))]
    return ", ".join(parts)[:255] if parts else None


def _schedule_entry(task: dict[str, Any]) -> dict[str, Any]:
    weekday = _coerce_int(task.get("weekday"))
    return {
        "date": task.get("date"),
        "start_time": task.get("startTime"),
        "weekday": weekday,
        "weekday_name": _WEEKDAY_NAMES[weekday] if weekday is not None and 0 <= weekday < 7 else None,
        "clean_mode": task.get("cleanMode"),
        "clean_intensity": task.get("cleanIntensity"),
        "water_gover": task.get("waterGover"),
        "clean_areas": task.get("cleanAreas"),
        "user_select": task.get("userSelect"),
    }


def _occurrence(entry: dict[str, Any], now: datetime, tz: tzinfo) -> datetime | None:
    """Return the first start of ``entry`` at or after ``now``.

    The task's ``date`` is its next run as of the report. Past dates roll
    forward a week at a time (the app's automation schedule repeats weekly);
    without a usable date the next matching ``weekday`` is used.
    """
    try:
        clock = time.fromisoformat(str(entry.get("start_time") or "").strip())
    except ValueError:
        return None
    local_now = now.astimezone(tz)
    try:
        day = date.fromisoformat(str(entry.get("date") or "").strip())
    except ValueError:
        weekday = entry.get("weekday")
        if not isinstance(weekday, int) or not 0 <= weekday < 7:
            return None
        # Python's weekday() counts from Monday; the report counts from Sunday.
        day = local_now.date() + timedelta(days=(weekday - (local_now.weekday() + 1) % 7) % 7)
    start = datetime.combine(day, clock, tzinfo=tz)
    while start < local_now:
        start += timedelta(days=7)
    return start


def next_scheduled_clean(
    schedule: list[dict[str, Any]], now: datetime, tz: tzinfo
) -> tuple[datetime | None, dict[str, Any] | None]:
    """Return the next scheduled start and its schedule entry, or ``(None, None)``."""
    best: tuple[datetime, dict[str, Any]] | None = None
    for entry in schedule:
        start = _occurrence(entry, now, tz)
        if start is not None and (best is None or start < best[0]):
            best = (start, entry)
    return best if best is not None else (None, None)


def _schedule_state(report: dict[str, Any], now: datetime, tz: tzinfo) -> EntityState | None:
    tasks = report.get("autoTasks")
    if not isinstance(tasks, list):
        return None
    schedule = [_schedule_entry(task) for task in tasks if isinstance(task, dict)]
    start, _entry = next_scheduled_clean(schedule, now, tz)
    return EntityState(start, {"schedule": schedule})


def report_entity_states(payload: dict[str, Any], now: datetime, tz: tzinfo) -> dict[str, EntityState]:
    """Map the non-machine ``*Report`` sections of one shadow payload to entity states."""
    states: dict[str, EntityState] = {}

    schedule = _section(payload, "AutomationTaskReport")
    if schedule is not None and (schedule_state := _schedule_state(schedule, now, tz)) is not None:
        states["next_scheduled_clean"] = schedule_state

    if (settings := _section(payload, "AutomationTaskSettingReport")) is not None:
        for field, key in _SCHEDULE_FLAGS.items():
            if field in settings:
                states[key] = EntityState(_coerce_bool(settings.get(field)))

    if (life := _section(payload, "LifeTimeReport")) is not None and life.get("battery") is not None:
        states["battery_health"] = EntityState(_coerce_int(life.get("battery")))

    if (op_info := _section(payload, "OpInfoReport")) is not None:
        millivolts = _coerce_float(op_info.get("batVoltage"))
        milliamps = _coerce_float(op_info.get("batCurrent"))
        if millivolts is not None:
            states["battery_voltage"] = EntityState(round(millivolts / 1000.0, 3))
        if milliamps is not None:
            states["battery_current"] = EntityState(milliamps)
        if millivolts is not None and milliamps is not None:
            states["battery_power"] = EntityState(round(millivolts * milliamps / 1_000_000.0, 2))
        if op_info.get("batTemperature") is not None:
            states["battery_temperature"] = EntityState(_coerce_float(op_info.get("batTemperature")))

    if (basket := _section(payload, "GetRubbishBoxStatusReport")) is not None:
        raw = {"blockage": basket.get("blockage"), "in_place": basket.get("inPlace"), "health": basket.get("health")}
        if basket.get("blockage") is not None:
            states["debris_basket_blocked"] = EntityState(_coerce_bool(basket.get("blockage")), raw)
        if basket.get("inPlace") is not None:
            states["debris_basket_in_place"] = EntityState(_coerce_bool(basket.get("inPlace")), raw)
        if basket.get("health") is not None:
            states["debris_basket_health"] = EntityState(_coerce_int(basket.get("health")), raw)

    if (estimate := _section(payload, "TaskEstimateReport")) is not None:
        times = estimate.get("cleanTime")
        areas = estimate.get("cleanArea")
        if isinstance(times, list):
            states["cleaning_estimates"] = EntityState(
                ", ".join(str(value) for value in times)[:255] or None,
                {"clean_time": list(times), "clean_area": list(areas) if isinstance(areas, list) else None},
            )

    if (finish := _section(payload, "FinishTaskReport")) is not None:
        task = finish.get("task")
        if isinstance(task, dict) and task.get("cleanResult") is not None:
            name_id = task.get("nameID")
            states["last_cleaning_result"] = EntityState(
                _coerce_int(task.get("cleanResult")),
                {
                    "task_kind": name_id.split("_", 1)[0].capitalize() if isinstance(name_id, str) else None,
                    "task_type": task.get("taskType"),
                    "clean_mode": task.get("cleanMode"),
                    "clean_intensity": task.get("cleanIntensity"),
                    "clean_areas": task.get("cleanAreas"),
                },
            )

    if (ota_result := _section(payload, "OtaResultReport")) is not None:
        for component in _FIRMWARE_COMPONENTS:
            part = ota_result.get(component)
            if isinstance(part, dict) and part.get("version") is not None:
                states[f"{component}_version"] = EntityState(str(part["version"]), {"state": part.get("state")})

    if (ota_status := _section(payload, "OtaStatusReport")) is not None:
        if ota_status.get("version") is not None:
            states["main_version"] = EntityState(ota_status.get("version"))
        message = ota_status.get("msg")
        if isinstance(message, str) and message.strip():
            states["ota_state"] = EntityState(
                message.strip(),
                {
                    "state": ota_status.get("state"),
                    "progress": ota_status.get("progress"),
                    "error": ota_status.get("error"),
                },
            )

    if (voice := _section(payload, "VoiceBroadcastReport")) is not None and voice.get("volume") is not None:
        states["voice_volume"] = EntityState(
            _coerce_int(voice.get("volume")),
            {
                "enabled": _coerce_bool(voice.get("enable")),
                "language": voice.get("language"),
                "timbre": voice.get("timbre"),
            },
        )

    if (inspection := _section(payload, "InspectionSettingReport")) is not None and "camera" in inspection:
        states["camera"] = EntityState(_coerce_bool(inspection.get("camera")))

    if (airbag := _section(payload, "AirBagStatusReport")) is not None and airbag.get("status") is not None:
        states["airbag_status"] = EntityState(_coerce_int(airbag.get("status")))

    for section_key, key in _MODE_SECTIONS.items():
        section = _section(payload, section_key)
        if section is not None and section.get("mode") is not None:
            states[key] = EntityState(_coerce_int(section.get("mode")))

    for section_key, key in _SETTINGS_SECTIONS.items():
        section = _section(payload, section_key)
        if section is not None and (summary := _summary(section)) is not None:
            states[key] = EntityState(summary, dict(section))

    return states
