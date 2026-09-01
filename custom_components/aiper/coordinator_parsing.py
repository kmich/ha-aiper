"""Pure payload-parsing and metadata-merge helpers for the coordinator.

These functions have no dependency on Home Assistant runtime state or the
coordinator instance. They are split out so the coordinator module stays focused
on orchestration and so parser behavior can be tested in isolation.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from homeassistant.util import dt as dt_util

from .const import CLEAN_PATH_LABEL_TO_VALUE, mode_label
from .state import RawDeviceData

__all__ = [
    "LIVE_STATE_KEYS",
    "_ensure_utc_aware",
    "_slugify",
    "_norm_key",
    "_merge_discovery_metadata",
    "_merge_static_metadata",
    "_parse_dt",
    "_clean_path_value",
    "_deep_get",
    "_number",
    "_parse_cleaning_history",
    "_parse_consumables",
]


# Keys whose values are owned by live MQTT/shadow state and must not be
# overwritten by slower REST discovery metadata.
LIVE_STATE_KEYS = frozenset(
    {
        "battLevel",
        "battery",
        "ble",
        "clean_path",
        "in_water",
        "last_seen",
        "link",
        "machineStatus",
        "mode",
        "nearFieldBind",
        "online",
        "runTime",
        "sta",
        "status",
        "temp",
        "warn",
        "warn_code",
        "warning",
        "wifiName",
        "wifiRssi",
    }
)


def _ensure_utc_aware(value: datetime | None) -> datetime | None:
    """Ensure a datetime is timezone-aware in UTC."""
    if value is None:
        return None
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


# Slower-changing data refresh intervals are configurable via options.


def _slugify(text: str) -> str:
    """Make a stable slug for entity keys."""
    out = []
    for ch in (text or "").strip().lower():
        if ch.isalnum():
            out.append(ch)
        elif out and out[-1] != "_":
            out.append("_")
    s = "".join(out).strip("_")
    return s or "unknown"


def _norm_key(key: str) -> str:
    """Normalize a key for fuzzy matching (case/underscore-insensitive)."""
    return "".join(ch for ch in (key or "").lower() if ch.isalnum())


def _merge_discovery_metadata(
    existing: RawDeviceData,
    discovered: RawDeviceData,
    *,
    include_live: bool = False,
) -> RawDeviceData:
    """Merge discovery metadata while preserving cached fields."""
    merged = dict(existing)
    for key, value in discovered.items():
        if value is None:
            continue
        if not include_live and key in LIVE_STATE_KEYS:
            continue
        merged[key] = value
    return merged


def _merge_static_metadata(existing: RawDeviceData, discovered: RawDeviceData) -> RawDeviceData:
    """Merge discovery metadata without overwriting MQTT-owned live state."""
    return _merge_discovery_metadata(existing, discovered, include_live=False)


def _parse_dt(value: Any) -> datetime | None:
    """Parse a datetime value coming from Aiper payloads."""
    if value is None:
        return None
    if isinstance(value, datetime):
        return _ensure_utc_aware(value)
    # Epoch seconds or milliseconds
    if isinstance(value, (int, float)):
        try:
            v = float(value)
            if v > 10_000_000_000:  # ms
                v = v / 1000.0
            return datetime.fromtimestamp(v, tz=UTC)
        except Exception:
            return None
    if isinstance(value, str):
        s = value.strip()
        if not s:
            return None
        # ISO8601 / HA parser
        try:
            dt = dt_util.parse_datetime(s)
            if dt:
                return _ensure_utc_aware(dt)
        except Exception:
            dt = None
        # Common app formats
        for fmt in (
            "%Y-%m-%d %H:%M:%S",
            "%Y-%m-%d %H:%M",
            "%m/%d/%Y %H:%M",
            "%m/%d/%Y %H:%M:%S",
            "%m/%d/%Y,%H:%M",
            "%m/%d/%Y,%H:%M:%S",
        ):
            try:
                return datetime.strptime(s, fmt).replace(tzinfo=UTC)
            except Exception:
                continue
    return None


def _clean_path_value(val: Any) -> int | None:
    """Normalize a clean-path value to a numeric ID.

    Observed payload variance:
      - integer 0/1 (app/server)
      - stringified integers "0"/"1"
      - labels like "S-shaped" / "Adaptive" (shadow/app report)
      - sentinel -1 (treat as default 0)
    """

    if val is None:
        return None

    try:
        if isinstance(val, int):
            return 0 if val == -1 else int(val)
        if isinstance(val, float):
            iv = int(val)
            return 0 if iv == -1 else iv
        if isinstance(val, str):
            s = val.strip()
            if not s:
                return None
            # Numeric strings.
            if s.lstrip("-").isdigit():
                iv = int(s)
                return 0 if iv == -1 else iv

            # Normalize common label variants.
            norm = " ".join(s.lower().replace("_", " ").replace("-", " ").split())
            for label, pid in CLEAN_PATH_LABEL_TO_VALUE.items():
                lnorm = " ".join(str(label).lower().replace("_", " ").replace("-", " ").split())
                if norm == lnorm:
                    return int(pid)

            # Heuristics for unknown firmware spellings.
            if "adaptive" in norm:
                return 1
            if "s" in norm and "shape" in norm:
                return 0
    except Exception:
        return None

    return None


def _deep_get(item: dict[str, Any], keys: tuple[str, ...]) -> Any:
    """Find a value by fuzzy key match in a nested dict/list payload."""
    wanted = {_norm_key(key) for key in keys}
    stack: list[Any] = [item]
    while stack:
        obj = stack.pop()
        if isinstance(obj, dict):
            for key, value in obj.items():
                if isinstance(key, str) and _norm_key(key) in wanted:
                    return value
                if isinstance(value, (dict, list)):
                    stack.append(value)
        elif isinstance(obj, list):
            stack.extend(value for value in obj if isinstance(value, (dict, list)))
    return None


def _number(value: Any) -> float | None:
    if value is None or isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, str):
        text = value.strip().lower()
        digits = "".join(ch for ch in text if ch.isdigit() or ch in ".-")
        if not digits or digits in {".", "-", "-."}:
            return None
        try:
            return float(digits)
        except ValueError:
            return None
    return None


def _parse_cleaning_history(raw: Any) -> tuple[int | None, float | None, list[dict[str, Any]]]:
    """Parse cleaning history/totals payloads from regional Aiper APIs."""
    root = raw if isinstance(raw, dict) else {}
    data = root.get("data") if isinstance(root.get("data"), (dict, list)) else raw

    rec_list: list[Any] = []
    if isinstance(data, list):
        rec_list = data
    elif isinstance(data, dict):
        for list_key in ("list", "records", "recordList", "history", "items"):
            if isinstance(data.get(list_key), list):
                rec_list = data[list_key]
                break
        if not rec_list:
            for container_key in ("data", "result", "page"):
                sub = data.get(container_key)
                if not isinstance(sub, dict):
                    continue
                for list_key in ("list", "records", "recordList", "history", "items"):
                    if isinstance(sub.get(list_key), list):
                        rec_list = sub[list_key]
                        break
                if rec_list:
                    break

    count_keys = (
        "totalNumberOfCleanings",
        "totalCleanCount",
        "totalCleanings",
        "totalNumber",
        "totalCount",
        "totalTimes",
        "totalCleanTimes",
        "totalRecords",
        "cleanCount",
        "cleanTimes",
        "total",
    )
    time_keys = (
        "totalCleaningTime",
        "totalCleanTime",
        "totalCleanHour",
        "totalCleanHours",
        "totalCleaningHours",
        "totalCleanMinute",
        "totalCleanMinutes",
        "totalCleaningMinutes",
        "totalCleanSeconds",
        "totalDuration",
        "totalCleaningDuration",
        "cleanTimeTotal",
        "totalWorkTime",
        "totalTime",
        "totalHours",
        "totalMinutes",
        "totalSeconds",
        "sumTime",
        "sumCleanTime",
    )

    def _walk(obj: Any) -> list[tuple[str, Any]]:
        pairs: list[tuple[str, Any]] = []
        if isinstance(obj, dict):
            for key, value in obj.items():
                if isinstance(key, str):
                    pairs.append((key, value))
                if isinstance(value, (dict, list)):
                    pairs.extend(_walk(value))
        elif isinstance(obj, list):
            for value in obj:
                if isinstance(value, (dict, list)):
                    pairs.extend(_walk(value))
        return pairs

    all_pairs = _walk(root)
    total_count: int | None = None
    for key in count_keys:
        value = next((value for found_key, value in all_pairs if _norm_key(found_key) == _norm_key(key)), None)
        num = _number(value)
        if num is not None and num >= 0:
            total_count = int(num)
            break

    def _hours_from_value(key: str, value: Any) -> float | None:
        num = _number(value)
        if num is None or num < 0:
            return None
        key_norm = _norm_key(key)
        value_text = str(value).strip().lower() if isinstance(value, str) else ""
        if "hour" in key_norm or "hour" in value_text or value_text.endswith("h"):
            return num
        if "second" in key_norm or "sec" in value_text or value_text.endswith("s"):
            return num / 3600.0
        if "minute" in key_norm or "min" in value_text:
            return num / 60.0
        return num / 60.0

    total_hours: float | None = None
    for key in time_keys:
        value = next((value for found_key, value in all_pairs if _norm_key(found_key) == _norm_key(key)), None)
        hours = _hours_from_value(key, value)
        if hours is not None:
            total_hours = round(hours, 3)
            break

    def _minutes_from_value(value: Any) -> float | None:
        num = _number(value)
        if num is None or num < 0:
            return None
        text = str(value).strip().lower() if isinstance(value, str) else ""
        if "hour" in text or text.endswith("h"):
            return num * 60.0
        if "sec" in text or text.endswith("s"):
            return num / 60.0
        if "min" in text:
            return num
        return num / 60.0 if num > 300 else num

    def _find_dt_any(item: dict[str, Any]) -> Any:
        for key in (
            "utcStartTimeStamp",
            "utcEndTimeStamp",
            "utcStartTime",
            "utcEndTime",
            "utcBeginTimeStamp",
            "utcBeginTime",
            "utcFinishTimeStamp",
            "utcFinishTime",
            "startTimeStamp",
            "endTimeStamp",
            "startTimestamp",
            "endTimestamp",
            "startTime",
            "cleanStartTime",
            "beginTime",
            "createTime",
            "cleanTime",
            "cleanDate",
            "recordTime",
            "dateTime",
            "start",
            "begin",
            "time",
        ):
            if item.get(key) is not None:
                return item.get(key)
        for _key, value in _walk(item):
            if isinstance(value, str):
                text = value.strip()
                if any(ch.isdigit() for ch in text) and (":" in text or "-" in text or "/" in text):
                    return value
            elif isinstance(value, (int, float)) and value > 1_000_000_000:
                return value
        return None

    # Duration key lookup table: (key, unit_hint). Keys with explicit unit hints in
    # their name (e.g. "cleanTimeMin") bypass the heuristic unit detection.
    _DURATION_KEY_UNITS: tuple[tuple[str, str | None], ...] = (
        ("cleanTimeMin", "min"),
        ("cleanTimeMinute", "min"),
        ("cleaningTimeMin", "min"),
        ("cleanTimeSec", "sec"),
        ("cleanTimeSecond", "sec"),
        ("cleanTimeHour", "hour"),
        ("cleanTimeHours", "hour"),
        ("duration", None),
        ("durationTime", None),
        ("cleanTime", None),
        ("cleaningTime", None),
        ("runTime", None),
        ("useTime", None),
        ("lastTime", None),
        ("timeUsed", None),
    )

    records: list[dict[str, Any]] = []
    for item in rec_list:
        if not isinstance(item, dict):
            continue
        mode_id = _deep_get(item, ("modeId", "mode_id", "cleanMode", "cleanType", "mode", "type"))
        mode_name = _deep_get(item, ("modeName", "cleanModeName", "mode_name", "name", "cleanTypeName"))
        mode_id_num = _number(mode_id)
        mode_id_int = int(mode_id_num) if mode_id_num is not None else None
        if mode_name is None and mode_id_int is not None:
            mode_name = mode_label(mode_id_int)
        if mode_name is None and mode_id is not None:
            mode_name = str(mode_id)

        duration_min: float | None = None
        for _dur_key, _unit_hint in _DURATION_KEY_UNITS:
            _dur_val = item.get(_dur_key)
            if _dur_val is None:
                _dur_val = _deep_get(item, (_dur_key,))
            if _dur_val is None:
                continue
            _num = _number(_dur_val)
            if _num is None or _num < 0:
                continue
            if _unit_hint == "min":
                duration_min = _num
            elif _unit_hint == "sec":
                duration_min = _num / 60.0
            elif _unit_hint == "hour":
                duration_min = _num * 60.0
            else:
                duration_min = _minutes_from_value(_dur_val)
            break
        records.append(
            {
                "mode_id": mode_id_int,
                "mode": str(mode_name or "Unknown"),
                "start": _parse_dt(_find_dt_any(item)),
                "duration_min": round(duration_min, 1) if duration_min is not None else None,
                "raw": item,
            }
        )

    records.sort(key=lambda record: record.get("start") or datetime.min.replace(tzinfo=UTC), reverse=True)

    if total_count is None and records:
        total_count = len(records)
    if total_hours is None:
        try:
            duration_sum = sum(
                float(record["duration_min"]) for record in records if record.get("duration_min") is not None
            )
        except Exception:
            duration_sum = 0.0
        if duration_sum > 0:
            total_hours = round(duration_sum / 60.0, 3)

    return total_count, total_hours, records


def _parse_consumables(raw: Any) -> list[dict[str, Any]]:
    """Normalize consumables payloads into a list."""
    data = raw.get("data") if isinstance(raw, dict) and "data" in raw else raw
    if isinstance(data, dict):
        for list_key in ("list", "consumables", "consumableList", "consumablesList", "items"):
            value = data.get(list_key)
            if isinstance(value, list):
                data = value
                break
            if isinstance(value, dict) and isinstance(value.get("list"), list):
                data = value.get("list")
                break

    if not isinstance(data, list):
        return []

    def _dynamic_value(item: dict[str, Any], *keys: str) -> Any:
        fields = item.get("dynamicsFields")
        wanted = {_norm_key(key) for key in keys}
        if isinstance(fields, list):
            for field in fields:
                if not isinstance(field, dict):
                    continue
                key = field.get("key")
                if isinstance(key, str) and _norm_key(key) in wanted:
                    return field.get("value")
        return None

    out: list[dict[str, Any]] = []
    for item in data:
        if not isinstance(item, dict):
            continue

        name = _deep_get(item, ("consumablesName", "consumableName", "name", "title", "consumable", "consumables"))
        if not name:
            name = _dynamic_value(item, "consumable_name", "consumablesName", "consumableName", "name")
        if not name:
            name = item.get("type") or item.get("consumableType") or "Consumable"
        name = str(name)

        remaining = _deep_get(
            item,
            (
                "componentReplaceRemainHour",
                "component_replace_remain_hour",
                "componentReplaceRemainHours",
                "componentReplaceRemainTime",
                "componentReplaceRemain",
                "componentReplacementRemainHour",
                "replaceRemainHour",
                "remainTime",
                "remaining",
                "remainingTime",
                "remain",
                "remain_time",
                "leftTime",
                "left_time",
                "timeLeft",
                "remainHours",
            ),
        )
        if remaining is None:
            remaining = _dynamic_value(item, "component_replace")
        remaining_hours = _number(remaining)

        if remaining_hours is None:
            for key, value in item.items():
                if not isinstance(key, str):
                    continue
                key_norm = _norm_key(key)
                if ("remain" in key_norm or "left" in key_norm) and ("hour" in key_norm or key_norm.endswith("h")):
                    remaining_hours = _number(value)
                    if remaining_hours is not None:
                        break

        percent_left = None
        used_percent = _number(_deep_get(item, ("usePercentage", "use_percent", "usedPercent", "used_percentage")))
        if used_percent is not None:
            percent_left = max(0.0, min(100.0, 100.0 - used_percent))

        if percent_left is None:
            percent = _number(
                _deep_get(
                    item,
                    (
                        "percent",
                        "remainPercent",
                        "remainingPercent",
                        "leftPercent",
                        "left_percent",
                        "remainPct",
                        "remain_rate",
                    ),
                )
            )
            if percent is not None:
                percent_left = max(0.0, min(100.0, percent))

        if percent_left is None and remaining_hours is not None:
            longest = _number(_deep_get(item, ("longestUseTime", "maxUseTime", "max_time", "longest_use_time")))
            if longest and longest > 0:
                percent_left = max(0.0, min(100.0, (remaining_hours / longest) * 100.0))

        last_val = _deep_get(
            item,
            (
                "componentReplaceLastTime",
                "componentReplaceLastTimestamp",
                "componentReplaceLastTimeStamp",
                "maintainLastChangeTime",
                "lastChangeTime",
                "lastReplacementTime",
                "lastReplaceTime",
                "lastReplace",
                "replaceTime",
                "lastReplacement",
                "last_replacement_time",
            ),
        )
        if last_val is None:
            last_val = _dynamic_value(item, "lastChangeTime")
        last_rep = _parse_dt(last_val)

        if last_rep is None:
            for key, value in item.items():
                if not isinstance(key, str):
                    continue
                key_norm = _norm_key(key)
                if (
                    "last" in key_norm
                    and "time" in key_norm
                    and not any(marker in key_norm for marker in ("start", "end", "create", "update"))
                ):
                    last_rep = _parse_dt(value)
                    if last_rep is not None:
                        break

        cid = item.get("id") or item.get("consumableId") or item.get("type")
        key = _slugify(f"{cid}_{name}" if cid else name)

        out.append(
            {
                "key": key,
                "name": name,
                "remaining_hours": remaining_hours,
                "percent_left": round(percent_left, 1) if percent_left is not None else None,
                "last_replacement": last_rep,
                "raw": item,
            }
        )
    return out
