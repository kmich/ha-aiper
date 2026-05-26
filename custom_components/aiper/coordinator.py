"""Data update coordinator for Aiper integration."""

from __future__ import annotations

import logging
from contextlib import suppress
from datetime import UTC, datetime, timedelta
from typing import Any

from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator, UpdateFailed
from homeassistant.util import dt as dt_util

from .api import AiperApi
from .const import (
    CLEAN_PATH_LABEL_TO_VALUE,
    DEFAULT_METADATA_REFRESH_HOURS,
    DOMAIN,
    mode_label,
    status_running,
)
from .profiles import Capability, derive_device_profile, has_capability
from .state import (
    DevicesState,
    DeviceState,
    RawDeviceData,
    _coerce_bool,
    merge_device_state,
    normalize_clean_path_update,
    normalize_device_state,
    normalize_machine_update,
    normalize_mode_options_update,
    normalize_netstat_update,
    normalize_opinfo_update,
    normalize_ota_update,
    normalize_w2_alarm_update,
    normalize_w2_info_update,
    normalize_w2_lifetime_update,
    normalize_w2_sensor_status_update,
    normalize_w2_wqs_update,
    supported_mode_ids_from_payload,
)

_LOGGER = logging.getLogger(__name__)

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

LIVE_REFRESH_INTERVAL = timedelta(minutes=5)


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

        duration_value = _deep_get(
            item,
            ("duration", "durationTime", "cleaningTime", "runTime", "useTime", "lastTime", "timeUsed"),
        )
        duration_min = _minutes_from_value(duration_value)
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


class AiperDataUpdateCoordinator(DataUpdateCoordinator[DevicesState]):
    """Class to manage fetching Aiper data."""

    def __init__(
        self,
        hass: HomeAssistant,
        api: AiperApi,
        metadata_refresh_hours: int = DEFAULT_METADATA_REFRESH_HOURS,
        config_entry: ConfigEntry | None = None,
    ) -> None:
        """Initialize the coordinator."""
        self._metadata_refresh = timedelta(hours=max(1, int(metadata_refresh_hours)))
        self._last_online: dict[str, bool | None] = {}

        super().__init__(
            hass,
            _LOGGER,
            config_entry=config_entry,
            name=DOMAIN,
            update_interval=min(self._metadata_refresh, LIVE_REFRESH_INTERVAL),
        )
        self.api = api
        self._devices: dict[str, RawDeviceData] = {}
        self._last_metadata_fetch: dict[str, datetime] = {}
        self._history_cache: dict[str, dict[str, Any]] = {}
        self._consumables_cache: dict[str, list[dict[str, Any]]] = {}
        self._clean_path_cache: dict[str, int] = {}

        # Command tracking (for community-friendly UX)
        # We do not apply optimistic state changes; instead we track pending commands
        # and mark them confirmed when the device reports the new value.
        self._command_state: dict[str, dict[str, dict[str, Any]]] = {}
        # Structure: {sn: {"pending": {kind: {...}}, "last": {kind: {...}}}}

    def _apply_device_profile(self, sn: str) -> None:
        """Derive and store family/capability metadata for a device."""
        device = self._devices.setdefault(sn, {})
        profile_input = {
            **device,
            "consumables": self._consumables_cache.get(sn) or device.get("consumables") or [],
        }
        profile = derive_device_profile(profile_input)
        device["profile_family"] = profile.family.value
        device["capabilities"] = sorted(capability.value for capability in profile.capabilities)
        if not device.get("supported_mode_ids"):
            device["supported_mode_ids"] = list(profile.mode_map.keys())
        device["mode_map"] = profile.mode_map

    async def _async_update_data(self) -> DevicesState:
        """Fetch data from API."""
        try:
            now = dt_util.utcnow()

            # Normalize cached timestamps (defensive against earlier versions).
            for _sn, _ts in list(self._last_metadata_fetch.items()):
                self._last_metadata_fetch[_sn] = _ensure_utc_aware(_ts) or dt_util.utcnow()

            discovered_devices: list[RawDeviceData] | None = None
            try:
                discovered_devices = await self.api.get_devices()
                _LOGGER.debug("Got %d devices from API", len(discovered_devices))
                for discovered in discovered_devices:
                    sn = discovered.get("sn")
                    if sn:
                        serial = str(sn)
                        self._devices[serial] = _merge_discovery_metadata(
                            self._devices.get(serial, {}),
                            dict(discovered),
                            include_live=True,
                        )
            except Exception as err:
                if not self._devices:
                    raise
                _LOGGER.debug("Live device refresh failed, using cached device state: %s", err)

            devices = list(self._devices.values())
            metadata_due_serials: set[str] = set()
            for device in devices:
                sn = device.get("sn")
                if not sn:
                    continue
                last_metadata = _ensure_utc_aware(self._last_metadata_fetch.get(str(sn)))
                if last_metadata is None or (now - last_metadata) >= self._metadata_refresh:
                    metadata_due_serials.add(str(sn))

            for device in devices:
                sn = device.get("sn")
                if not sn:
                    continue

                sn = str(sn)
                metadata_due = sn in metadata_due_serials

                current_device_state = (self.data or {}).get(sn) if self.data else None
                online_entity = current_device_state.get("online") if current_device_state else None
                online_state = _coerce_bool((self._devices.get(sn) or {}).get("online"))
                if online_state is None:
                    online_state = (
                        online_entity.value
                        if online_entity is not None and isinstance(online_entity.value, bool)
                        else None
                    )
                if online_state is None:
                    online_state = self._last_online.get(sn)

                self._last_online[sn] = online_state

                self._devices[sn]["online"] = online_state
                if online_state is False:
                    self._devices[sn]["ble"] = 0
                    self._devices[sn]["sta"] = 0
                    self._devices[sn]["nearFieldBind"] = 0
                    self._devices[sn]["link"] = 0
                    self._devices[sn]["wifiName"] = None
                    self._devices[sn]["wifiRssi"] = None

                if metadata_due:
                    info = None
                    try:
                        info = await self.api.get_device_info(sn)
                    except Exception as err:
                        _LOGGER.debug("Device info metadata refresh failed for %s: %s", sn, err)
                    if isinstance(info, dict):
                        self._devices[sn]["info"] = info

                    raw_hist = None
                    try:
                        raw_hist = await self.api.get_cleaning_history(sn)
                    except Exception as err:
                        _LOGGER.debug("Cleaning history fetch failed for %s: %s", sn, err)
                    if raw_hist is not None:
                        try:
                            total_count, total_hours, records = _parse_cleaning_history(raw_hist)
                        except Exception as err:
                            _LOGGER.debug("Cleaning history parse failed for %s: %s", sn, err)
                            total_count, total_hours, records = None, None, []
                        self._history_cache[sn] = {
                            "total_count": total_count,
                            "total_hours": total_hours,
                            "records": records,
                            "raw": raw_hist,
                        }

                    raw_cons = None
                    try:
                        raw_cons = await self.api.get_consumables(sn)
                    except Exception as err:
                        _LOGGER.debug("Consumables fetch failed for %s: %s", sn, err)
                    cons_list = _parse_consumables(raw_cons)
                    # Always update cache when the call returned (even if parsing yielded empty),
                    # to avoid requiring an integration reload to observe new values.
                    if raw_cons is not None:
                        self._consumables_cache[sn] = cons_list
                    self._last_metadata_fetch[sn] = now

                hist = self._history_cache.get(sn) or {}
                total_hours = hist.get("total_hours")
                records = hist.get("records") or []
                last_record = records[0] if isinstance(records, list) and records else None
                self._devices[sn]["total_cleanings"] = hist.get("total_count")
                self._devices[sn]["total_cleaning_hours"] = total_hours
                self._devices[sn]["total_cleaning_minutes"] = (
                    round(float(total_hours) * 60) if isinstance(total_hours, (int, float)) else None
                )
                self._devices[sn]["cleaning_records"] = records
                if isinstance(last_record, dict):
                    self._devices[sn]["last_cleaning_mode"] = last_record.get("mode")
                    self._devices[sn]["last_cleaning_start"] = last_record.get("start")
                    self._devices[sn]["last_cleaning_duration_min"] = last_record.get("duration_min")

                # Derive supported modes only from observed info metadata.
                # Family profiles provide typed defaults when the list is absent.
                info = self._devices[sn].get("info")
                supported_ids = supported_mode_ids_from_payload(info) if isinstance(info, dict) else []
                explicit_supported_modes = bool(supported_ids)
                self._devices[sn]["supported_mode_ids"] = supported_ids
                self._devices[sn]["supported_modes_explicit"] = explicit_supported_modes

                # Canonicalize optional info fields if discovery metadata provides them.
                info_data = info if isinstance(info, dict) else {}
                if info_data.get("model") is not None:
                    self._devices[sn]["model"] = info_data.get("model")
                self._devices[sn]["fw_main"] = info_data.get("mainFirmwareVersion")
                self._devices[sn]["fw_mcu"] = info_data.get("mcuFirmwareVersion")
                self._devices[sn]["ip_address"] = info_data.get("ip")
                self._devices[sn]["ap_hotspot"] = info_data.get("wifiName")
                self._devices[sn]["bluetooth_name"] = info_data.get("bleName")
                self._devices[sn]["consumables"] = self._consumables_cache.get(sn) or []
                self._apply_device_profile(sn)

                if has_capability(self._devices[sn], Capability.CLEAN_PATH):
                    self._devices[sn]["clean_path"] = self._clean_path_cache.get(sn)
                else:
                    self._devices[sn]["clean_path"] = None

            # Expire pending commands (UI hints)
            for _sn in list(self._command_state.keys()):
                with suppress(Exception):
                    self.expire_pending_commands(_sn)

            # Publish normalized device data.
            result: DevicesState = {}
            for sn, device in self._devices.items():
                normalized = normalize_device_state(device)
                current = (self.data or {}).get(sn) if self.data else None
                if current:
                    # MQTT is authoritative for live machine state. Remove stale
                    # REST-derived values so they don't overwrite live MQTT state
                    # on the 5-minute slow refresh.
                    #
                    # Use the presence of a real status code as the gate: a non-None
                    # "code" attribute on the current status means we have authoritative
                    # machine-state data (from MQTT or from a REST machineStatus field).
                    # A missing code means the current status is a fallback placeholder
                    # ("Idle" when no machineStatus is known) — in that case we let the
                    # incoming REST values flow through freely.
                    current_status = current.get("status")
                    if current_status is not None and current_status.attributes.get("code") is not None:
                        for _key in ("running", "status", "charging", "mode"):
                            normalized.pop(_key, None)
                    result[sn] = merge_device_state(current, normalized, ignore_none=True)
                else:
                    result[sn] = normalized

            _LOGGER.debug("Coordinator updated devices=%s", list(result.keys()))
            return result

        except Exception as err:
            _LOGGER.error("Error fetching data: %s", err)
            raise UpdateFailed(f"Error communicating with API: {err}") from err

    def handle_shadow_update(self, sn: str | dict, data: dict | None = None) -> None:
        """Handle a shadow update from MQTT.

        The integration supports two callback styles:
          - handle_shadow_update(sn, data)
          - handle_shadow_update(data)

        In the single-argument form, we attempt to extract the serial number
        from the payload ("_sn", "sn", or "data.sn").

        The AWS IoT SDK invokes subscription callbacks on a background thread.
        Home Assistant state updates must occur on the HA event loop.
        """
        if data is None and isinstance(sn, dict):
            payload = sn
            data = payload
            payload_data = payload.get("data")
            serial = (
                payload.get("_sn")
                or payload.get("sn")
                or (payload_data.get("sn") if isinstance(payload_data, dict) else None)
            )
            if not serial:
                _LOGGER.debug("Ignoring MQTT update with no serial number: %s", payload)
                return
            sn = str(serial)

        if data is None:
            return

        try:
            self.hass.loop.call_soon_threadsafe(self._apply_shadow_update, str(sn), data)
        except Exception:
            # Fallback (should not generally happen)
            self._apply_shadow_update(str(sn), data)

    def make_shadow_callback(self, sn: str):
        """Return a callback suitable for AWS IoT MQTT subscriptions."""

        def _cb(data: dict) -> None:
            self.handle_shadow_update(sn, data)

        return _cb

    def _apply_shadow_update(self, sn: str, data: dict) -> None:
        """Apply a shadow update and notify listeners (runs on HA loop)."""
        try:
            topic = data.get("_topic") if isinstance(data, dict) else None
            keys = list(data.keys()) if isinstance(data, dict) else [type(data).__name__]
            _LOGGER.debug("Shadow update for %s topic=%s keys=%s", sn, topic, keys)
        except Exception:
            _LOGGER.debug("Shadow update for %s (unparsed)", sn)
        self._on_shadow_update(sn, data)

    def _on_shadow_update(self, sn: str, data: dict) -> None:
        """Process shadow update from MQTT."""
        topic = data.get("_topic") if isinstance(data, dict) else None

        def _publish_updates(updates: DeviceState) -> None:
            if not updates:
                return
            current = (self.data or {}).get(sn) if self.data else None
            if current is None:
                current = normalize_device_state(self._devices.get(sn, {}))
            new_data: DevicesState = dict(self.data or {})
            new_data[sn] = merge_device_state(current, updates)
            self.async_set_updated_data(new_data)

        def _cache_clean_path(update: DeviceState) -> None:
            clean_path = update.get("clean_path")
            if clean_path is None:
                return
            code = clean_path.attributes.get("code")
            if code is not None:
                self.set_clean_path_cache(sn, int(code))

        def _clean_path_updates(payload: Any) -> DeviceState:
            if not isinstance(payload, dict):
                return {}
            update = normalize_clean_path_update(payload)
            _cache_clean_path(update)
            return update

        if isinstance(topic, str) and "shadow/update/delta" in topic:
            state = data.get("state") if isinstance(data, dict) else None
            delta_machine = state.get("Machine") if isinstance(state, dict) else None
            _publish_updates(_clean_path_updates(delta_machine))
            _LOGGER.debug("Ignoring desired-only shadow delta for %s", sn)
            return

        payload = data

        # AWS IoT shadow 'documents' messages: extract current.state.reported when present.
        if isinstance(topic, str) and "shadow/update/documents" in topic and isinstance(data, dict):
            current = data.get("current") or {}
            if isinstance(current, dict):
                cur_state = current.get("state") or {}
                if isinstance(cur_state, dict):
                    desired = cur_state.get("desired")
                    if isinstance(desired, dict):
                        _publish_updates(_clean_path_updates(desired.get("Machine")))
                    if isinstance(cur_state.get("reported"), dict):
                        payload = cur_state.get("reported") or {}
                    else:
                        payload = cur_state

        # Standard shadow payloads: only accept reported state. Desired/delta is
        # command intent, not current device state, except cleanPath preference on
        # firmwares that never report it.
        if isinstance(payload, dict) and isinstance(payload.get("state"), dict):
            state_payload = payload.get("state") or {}
            for candidate in (state_payload.get("desired"), state_payload.get("delta")):
                if isinstance(candidate, dict):
                    _publish_updates(_clean_path_updates(candidate.get("Machine")))
            if isinstance(state_payload.get("reported"), dict):
                payload = state_payload.get("reported") or {}
            else:
                if any(key in state_payload for key in ("desired", "delta")):
                    _LOGGER.debug(
                        "Ignoring non-reported shadow update for %s (keys=%s)", sn, list(state_payload.keys())
                    )
                    return
                if isinstance(state_payload, dict):
                    payload = state_payload

        if not isinstance(payload, dict):
            return

        raw_device = self._devices.setdefault(sn, {})
        self._apply_device_profile(sn)
        current_state = (self.data or {}).get(sn) if self.data else None
        updates: DeviceState = {}
        machine: dict[str, Any] = {}

        if "Machine" in payload and isinstance(payload.get("Machine"), dict):
            machine = dict(payload.get("Machine") or {})
        elif "machine" in payload and isinstance(payload.get("machine"), dict):
            machine = dict(payload.get("machine") or {})
        elif payload.get("type") == "Machine":
            machine_data = payload.get("data") or {}
            for key in (
                "status",
                "mode",
                "cap",
                "warn",
                "run_time",
                "in_water",
                "warn_code",
                "temp",
                "solar_status",
                "link",
                "cleanPath",
                "clean_path",
            ):
                if key in machine_data and machine_data.get(key) is not None:
                    machine[key] = machine_data.get(key)

            report = machine_data.get("report")
            if isinstance(report, str):
                parsed = self._parse_machine_report(report)
                if parsed:
                    machine.update({key: value for key, value in parsed.items() if key != "records"})

        if machine:
            updates = merge_device_state(updates, normalize_machine_update(raw_device, machine, current_state))

        netstat: dict[str, Any] = {}
        if "NetStat" in payload and isinstance(payload.get("NetStat"), dict):
            netstat = dict(payload.get("NetStat") or {})
        elif "netstat" in payload and isinstance(payload.get("netstat"), dict):
            netstat = dict(payload.get("netstat") or {})
        elif payload.get("type") == "NetStat" and isinstance(payload.get("data"), dict):
            netstat = dict(payload.get("data") or {})

        if netstat:
            updates = merge_device_state(updates, normalize_netstat_update(netstat))
        online_update = updates.get("online")
        curr_mqtt_online = online_update.value if online_update else None
        if curr_mqtt_online is not None:
            self._last_online[sn] = curr_mqtt_online

        for key in ("OpInfo", "OtaStatus", "CycleWork", "GetWorkMode", "RubbishBoxStatus"):
            component = None
            if key in payload and isinstance(payload.get(key), dict):
                component = payload.get(key) or {}
            elif payload.get("type") == key and isinstance(payload.get("data"), dict):
                component = payload.get("data") or {}
            if not isinstance(component, dict):
                continue
            lower_key = key.lower()
            if lower_key == "opinfo":
                interim_state = merge_device_state(current_state, updates) if updates else current_state
                updates = merge_device_state(updates, normalize_opinfo_update(component, interim_state))
            elif lower_key == "otastatus":
                updates = merge_device_state(updates, normalize_ota_update(component))
            elif lower_key == "getworkmode":
                updates = merge_device_state(updates, normalize_mode_options_update(raw_device, component))
                updates = merge_device_state(updates, normalize_clean_path_update(component))
            else:
                updates = merge_device_state(updates, normalize_clean_path_update(component))
            _cache_clean_path(updates)

        for key in ("W2Info", "W2WQS", "W2LifeTime", "W2SensorStatus", "W2AlarmMessage"):
            component = None
            if key in payload and isinstance(payload.get(key), dict):
                component = payload.get(key) or {}
            elif payload.get("type") == key and isinstance(payload.get("data"), dict):
                component = payload.get("data") or {}
            if not isinstance(component, dict):
                continue

            interim_state = merge_device_state(current_state, updates) if updates else current_state
            if key == "W2Info":
                updates = merge_device_state(updates, normalize_w2_info_update(component))
            elif key == "W2WQS":
                updates = merge_device_state(updates, normalize_w2_wqs_update(component))
            elif key == "W2LifeTime":
                updates = merge_device_state(updates, normalize_w2_lifetime_update(component, interim_state))
            elif key == "W2SensorStatus":
                updates = merge_device_state(updates, normalize_w2_sensor_status_update(component, interim_state))
            elif key == "W2AlarmMessage":
                updates = merge_device_state(updates, normalize_w2_alarm_update(component))

        # Update last-seen time on any MQTT activity.
        try:
            if sn in self._devices:
                self._devices[sn]["last_seen"] = dt_util.utcnow()
        except Exception:
            pass

        _publish_updates(updates)

        # Confirm pending commands when the device reports the new value.
        with suppress(Exception):
            self._confirm_pending_commands(sn, machine)

    @staticmethod
    def _parse_machine_report(report: str) -> dict[str, Any]:
        """Parse Aiper Machine report strings into structured fields."""
        result: dict[str, Any] = {}
        try:
            lines = [ln.strip() for ln in report.splitlines() if ln.strip()]
            for ln in lines:
                if ln.startswith("+INFO:"):
                    parts = ln.split(":", 1)[1].split(",")
                    parts = [p.strip() for p in parts if p.strip()]
                    # Known order (observed): status, mode, cap, warn, run_time, in_water[, warn_code]
                    if len(parts) >= 3:
                        result["status"] = int(parts[0])
                        result["mode"] = int(parts[1])
                        result["cap"] = int(parts[2])
                    if len(parts) >= 4:
                        result["warn"] = int(parts[3])
                    if len(parts) >= 5:
                        result["run_time"] = int(parts[4])
                    if len(parts) >= 6:
                        result["in_water"] = int(parts[5])
                    if len(parts) >= 7:
                        result["warn_code"] = int(parts[6])
                elif ln.startswith("+WARN:"):
                    # Observed: "+WARN:0" or "+WARN:1,<code>".
                    parts = ln.split(":", 1)[1].split(",")
                    parts = [p.strip() for p in parts if p.strip()]
                    if len(parts) >= 1:
                        result["warn"] = int(parts[0])
                    if len(parts) >= 2:
                        result["warn_code"] = int(parts[1])
                elif ln.startswith("+WORKMODE:") or ln.startswith("+MODE:"):
                    # Some firmwares respond with explicit mode lines.
                    # Example patterns (unconfirmed): "+WORKMODE:<n>" or "+MODE:<n>".
                    try:
                        val = ln.split(":", 1)[1].split(",", 1)[0].strip()
                        result["mode"] = int(val)
                    except Exception:
                        pass
        except Exception:
            return {}
        return result

    def get_device(self, sn: str) -> DeviceState | None:
        """Get device data by serial number."""
        if self.data:
            return self.data.get(sn)
        return None

    # -----------------
    # Command tracking
    # -----------------

    PENDING_TIMEOUT_SECONDS = 8

    def _ensure_cmd_state(self, sn: str) -> dict[str, dict[str, Any]]:
        st = self._command_state.get(sn)
        if st is None:
            st = {"pending": {}, "last": {}}
            self._command_state[sn] = st
        st.setdefault("pending", {})
        st.setdefault("last", {})
        return st

    def note_command_sent(self, sn: str, kind: str, target: Any, *, source: str = "select") -> None:
        """Record that a command was sent and mark it pending until confirmed."""
        now = dt_util.utcnow()
        st = self._ensure_cmd_state(sn)
        st["pending"][kind] = {
            "target": target,
            "since": now.isoformat(),
            "source": source,
        }
        st["last"][kind] = {
            "target": target,
            "time": now.isoformat(),
            "source": source,
            "result": "sent",
            "confirmed": False,
        }
        self.async_update_listeners()

    def note_command_failed(
        self,
        sn: str,
        kind: str,
        target: Any,
        *,
        reason: str | None = None,
        source: str = "select",
    ) -> None:
        """Record a command failure and clear any matching pending entry."""
        now = dt_util.utcnow()
        st = self._ensure_cmd_state(sn)
        pend = st.get("pending", {})
        if kind in pend and isinstance(pend.get(kind), dict) and pend[kind].get("target") == target:
            pend.pop(kind, None)
        st["last"][kind] = {
            "target": target,
            "time": now.isoformat(),
            "source": source,
            "result": "failed",
            "reason": reason,
            "confirmed": False,
        }
        self.async_update_listeners()

    def get_command_state(self, sn: str) -> dict[str, Any]:
        """Return a shallow copy of pending/last command state for entities."""
        st = self._command_state.get(sn) or {"pending": {}, "last": {}}
        return {
            "pending": dict(st.get("pending", {})),
            "last": dict(st.get("last", {})),
        }

    def get_pending_command_target(self, sn: str, kind: str) -> Any:
        """Return a non-expired pending command target, if present."""
        self.expire_pending_commands(sn)
        st = self._command_state.get(sn) or {}
        pending = st.get("pending") or {}
        info = pending.get(kind) if isinstance(pending, dict) else None
        if info is None and kind == "mode" and isinstance(pending, dict):
            info = pending.get("cleaning_mode")
        elif info is None and kind == "cleaning_mode" and isinstance(pending, dict):
            info = pending.get("mode")
        return info.get("target") if isinstance(info, dict) else None

    def expire_pending_commands(self, sn: str) -> None:
        """Expire pending commands that have not been confirmed within the timeout."""
        st = self._command_state.get(sn)
        if not st:
            return
        pend = st.get("pending", {})
        if not isinstance(pend, dict) or not pend:
            return
        now = dt_util.utcnow()
        expired: list[str] = []
        for kind, info in pend.items():
            if not isinstance(info, dict):
                continue
            since_raw = info.get("since")
            try:
                since = dt_util.parse_datetime(since_raw) if isinstance(since_raw, str) else None
            except Exception:
                since = None
            if since is None:
                continue
            if (now - since).total_seconds() >= self.PENDING_TIMEOUT_SECONDS:
                expired.append(kind)
        for kind in expired:
            info = pend.pop(kind, None) or {}
            st.setdefault("last", {})[kind] = {
                "target": info.get("target"),
                "time": now.isoformat(),
                "source": info.get("source"),
                "result": "timeout",
                "confirmed": False,
            }
        if expired:
            self.async_update_listeners()

    def _confirm_pending_commands(self, sn: str, machine: dict[str, Any]) -> None:
        """Mark pending commands confirmed when reported state matches targets."""
        st = self._command_state.get(sn)
        if not st:
            return
        pend = st.get("pending", {})
        if not isinstance(pend, dict) or not pend:
            return

        def _to_int(v: Any) -> int | None:
            try:
                return int(v)
            except Exception:
                return None

        reported_mode = _to_int(machine.get("mode"))
        reported_status = _to_int(machine.get("status"))
        reported_running = status_running(reported_status) if reported_status is not None else None
        # Clean path is especially inconsistent across firmwares; normalize.
        reported_clean_path = self._extract_clean_path_value(sn, machine)

        now = dt_util.utcnow().isoformat()
        changed = False

        for mode_kind in ("mode", "cleaning_mode"):
            if mode_kind not in pend:
                continue
            tgt = _to_int((pend.get(mode_kind) or {}).get("target"))
            if tgt is not None and reported_mode is not None and tgt == reported_mode:
                pend.pop(mode_kind, None)
                st.setdefault("last", {})[mode_kind] = {
                    "target": tgt,
                    "time": now,
                    "source": "device_report",
                    "result": "confirmed",
                    "confirmed": True,
                }
                changed = True

        if "running" in pend:
            tgt = (pend.get("running") or {}).get("target")
            if isinstance(tgt, bool) and reported_running is not None and tgt == reported_running:
                pend.pop("running", None)
                st.setdefault("last", {})["running"] = {
                    "target": tgt,
                    "time": now,
                    "source": "device_report",
                    "result": "confirmed",
                    "confirmed": True,
                }
                changed = True

        if "clean_path" in pend:
            tgt = _clean_path_value((pend.get("clean_path") or {}).get("target"))
            if tgt is not None and reported_clean_path is not None and tgt == reported_clean_path:
                pend.pop("clean_path", None)
                st.setdefault("last", {})["clean_path"] = {
                    "target": tgt,
                    "time": now,
                    "source": "device_report",
                    "result": "confirmed",
                    "confirmed": True,
                }
                changed = True

        if changed:
            self.async_update_listeners()

    # -----------------
    # Clean path cache
    # -----------------

    def _extract_clean_path_value(self, sn: str, machine: dict[str, Any] | None = None) -> int | None:
        """Best-effort extraction of clean-path from known payload containers.

        Different firmwares publish clean path under different keys/containers:
        - Current normalized entity attributes
        - Current Machine payload
        Returns a normalized integer when possible.
        """
        if machine is None:
            clean_path = ((self.data or {}).get(sn) or {}).get("clean_path")
            if clean_path is not None:
                value = _clean_path_value(clean_path.attributes.get("code"))
                if value is not None:
                    return value
                value = _clean_path_value(clean_path.value)
                if value is not None:
                    return value
            machine = {}

        if isinstance(machine, dict):
            v = _clean_path_value(machine.get("cleanPath"))
            if v is not None:
                return v

        return None

    def set_clean_path_cache(self, sn: str, value: int) -> None:
        """Update cached clean-path preference."""
        self._clean_path_cache[sn] = int(value)

    def get_clean_path(self, sn: str) -> int | None:
        """Get current clean-path preference.

        Community-friendly behavior:
        - Prefer the normalized entity state
        - Fall back to the command/cache value
        """
        v = self._extract_clean_path_value(sn)
        if v is not None:
            return v

        if sn in self._devices and "clean_path" in self._devices[sn]:
            try:
                val = self._devices[sn].get("clean_path")
                v = _clean_path_value(val)
                return v
            except Exception:
                return None

        val = self._clean_path_cache.get(sn)
        return _clean_path_value(val)
