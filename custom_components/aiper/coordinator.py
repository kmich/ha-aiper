"""Data update coordinator for Aiper integration."""
from __future__ import annotations

import logging
from datetime import timedelta, datetime, timezone
from typing import Any

from homeassistant.core import HomeAssistant
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator, UpdateFailed
from homeassistant.util import dt as dt_util

from .api import AiperApi
from .const import DEFAULT_SCAN_INTERVAL, DEFAULT_HISTORY_REFRESH_HOURS, DEFAULT_CONSUMABLES_REFRESH_HOURS, DEFAULT_CLEAN_PATH_REFRESH_HOURS, DOMAIN, MODE_MAP, CLEAN_PATH_LABEL_TO_VALUE

_LOGGER = logging.getLogger(__name__)


def _ensure_utc_aware(value: datetime | None) -> datetime | None:
    """Ensure a datetime is timezone-aware in UTC."""
    if value is None:
        return None
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


# Fast polling window used to reduce the perceived latency when the device
# transitions from Offline -> Online. We keep this short to limit cloud API load.
FAST_SCAN_INTERVAL_SECONDS = 5
FAST_SCAN_WINDOW_SECONDS = 180

# Slower-changing data refresh intervals are configurable via options.


def _coerce_bool(val: Any) -> bool | None:
    """Coerce common Aiper 0/1/bool/string values into a boolean.

    Returns None if val is None or cannot be interpreted.
    """
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


def _deep_get(obj: Any, keys: tuple[str, ...]) -> Any:
    """Best-effort deep lookup for the first non-null value.

    Aiper REST responses vary significantly by region/firmware and often nest
    values under wrapper objects. This helper searches dict/list structures
    breadth-first for any of the provided keys, using a normalized comparison.
    """
    if obj is None:
        return None

    wanted = {_norm_key(k) for k in keys}
    queue: list[Any] = [obj]
    seen: set[int] = set()

    while queue:
        cur = queue.pop(0)
        oid = id(cur)
        if oid in seen:
            continue
        seen.add(oid)

        if isinstance(cur, dict):
            for k, v in cur.items():
                if v is None:
                    continue
                if _norm_key(str(k)) in wanted:
                    return v
            for v in cur.values():
                if isinstance(v, (dict, list)):
                    queue.append(v)
        elif isinstance(cur, list):
            for it in cur:
                if isinstance(it, (dict, list)):
                    queue.append(it)

    return None


def _deep_collect(obj: Any, keys: tuple[str, ...]) -> list[tuple[str, Any]]:
    """Collect all matching key/value pairs found anywhere in a nested structure."""
    if obj is None:
        return []
    wanted = {_norm_key(k) for k in keys}
    found: list[tuple[str, Any]] = []
    queue: list[Any] = [obj]
    seen: set[int] = set()

    while queue:
        cur = queue.pop(0)
        oid = id(cur)
        if oid in seen:
            continue
        seen.add(oid)

        if isinstance(cur, dict):
            for k, v in cur.items():
                if v is None:
                    continue
                if _norm_key(str(k)) in wanted:
                    found.append((str(k), v))
                if isinstance(v, (dict, list)):
                    queue.append(v)
        elif isinstance(cur, list):
            for it in cur:
                if isinstance(it, (dict, list)):
                    queue.append(it)

    return found


def _key_rank(key: str, priority: tuple[str, ...]) -> int:
    nk = _norm_key(key)
    for i, pk in enumerate(priority):
        if nk == _norm_key(pk):
            return i
    return len(priority)



def _parse_dt(value: Any) -> datetime | None:
    """Parse a datetime value coming from Aiper payloads."""
    if value is None:
        return None
    if isinstance(value, datetime):
        return value
    # Epoch seconds or milliseconds
    if isinstance(value, (int, float)):
        try:
            v = float(value)
            if v > 10_000_000_000:  # ms
                v = v / 1000.0
            return datetime.fromtimestamp(v, tz=timezone.utc)
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
                return dt
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
                return datetime.strptime(s, fmt).replace(tzinfo=timezone.utc)
            except Exception:
                continue
    return None


def _mode_label(mode_id: Any) -> str | None:
    try:
        if mode_id is None:
            return None
        mid = int(mode_id)
        return MODE_MAP.get(mid, f"Mode {mid}")
    except Exception:
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


def _parse_cleaning_history(raw: Any) -> tuple[int | None, float | None, list[dict[str, Any]]]:
    """Parse the cleaning history/totals payload.

    Aiper's API varies by region/firmware. Totals (count/time) may appear at the
    root payload, under `data`, or under nested wrapper keys.
    """

    root = raw if isinstance(raw, dict) else {}

    # Identify a record list (if present) while keeping `root` for totals search.
    data = raw
    if isinstance(raw, dict) and raw.get('data') is not None:
        data = raw.get('data')

    # Unwrap common list containers for records.
    rec_list = None
    if isinstance(data, dict):
        # direct list keys
        for lk in ('list', 'records', 'recordList', 'history', 'items'):
            if isinstance(data.get(lk), list):
                rec_list = data.get(lk)
                break
        # nested list containers
        if rec_list is None:
            for lk in ('data', 'result', 'page'):
                sub = data.get(lk)
                if isinstance(sub, dict):
                    for lk2 in ('list', 'records', 'recordList', 'items'):
                        if isinstance(sub.get(lk2), list):
                            rec_list = sub.get(lk2)
                            break
                if rec_list is not None:
                    break
    elif isinstance(data, list):
        rec_list = data

    if rec_list is None:
        rec_list = []

    records_len = len(rec_list) if isinstance(rec_list, list) else 0

    def _norm_key(key: str) -> str:
        return ''.join(ch for ch in key.lower() if ch.isalnum())

    def _key_rank(key: str, preferred: tuple[str, ...]) -> int:
        nk = _norm_key(key)
        for idx, cand in enumerate(preferred):
            if _norm_key(cand) == nk:
                return idx
        for idx, cand in enumerate(preferred):
            if _norm_key(cand) in nk or nk in _norm_key(cand):
                return idx + 50
        return 999

    def _num(v):
        if v is None:
            return None
        if isinstance(v, (int, float)):
            return float(v)
        if isinstance(v, str):
            s = v.strip().lower()
            digits = ''.join(ch for ch in s if (ch.isdigit() or ch == '.'))
            if not digits:
                return None
            try:
                return float(digits)
            except Exception:
                return None
        return None

    def _hours_candidates(v):
        """Return plausible hours values from a raw duration/total.

        For ambiguous numeric totals (e.g., 270), we prefer interpreting as MINUTES
        before SECONDS, because Aiper's totals are commonly minute-based.
        """
        if v is None:
            return []
        if isinstance(v, str):
            s = v.strip().lower()
            n = _num(s)
            if n is None:
                return []
            if 'hour' in s or s.endswith('h'):
                return [n]
            if 'min' in s:
                return [n / 60.0]
            if 'sec' in s or s.endswith('s'):
                return [n / 3600.0]
            # ambiguous numeric string: prefer minutes, then seconds, then hours
            return [n / 60.0, n / 3600.0, n]

    COUNT_KEYS = (
        'totalNumberOfCleanings',
        'totalCleanCount',
        'totalCleanings',
        'totalNumber',
        'totalCount',
        'totalTimes',
        'totalCleanTimes',
        'totalRecords',
        'cleanCount',
        'cleanTimes',
        'total',
    )
    TIME_KEYS = (
        'totalCleaningTime',
        'totalCleanTime',
        'totalCleanHour',
        'totalCleanHours',
        'totalCleaningHours',
        'totalCleanMinute',
        'totalCleanMinutes',
        'totalCleaningMinutes',
        'totalCleanSeconds',
        'totalDuration',
        'totalCleaningDuration',
        'cleanTimeTotal',
        'totalWorkTime',
        'totalTime',
        'totalHours',
        'totalMinutes',
        'totalSeconds',
        'sumTime',
        'sumCleanTime',
    )

    def _deep_collect(obj, keys):
        if isinstance(obj, dict):
            for k, v in obj.items():
                if isinstance(k, str):
                    nk = _norm_key(k)
                    for cand in keys:
                        if _norm_key(cand) == nk:
                            yield k, v
                            break
                if isinstance(v, (dict, list)):
                    yield from _deep_collect(v, keys)
        elif isinstance(obj, list):
            for it in obj:
                if isinstance(it, (dict, list)):
                    yield from _deep_collect(it, keys)

    def _collect_total_like(obj, want='time'):
        # Heuristic collector for totals that are not in known key lists.
        if isinstance(obj, dict):
            for k, v in obj.items():
                if not isinstance(k, str):
                    continue
                nk = _norm_key(k)
                if any(x in nk for x in ('page', 'size', 'current', 'last', 'start', 'begin', 'create', 'update')):
                    pass
                else:
                    has_total = ('total' in nk) or ('sum' in nk) or ('all' in nk)
                    if want == 'time':
                        has_metric = any(x in nk for x in ('time', 'hour', 'minute', 'second', 'duration'))
                    else:
                        has_metric = any(x in nk for x in ('count', 'times', 'number', 'records'))
                    if has_total and has_metric:
                        yield k, v
                if isinstance(v, (dict, list)):
                    yield from _collect_total_like(v, want=want)
        elif isinstance(obj, list):
            for it in obj:
                if isinstance(it, (dict, list)):
                    yield from _collect_total_like(it, want=want)

    def _collect_time_loose(obj):
        # Collect time-like totals that may not include the word 'total'
        if isinstance(obj, dict):
            for k, v in obj.items():
                if not isinstance(k, str):
                    continue
                nk = _norm_key(k)
                # Skip obvious non-total fields
                if any(x in nk for x in ('start', 'begin', 'end', 'create', 'update', 'record', 'list', 'page', 'size', 'current')):
                    pass
                else:
                    if ('clean' in nk or 'swim' in nk) and any(x in nk for x in ('time', 'hour', 'minute', 'second', 'duration')):
                        yield k, v
                if isinstance(v, (dict, list)):
                    yield from _collect_time_loose(v)
        elif isinstance(obj, list):
            for it in obj:
                if isinstance(it, (dict, list)):
                    yield from _collect_time_loose(it)


    sources = []
    if isinstance(root, dict):
        sources.append(root)
    if isinstance(data, dict) and data is not root:
        sources.append(data)

    count_cands = []
    time_cands = []

    for src in sources:
        for k, v in _deep_collect(src, COUNT_KEYS):
            try:
                n = _num(v)
                if n is None:
                    continue
                c = int(n)
                if c > 0:
                    count_cands.append((k, c))
            except Exception:
                continue
        for k, v in _deep_collect(src, TIME_KEYS):
            for h in _hours_candidates(v):
                if h and h > 0:
                    time_cands.append((k, h))
        # heuristic fallbacks
        for k, v in _collect_total_like(src, want='count'):
            n = _num(v)
            if n is not None:
                c = int(n)
                if c > 0:
                    count_cands.append((k, c))
        for k, v in _collect_total_like(src, want='time'):
            for h in _hours_candidates(v):
                if h and h > 0:
                    time_cands.append((k, h))
        # loose time totals (no 'total' keyword)
        for k, v in _collect_time_loose(src):
            for h in _hours_candidates(v):
                if h and h > 0:
                    time_cands.append((k, h))


    # de-dup
    def _dedup(pairs):
        seen=set(); out=[]
        for k,v in pairs:
            kk=_norm_key(k)
            if (kk,v) in seen:
                continue
            seen.add((kk,v))
            out.append((k,v))
        return out
    count_cands=_dedup(count_cands)
    time_cands=_dedup(time_cands)

    total_count = None
    total_hours = None

    best_score = -1e18
    best_pair = (None, None)

    def score_pair(ck, c, tk, h):
        if c <= 0 or h <= 0:
            return -1e18
        avg_min = (h * 60.0) / float(c)
        if not (10.0 <= avg_min <= 240.0):
            return -1e18
        score = 1000.0
        score -= abs(avg_min - 60.0) * 2.0
        if c >= records_len:
            score += 50.0
        else:
            score -= 50.0
        score -= _key_rank(ck, COUNT_KEYS) * 5.0
        score -= _key_rank(tk, TIME_KEYS) * 5.0
        if h > 5000:
            score -= 2000
        if c > 100000:
            score -= 2000
        return score

    if count_cands and time_cands:
        for ck, c in count_cands:
            for tk, h in time_cands:
                sc = score_pair(ck, c, tk, h)
                if sc > best_score:
                    best_score = sc
                    best_pair = ((ck, c), (tk, h))
        if best_pair[0]:
            total_count = best_pair[0][1]
        if best_pair[1]:
            total_hours = round(best_pair[1][1], 3)
    else:
        if count_cands:
            count_cands.sort(key=lambda x: _key_rank(x[0], COUNT_KEYS))
            total_count = count_cands[0][1]
        if time_cands:
            time_cands.sort(key=lambda x: _key_rank(x[0], TIME_KEYS))
            total_hours = round(time_cands[0][1], 3)

    def _minutes_from_value(v: Any) -> float | None:
        if v is None:
            return None
        if isinstance(v, str):
            s = v.strip().lower()
            n = _num(s)
            if n is None:
                return None
            if 'hour' in s or s.endswith('h'):
                return n * 60.0
            if 'min' in s:
                return n
            if 'sec' in s or s.endswith('s'):
                return n / 60.0
            if n > 300:
                return n / 60.0
            return n
        n = _num(v)
        if n is None:
            return None
        as_sec = n / 60.0
        as_min = n
        cand=[]
        if 0.5 <= as_sec <= 300:
            cand.append((0, as_sec))
        if 0.5 <= as_min <= 300:
            cand.append((1, as_min))
        if cand:
            cand.sort(key=lambda x: x[0])
            return float(cand[0][1])
        return float(as_sec if n > 300 else as_min)

    records: list[dict[str, Any]] = []

    # Helper to find any plausible datetime value in a record item.
    def _find_dt_any(item: dict) -> Any:
        for k in (
            'utcStartTimeStamp','utcEndTimeStamp','utcStartTime','utcEndTime',
            'utcBeginTimeStamp','utcBeginTime','utcFinishTimeStamp','utcFinishTime',
            'startTimeStamp','endTimeStamp','startTimestamp','endTimestamp',
            'startTime','cleanStartTime','beginTime','createTime','cleanTime','cleanDate','recordTime','dateTime','start','begin','time'
        ):
            v = item.get(k)
            if v is not None:
                return v
        # deep scan for datetime-like strings
        stack=[item]
        while stack:
            obj=stack.pop()
            if isinstance(obj, dict):
                for _,v in obj.items():
                    if isinstance(v, (dict, list)):
                        stack.append(v)
                    elif isinstance(v, str):
                        s=v.strip()
                        if any(ch.isdigit() for ch in s) and (':' in s or '-' in s or '/' in s):
                            return v
                    elif isinstance(v, (int, float)) and v > 1_000_000_000:
                        return v
            elif isinstance(obj, list):
                for v in obj:
                    if isinstance(v, (dict, list)):
                        stack.append(v)
        return None

    if isinstance(rec_list, list):
        for item in rec_list:
            if not isinstance(item, dict):
                continue

            mode_id = _deep_get(item, ("modeId", "mode_id", "cleanMode", "cleanType", "mode", "type"))
            mode_name = _deep_get(item, ("modeName", "cleanModeName", "mode_name", "name", "cleanTypeName"))
            try:
                mid_int = int(mode_id) if mode_id is not None and str(mode_id).strip().lstrip('-').isdigit() else None
            except Exception:
                mid_int = None
            if mode_name is None and mid_int is not None:
                mode_name = MODE_MAP.get(mid_int, f"Mode {mid_int}")
            if mode_name is None and mode_id is not None:
                mode_name = str(mode_id)
            if mode_name is None:
                mode_name = "Unknown"

            start_val = _find_dt_any(item)
            start_dt = _parse_dt(start_val)
            if start_dt is None and isinstance(start_val, (int, float)) and start_val > 10_000_000_000:
                start_dt = datetime.fromtimestamp(float(start_val) / 1000.0, tz=timezone.utc)

            dur_val = _deep_get(item, ("duration", "durationTime", "cleanTime", "cleaningTime", "runTime", "useTime", "lastTime", "timeUsed"))
            dur_min = _minutes_from_value(dur_val)

            records.append({
                "mode_id": mid_int,
                "mode": str(mode_name),
                "start": start_dt,
                "duration_min": round(float(dur_min), 1) if dur_min is not None else None,
                "raw": item,
            })

    records.sort(key=lambda r: r.get('start') or datetime.min.replace(tzinfo=timezone.utc), reverse=True)


    # Fallback: if the record list appears to contain the full history (or most of it),
    # compute total hours from the sum of record durations. This avoids unit/field drift
    # across regional API variants and prevents obviously incorrect totals.
    try:
        dur_sum_min = sum(float(r.get('duration_min')) for r in records if r.get('duration_min') is not None)
    except Exception:
        dur_sum_min = 0.0
    total_hours_from_records = (dur_sum_min / 60.0) if dur_sum_min > 0 else None

    def _avg_min(h, c):
        try:
            return (float(h) * 60.0) / float(c)
        except Exception:
            return None

    if total_hours_from_records is not None:
        # Determine if we likely have the full dataset
        likely_full = False
        if total_count is not None and isinstance(total_count, int) and total_count > 0:
            if records_len >= total_count:
                likely_full = True
        else:
            # no total count; assume list is authoritative
            likely_full = records_len >= 10

        # Sanity check existing total_hours
        avg_existing = _avg_min(total_hours, total_count) if (total_hours is not None and total_count) else None
        avg_records = _avg_min(total_hours_from_records, (total_count or records_len))

        existing_sane = (avg_existing is not None and 10.0 <= avg_existing <= 240.0)
        records_sane = (avg_records is not None and 10.0 <= avg_records <= 240.0)

        if total_hours is None and (likely_full or (total_count is None and records_len >= 10)):
            total_hours = round(total_hours_from_records, 3)
        elif likely_full and records_sane:
            # Prefer record-derived when existing is missing/insane or far away
            if (not existing_sane):
                total_hours = round(total_hours_from_records, 3)
            else:
                try:
                    if abs(float(total_hours) - float(total_hours_from_records)) / max(float(total_hours_from_records), 1.0) > 0.2:
                        total_hours = round(total_hours_from_records, 3)
                except Exception:
                    pass

    # If total_count is missing but we have records, populate it
    if total_count is None and records_len > 0:
        total_count = records_len

    return total_count, total_hours, records



def _parse_consumables(raw: Any) -> list[dict[str, Any]]:
    """Normalize consumables payload into a list.

    The consumables endpoint has multiple variants. For Scuba X1 (T1), we
    commonly see items with:
      - componentReplaceRemainHour (hours remaining)
      - lastChangeTime (epoch ms)
      - usePercentage (percent used; 0 means 100% left)
      - longestUseTime (string hours, often 8760)
      - dynamicsFields list with keys like component_replace, lastChangeTime
    """

    data = raw
    if isinstance(raw, dict) and "data" in raw:
        data = raw.get("data")

    # Unwrap common containers
    if isinstance(data, dict):
        for lk in ("list", "consumables", "consumableList", "consumablesList", "items"):
            if isinstance(data.get(lk), list):
                data = data.get(lk)
                break
            if isinstance(data.get(lk), dict):
                sub = data.get(lk) or {}
                if isinstance(sub.get("list"), list):
                    data = sub.get("list")
                    break

    out: list[dict[str, Any]] = []
    if not isinstance(data, list):
        return out

    def _to_float(v):
        if v is None:
            return None
        if isinstance(v, (int, float)):
            return float(v)
        if isinstance(v, str):
            s = v.strip()
            digits = "".join(ch for ch in s if (ch.isdigit() or ch == "."))
            if not digits:
                return None
            try:
                return float(digits)
            except Exception:
                return None
        return None

    def _dyn_get(item: dict, key: str):
        # Search dynamicsFields list for a matching key
        df = item.get("dynamicsFields")
        if isinstance(df, list):
            for it in df:
                if isinstance(it, dict) and str(it.get("key")).strip().lower() == key.lower():
                    return it.get("value")
        return None

    for item in data:
        if not isinstance(item, dict):
            continue

        name = _deep_get(item, ("consumablesName", "consumableName", "name", "title", "consumable", "consumables"))
        if not name:
            name = item.get("type") or item.get("consumableType") or "Consumable"
        name = str(name)

        # Remaining hours
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
            remaining = _dyn_get(item, "component_replace")
        remaining_hours = _to_float(remaining)

        # Heuristic fallback: find any remain/left hour-ish field
        if remaining_hours is None:
            try:
                for k, v in item.items():
                    if v is None or not isinstance(k, str):
                        continue
                    nk = ''.join(ch for ch in k.lower() if ch.isalnum())
                    if ('remain' in nk or 'left' in nk) and ('hour' in nk or nk.endswith('h')):
                        vv = _to_float(v)
                        if vv is not None and vv >= 0:
                            remaining_hours = vv
                            break
            except Exception:
                pass


        # Percent left
        percent_left = None
        use_pct = _deep_get(item, ("usePercentage", "use_percent", "usedPercent", "used_percentage"))
        use_pct_f = _to_float(use_pct)
        if use_pct_f is not None:
            # usePercentage is percent used (0 means 100% left)
            percent_left = max(0.0, min(100.0, 100.0 - use_pct_f))

        if percent_left is None:
            pct = _deep_get(item, ("percent", "remainPercent", "remainingPercent", "leftPercent", "left_percent", "remainPct", "remain_rate"))
            pct_f = _to_float(pct)
            if pct_f is not None:
                # assume already percent left
                percent_left = max(0.0, min(100.0, pct_f))

        # If still missing, compute from remaining/longest if available
        if percent_left is None and remaining_hours is not None:
            longest = _deep_get(item, ("longestUseTime", "maxUseTime", "max_time", "longest_use_time"))
            longest_f = _to_float(longest)
            if longest_f and longest_f > 0:
                percent_left = max(0.0, min(100.0, (remaining_hours / longest_f) * 100.0))

        # Last replacement time
        last_val = _deep_get(item, ("componentReplaceLastTime", "componentReplaceLastTimestamp", "componentReplaceLastTimeStamp", "lastChangeTime", "lastReplacementTime", "lastReplaceTime", "lastReplace", "replaceTime", "lastReplacement", "last_replacement_time"))
        if last_val is None:
            last_val = _dyn_get(item, "lastChangeTime")
        last_rep = _parse_dt(last_val)

        # Heuristic fallback: any last-replace timestamp field
        if last_rep is None:
            try:
                for k, v in item.items():
                    if v is None or not isinstance(k, str):
                        continue
                    nk = ''.join(ch for ch in k.lower() if ch.isalnum())
                    if 'last' in nk and 'time' in nk and not any(x in nk for x in ('start','end','create','update')):
                        dt = _parse_dt(v)
                        if dt is not None:
                            last_rep = dt
                            break
            except Exception:
                pass


        # Heuristic fallback: find any last replacement time-ish field
        if last_rep is None:
            try:
                for k, v in item.items():
                    if v is None or not isinstance(k, str):
                        continue
                    nk = ''.join(ch for ch in k.lower() if ch.isalnum())
                    if 'last' in nk and 'time' in nk:
                        dt = _parse_dt(v)
                        if dt is not None:
                            last_rep = dt
                            break
            except Exception:
                pass


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


class AiperDataUpdateCoordinator(DataUpdateCoordinator[dict[str, Any]]):
    """Class to manage fetching Aiper data."""

    def __init__(
        self,
        hass: HomeAssistant,
        api: AiperApi,
        scan_interval: int = DEFAULT_SCAN_INTERVAL,
        history_refresh_hours: int = DEFAULT_HISTORY_REFRESH_HOURS,
        consumables_refresh_hours: int = DEFAULT_CONSUMABLES_REFRESH_HOURS,
        clean_path_refresh_hours: int = DEFAULT_CLEAN_PATH_REFRESH_HOURS,
    ) -> None:
        """Initialize the coordinator."""
        self._normal_interval = timedelta(seconds=max(5, int(scan_interval)))
        self._fast_interval = timedelta(seconds=FAST_SCAN_INTERVAL_SECONDS)
        self._fast_poll_until = None  # type: ignore[assignment]
        self._last_online: dict[str, bool | None] = {}
        self._last_fast_trigger = None  # type: ignore[assignment]

        super().__init__(
            hass,
            _LOGGER,
            name=DOMAIN,
            update_interval=self._normal_interval,
        )
        self.api = api
        self._devices: dict[str, dict] = {}
        self._shadow_data: dict[str, dict] = {}
        # Additional REST-derived data that updates on a slower cadence.
        self._last_history_fetch: dict[str, datetime] = {}
        self._last_consumables_fetch: dict[str, datetime] = {}
        self._history_cache: dict[str, dict[str, Any]] = {}
        self._consumables_cache: dict[str, list[dict[str, Any]]] = {}
        self._last_clean_path_fetch: dict[str, datetime] = {}
        self._clean_path_cache: dict[str, int] = {}

        # Configurable refresh cadences (slower-changing data)
        self._history_refresh = timedelta(hours=max(1, int(history_refresh_hours)))
        self._consumables_refresh = timedelta(hours=max(1, int(consumables_refresh_hours)))
        self._clean_path_refresh = timedelta(hours=max(1, int(clean_path_refresh_hours)))

        # Command tracking (for community-friendly UX)
        # We do not apply optimistic state changes; instead we track pending commands
        # and mark them confirmed when the device reports the new value.
        self._command_state: dict[str, dict[str, dict[str, Any]]] = {}
        # Structure: {sn: {"pending": {kind: {...}}, "last": {kind: {...}}}}

    def _start_fast_poll_window(self, reason: str = "") -> None:
        """Enable a short fast-poll window and request an immediate refresh.

        This is used when the device appears to have come online (typically
        indicated by MQTT netstat updates) but the authoritative REST endpoint
        has not yet reflected the change.
        """
        now = dt_util.utcnow()
        self._last_fast_trigger = _ensure_utc_aware(self._last_fast_trigger)
        # Throttle triggers to avoid storming the cloud API on noisy MQTT traffic.
        if self._last_fast_trigger and (now - self._last_fast_trigger).total_seconds() < 5:
            return
        self._last_fast_trigger = now
        self._fast_poll_until = now + timedelta(seconds=FAST_SCAN_WINDOW_SECONDS)
        if self.update_interval != self._fast_interval:
            self.update_interval = self._fast_interval
        if reason:
            _LOGGER.debug("Fast poll window started (%s)", reason)
        # Request a refresh immediately; the coordinator will then schedule the
        # next refresh according to update_interval.
        self.hass.async_create_task(self.async_request_refresh())

    async def _async_update_data(self) -> dict[str, Any]:
        """Fetch data from API."""
        try:
            transitioned_online = False
            now = dt_util.utcnow()

            # Normalize cached timestamps (defensive against earlier versions)
            for _d in (self._last_history_fetch, self._last_consumables_fetch, self._last_clean_path_fetch):
                for _sn, _ts in list(_d.items()):
                    _d[_sn] = _ensure_utc_aware(_ts) or dt_util.utcnow()

            # Get device list
            devices = await self.hass.async_add_executor_job(self.api.get_devices)
            _LOGGER.debug("Got %d devices from API", len(devices))
            
            for device in devices:
                sn = device.get("sn")
                if not sn:
                    continue
                    
                self._devices[sn] = device
                
                # Get device online status
                status = None
                try:
                    status = await self.hass.async_add_executor_job(
                        self.api.get_device_status, sn
                    )
                except Exception as err:
                    _LOGGER.debug("Device %s status fetch failed: %s", sn, err)
                if status:
                    self._devices[sn]["status_data"] = status
                    if isinstance(status, dict):
                        _LOGGER.debug("Device %s status online=%s", sn, status.get("online"))
                    # Track last-seen when REST responds (even if device is Offline).
                    self._devices[sn]["_ha_last_seen"] = now
                # Get detailed device info (may contain state)
                info = None
                try:
                    info = await self.hass.async_add_executor_job(
                        self.api.get_device_info, sn
                    )
                except Exception as err:
                    _LOGGER.debug("Device %s info fetch failed: %s", sn, err)
                if info:
                    self._devices[sn]["info"] = info

                    # Try to extract shadow-like data from info
                    if "shadow" not in self._shadow_data.get(sn, {}):
                        self._shadow_data.setdefault(sn, {})
                        # Some APIs return state in the device info
                        if "battery" in info or "cap" in info:
                            self._shadow_data[sn]["machine"] = {
                                "cap": info.get("battery", info.get("cap")),
                                "status": info.get("status", info.get("workStatus")),
                                "mode": info.get("mode", info.get("workMode")),
                            }
                        if "online" in info:
                            self._shadow_data[sn]["netstat"] = {
                                "online": 1 if info.get("online") else 0,
                            }

                    # Track last-seen when REST responds.
                    self._devices[sn]["_ha_last_seen"] = now
            
                # Compute authoritative online state and squash stale connectivity fields when offline.
                online_state = None
                status_data = (self._devices.get(sn) or {}).get("status_data") or {}
                if isinstance(status_data, dict) and "online" in status_data:
                    online_state = _coerce_bool(status_data.get("online"))
                if online_state is None and "online" in (self._devices.get(sn) or {}):
                    online_state = _coerce_bool((self._devices.get(sn) or {}).get("online"))
                if online_state is None and info and isinstance(info, dict) and "online" in info:
                    online_state = _coerce_bool(info.get("online"))

                # Detect Offline -> Online transitions (authoritative REST only).
                prev = self._last_online.get(sn)
                sn_just_online = prev is False and online_state is True
                if sn_just_online:
                    transitioned_online = True
                self._last_online[sn] = online_state

                self._devices[sn]["_ha_online"] = online_state
                shadow = self._shadow_data.setdefault(sn, {})
                netstat = shadow.setdefault("netstat", {})
                if online_state is True:
                    netstat["online"] = 1
                elif online_state is False:
                    netstat["online"] = 0
                    netstat["ble"] = 0
                    netstat["sta"] = 0
                    netstat["nearFieldBind"] = 0
                    machine = shadow.setdefault("machine", {})
                    machine["link"] = 0
                    self._devices[sn]["wifiName"] = None
                    self._devices[sn]["wifiRssi"] = None

                # Derive supported modes (capability-driven). We use any list
                # present in REST info or MQTT payloads; otherwise fall back to
                # the known MODE_MAP keys.
                supported_ids: list[int] = []
                try:
                    candidates: list[Any] = []
                    if info and isinstance(info, dict):
                        for k in (
                            "modeList",
                            "workModeList",
                            "supportedModes",
                            "supportModes",
                            "cleanModeList",
                        ):
                            if k in info:
                                candidates.append(info.get(k))
                    # MQTT component
                    shadow = self._shadow_data.get(sn) or {}
                    gwm = shadow.get("getworkmode") or {}
                    if isinstance(gwm, dict):
                        for k in ("modeList", "workModeList", "supportedModes"):
                            if k in gwm:
                                candidates.append(gwm.get(k))

                    for cand in candidates:
                        if isinstance(cand, list):
                            for v in cand:
                                if isinstance(v, (int, float)):
                                    supported_ids.append(int(v))
                                elif isinstance(v, dict):
                                    for kk in ("mode", "id", "value"):
                                        if kk in v and v.get(kk) is not None:
                                            try:
                                                supported_ids.append(int(v.get(kk)))
                                            except Exception:
                                                pass
                                elif isinstance(v, str) and v.strip().isdigit():
                                    supported_ids.append(int(v.strip()))
                        elif isinstance(cand, (int, float)):
                            supported_ids.append(int(cand))
                    # De-dup and preserve ordering
                    seen = set()
                    supported_ids = [x for x in supported_ids if not (x in seen or seen.add(x))]
                except Exception:
                    supported_ids = []
                if not supported_ids:
                    supported_ids = list(MODE_MAP.keys())
                self._devices[sn]["_ha_supported_mode_ids"] = supported_ids

                # Parse device info / firmware (diagnostic). Keys vary by region/firmware.
                # We search across multiple blobs (device list, info, status, shadow) to
                # maximize compatibility across regional API variants.
                diag_blob = {
                    "device": device,
                    "info": info or {},
                    "status": status or {},
                    "shadow": self._shadow_data.get(sn, {}),
                }

                fw_main = _deep_get(
                    diag_blob,
                    (
                        "mainFirmwareVersion",
                        "mainVersion",
                        "mainVer",
                        "main_version",
                        "firmwareVersion",
                        "firmware",
                        "swVersion",
                        "version",
                    ),
                )
                fw_mcu = _deep_get(diag_blob, ("mcuFirmwareVersion", "mcuVersion", "mcuVer", "mcu_version", "mcu"))
                ip_addr = _deep_get(diag_blob, ("ipAddress", "ipAddr", "ip_address", "ip"))
                wifi_name = _deep_get(diag_blob, ("wifiName", "wifi_name", "wifiSsid", "ssid"))
                ap_hotspot = _deep_get(
                    diag_blob,
                    (
                        "apHotspot",
                        "apSsid",
                        "apSSID",
                        "apName",
                        "ap_hotspot",
                        "ap_ssid",
                        "hotspot",
                    ),
                )
                # Prefer the human-readable SSID from the app payload if present
                if isinstance(wifi_name, str) and wifi_name.strip():
                    if ap_hotspot is None or not isinstance(ap_hotspot, str) or not str(ap_hotspot).strip():
                        ap_hotspot = wifi_name

                bt_name = _deep_get(
                    diag_blob,
                    (
                        "bluetoothName",
                        "btName",
                        "bleName",
                        "bluetooth",
                        "ble",
                    ),
                )

                self._devices[sn]["_ha_fw_main"] = fw_main
                self._devices[sn]["_ha_fw_mcu"] = fw_mcu
                self._devices[sn]["_ha_ip_address"] = ip_addr
                self._devices[sn]["_ha_ap_hotspot"] = ap_hotspot
                self._devices[sn]["_ha_bluetooth_name"] = bt_name


                # Refresh slower-changing REST data only occasionally.
                # NOTE: These endpoints are historical/account-scoped in the app
                # and should populate even if the robot is currently Offline.

                # Cleaning history / totals
                last_h = _ensure_utc_aware(self._last_history_fetch.get(sn))
                if sn_just_online or last_h is None or (now - last_h) >= self._history_refresh:
                    raw_hist = None
                    try:
                        raw_hist = await self.hass.async_add_executor_job(self.api.get_cleaning_history, sn)
                    except Exception as err:
                        _LOGGER.debug("Cleaning history fetch failed for %s: %s", sn, err)
                    tcount, thours, recs = _parse_cleaning_history(raw_hist)
                    self._history_cache[sn] = {
                        "total_count": tcount,
                        "total_hours": thours,
                        "records": recs,
                        "raw": raw_hist,
                    }
                    self._last_history_fetch[sn] = now
                hist = self._history_cache.get(sn) or {}
                self._devices[sn]["_ha_total_cleanings"] = hist.get("total_count")
                self._devices[sn]["_ha_total_cleaning_hours"] = hist.get("total_hours")
                th = hist.get("total_hours")
                self._devices[sn]["_ha_total_cleaning_minutes"] = (round(th * 60) if isinstance(th, (int, float)) else None)
                records = hist.get("records") or []
                self._devices[sn]["_ha_cleaning_records"] = records
                # Last record
                last_rec = records[0] if isinstance(records, list) and records else None
                if isinstance(last_rec, dict):
                    self._devices[sn]["_ha_last_cleaning_mode"] = last_rec.get("mode")
                    self._devices[sn]["_ha_last_cleaning_start"] = last_rec.get("start")
                    self._devices[sn]["_ha_last_cleaning_duration_min"] = last_rec.get("duration_min")

                # Consumables
                last_c = _ensure_utc_aware(self._last_consumables_fetch.get(sn))
                if sn_just_online or last_c is None or (now - last_c) >= self._consumables_refresh:
                    raw_cons = None
                    try:
                        raw_cons = await self.hass.async_add_executor_job(self.api.get_consumables, sn)
                    except Exception as err:
                        _LOGGER.debug("Consumables fetch failed for %s: %s", sn, err)
                    cons_list = _parse_consumables(raw_cons)
                    # Always update cache when the call returned (even if parsing yielded empty),
                    # to avoid requiring an integration reload to observe new values.
                    if raw_cons is not None:
                        self._consumables_cache[sn] = cons_list
                    self._last_consumables_fetch[sn] = now
                self._devices[sn]["_ha_consumables"] = self._consumables_cache.get(sn) or []

                # Clean path preference
                last_p = _ensure_utc_aware(self._last_clean_path_fetch.get(sn))
                if sn_just_online or last_p is None or (now - last_p) >= self._clean_path_refresh:
                    val = None
                    try:
                        val = await self.hass.async_add_executor_job(self.api.query_clean_path_setting, sn)
                    except Exception as err:
                        _LOGGER.debug("Clean path fetch failed for %s: %s", sn, err)
                    # Only update cache if the API returned a value (avoid overwriting
                    # a previously known setting with None due to transient failures).
                    if val is not None:
                        self.set_clean_path_cache(sn, val)
                    self._last_clean_path_fetch[sn] = now
                self._devices[sn]["_ha_clean_path"] = self._clean_path_cache.get(sn)

            # Expire pending commands (UI hints)
            for _sn in list(self._command_state.keys()):
                try:
                    self.expire_pending_commands(_sn)
                except Exception:
                    pass

            # Adapt polling cadence.
            if transitioned_online:
                self._fast_poll_until = now + timedelta(seconds=FAST_SCAN_WINDOW_SECONDS)
                self.update_interval = self._fast_interval
                _LOGGER.debug(
                    "Detected Offline->Online transition; enabling fast polling for %ss",
                    FAST_SCAN_WINDOW_SECONDS,
                )

            if self._fast_poll_until and now >= self._fast_poll_until:
                # Fast window expired; return to normal cadence.
                self._fast_poll_until = None
                if self.update_interval != self._normal_interval:
                    self.update_interval = self._normal_interval

            # Merge device data with shadow data
            result = {}
            for sn, device in self._devices.items():
                result[sn] = {
                    **device,
                    "shadow": self._shadow_data.get(sn, {}),
                }

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

        AWSIoTPythonSDK invokes subscription callbacks on a background thread.
        Home Assistant state updates must occur on the HA event loop.
        """
        if data is None and isinstance(sn, dict):
            payload = sn
            data = payload
            sn = (
                payload.get("_sn")
                or payload.get("sn")
                or (payload.get("data") or {}).get("sn")
            )
            if not sn:
                _LOGGER.debug("Ignoring MQTT update with no serial number: %s", payload)
                return

        if data is None:
            return

        try:
            self.hass.loop.call_soon_threadsafe(self._apply_shadow_update, str(sn), data)
        except Exception:
            # Fallback (should not generally happen)
            self._apply_shadow_update(str(sn), data)

    def make_shadow_callback(self, sn: str):
        """Return a callback suitable for AWSIoTPythonSDK subscribe()."""

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
        shadow = self._shadow_data.setdefault(sn, {})

        def _deep_merge(dst: dict, src: dict) -> dict:
            """Recursively merge src into dst.

            Aiper devices often publish partial updates (e.g. only +WARN or
            +RECORDS). Replacing the entire machine/netstat payload causes HA
            entities to flicker to Unknown/unavailable. We therefore merge
            fields and only overwrite keys that are explicitly present.
            """
            for key, val in (src or {}).items():
                if isinstance(val, dict) and isinstance(dst.get(key), dict):
                    _deep_merge(dst[key], val)
                else:
                    dst[key] = val
            return dst

        # AWS IoT shadow messages often look like:
        # {"state": {"reported": {...}}} or {"state": {"delta": {...}}}
        #
        # NOTE: AWS also publishes *delta-only* messages on $aws/.../shadow/update/delta.
        # These contain desired state (e.g., Machine.mode) but are not authoritative
        # for the device's current state. If we merge them, the UI can oscillate
        # between the real reported mode and an unfulfilled desired mode.
        # Determine source topic (if available) to safely ignore desired-only deltas.
        topic = data.get("_topic") if isinstance(data, dict) else None
        if isinstance(topic, str) and "shadow/update/delta" in topic:
            # Delta topics contain desired-state only. We generally ignore them to
            # avoid UI oscillation, *but* some firmwares never report certain
            # preferences (notably cleanPath). Capture those as a fallback.
            try:
                st = data.get("state") if isinstance(data, dict) else None
                if isinstance(st, dict):
                    m = st.get("Machine")
                    if isinstance(m, dict):
                        cp = _clean_path_value(
                            m.get("cleanPath")
                            or m.get("clean_path")
                            or m.get("cleanPathSetting")
                            or m.get("clean_path_setting")
                        )
                        if cp is not None:
                            dm = shadow.setdefault("desired_machine", {})
                            dm["cleanPath"] = int(cp)
            except Exception:
                pass

            _LOGGER.debug("Ignoring shadow delta message for %s", sn)
            return

        payload = data

        # AWS IoT shadow 'documents' messages: extract current.state.reported when present.
        if isinstance(topic, str) and "shadow/update/documents" in topic and isinstance(data, dict):
            current = data.get("current") or {}
            if isinstance(current, dict):
                cur_state = current.get("state") or {}
                # Capture desired cleanPath from documents messages (some devices
                # never include it in reported state).
                try:
                    if isinstance(cur_state, dict):
                        des = cur_state.get("desired")
                        if isinstance(des, dict):
                            m = des.get("Machine")
                            if isinstance(m, dict):
                                cp = _clean_path_value(
                                    m.get("cleanPath")
                                    or m.get("clean_path")
                                    or m.get("cleanPathSetting")
                                    or m.get("clean_path_setting")
                                )
                                if cp is not None:
                                    dm = shadow.setdefault("desired_machine", {})
                                    dm["cleanPath"] = int(cp)
                except Exception:
                    pass

                if isinstance(cur_state, dict) and isinstance(cur_state.get("reported"), dict):
                    payload = cur_state.get("reported") or {}
                elif isinstance(cur_state, dict):
                    payload = cur_state

        # Standard shadow payloads: only accept 'reported'. Ignore 'desired'/'delta' to avoid UI oscillation.
        if isinstance(payload, dict) and isinstance(payload.get("state"), dict):
            state = payload.get("state") or {}
            # Capture desired cleanPath preference (reported often omits it).
            try:
                for cand in (state.get("desired"), state.get("delta")):
                    if isinstance(cand, dict):
                        m = cand.get("Machine")
                        if isinstance(m, dict):
                            cp = _clean_path_value(
                                m.get("cleanPath")
                                or m.get("clean_path")
                                or m.get("cleanPathSetting")
                                or m.get("clean_path_setting")
                            )
                            if cp is not None:
                                dm = shadow.setdefault("desired_machine", {})
                                dm["cleanPath"] = int(cp)
            except Exception:
                pass
            if isinstance(state.get("reported"), dict):
                payload = state.get("reported") or {}
            else:
                # If this is desired/delta-only, ignore.
                if any(k in state for k in ("desired", "delta")):
                    _LOGGER.debug("Ignoring non-reported shadow update for %s (keys=%s)", sn, list(state.keys()))
                    return
                payload = state

        # Some upstream messages wrap a nested payload under "data".

        if isinstance(payload, dict) and "data" in payload and isinstance(payload.get("data"), dict) and payload.get("type"):
            # e.g. {"type": "Machine", "data": {...}}
            pass

        # Handle different Aiper message formats.
        # IMPORTANT: always merge into existing state to avoid flicker.
        machine = shadow.setdefault("machine", {})
        if "Machine" in payload and isinstance(payload.get("Machine"), dict):
            _deep_merge(machine, payload.get("Machine") or {})
        elif "machine" in payload and isinstance(payload.get("machine"), dict):
            _deep_merge(machine, payload.get("machine") or {})
        elif payload.get("type") == "Machine":
            machine_data = payload.get("data") or {}

            update: dict[str, Any] = {}

            # Copy any structured fields that are present.
            for k in (
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
                if k in machine_data and machine_data.get(k) is not None:
                    update[k] = machine_data.get(k)

            # Some devices publish condensed "report" strings.
            report = machine_data.get("report")
            if isinstance(report, str):
                parsed = self._parse_machine_report(report)
                if parsed:
                    # records are additive; do not overwrite
                    if "records" in parsed:
                        recs = machine.setdefault("records", [])
                        if isinstance(recs, list):
                            recs.extend(parsed.get("records") or [])
                        parsed = {k: v for k, v in parsed.items() if k != "records"}
                    update.update(parsed)

            if update:
                _deep_merge(machine, update)

        netstat = shadow.setdefault("netstat", {})
        prev_mqtt_online = _coerce_bool(netstat.get("online"))
        if "NetStat" in payload and isinstance(payload.get("NetStat"), dict):
            _deep_merge(netstat, payload.get("NetStat") or {})
        elif "netstat" in payload and isinstance(payload.get("netstat"), dict):
            _deep_merge(netstat, payload.get("netstat") or {})
        elif payload.get("type") == "NetStat":
            if isinstance(payload.get("data"), dict):
                _deep_merge(netstat, payload.get("data") or {})

        # If MQTT indicates the device has just come online, start a short fast
        # polling window so the authoritative REST status can catch up quickly.
        curr_mqtt_online = _coerce_bool(netstat.get("online"))
        if prev_mqtt_online is not True and curr_mqtt_online is True:
            rest_online = None
            try:
                if self.data is not None and sn in self.data:
                    rest_online = _coerce_bool((self.data.get(sn) or {}).get("_ha_online"))
            except Exception:
                rest_online = None
            if rest_online is None:
                rest_online = self._last_online.get(sn)
            if rest_online is False:
                self._start_fast_poll_window(reason=f"mqtt_online_transition:{sn}")

        # Store other shadow components (as discovered). These also arrive as
        # partial updates; merge to prevent "Unknown" flicker.
        for key in ["OpInfo", "OtaStatus", "CycleWork", "GetWorkMode", "RubbishBoxStatus"]:
            lk = key.lower()
            comp = shadow.setdefault(lk, {})
            if key in payload and isinstance(payload.get(key), dict):
                _deep_merge(comp, payload.get(key) or {})
            elif payload.get("type") == key and isinstance(payload.get("data"), dict):
                _deep_merge(comp, payload.get("data") or {})
        
        self._shadow_data[sn] = shadow

        # Promote cleanPath discovered in other components into machine (best-effort).
        try:
            if isinstance(machine, dict) and machine.get("cleanPath") is None and machine.get("clean_path") is None:
                cp = self._extract_clean_path_value(sn, machine)
                if cp is not None:
                    machine["cleanPath"] = cp
        except Exception:
            pass

        # Merge shadow into current coordinator data and notify listeners.
        if self.data is not None:
            new_data: dict[str, Any] = dict(self.data)
            dev = dict(new_data.get(sn, {}))
            dev["shadow"] = shadow
            new_data[sn] = dev
            self.async_set_updated_data(new_data)

        # Update last-seen time on any MQTT activity.
        try:
            if sn in self._devices:
                self._devices[sn]["_ha_last_seen"] = dt_util.utcnow()
        except Exception:
            pass

        # Confirm pending commands when the device reports the new value.
        try:
            self._confirm_pending_commands(sn, shadow.get("machine") or {})
        except Exception:
            pass

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
                elif ln.startswith("+RECORDS:"):
                    # Optional: history records. Keep raw for later reverse engineering.
                    # +RECORDS:<idx>,<type>,<date>,<time>,<value>
                    # Do not overwrite anything; store as list.
                    recs = result.setdefault("records", [])
                    recs.append(ln)
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

    def get_device(self, sn: str) -> dict | None:
        """Get device data by serial number."""
        if self.data:
            return self.data.get(sn)
        return None

    def get_machine_state(self, sn: str) -> dict:
        """Get the Machine shadow state for a device."""
        device = self.get_device(sn)
        if device and "shadow" in device:
            return device["shadow"].get("machine", {})
        return {}


    def get_netstat(self, sn: str) -> dict:
        """Get the NetStat shadow state for a device."""
        device = self.get_device(sn)
        if device and "shadow" in device:
            return device["shadow"].get("netstat", {})
        return {}

    # -----------------
    # Command tracking
    # -----------------

    PENDING_TIMEOUT_SECONDS = 120

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
            try:
                since = dt_util.parse_datetime(info.get("since")) if info.get("since") else None
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
        # Clean path is especially inconsistent across firmwares; normalize.
        reported_clean_path = self._extract_clean_path_value(sn, machine)

        now = dt_util.utcnow().isoformat()
        changed = False

        if "mode" in pend:
            tgt = _to_int((pend.get("mode") or {}).get("target"))
            if tgt is not None and reported_mode is not None and tgt == reported_mode:
                pend.pop("mode", None)
                st.setdefault("last", {})["mode"] = {
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
        - Machine.cleanPath (or clean_path)
        - Nested machine/settings keys
        - GetWorkMode / CycleWork / OpInfo payloads
        - REST info blobs

        Returns a normalized integer when possible.
        """
        try:
            if machine is None:
                machine = self.get_machine_state(sn) or {}
        except Exception:
            machine = machine or {}

        # Direct keys first.
        if isinstance(machine, dict):
            for k in ("cleanPath", "clean_path"):
                if k in machine and machine.get(k) is not None:
                    v = _clean_path_value(machine.get(k))
                    if v is not None:
                        return v

        # Deep search within machine (some firmwares nest values under settings/config).
        try:
            v = _clean_path_value(
                _deep_get(
                    machine,
                    (
                        "cleanPath",
                        "clean_path",
                        "cleanPathSetting",
                        "clean_path_setting",
                        "path",
                        "sweepPath",
                        "swimPath",
                    ),
                )
            )
            if v is not None:
                return v
        except Exception:
            pass

        # Search other shadow components that may carry the value.
        shadow = self._shadow_data.get(sn) or {}
        if isinstance(shadow, dict):
            for comp_key in ("getworkmode", "cyclework", "opinfo", "rubbishboxstatus", "otastatus"):
                comp = shadow.get(comp_key)
                if isinstance(comp, dict):
                    try:
                        v = _clean_path_value(
                            _deep_get(
                                comp,
                                (
                                    "cleanPath",
                                    "clean_path",
                                    "cleanPathSetting",
                                    "clean_path_setting",
                                    "path",
                                    "sweepPath",
                                    "swimPath",
                                ),
                            )
                        )
                        if v is not None:
                            return v
                    except Exception:
                        continue

        # REST info blob (if present)
        try:
            dev = self._devices.get(sn) or {}
            info = dev.get("info") if isinstance(dev, dict) else None
            if isinstance(info, dict):
                v = _clean_path_value(
                    _deep_get(
                        info,
                        (
                            "cleanPath",
                            "clean_path",
                            "cleanPathSetting",
                            "clean_path_setting",
                            "path",
                        ),
                    )
                )
                if v is not None:
                    return v
        except Exception:
            pass

        return None


    def set_clean_path_cache(self, sn: str, value: int) -> None:
        """Update cached clean-path preference (used by REST polling)."""
        self._clean_path_cache[sn] = int(value)
        self._last_clean_path_fetch[sn] = dt_util.utcnow()

    def get_clean_path(self, sn: str) -> int | None:
        """Get current clean-path preference.

        Community-friendly behavior:
        - Prefer device-reported state from MQTT/shadow (where available)
        - Fall back to the REST-polled cached value
        """
        v = self._extract_clean_path_value(sn)
        if v is not None:
            return v

        # Some firmwares never report cleanPath in reported state. In those
        # cases, we fall back to the last desired value seen on the shadow.
        try:
            shadow = self._shadow_data.get(sn) or {}
            dm = shadow.get("desired_machine") if isinstance(shadow, dict) else None
            if isinstance(dm, dict):
                dv = _clean_path_value(
                    dm.get("cleanPath")
                    or dm.get("clean_path")
                    or dm.get("cleanPathSetting")
                    or dm.get("clean_path_setting")
                )
                if dv is not None:
                    return dv
        except Exception:
            pass

        if sn in self._devices and "_ha_clean_path" in self._devices[sn]:
            try:
                val = self._devices[sn].get("_ha_clean_path")
                v = _clean_path_value(val)
                return v
            except Exception:
                return None

        val = self._clean_path_cache.get(sn)
        return _clean_path_value(val)
