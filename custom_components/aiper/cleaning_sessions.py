"""Per-device ledger of recently recognized cleaning sessions.

The same cleaning run can reach the integration twice: once as a live MQTT
report (Scuba V3 Ultra ``FinishTaskReport``) and again later as a REST history
row. This module reconciles those reports into one summary per run, keeps a
bounded history, and records which completions have already been announced so
that redelivery, reconnects, backfilled history and restarts stay quiet.

It is pure Python and has no Home Assistant dependency.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any

__all__ = [
    "MAX_SESSIONS_PER_DEVICE",
    "STORE_VERSION",
    "CleaningSession",
    "IngestResult",
    "SessionLedger",
    "candidate_from_finish",
    "candidate_from_record",
]

MAX_SESSIONS_PER_DEVICE = 20
STORE_VERSION = 1
# Two reports describe the same run when their finish (or start) times fall
# inside this window and their durations do not contradict each other.
MATCH_TOLERANCE = timedelta(minutes=5)
# A shared run identifier needs a much tighter timestamp agreement.
RUN_ID_TOLERANCE = timedelta(seconds=120)
DURATION_TOLERANCE = 0.2
DURATION_FLOOR_MIN = 1.0


@dataclass
class CleaningSession:
    """One recognized cleaning run. Every field except ``session_id`` may be missing."""

    session_id: str
    start: datetime | None = None
    finish: datetime | None = None
    duration_min: float | None = None
    mode: str | None = None
    result: int | None = None
    run_id: str | None = None
    sources: set[str] = field(default_factory=set)
    announced: bool = False
    unresolved: bool = False

    @classmethod
    def create(
        cls,
        sn: str,
        *,
        source: str,
        start: datetime | None = None,
        finish: datetime | None = None,
        duration_min: float | None = None,
        mode: str | None = None,
        result: int | None = None,
        run_id: str | None = None,
    ) -> CleaningSession:
        """Build a session whose identifier is derived from its strongest timestamp."""
        return cls(
            session_id=_session_id(sn, start, finish, run_id),
            start=_utc(start),
            finish=_utc(finish),
            duration_min=duration_min,
            mode=mode,
            result=result,
            run_id=run_id,
            sources={source},
        )

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable form for storage."""
        return {
            "session_id": self.session_id,
            "start": self.start.isoformat() if self.start else None,
            "finish": self.finish.isoformat() if self.finish else None,
            "duration_min": self.duration_min,
            "mode": self.mode,
            "result": self.result,
            "run_id": self.run_id,
            "sources": sorted(self.sources),
            "announced": self.announced,
            "unresolved": self.unresolved,
        }

    @classmethod
    def from_dict(cls, data: Any) -> CleaningSession | None:
        """Restore a session, returning None for unusable stored data."""
        if not isinstance(data, dict) or not isinstance(data.get("session_id"), str):
            return None
        duration = data.get("duration_min")
        result = data.get("result")
        sources = data.get("sources")
        return cls(
            session_id=data["session_id"],
            start=_parse_iso(data.get("start")),
            finish=_parse_iso(data.get("finish")),
            duration_min=float(duration)
            if isinstance(duration, (int, float)) and not isinstance(duration, bool)
            else None,
            mode=data["mode"] if isinstance(data.get("mode"), str) else None,
            result=result if isinstance(result, int) and not isinstance(result, bool) else None,
            run_id=data["run_id"] if isinstance(data.get("run_id"), str) else None,
            sources={s for s in sources if isinstance(s, str)} if isinstance(sources, list) else set(),
            announced=data.get("announced") is True,
            unresolved=data.get("unresolved") is True,
        )

    def sort_key(self) -> datetime:
        """Newest-first ordering key."""
        return self.finish or self.start or datetime.min.replace(tzinfo=UTC)


@dataclass
class IngestResult:
    """Outcome of offering one candidate to the ledger."""

    session: CleaningSession
    created: bool = False
    enriched: bool = False


def _utc(value: datetime | None) -> datetime | None:
    if value is None:
        return None
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


def _parse_iso(value: Any) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        return _utc(datetime.fromisoformat(value))
    except ValueError:
        return None


def _session_id(sn: str, start: datetime | None, finish: datetime | None, run_id: str | None) -> str:
    start_utc, finish_utc = _utc(start), _utc(finish)
    if finish_utc is not None:
        basis = f"{sn}|f|{int(finish_utc.timestamp())}"
    elif start_utc is not None:
        basis = f"{sn}|s|{int(start_utc.timestamp())}|{run_id or ''}"
    else:
        basis = f"{sn}|r|{run_id or ''}"
    return hashlib.sha256(basis.encode()).hexdigest()[:16]


def _durations_compatible(a: float | None, b: float | None) -> bool:
    if a is None or b is None:
        return True
    return abs(a - b) <= max(DURATION_TOLERANCE * max(a, b), DURATION_FLOOR_MIN)


def _within(a: datetime | None, b: datetime | None, window: timedelta) -> bool | None:
    """Compare two optional timestamps; None means they cannot be compared."""
    if a is None or b is None:
        return None
    return abs(a - b) <= window


def _matches(existing: CleaningSession, cand: CleaningSession) -> bool:
    if existing.run_id and cand.run_id and existing.run_id == cand.run_id:
        close = _within(existing.finish, cand.finish, RUN_ID_TOLERANCE)
        if close is not None:
            return close
        close = _within(existing.start, cand.start, RUN_ID_TOLERANCE)
        return True if close is None else close
    finish_close = _within(existing.finish, cand.finish, MATCH_TOLERANCE)
    if finish_close is not None:
        return finish_close and _durations_compatible(existing.duration_min, cand.duration_min)
    start_close = _within(existing.start, cand.start, MATCH_TOLERANCE)
    if start_close is not None:
        return start_close and _durations_compatible(existing.duration_min, cand.duration_min)
    return False


_MERGE_FIELDS = ("start", "finish", "duration_min", "mode", "result", "run_id")


class SessionLedger:
    """Bounded per-device record of reconciled cleaning sessions."""

    def __init__(self) -> None:
        self._sessions: dict[str, list[CleaningSession]] = {}
        self._baselined: set[str] = set()

    # -- queries ---------------------------------------------------------
    def sessions(self, sn: str) -> list[CleaningSession]:
        """Return the device's sessions, newest first."""
        return list(self._sessions.get(sn, []))

    def latest(self, sn: str) -> CleaningSession | None:
        """Return the most recent resolved session, if any."""
        return next((s for s in self._sessions.get(sn, []) if not s.unresolved), None)

    def is_baselined(self, sn: str) -> bool:
        """Whether history for this device has already been seeded quietly."""
        return sn in self._baselined

    def pending(self) -> list[tuple[str, CleaningSession]]:
        """Confirmed, not-yet-announced completions, oldest first per device."""
        out: list[tuple[str, CleaningSession]] = []
        for sn, sessions in self._sessions.items():
            out.extend(
                (sn, s)
                for s in reversed(sessions)
                if not s.announced and not s.unresolved and s.sources and s.finish is not None
            )
        return out

    def summary(self) -> dict[str, int]:
        """Return value-free counts for diagnostics."""
        every = [s for sessions in self._sessions.values() for s in sessions]
        return {
            "devices": len(self._sessions),
            "sessions": len(every),
            "announced": sum(1 for s in every if s.announced),
            "unresolved": sum(1 for s in every if s.unresolved),
            "baselined_devices": len(self._baselined),
        }

    # -- mutation --------------------------------------------------------
    def ingest(self, sn: str, cand: CleaningSession, *, quiet_before: datetime | None = None) -> IngestResult:
        """Merge a candidate into the ledger, or record it as a new session."""
        sessions = self._sessions.setdefault(sn, [])
        matches = [s for s in sessions if not s.unresolved and _matches(s, cand)]
        if len(matches) == 1:
            result = IngestResult(matches[0], enriched=self._merge(matches[0], cand))
        elif len(matches) > 1:
            duplicate = next((s for s in sessions if s.unresolved and s.session_id == cand.session_id), None)
            if duplicate is not None:
                return IngestResult(duplicate)
            cand.unresolved = True
            result = IngestResult(self._insert(sessions, cand), created=True)
        else:
            # Two different runs can end in the same second; keep identifiers unique.
            taken = {s.session_id for s in sessions}
            while cand.session_id in taken:
                cand.session_id = hashlib.sha256(f"{cand.session_id}|collision".encode()).hexdigest()[:16]
            result = IngestResult(self._insert(sessions, cand), created=True)
        session = result.session
        if quiet_before is not None and session.finish is not None and session.finish < quiet_before:
            session.announced = True
        return result

    def baseline(self, sn: str) -> None:
        """Mark everything known for a device as already announced."""
        for session in self._sessions.get(sn, []):
            session.announced = True
        self._baselined.add(sn)

    def mark_announced(self, sn: str, session_id: str) -> bool:
        """Record that a completion was announced. Returns False for unknown sessions."""
        for session in self._sessions.get(sn, []):
            if session.session_id == session_id:
                session.announced = True
                return True
        return False

    @staticmethod
    def _merge(existing: CleaningSession, cand: CleaningSession) -> bool:
        changed = False
        for name in _MERGE_FIELDS:
            if getattr(existing, name) is None and getattr(cand, name) is not None:
                setattr(existing, name, getattr(cand, name))
                changed = True
        if not cand.sources <= existing.sources:
            existing.sources |= cand.sources
            changed = True
        return changed

    @staticmethod
    def _insert(sessions: list[CleaningSession], cand: CleaningSession) -> CleaningSession:
        sessions.append(cand)
        sessions.sort(key=CleaningSession.sort_key, reverse=True)
        del sessions[MAX_SESSIONS_PER_DEVICE:]
        return cand

    # -- persistence -----------------------------------------------------
    def to_store(self) -> dict[str, Any]:
        """Return the JSON-serializable ledger."""
        return {
            "version": STORE_VERSION,
            "baselined": sorted(self._baselined),
            "devices": {sn: [s.to_dict() for s in sessions] for sn, sessions in self._sessions.items()},
        }

    @classmethod
    def from_store(cls, data: Any) -> SessionLedger:
        """Restore a ledger; unusable data yields an empty one."""
        ledger = cls()
        if not isinstance(data, dict) or data.get("version") != STORE_VERSION:
            return ledger
        baselined = data.get("baselined")
        if isinstance(baselined, list):
            ledger._baselined = {sn for sn in baselined if isinstance(sn, str)}
        devices = data.get("devices")
        if isinstance(devices, dict):
            for sn, rows in devices.items():
                if not isinstance(sn, str) or not isinstance(rows, list):
                    continue
                restored = [s for s in (CleaningSession.from_dict(row) for row in rows) if s is not None]
                restored.sort(key=CleaningSession.sort_key, reverse=True)
                ledger._sessions[sn] = restored[:MAX_SESSIONS_PER_DEVICE]
        return ledger


def _epoch(value: Any) -> datetime | None:
    if isinstance(value, bool) or value is None:
        return None
    try:
        number = float(value)
    except (TypeError, ValueError):
        return None
    if number <= 0:
        return None
    if number > 10_000_000_000:
        number /= 1000.0
    try:
        return datetime.fromtimestamp(number, tz=UTC)
    except (OverflowError, OSError, ValueError):
        return None


def candidate_from_finish(sn: str, finish: dict[str, Any], summary: dict[str, Any]) -> CleaningSession | None:
    """Build a candidate from a V3 Ultra ``FinishTaskReport`` and its derived summary.

    Without the report's own finish timestamp the completion cannot be dated,
    so no candidate is produced.
    """
    finished_at = _epoch(finish.get("ts"))
    task = finish.get("task")
    if finished_at is None or not isinstance(task, dict):
        return None
    result = task.get("cleanResult")
    name_id = task.get("nameID")
    duration = summary.get("last_cleaning_duration")
    return CleaningSession.create(
        sn,
        source="mqtt",
        start=summary.get("last_cleaning_start"),
        finish=finished_at,
        duration_min=float(duration) if isinstance(duration, (int, float)) and not isinstance(duration, bool) else None,
        mode=summary.get("last_cleaning_mode"),
        result=result if isinstance(result, int) and not isinstance(result, bool) else None,
        run_id=name_id if isinstance(name_id, str) and name_id else None,
    )


def candidate_from_record(sn: str, record: dict[str, Any]) -> CleaningSession | None:
    """Build a candidate from one parsed REST cleaning-history record."""
    start = record.get("start")
    if not isinstance(start, datetime):
        return None
    duration = record.get("duration_min")
    duration_min = float(duration) if isinstance(duration, (int, float)) and not isinstance(duration, bool) else None
    finish = start + timedelta(minutes=duration_min) if duration_min is not None else None
    mode = record.get("mode")
    return CleaningSession.create(
        sn,
        source="rest",
        start=start,
        finish=finish,
        duration_min=duration_min,
        mode=mode if isinstance(mode, str) else None,
    )
