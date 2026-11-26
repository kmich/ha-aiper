"""Cleaning-session ledger: reconciliation, announcement state and persistence."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from typing import Any, cast

from custom_components.aiper.cleaning_sessions import (
    MAX_SESSIONS_PER_DEVICE,
    CleaningSession,
    SessionLedger,
    candidate_from_finish,
    candidate_from_record,
)
from tests.coordinator_factory import BaseFakeApi, make_coordinator
from tests.test_scuba_v3_ultra import FINISH, GET, SN, WORKING, _accepted, _coordinator

T0 = datetime(2026, 10, 25, 20, 5, 47, tzinfo=UTC)


def _mqtt(
    finish: datetime, *, start: datetime | None = None, duration: float | None = None, run_id: str | None = "Custom_1"
) -> CleaningSession:
    return CleaningSession.create(
        SN, source="mqtt", start=start, finish=finish, duration_min=duration, mode="Custom", result=4, run_id=run_id
    )


def _rest(start: datetime, duration: float | None = 104.0, mode: str | None = "Custom") -> CleaningSession:
    record = {"start": start, "duration_min": duration, "mode": mode}
    candidate = candidate_from_record(SN, record)
    assert candidate is not None
    return candidate


def test_mqtt_then_rest_enrich_one_session() -> None:
    ledger = SessionLedger()
    first = ledger.ingest(SN, _mqtt(T0 + timedelta(minutes=104), start=T0, duration=103.9))
    assert first.created

    second = ledger.ingest(SN, _rest(T0 + timedelta(seconds=30), duration=104.0, mode="Smart"))

    assert not second.created
    assert len(ledger.sessions(SN)) == 1
    session = ledger.sessions(SN)[0]
    assert session.sources == {"mqtt", "rest"}
    # Existing non-null fields are never overwritten by a later source.
    assert session.mode == "Custom"
    assert session.result == 4


def test_rest_then_mqtt_fills_missing_fields() -> None:
    ledger = SessionLedger()
    ledger.ingest(SN, _rest(T0, duration=None))
    result = ledger.ingest(SN, _mqtt(T0 + timedelta(minutes=104), start=T0, duration=103.9))

    assert result.enriched
    session = ledger.sessions(SN)[0]
    assert session.finish == T0 + timedelta(minutes=104)
    assert session.duration_min == 103.9
    assert session.result == 4
    assert len(ledger.sessions(SN)) == 1


def test_duplicate_delivery_is_idempotent() -> None:
    ledger = SessionLedger()
    ledger.ingest(SN, _mqtt(T0))
    again = ledger.ingest(SN, _mqtt(T0))

    assert not again.created
    assert not again.enriched
    assert len(ledger.sessions(SN)) == 1


def test_two_adjacent_runs_stay_distinct() -> None:
    ledger = SessionLedger()
    ledger.ingest(SN, _mqtt(T0, run_id="Custom_1"))
    ledger.ingest(SN, _mqtt(T0 + timedelta(hours=2), run_id="Custom_2"))
    ledger.ingest(SN, _rest(T0 + timedelta(hours=1), duration=20.0))

    sessions = ledger.sessions(SN)
    assert len(sessions) == 3
    assert [s.sort_key() for s in sessions] == sorted((s.sort_key() for s in sessions), reverse=True)


def test_out_of_order_delivery_sorts_newest_first() -> None:
    ledger = SessionLedger()
    ledger.ingest(SN, _mqtt(T0 + timedelta(days=1), run_id="Custom_2"))
    ledger.ingest(SN, _mqtt(T0, run_id="Custom_1"))

    assert [s.run_id for s in ledger.sessions(SN)] == ["Custom_2", "Custom_1"]
    latest = ledger.latest(SN)
    assert latest is not None and latest.run_id == "Custom_2"


def test_midnight_crossing_run_matches_by_finish() -> None:
    start = datetime(2026, 10, 25, 23, 40, tzinfo=UTC)
    finish = datetime(2026, 10, 26, 0, 40, tzinfo=UTC)
    ledger = SessionLedger()
    ledger.ingest(SN, _mqtt(finish, start=start, duration=60.0))
    ledger.ingest(SN, _rest(start, duration=60.0))

    assert len(ledger.sessions(SN)) == 1


def test_missing_start_still_matches_on_finish() -> None:
    ledger = SessionLedger()
    ledger.ingest(SN, _mqtt(T0 + timedelta(minutes=104), run_id=None))
    ledger.ingest(SN, _rest(T0, duration=104.0))

    assert len(ledger.sessions(SN)) == 1


def test_contradicting_duration_does_not_merge() -> None:
    ledger = SessionLedger()
    ledger.ingest(SN, _mqtt(T0 + timedelta(minutes=104), duration=104.0, run_id=None))
    # Same finish window but a very different length: a different run.
    ledger.ingest(SN, _rest(T0 + timedelta(minutes=94), duration=10.0))

    sessions = ledger.sessions(SN)
    assert len(sessions) == 2
    # Both end in the same second, yet keep distinct identifiers.
    assert len({s.session_id for s in sessions}) == 2


def test_same_run_id_with_distant_finish_is_a_new_session() -> None:
    ledger = SessionLedger()
    ledger.ingest(SN, _mqtt(T0, run_id="Memory_1"))
    ledger.ingest(SN, _mqtt(T0 + timedelta(days=1), run_id="Memory_1"))

    assert len(ledger.sessions(SN)) == 2


def test_same_run_id_without_comparable_times_matches() -> None:
    ledger = SessionLedger()
    ledger.ingest(SN, CleaningSession.create(SN, source="mqtt", run_id="Custom_9"))
    ledger.ingest(SN, CleaningSession.create(SN, source="rest", run_id="Custom_9", start=T0))

    assert len(ledger.sessions(SN)) == 1


def test_same_run_id_compares_starts_when_finish_missing() -> None:
    ledger = SessionLedger()
    ledger.ingest(SN, CleaningSession.create(SN, source="mqtt", run_id="Custom_9", start=T0))
    ledger.ingest(SN, CleaningSession.create(SN, source="mqtt", run_id="Custom_9", start=T0 + timedelta(days=1)))

    assert len(ledger.sessions(SN)) == 2


def test_ambiguous_match_stays_unresolved_and_is_never_announced() -> None:
    ledger = SessionLedger()
    ledger.ingest(SN, _mqtt(T0, run_id=None))
    ledger.ingest(SN, _mqtt(T0 + timedelta(minutes=8), run_id=None))
    assert len(ledger.sessions(SN)) == 2

    # Within five minutes of both existing finishes.
    ambiguous = _mqtt(T0 + timedelta(minutes=4), run_id=None)
    result = ledger.ingest(SN, ambiguous)

    assert result.created
    assert result.session.unresolved
    assert len(ledger.sessions(SN)) == 3
    assert result.session.session_id not in {s.session_id for _, s in ledger.pending() if s.unresolved}
    assert all(not s.unresolved for _, s in ledger.pending())

    # Redelivering the same ambiguous report does not add another row.
    again = ledger.ingest(SN, _mqtt(T0 + timedelta(minutes=4), run_id=None))
    assert not again.created
    assert len(ledger.sessions(SN)) == 3
    latest = ledger.latest(SN)
    assert latest is not None and not latest.unresolved


def test_same_session_id_merges_even_without_time_match() -> None:
    ledger = SessionLedger()
    ledger.ingest(SN, CleaningSession.create(SN, source="mqtt", run_id="Custom_5"))
    result = ledger.ingest(SN, CleaningSession.create(SN, source="mqtt", run_id="Custom_5", mode="Custom"))

    assert not result.created
    assert result.enriched
    assert len(ledger.sessions(SN)) == 1


def test_pending_requires_finish_and_announcement_is_sticky() -> None:
    ledger = SessionLedger()
    ledger.ingest(SN, _rest(T0, duration=None))
    assert ledger.pending() == []

    ledger.ingest(SN, _mqtt(T0 + timedelta(minutes=104), start=T0))
    pending = ledger.pending()
    assert len(pending) == 1
    sn, session = pending[0]
    assert sn == SN

    assert ledger.mark_announced(SN, session.session_id)
    assert not ledger.mark_announced(SN, "missing")
    assert ledger.pending() == []
    # A late REST row for the same run never un-announces it.
    ledger.ingest(SN, _rest(T0, duration=104.0))
    assert ledger.pending() == []


def test_quiet_before_marks_old_completions_announced() -> None:
    ledger = SessionLedger()
    cutoff = T0 + timedelta(hours=1)
    ledger.ingest(SN, _mqtt(T0), quiet_before=cutoff)
    ledger.ingest(SN, _mqtt(T0 + timedelta(hours=3), run_id="Custom_2"), quiet_before=cutoff)

    assert [s.run_id for _, s in ledger.pending()] == ["Custom_2"]


def test_baseline_silences_known_sessions_once() -> None:
    ledger = SessionLedger()
    ledger.ingest(SN, _mqtt(T0))
    assert not ledger.is_baselined(SN)
    ledger.baseline(SN)

    assert ledger.is_baselined(SN)
    assert ledger.pending() == []
    ledger.ingest(SN, _mqtt(T0 + timedelta(days=1), run_id="Custom_2"))
    assert len(ledger.pending()) == 1


def test_ledger_is_bounded() -> None:
    ledger = SessionLedger()
    for index in range(MAX_SESSIONS_PER_DEVICE + 5):
        ledger.ingest(SN, _mqtt(T0 + timedelta(days=index), run_id=f"Custom_{index}"))

    sessions = ledger.sessions(SN)
    assert len(sessions) == MAX_SESSIONS_PER_DEVICE
    assert sessions[0].run_id == f"Custom_{MAX_SESSIONS_PER_DEVICE + 4}"


def test_store_round_trip_preserves_announcements() -> None:
    ledger = SessionLedger()
    ledger.ingest(SN, _mqtt(T0, start=T0 - timedelta(minutes=90), duration=90.0))
    ledger.baseline(SN)
    payload = json.loads(json.dumps(ledger.to_store()))

    restored = SessionLedger.from_store(payload)

    assert restored.is_baselined(SN)
    assert restored.sessions(SN)[0].to_dict() == ledger.sessions(SN)[0].to_dict()
    assert restored.pending() == []
    assert restored.summary() == {"devices": 1, "sessions": 1, "announced": 1, "unresolved": 0, "baselined_devices": 1}


def test_corrupt_store_yields_empty_ledger() -> None:
    bad_stores: tuple[Any, ...] = (None, [], {"version": 99}, {"version": 1, "devices": []})
    for bad in bad_stores:
        assert SessionLedger.from_store(bad).summary()["sessions"] == 0

    partly_bad: dict[str, Any] = {
        "version": 1,
        "baselined": ["ok", 5],
        "devices": {
            "ok": [
                {"session_id": "a", "finish": "not a date", "duration_min": True, "result": True, "sources": "x"},
                {"no": "id"},
                "junk",
            ],
            5: [],
            "bad": "nope",
        },
    }
    restored = SessionLedger.from_store(partly_bad)

    assert restored.is_baselined("ok")
    only = restored.sessions("ok")
    assert len(only) == 1
    assert only[0].finish is None and only[0].duration_min is None and only[0].result is None
    assert only[0].sources == set()


def test_candidate_builders_reject_unusable_input() -> None:
    assert candidate_from_finish(SN, {"task": {}}, {}) is None
    assert candidate_from_finish(SN, {"ts": "x", "task": {}}, {}) is None
    assert candidate_from_finish(SN, {"ts": -1, "task": {}}, {}) is None
    assert candidate_from_finish(SN, {"ts": True, "task": {}}, {}) is None
    assert candidate_from_finish(SN, {"ts": 10**40, "task": {}}, {}) is None
    assert candidate_from_finish(SN, {"ts": 1792964983, "task": "x"}, {}) is None
    assert candidate_from_record(SN, {"start": None}) is None

    seconds = candidate_from_finish(SN, {"ts": 1792964983, "task": {"nameID": "Memory_1", "cleanResult": 1}}, {})
    assert seconds is not None and seconds.finish == datetime.fromtimestamp(1792964983, tz=UTC)
    assert seconds.run_id == "Memory_1" and seconds.result == 1

    no_duration = candidate_from_record(SN, {"start": T0, "duration_min": True, "mode": 3})
    assert no_duration is not None and no_duration.finish is None and no_duration.mode is None


def test_naive_datetimes_are_treated_as_utc() -> None:
    session = CleaningSession.create(SN, source="rest", start=datetime(2026, 10, 25, 20, 0))
    assert session.start == datetime(2026, 10, 25, 20, 0, tzinfo=UTC)
    assert CleaningSession.create(SN, source="rest", start=None).session_id


def _quiet_coordinator() -> Any:
    coordinator = _coordinator()
    # The captured finish is far older than "now"; allow it to be announced.
    coordinator._session_quiet_before = datetime(2020, 1, 1, tzinfo=UTC)
    return coordinator


def test_coordinator_records_mqtt_finish_once_per_redelivery() -> None:
    coordinator = _quiet_coordinator()

    coordinator._on_shadow_update(SN, _accepted(WORKING, topic=GET))
    coordinator._on_shadow_update(SN, _accepted(FINISH))
    coordinator._on_shadow_update(SN, _accepted(FINISH))

    pending = coordinator.pending_completions()
    assert len(pending) == 1
    sn, session = pending[0]
    assert sn == SN
    assert session.sources == {"mqtt"}
    assert session.result == 4
    assert session.mode == "Custom"
    assert session.duration_min is not None

    coordinator.mark_completion_announced(SN, session.session_id)
    coordinator._on_shadow_update(SN, _accepted(FINISH))
    assert coordinator.pending_completions() == []
    assert coordinator.diagnostics()["cleaning_sessions"]["announced"] == 1


def test_coordinator_ignores_finish_without_timestamp() -> None:
    coordinator = _quiet_coordinator()
    finish = {"FinishTaskReport": {"task": {"nameID": "Custom_1", "cleanResult": 4}}}

    coordinator._on_shadow_update(SN, _accepted(finish))

    assert coordinator.pending_completions() == []


def test_history_baseline_is_quiet_then_new_rest_run_is_announceable() -> None:
    coordinator = make_coordinator(BaseFakeApi())
    now = datetime.now(UTC)
    old = {"start": now - timedelta(days=2), "duration_min": 60.0, "mode": "Auto"}
    new = {"start": now - timedelta(minutes=30), "duration_min": 20.0, "mode": "Auto"}

    coordinator._ingest_history_sessions(SN, [old])
    assert coordinator.pending_completions() == []

    # A run that finished after startup is a genuine completion.
    coordinator._session_quiet_before = now - timedelta(hours=1)
    coordinator._ingest_history_sessions(SN, [new, old])
    pending = coordinator.pending_completions()
    assert len(pending) == 1
    assert pending[0][1].sources == {"rest"}


async def test_restore_without_store_and_with_store() -> None:
    coordinator = make_coordinator(BaseFakeApi())
    await coordinator.async_restore_cleaning_sessions()
    coordinator._save_sessions()  # no store: no-op

    class _Store:
        def __init__(self, data: Any, fail: bool = False) -> None:
            self.data = data
            self.fail = fail
            self.saved: list[Any] = []

        async def async_load(self) -> Any:
            if self.fail:
                raise OSError("disk")
            return self.data

        def async_delay_save(self, getter: Any, delay: float) -> None:
            self.saved.append(getter())

    ledger = SessionLedger()
    ledger.ingest(SN, _mqtt(T0))
    ledger.baseline(SN)

    coordinator._sessions_store = _Store(ledger.to_store())  # type: ignore[assignment]
    await coordinator.async_restore_cleaning_sessions()
    assert coordinator._session_ledger.is_baselined(SN)

    coordinator.mark_completion_announced(SN, "unknown")  # nothing to persist
    session_id = coordinator._session_ledger.sessions(SN)[0].session_id
    coordinator._ingest_history_sessions(SN, [])
    coordinator.mark_completion_announced(SN, session_id)
    assert cast(Any, coordinator._sessions_store).saved

    coordinator._sessions_store = _Store(None, fail=True)  # type: ignore[assignment]
    await coordinator.async_restore_cleaning_sessions()
    assert coordinator._session_ledger.is_baselined(SN)


def test_candidates_without_comparable_times_do_not_match() -> None:
    ledger = SessionLedger()
    ledger.ingest(SN, _mqtt(T0, run_id=None))
    ledger.ingest(SN, CleaningSession.create(SN, source="rest", mode="Auto"))

    assert len(ledger.sessions(SN)) == 2
