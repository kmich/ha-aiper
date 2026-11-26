"""Cleaning-finished event entity: announcement rules and platform wiring."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from typing import Any, cast

import pytest
from homeassistant.components.event import EventEntity

from custom_components import aiper
from custom_components.aiper import event as event_platform
from custom_components.aiper.cleaning_sessions import CleaningSession, SessionLedger
from custom_components.aiper.entity import AiperEntity
from custom_components.aiper.event import (
    EVENT_CLEANING_FINISHED,
    AiperCleaningFinishedEvent,
    completion_event_attributes,
)
from custom_components.aiper.profiles import Capability, derive_device_profile
from custom_components.aiper.state import normalize_device_state
from tests.coordinator_factory import BaseFakeApi, make_coordinator

SN = "SN1234567890"
OTHER = "SN0000000002"
T0 = datetime(2026, 10, 25, 20, 5, 47, tzinfo=UTC)


def _device(model: str = "Scuba_V3_Ultra") -> dict[str, Any]:
    return {"sn": SN, "name": "Pool", "model": model, "online": True}


def _setup(model: str = "Scuba_V3_Ultra") -> tuple[Any, AiperCleaningFinishedEvent, list[tuple[str, dict[str, Any]]]]:
    coordinator = make_coordinator(BaseFakeApi())
    coordinator.data = {SN: normalize_device_state(_device(model))}
    entity = AiperCleaningFinishedEvent(coordinator, SN, coordinator.data[SN])
    fired: list[tuple[str, dict[str, Any]]] = []
    cast(Any, entity)._trigger_event = lambda event_type, attrs=None: fired.append((event_type, dict(attrs or {})))
    cast(Any, entity).async_write_ha_state = lambda: None
    return coordinator, entity, fired


def _session(finish: datetime = T0, run_id: str = "Custom_1") -> CleaningSession:
    return CleaningSession.create(
        SN,
        source="mqtt",
        start=finish - timedelta(minutes=30),
        finish=finish,
        duration_min=30.0,
        mode="Custom",
        result=4,
        run_id=run_id,
    )


def test_completion_event_attributes_omit_unknown_values() -> None:
    full = completion_event_attributes(_session())
    assert full["duration_min"] == 30.0
    assert full["mode"] == "Custom"
    assert full["result"] == 4
    assert full["finished_at"] == T0.isoformat()
    assert full["sources"] == ["mqtt"]

    sparse = completion_event_attributes(CleaningSession.create(SN, source="rest", run_id="Custom_2"))
    assert set(sparse) == {"session_id", "sources"}


def test_unique_id_and_platform_order_are_stable() -> None:
    _coordinator, entity, _fired = _setup()
    assert entity.unique_id == f"{SN}_cleaning_finished"
    # Existing platforms keep their position; the event platform is appended.
    assert [str(p) for p in aiper.PLATFORMS[:5]] == ["sensor", "binary_sensor", "button", "select", "switch"]
    assert str(aiper.PLATFORMS[-1]) == "event"


def test_only_v3_ultra_advertises_completion_capability() -> None:
    assert Capability.CLEANING_COMPLETION in derive_device_profile(_device()).capabilities
    for model in ("Scuba_V3", "Scuba_S1_2025", "Scuba_X1", "Scuba_S3", "Surfer_S2"):
        assert Capability.CLEANING_COMPLETION not in derive_device_profile(_device(model)).capabilities


def test_new_completion_fires_exactly_once() -> None:
    coordinator, entity, fired = _setup()
    coordinator._session_ledger.ingest(SN, _session())

    entity._handle_coordinator_update()
    entity._handle_coordinator_update()

    assert len(fired) == 1
    event_type, attrs = fired[0]
    assert event_type == EVENT_CLEANING_FINISHED
    assert attrs["duration_min"] == 30.0
    assert coordinator.pending_completions() == []


def test_redelivery_and_reconnect_stay_quiet() -> None:
    coordinator, entity, fired = _setup()
    coordinator._session_ledger.ingest(SN, _session())
    entity._handle_coordinator_update()

    # The same run arrives again (MQTT redelivery after a reconnect, then REST history).
    coordinator._session_ledger.ingest(SN, _session())
    coordinator._ingest_history_sessions(
        SN, [{"start": T0 - timedelta(minutes=30), "duration_min": 30.0, "mode": "Custom"}]
    )
    entity._handle_coordinator_update()

    assert len(fired) == 1


def test_restart_with_restored_ledger_stays_quiet_then_announces_next_run() -> None:
    coordinator, entity, fired = _setup()
    coordinator._session_ledger.ingest(SN, _session())
    entity._handle_coordinator_update()
    stored = coordinator._session_ledger.to_store()

    # Simulate a restart: a fresh coordinator restored from the persisted ledger.
    restarted, restarted_entity, restarted_fired = _setup()
    restarted._session_ledger = SessionLedger.from_store(stored)
    restarted._session_ledger.ingest(SN, _session())
    restarted_entity._handle_coordinator_update()
    assert restarted_fired == []

    restarted._session_ledger.ingest(SN, _session(T0 + timedelta(hours=3), "Custom_2"))
    restarted_entity._handle_coordinator_update()
    assert len(restarted_fired) == 1
    assert len(fired) == 1


def test_unresolved_session_never_announces() -> None:
    coordinator, entity, fired = _setup()
    ledger = coordinator._session_ledger
    ledger.ingest(SN, _session(T0, "Custom_1"))
    ledger.ingest(SN, _session(T0 + timedelta(minutes=8), "Custom_2"))
    for _sn, session in ledger.pending():
        ledger.mark_announced(SN, session.session_id)

    ledger.ingest(SN, CleaningSession.create(SN, source="rest", finish=T0 + timedelta(minutes=4)))
    entity._handle_coordinator_update()

    assert fired == []


def test_other_devices_completions_are_not_announced_here() -> None:
    coordinator, entity, fired = _setup()
    other = CleaningSession.create(OTHER, source="mqtt", finish=T0, run_id="Custom_7")
    coordinator._session_ledger.ingest(OTHER, other)

    entity._handle_coordinator_update()

    assert fired == []
    assert len(coordinator.pending_completions()) == 1


def test_missing_device_leaves_completion_pending() -> None:
    coordinator, entity, fired = _setup()
    coordinator._session_ledger.ingest(SN, _session())
    coordinator.data = {}
    entity._handle_coordinator_update()
    assert fired == []
    assert len(coordinator.pending_completions()) == 1


async def test_completion_before_entity_exists_is_announced_when_added(monkeypatch: pytest.MonkeyPatch) -> None:
    coordinator, entity, fired = _setup()
    coordinator._session_ledger.ingest(SN, _session())

    async def _no_parent(self: Any) -> None:
        return None

    monkeypatch.setattr(EventEntity, "async_added_to_hass", _no_parent, raising=False)
    monkeypatch.setattr(AiperEntity, "async_added_to_hass", _no_parent, raising=False)
    await entity.async_added_to_hass()

    assert len(fired) == 1


async def test_setup_creates_entities_only_for_supported_devices() -> None:
    coordinator = make_coordinator(BaseFakeApi())

    def _with_caps(device: dict[str, Any]) -> dict[str, Any]:
        caps = sorted(cap.value for cap in derive_device_profile(device).capabilities)
        return {**device, "capabilities": caps}

    coordinator.data = {
        SN: normalize_device_state(_with_caps(_device())),
        OTHER: normalize_device_state(_with_caps({**_device("Scuba_X1"), "sn": OTHER})),
    }
    added: list[Any] = []
    unload: list[Any] = []
    entry = SimpleNamespace(
        runtime_data=SimpleNamespace(coordinator=coordinator),
        async_on_unload=unload.append,
    )
    cast(Any, coordinator).async_add_listener = lambda *_a, **_k: lambda: None

    await event_platform.async_setup_entry(cast(Any, None), cast(Any, entry), cast(Any, added.extend))

    assert [e.unique_id for e in added] == [f"{SN}_cleaning_finished"]
    assert len(unload) == 1
