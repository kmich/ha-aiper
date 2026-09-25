"""Scuba S1 (``Scuba_S1_2025``) lifecycle reconciliation heuristics.

The S1 reports its lifecycle through several MQTT topics and a REST device
list that disagree in characteristic, hardware-verified ways (stale replays,
REST charging snapshots behind a latched MQTT "Cleaning", missing water
state). This module holds those model-specific rules and their diagnostics
state so the coordinator only decides *when* to apply them.
"""

from __future__ import annotations

import logging
from copy import deepcopy
from datetime import datetime, timedelta
from typing import Any

from homeassistant.util import dt as dt_util

from .const import Status, status_value
from .coordinator_parsing import _ensure_utc_aware
from .state_common import _coerce_bool, _coerce_int

_LOGGER = logging.getLogger(__name__)

# The S1 publishes the same lifecycle through several MQTT topics. On two
# consecutive physical cycles, a current Parked report was followed within
# 250 ms by an older Cleaning snapshot and then another current Parked report.
# A genuine physical restart cannot occur in this narrow interval, so terminal
# evidence wins briefly while redundant topic snapshots settle.
LIFECYCLE_REPLAY_GUARD = timedelta(seconds=2)
# On 2026-08-27 a coherent S1 Cleaning/Wet/nonzero-runtime report was followed
# by redundant Idle/zero snapshots at 137 ms and 8.7 seconds. The latter became
# persistent for the entire submerged cycle. A verified S1 cycle ends with a
# terminal Parked/Charging status, not an Idle snapshot, so preserve a newly
# confirmed running sample while the redundant MQTT topics settle.
START_REPLAY_GUARD = timedelta(seconds=15)
TERMINAL_STATUS_CODES = frozenset({2, 3, 10})
RUNNING_STATUS_CODES = frozenset({1})
IDLE_STATUS_CODES = frozenset({0})
REPLAY_LIFECYCLE_FIELDS = frozenset({"status", "mode", "cap", "run_time", "in_water"})


class S1StateReconciler:
    """Per-account state and rules for reconciling Scuba S1 lifecycle reports."""

    def __init__(self) -> None:
        """Initialize empty per-device evidence."""
        self.battery_samples: dict[str, list[dict[str, Any]]] = {}
        self.last_mqtt_machine_report: dict[str, dict[str, Any]] = {}
        self.terminal_report_at: dict[str, datetime] = {}
        self.confirmed_running_report: dict[str, dict[str, Any]] = {}
        self.replay_suppressions: dict[str, dict[str, Any]] = {}
        self.reconciliation: dict[str, dict[str, Any]] = {}

    def reconcile_rest_device(
        self,
        serial: str,
        discovered: dict[str, Any],
        merged_device: dict[str, Any],
        rest_live_fields: set[str],
        *,
        now: datetime,
        mqtt_preferred_fields: frozenset[str],
    ) -> bool:
        """Apply S1 rules to one REST device-list entry.

        Mutates ``merged_device`` and ``rest_live_fields`` in place. Returns
        True when the REST snapshot is an explicit physical correction
        (charging / battery rise) whose live fields must override MQTT this
        cycle regardless of MQTT recency.
        """
        forced = False
        rest_status = _coerce_int(discovered.get("machineStatus"))
        if rest_status in (2, 3):
            if self.mqtt_reports_running_since(serial, since=now - timedelta(minutes=2)):
                # A recent MQTT report still shows Cleaning, so
                # this REST charging snapshot is the stale one.
                # Keep MQTT authoritative for the live fields
                # this cycle instead of applying the charging
                # reconciliation below.
                rest_live_fields.difference_update(mqtt_preferred_fields)
            else:
                # Captured on S1 V2.0.1 after a low-battery
                # cycle: REST resumed with current status 2
                # while the last MQTT report remained
                # Cleaning/Wet for hours. A physically charging
                # cleaner is necessarily dry, stopped, and
                # outside an active cleaning mode.
                merged_device["in_water"] = 0
                merged_device["mode"] = 0
                merged_device["runTime"] = 0
                forced = True
                self.record_reconciliation(serial, trigger="rest_machine_status", rest_status=rest_status)
        elif rest_status in (1, 10):
            # On S1 V2.0.1 the device-list poll reports
            # in_water=0 while status 1 still confirms active
            # cleaning. The S1 also parks underwater with status
            # 10, for which REST omits water state. Cleaning is
            # therefore authoritative; Parked implies Wet only
            # when REST has no newer explicit water report.
            if rest_status == 1 or "in_water" not in discovered:
                merged_device["in_water"] = 1
        elif (
            rest_status is None
            and discovered.get("online") is not False
            and self.battery_rise_indicates_charging(serial)
        ):
            # Conservative fallback only: three increasing
            # samples spanning at least two minutes, no explicit
            # REST status, and no newer MQTT Machine report.
            merged_device["machineStatus"] = 2
            merged_device["in_water"] = 0
            merged_device["mode"] = 0
            merged_device["runTime"] = 0
            forced = True
            self.record_reconciliation(serial, trigger="battery_rise_fallback")
        return forced

    def apply_mqtt_machine(
        self,
        sn: str,
        machine: dict[str, Any],
        *,
        observed_at: datetime,
        observed_at_explicit: bool,
        received_at: datetime,
        topic: Any,
    ) -> dict[str, Any]:
        """Filter replayed lifecycle fields from an S1 MQTT Machine report and record it."""
        if self.suppress_lifecycle_replay(
            sn,
            machine,
            observed_at=observed_at,
            observed_at_explicit=observed_at_explicit,
            received_at=received_at,
            topic=topic,
        ):
            machine = {key: value for key, value in machine.items() if key not in REPLAY_LIFECYCLE_FIELDS}
        mqtt_status = _coerce_int(machine.get("status"))
        self.last_mqtt_machine_report[sn] = {"observed_at": received_at, "status": mqtt_status}
        if mqtt_status in (2, 3):
            self.record_reconciliation(sn, trigger="mqtt_machine_status", rest_status=None)
        return machine

    def record_battery_sample(self, sn: str, value: Any, observed_at: datetime) -> None:
        """Retain a small, non-sensitive battery trend for S1 fallback logic."""
        battery = _coerce_int(value)
        if battery is None:
            return
        samples = self.battery_samples
        history = samples.setdefault(sn, [])
        history.append({"observed_at": observed_at, "battery": battery})
        del history[:-3]

    def battery_rise_indicates_charging(self, sn: str) -> bool:
        """Return true for a sustained S1 rise without a newer MQTT report."""
        history = self.battery_samples.get(sn) or []
        if len(history) < 3:
            return False
        first, middle, last = history[-3:]
        if not (first["battery"] < middle["battery"] < last["battery"]):
            return False
        if last["battery"] - first["battery"] < 2:
            return False
        if (last["observed_at"] - first["observed_at"]).total_seconds() < 120:
            return False
        mqtt_report = self.last_mqtt_machine_report.get(sn) or {}
        mqtt_at = _ensure_utc_aware(mqtt_report.get("observed_at"))
        return mqtt_at is None or mqtt_at <= first["observed_at"]

    def mqtt_reports_running_since(self, sn: str, *, since: datetime) -> bool:
        """Return True if a Scuba S1 MQTT report at/after `since` still shows Cleaning."""
        mqtt_report = self.last_mqtt_machine_report.get(sn) or {}
        mqtt_at = _ensure_utc_aware(mqtt_report.get("observed_at"))
        if mqtt_at is None or mqtt_at < since:
            return False
        return mqtt_report.get("status") == int(Status.CLEANING)

    def record_reconciliation(
        self,
        sn: str,
        *,
        trigger: str,
        rest_status: int | None = None,
    ) -> None:
        """Record why S1 operational state was reconciled for diagnostics."""
        history = self.battery_samples.get(sn) or []
        records = self.reconciliation
        previous = records.get(sn) or {}
        events = list(previous.get("events") or [])
        event = {
            "trigger": trigger,
            "observed_at": dt_util.utcnow().isoformat(),
            "rest_status": rest_status,
            "battery_samples": [
                {"observed_at": sample["observed_at"].isoformat(), "battery": sample["battery"]} for sample in history
            ],
            "applied": {
                "charging": True,
                "running": False,
                "in_water": False,
                "mode": 0,
                "runtime": 0,
            },
        }
        if not events or (events[-1].get("trigger"), events[-1].get("rest_status")) != (
            trigger,
            rest_status,
        ):
            events.append(deepcopy(event))
            del events[:-20]
        records[sn] = {**event, "events": events}

    @staticmethod
    def mqtt_source_label(topic: Any) -> str:
        """Return a stable, identifier-free MQTT source label."""
        if not isinstance(topic, str):
            return "unknown"
        if "shadow/get/accepted" in topic:
            return "shadow_get"
        if "shadow/update/documents" in topic:
            return "shadow_documents"
        if "shadow/update/accepted" in topic:
            return "shadow_update"
        if "upChan" in topic:
            return "up_channel"
        if "app/report" in topic:
            return "app_report"
        if "shadow/report" in topic:
            return "device_report"
        return "other"

    def suppress_lifecycle_replay(
        self,
        sn: str,
        machine: dict[str, Any],
        *,
        observed_at: datetime,
        observed_at_explicit: bool,
        received_at: datetime,
        topic: Any,
    ) -> bool:
        """Reject physically impossible S1 lifecycle replays."""
        raw_status = _coerce_int(machine.get("status"))
        base_status = status_value(raw_status)
        terminal_reports = self.terminal_report_at
        running_reports = self.confirmed_running_report

        if base_status in TERMINAL_STATUS_CODES:
            terminal_reports[sn] = received_at
            running_reports.pop(sn, None)
            return False
        now = _ensure_utc_aware(received_at) or dt_util.utcnow()
        suppression_kind: str | None = None
        suppression_age: timedelta | None = None
        suppression_guard: timedelta | None = None

        if base_status in RUNNING_STATUS_CODES:
            terminal_at = _ensure_utc_aware(terminal_reports.get(sn))
            if terminal_at is not None:
                age = now - terminal_at
                if timedelta(0) <= age <= LIFECYCLE_REPLAY_GUARD:
                    suppression_kind = "terminal_to_running"
                    suppression_age = age
                    suppression_guard = LIFECYCLE_REPLAY_GUARD

            if suppression_kind is None:
                run_time = _coerce_int(machine.get("run_time"))
                in_water = _coerce_bool(machine.get("in_water"))
                if (run_time is not None and run_time > 0) or in_water is True:
                    running_reports[sn] = {
                        "observed_at": _ensure_utc_aware(observed_at) or now,
                        "observed_at_explicit": observed_at_explicit,
                        "received_at": now,
                        "source": self.mqtt_source_label(topic),
                    }
                return False

        elif base_status in IDLE_STATUS_CODES:
            running_report = running_reports.get(sn) or {}
            running_received_at = _ensure_utc_aware(running_report.get("received_at"))
            running_observed_at = _ensure_utc_aware(running_report.get("observed_at"))
            idle_age = now - running_received_at if running_received_at is not None else None
            explicitly_older = (
                observed_at_explicit
                and bool(running_report.get("observed_at_explicit"))
                and running_observed_at is not None
                and (_ensure_utc_aware(observed_at) or now) < running_observed_at
            )
            if explicitly_older or (idle_age is not None and timedelta(0) <= idle_age <= START_REPLAY_GUARD):
                suppression_kind = "running_to_idle"
                suppression_age = idle_age
                suppression_guard = START_REPLAY_GUARD
            elif idle_age is not None and idle_age > START_REPLAY_GUARD:
                # A newer Idle outside the narrow settling window is allowed.
                # Do not let the old start protect against later uncorrelated
                # Idle samples unless their own timestamp proves they are old.
                running_reports.pop(sn, None)
                return False
            else:
                return False
        else:
            return False

        if suppression_kind is None or suppression_age is None or suppression_guard is None:
            return False

        suppressions = self.replay_suppressions
        previous = suppressions.get(sn) or {}
        suppressions[sn] = {
            "count": int(previous.get("count") or 0) + 1,
            "last_suppressed_at": now.isoformat(),
            "source": self.mqtt_source_label(topic),
            "status": base_status,
            "kind": suppression_kind,
            "age_seconds": round(suppression_age.total_seconds(), 3),
            "guard_seconds": suppression_guard.total_seconds(),
        }
        if suppression_kind == "terminal_to_running":
            # Retain the established diagnostics key for compatibility with
            # existing issue reports and tests.
            suppressions[sn]["terminal_age_seconds"] = round(suppression_age.total_seconds(), 3)
        _LOGGER.debug(
            "Suppressed S1 MQTT lifecycle replay kind=%s source=%s status=%s age=%.3fs",
            suppression_kind,
            self.mqtt_source_label(topic),
            base_status,
            suppression_age.total_seconds(),
        )
        return True
