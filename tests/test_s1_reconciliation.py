"""Direct unit tests for the Scuba S1 reconciliation rules."""

from __future__ import annotations

from datetime import timedelta

import pytest
from homeassistant.util import dt as dt_util

from custom_components.aiper.s1_reconciliation import S1StateReconciler

SN = "SN1234567890"


def _suppress(reconciler: S1StateReconciler, status: int, *, received_offset: float = 0.0, **machine) -> bool:
    now = dt_util.utcnow() + timedelta(seconds=received_offset)
    return reconciler.suppress_lifecycle_replay(
        SN,
        {"status": status, **machine},
        observed_at=now,
        observed_at_explicit=False,
        received_at=now,
        topic=None,
    )


def test_battery_samples_ignore_non_numeric_and_keep_last_three() -> None:
    reconciler = S1StateReconciler()
    now = dt_util.utcnow()

    reconciler.record_battery_sample(SN, "n/a", now)
    assert SN not in reconciler.battery_samples
    for offset, level in enumerate((10, 20, 30, 40)):
        reconciler.record_battery_sample(SN, level, now + timedelta(minutes=offset))
    assert [s["battery"] for s in reconciler.battery_samples[SN]] == [20, 30, 40]


@pytest.mark.parametrize(
    ("levels", "spacing_s", "expected"),
    [
        ((50, 51), 120, False),  # too few samples
        ((50, 52, 51), 120, False),  # not strictly rising
        ((50, 50.5, 51), 120, False),  # rise under 2 points
        ((50, 52, 54), 30, False),  # spans under two minutes
        ((50, 52, 54), 90, True),
    ],
)
def test_battery_rise_rules(levels, spacing_s, expected) -> None:
    reconciler = S1StateReconciler()
    start = dt_util.utcnow()
    reconciler.battery_samples[SN] = [
        {"observed_at": start + timedelta(seconds=spacing_s * i), "battery": level} for i, level in enumerate(levels)
    ]

    assert reconciler.battery_rise_indicates_charging(SN) is expected


@pytest.mark.parametrize(
    ("topic", "label"),
    [
        (None, "unknown"),
        ("$aws/things/x/shadow/get/accepted", "shadow_get"),
        ("$aws/things/x/shadow/update/documents", "shadow_documents"),
        ("$aws/things/x/shadow/update/accepted", "shadow_update"),
        ("aiper/things/x/upChan", "up_channel"),
        ("aiper/things/x/app/report", "app_report"),
        ("aiper/things/x/shadow/report", "device_report"),
        ("something/else", "other"),
    ],
)
def test_mqtt_source_labels(topic, label) -> None:
    assert S1StateReconciler.mqtt_source_label(topic) == label


def test_idle_without_prior_running_report_and_unknown_status_pass_through() -> None:
    reconciler = S1StateReconciler()

    assert _suppress(reconciler, 0) is False
    assert _suppress(reconciler, 6) is False  # Sleeping: not a lifecycle status


def test_mqtt_charging_report_records_reconciliation() -> None:
    reconciler = S1StateReconciler()
    now = dt_util.utcnow()

    machine = reconciler.apply_mqtt_machine(
        SN, {"status": 3, "cap": 90}, observed_at=now, observed_at_explicit=False, received_at=now, topic=None
    )

    assert machine == {"status": 3, "cap": 90}
    assert reconciler.last_mqtt_machine_report[SN]["status"] == 3
    assert reconciler.reconciliation[SN]["trigger"] == "mqtt_machine_status"
