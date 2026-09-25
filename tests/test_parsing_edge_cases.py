"""Edge-case tests for cloud payload parsers (history, consumables, datetimes)."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from custom_components.aiper.coordinator_parsing import (
    _merge_discovery_metadata,
    _number,
    _parse_cleaning_history,
    _parse_consumables,
    _parse_dt,
)


def test_merge_discovery_metadata_skips_none_and_live_keys() -> None:
    merged = _merge_discovery_metadata({"name": "old", "battLevel": 10}, {"name": None, "battLevel": 50, "fw": "2"})

    assert merged == {"name": "old", "battLevel": 10, "fw": "2"}


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        (None, None),
        (datetime(2026, 1, 1, 12, 0), datetime(2026, 1, 1, 12, 0, tzinfo=UTC)),
        (1_767_268_800, datetime(2026, 1, 1, 12, 0, tzinfo=UTC)),
        (1_767_268_800_000, datetime(2026, 1, 1, 12, 0, tzinfo=UTC)),
        (1e20, None),  # overflow
        ("   ", None),
        ("2026-01-01T12:00:00+00:00", datetime(2026, 1, 1, 12, 0, tzinfo=UTC)),
        ("2026-13-45 10:00", None),  # invalid date: HA parser raises
        ("01/02/2026 10:30", datetime(2026, 1, 2, 10, 30, tzinfo=UTC)),
        ("01/02/2026,10:30:15", datetime(2026, 1, 2, 10, 30, 15, tzinfo=UTC)),
        ("not a date", None),
        ([], None),
    ],
)
def test_parse_dt(value, expected) -> None:
    assert _parse_dt(value) == expected


@pytest.mark.parametrize(
    ("value", "expected"),
    [(True, None), (3, 3.0), ("12 h", 12.0), ("-", None), ("1.2.3", None), ({}, None)],
)
def test_number(value, expected) -> None:
    assert _number(value) == expected


def test_history_from_top_level_list_with_unit_hints() -> None:
    raw = {
        "data": [
            {"modeId": 2, "cleanTimeSec": 1800, "startTime": "2026-09-01 10:00:00"},
            {"mode": "Turbo", "cleanTimeHour": 1, "info": {"when": "2026-09-02 08:00"}},
            {"useTime": "90 min", "stamp": 1_788_000_000},
            {"duration": "2h"},
            "not a record",
        ]
    }

    total_count, total_hours, records = _parse_cleaning_history(raw)

    assert total_count == 4
    by_mode = {record["mode"]: record for record in records}
    assert by_mode["Floor"]["duration_min"] == 30.0
    assert by_mode["Turbo"]["duration_min"] == 60.0
    assert by_mode["Turbo"]["start"] == datetime(2026, 9, 2, 8, 0, tzinfo=UTC)
    by_duration = {record["duration_min"]: record for record in records}
    assert by_duration[90.0]["start"] == datetime.fromtimestamp(1_788_000_000, tz=UTC)
    assert by_duration[120.0]["start"] is None
    # Totals fall back to the sum of record durations when no total field exists.
    assert total_hours == round((30 + 60 + 90 + 120) / 60, 3)


def test_history_nested_container_and_explicit_totals() -> None:
    raw = {
        "data": {
            "page": {"records": [{"type": 7, "runTime": 400}]},
            "totalCleanSeconds": 7200,
            "totalTimes": "5",
        }
    }

    total_count, total_hours, records = _parse_cleaning_history(raw)

    assert total_count == 5
    assert total_hours == 2.0
    assert records[0]["mode"] == "Mode 7"
    assert records[0]["duration_min"] == round(400 / 60, 1)


@pytest.mark.parametrize(
    ("total", "hours"),
    [({"totalCleanHours": "3"}, 3.0), ({"totalTime": "7200 sec"}, 2.0), ({"totalTime": "30 min"}, 0.5)],
)
def test_history_total_time_units(total, hours) -> None:
    assert _parse_cleaning_history({"data": {"list": [], **total}})[1] == hours


def test_consumables_nested_list_and_dynamic_fields() -> None:
    raw = {
        "data": {
            "consumables": {
                "list": [
                    {
                        "type": "brush",
                        "dynamicsFields": [
                            "junk",
                            {"key": "consumable_name", "value": "Roller Brush"},
                            {"key": "component_replace", "value": "40"},
                            {"key": "lastChangeTime", "value": "2026-08-01 09:00:00"},
                        ],
                        "longestUseTime": 80,
                    },
                    {"consumableType": "filter", "filterRemainHour": "12", "percent": 150},
                    {"remainPercent": 20, "lastTimeFilterSwap": "2026-07-01 00:00", 5: "ignored"},
                    "junk",
                ]
            }
        }
    }

    brush, filt, other = _parse_consumables(raw)

    assert brush["name"] == "Roller Brush"
    assert brush["remaining_hours"] == 40.0
    assert brush["percent_left"] == 50.0
    assert brush["last_replacement"] == datetime(2026, 8, 1, 9, 0, tzinfo=UTC)
    assert filt["name"] == "filter"
    assert filt["remaining_hours"] == 12.0
    assert filt["percent_left"] == 100.0
    assert other["name"] == "Consumable"
    assert other["last_replacement"] == datetime(2026, 7, 1, 0, 0, tzinfo=UTC)


def test_consumables_used_percentage_and_unknown_shape() -> None:
    assert _parse_consumables({"data": {"items": [{"name": "Tread", "usePercentage": 30}]}})[0]["percent_left"] == 70.0
    assert _parse_consumables({"data": "nope"}) == []
