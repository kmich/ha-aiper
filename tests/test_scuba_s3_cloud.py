"""Exercise the Android N30 cloud response contract."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from zoneinfo import ZoneInfo

import pytest
from homeassistant.core import HomeAssistant
from homeassistant.util import dt as dt_util

from custom_components.aiper import sensor
from custom_components.aiper.api import AiperApi
from custom_components.aiper.coordinator_parsing import _parse_scuba_s3_cleaning_history
from custom_components.aiper.report_sections import next_scheduled_clean, scuba_s3_schedule_state
from custom_components.aiper.state import EntityState
from tests.coordinator_factory import BaseFakeApi, make_coordinator
from tests.test_platform_entities import _entity_by_key, _hass_with_device, _setup_platform

SN = "SYNTHETIC-S3"
ZONE = ZoneInfo("Asia/Singapore")
START = datetime(2026, 11, 26, 7, tzinfo=ZONE)
START_STAMP = int(START.timestamp() * 1000)
NOW = datetime(2026, 11, 26, 8, tzinfo=ZONE)


def test_live_s3_capture_matches_reported_times_and_schedule() -> None:
    path = Path(__file__).parent / "fixtures" / "scuba_s3_cloud_issue_59.json"
    calls = json.loads(path.read_text(encoding="utf-8"))["calls"]
    assert all(AiperApi._is_success(call["response"]) for call in calls.values())

    history = _parse_scuba_s3_cleaning_history(
        calls["history_page"]["response"], calls["history_statistics"]["response"]
    )
    assert history is not None
    count, hours, records = history
    assert (count, hours) == (2, 4.281)
    sydney = ZoneInfo("Australia/Sydney")
    assert [row["start"].astimezone(sydney) for row in records] == [
        datetime(2026, 11, 26, 7, 0, 26, tzinfo=sydney),
        datetime(2026, 11, 25, 7, 53, 41, tzinfo=sydney),
    ]
    assert [round(row["duration_min"]) for row in records] == [65, 191]
    assert [row["mode"] for row in records] == ["Scheduled", "Auto"]

    state = scuba_s3_schedule_state(calls["cycle_schedule"]["response"], sydney.key)
    assert state is not None
    schedule = state.attributes["schedule"]
    assert [(row["weekday_name"], row["start_time"], row["duration_minutes"]) for row in schedule] == [
        ("Tuesday", "07:00", 60),
        ("Thursday", "07:00", 60),
        ("Saturday", "07:00", 60),
    ]
    now = datetime(2026, 11, 27, 7, 40, tzinfo=sydney)
    assert next_scheduled_clean(schedule, now, sydney)[0] == datetime(2026, 11, 28, 7, tzinfo=sydney)


def test_history_page_uses_seconds_and_current_app_modes() -> None:
    history = _parse_scuba_s3_cleaning_history(
        {
            "data": {
                "total": 2,
                "list": [
                    {"utcStartTimeStamp": START_STAMP - 86_400_000, "cleanTime": 190 * 60, "taskType": 1},
                    {
                        "utcStartTimeStamp": START_STAMP,
                        "cleanTime": 65 * 60,
                        "taskType": 5,
                        "cleanAreaList": [2],
                    },
                ],
            }
        },
        {"data": {"cleanCount": 2}},
    )
    assert history is not None
    count, hours, records = history
    assert (count, hours) == (2, 4.25)
    assert [entry["mode"] for entry in records] == ["Floor", "Auto"]
    assert [entry["duration_min"] for entry in records] == [65, 190]
    assert records[0]["start"] == START.astimezone(UTC)


def test_partial_or_malformed_history_never_inflates_lifetime_hours() -> None:
    row: dict[str, Any] = {"utcStartTimeStamp": START_STAMP, "cleanTime": 299, "taskType": 999}
    history = _parse_scuba_s3_cleaning_history(
        {"data": {"total": 4, "list": [None, {"utcStartTimeStamp": 0}, row]}},
        None,
    )
    assert history is not None
    count, hours, records = history
    assert (count, hours) == (4, None)
    assert records[0]["duration_min"] == pytest.approx(299 / 60)
    assert records[0]["mode"] is None

    assert _parse_scuba_s3_cleaning_history({"data": None}, None) is None
    assert _parse_scuba_s3_cleaning_history({"data": {"total": 0, "list": []}}, None) == (0, 0.0, [])
    row["cleanTime"] = "Inf"
    history = _parse_scuba_s3_cleaning_history({"data": {"total": 1, "list": [row]}}, None)
    assert history is not None and history[1] is None and history[2][0]["duration_min"] is None


@pytest.mark.parametrize("duration_code,minutes", [(1, 45), (2, 60), (3, 90), ("unknown", None)])
def test_cycle_schedule_maps_weekdays_and_duration(duration_code: Any, minutes: int | None) -> None:
    state = scuba_s3_schedule_state(
        {"data": {"cleanTime": "07:00", "cleanDuration": duration_code, "cleanWeekList": [7, 0, 2, 4, 6]}},
        ZONE.key,
    )
    assert state is not None
    schedule = state.attributes["schedule"]
    assert [item["weekday_name"] for item in schedule] == ["Sunday", "Tuesday", "Thursday", "Saturday"]
    assert all(item["duration_minutes"] == minutes for item in schedule)


@pytest.mark.parametrize(
    "bad_plan",
    [{}, {"cleanWeekList": [True]}, {"cleanWeekList": [2], "cleanTime": "07:00+05:00"}, {"cleanWeekList": [2]}],
)
def test_invalid_cycle_schedule_leaves_last_known_plan_intact(bad_plan: dict[str, Any]) -> None:
    assert scuba_s3_schedule_state({"data": bad_plan}, None) is None


class _CloudApi(BaseFakeApi):
    _is_success = staticmethod(AiperApi._is_success)

    def __init__(self) -> None:
        self.page: dict[str, Any] = {
            "code": 0,
            "data": {
                "list": [{"utcStartTimeStamp": START_STAMP, "cleanTime": 65 * 60, "taskType": 2}],
                "total": 3,
            },
        }
        self.schedule: Any = {"cleanTime": "07:00", "cleanDuration": 2, "cleanWeekList": [2, 4, 6]}
        self.legacy_reads = 0

    def device_zone_name(self, _sn: str) -> str:
        return ZONE.key

    async def get_devices(self) -> list[dict[str, Any]]:
        return [{"sn": SN, "name": "Robot", "model": "Scuba_S3", "online": False}]

    async def get_device_info(self, _sn: str) -> dict[str, Any]:
        return {}

    async def get_cleaning_history(self, _sn: str) -> Any:
        self.legacy_reads += 1
        return {"code": 0, "data": {"total": 0, "list": []}}

    async def get_scuba_s3_history_page(self, _sn: str) -> dict[str, Any]:
        return self.page

    async def get_scuba_s3_history_statistics(self, _sn: str) -> Any:
        raise TimeoutError

    async def get_scuba_s3_cycle_schedule(self, _sn: str) -> dict[str, Any]:
        return {"code": 0, "data": self.schedule}

    async def get_consumables(self, _sn: str) -> None:
        return None


async def test_offline_s3_publishes_cloud_history_and_schedule_and_clears_schedule(hass: HomeAssistant) -> None:
    api = _CloudApi()
    coordinator = make_coordinator(api, hass=hass)
    coordinator.data = await coordinator._async_update_data()
    device = coordinator.data[SN]
    assert device["online"].value is False
    assert device["total_cleanings"].value == 3
    assert device["last_cleaning_mode"].value == "Floor"
    assert device["last_cleaning_duration"].value == 65
    assert device["total_cleaning_time"].value is None
    assert device["next_scheduled_clean"].attributes["time_zone"] == ZONE.key
    assert api.legacy_reads == 0

    api.page = {"code": 403}
    api.schedule = None
    coordinator._last_metadata_fetch.clear()
    coordinator.data = await coordinator._async_update_data()
    assert coordinator.data[SN]["total_cleanings"].value == 3
    assert coordinator.data[SN]["next_scheduled_clean"].attributes["schedule"] == []
    assert api.legacy_reads == 0


async def test_s3_falls_back_to_legacy_if_no_valid_new_history(hass: HomeAssistant) -> None:
    api = _CloudApi()
    api.page = {"code": 0, "data": {"unrecognized": True}}
    api.schedule = {"cleanWeekList": []}
    coordinator = make_coordinator(api, hass=hass)
    device = (await coordinator._async_update_data())[SN]
    assert device["total_cleanings"].value == 0
    assert device["next_scheduled_clean"].attributes["schedule"] == []
    assert api.legacy_reads == 1


async def test_schedule_sensor_uses_device_timezone(hass: HomeAssistant, monkeypatch: pytest.MonkeyPatch) -> None:
    entry, coordinator = _hass_with_device(hass, {"model": "Scuba_S3", "name": "Cleaner"})
    assert not any(
        getattr(getattr(entity, "entity_description", None), "key", None) == "next_scheduled_clean"
        for entity in await _setup_platform(sensor, hass, entry)
    )
    state = scuba_s3_schedule_state({"data": _CloudApi().schedule}, ZONE.key)
    assert isinstance(state, EntityState)
    coordinator.data["SN123"]["next_scheduled_clean"] = state
    monkeypatch.setattr(dt_util, "now", lambda: NOW.astimezone(UTC))
    schedule = _entity_by_key(await _setup_platform(sensor, hass, entry), "next_scheduled_clean")
    assert schedule.native_value == datetime(2026, 11, 28, 7, tzinfo=ZONE)
    assert schedule.extra_state_attributes["duration_minutes"] == 60
