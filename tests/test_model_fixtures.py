"""Contract tests for the seeded model fixtures and the onboarding pipeline.

Every ``tests/fixtures/models/*.json`` file must load into
``derive_device_profile`` cleanly and yield the capability set and mode map we
expect for that model. The expectations are snapshotted here on purpose: a
change in profile logic that shifts a supported model's surface should force a
deliberate edit to this file.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from custom_components.aiper.profiles import derive_device_profile, model_key
from tools import aiper_probe, fixture_from_probe

FIXTURES_DIR = Path(__file__).parent / "fixtures" / "models"
FIXTURE_FILES = sorted(FIXTURES_DIR.glob("*.json"))

# model_key -> expected derived profile surface.
EXPECTED_PROFILES: dict[str, dict[str, Any]] = {
    "scuba_s1_2025": {
        "family": "scuba",
        "capabilities": {
            "battery",
            "bluetooth",
            "charging",
            "clean_path",
            "device_link",
            "estimated_cleaning_time",
            "firmware",
            "in_water",
            "micromesh_filter",
            "mode_select",
            "mqtt_shadow",
            "online",
            "status",
            "warning",
            "wifi",
        },
        "mode_map": {1: "Auto", 2: "Floor", 3: "Wall", 5: "Scheduled"},
    },
    "scuba_p1_pro": {
        "family": "scuba",
        "capabilities": {
            "battery",
            "bluetooth",
            "charging",
            "clean_path",
            "device_link",
            "firmware",
            "in_water",
            "micromesh_filter",
            "mode_select",
            "mqtt_shadow",
            "online",
            "roller_brush",
            "status",
            "warning",
            "wifi",
        },
        "mode_map": {1: "Smart", 2: "Floor", 3: "Wall", 4: "Waterline", 5: "Scheduled"},
    },
    "scuba_v3": {
        "family": "scuba",
        "capabilities": {
            "battery",
            "bluetooth",
            "charging",
            "clean_path",
            "device_link",
            "firmware",
            "in_water",
            "micromesh_filter",
            "mode_select",
            "mqtt_shadow",
            "online",
            "status",
            "warning",
            "wifi",
        },
        "mode_map": {1: "Smart", 2: "Floor", 3: "Wall", 4: "Waterline", 5: "Scheduled"},
    },
    "scuba_x1": {
        "family": "scuba",
        "capabilities": {
            "battery",
            "bluetooth",
            "caterpillar_tread",
            "charge_type",
            "charging",
            "clean_path",
            "device_link",
            "firmware",
            "in_water",
            "micromesh_filter",
            "mode_select",
            "mqtt_shadow",
            "online",
            "propeller",
            "roller_brush",
            "status",
            "warning",
            "water_temperature",
            "wifi",
        },
        "mode_map": {1: "Smart", 2: "Floor", 3: "Wall", 4: "Waterline", 5: "Scheduled"},
    },
    "surfer_s2": {
        "family": "surfer",
        "capabilities": {
            "battery",
            "bluetooth",
            "charge_type",
            "charging",
            "device_link",
            "firmware",
            "micromesh_filter",
            "mqtt_shadow",
            "online",
            "propeller",
            "running_control",
            "solar_charging",
            "status",
            "warning",
            "wifi",
        },
        "mode_map": {0: "Off", 1: "Manual", 5: "Scheduled"},
    },
    "shark": {
        "family": "shark",
        "capabilities": {
            "battery",
            "bluetooth",
            "caterpillar_tread",
            "charge_type",
            "charging",
            "device_link",
            "firmware",
            "micromesh_filter",
            "mqtt_shadow",
            "online",
            "propeller",
            "roller_brush",
            "status",
            "warning",
            "wifi",
        },
        "mode_map": {},
    },
    "hydrocomm": {
        "family": "hydrocomm",
        "capabilities": {
            "battery",
            "bluetooth",
            "charge_type",
            "charging",
            "firmware",
            "mqtt_shadow",
            "online",
            "probe_status",
            "solar_charging",
            "status",
            "warning",
            "water_quality",
            "water_temperature",
            "wifi",
        },
        "mode_map": {},
    },
}


def test_every_expected_model_has_a_fixture() -> None:
    """The seed set and the expectation table must stay in lockstep."""
    stems = {path.stem for path in FIXTURE_FILES}
    assert stems == set(EXPECTED_PROFILES), f"fixture files {stems} != expectations {set(EXPECTED_PROFILES)}"


@pytest.mark.parametrize("fixture_path", FIXTURE_FILES, ids=lambda p: p.stem)
def test_model_fixture_derives_expected_profile(fixture_path: Path) -> None:
    """Each seeded fixture loads and derives its snapshotted profile."""
    device = json.loads(fixture_path.read_text(encoding="utf-8"))

    assert model_key(device) == fixture_path.stem

    profile = derive_device_profile(device)
    expected = EXPECTED_PROFILES[fixture_path.stem]

    assert profile.family.value == expected["family"]
    assert {cap.value for cap in profile.capabilities} == expected["capabilities"]
    assert profile.mode_map == expected["mode_map"]


def _fake_bundle_inputs() -> dict[str, Any]:
    """A probe-shaped payload seeded with fake secrets that must not survive."""
    secrets = {
        "token": "tok-LEAK-1111",
        "secretKey": "sk-LEAK-2222",
        "openId": "oid-LEAK-3333",
        "identityId": "eu-central-1:LEAK-4444",
    }
    device_info = {
        "ok": True,
        "data": {
            "sn": "SEEDSN123456",
            "model": "Scuba_V3",
            "name": "Scuba V3",
            "deviceType": "3",
            "fw_main": "V1.0.0",
            "auth": dict(secrets),
            "payload": {"data": {"session": {"token": secrets["token"]}}},
        },
    }
    return {
        "secrets": secrets,
        "device_info": device_info,
        "device_status": {"ok": True, "data": {"online": 1, "openId": secrets["openId"]}},
        "consumables": {"ok": True, "data": {"list": [], "identityId": secrets["identityId"]}},
        "shadow": {
            "_topic": "$aws/things/SEEDSN123456/shadow/get/accepted",
            "Machine": {"status": 1, "mode": 1, "temp": 28, "report": "+INFO: 1,1,80,0,12,1"},
            "credentials": {"secretKey": secrets["secretKey"]},
        },
    }


def test_build_bundle_redacts_secrets_and_stamps_versions() -> None:
    """aiper_probe.build_bundle must strip every fake credential value."""
    seed = _fake_bundle_inputs()
    bundle = aiper_probe.build_bundle(
        sn="SEEDSN123456",
        device_identity=seed["device_info"],
        device_status=seed["device_status"],
        consumables=seed["consumables"],
        device_shadow=seed["shadow"],
        machine_report=seed["shadow"]["Machine"]["report"],
        mode_query={"ok": True, "data": 1},
        clean_path_query={"ok": True, "data": 0},
    )

    blob = json.dumps(bundle)
    for name, value in seed["secrets"].items():
        assert value not in blob, f"{name} value leaked into the bundle"

    assert bundle["bundle_schema_version"] == aiper_probe.BUNDLE_SCHEMA_VERSION
    assert bundle["integration_version"] == aiper_probe.integration_version()
    assert bundle["integration_version"] != "unknown"
    # Serial numbers are intentionally preserved for correlation.
    assert bundle["sn"] == "SEEDSN123456"
    assert "SEEDSN123456" in blob


def test_fixture_from_probe_roundtrips_bundle_into_profile_stub() -> None:
    """A bundle turns into a derive-able device dict plus a TODO-marked stub."""
    seed = _fake_bundle_inputs()
    bundle = aiper_probe.build_bundle(
        sn="SEEDSN123456",
        device_identity=seed["device_info"],
        device_status=seed["device_status"],
        consumables=seed["consumables"],
        device_shadow=seed["shadow"],
        machine_report=seed["shadow"]["Machine"]["report"],
        mode_query={"ok": True, "data": 1},
        clean_path_query={"ok": True, "data": 0},
    )

    device, guesses = fixture_from_probe.build_fixture_device(bundle)
    assert model_key(device) == "scuba_v3"
    # derive_device_profile must accept the reconstructed dict without error.
    profile = derive_device_profile(device)
    assert profile.family.value == "scuba"

    stub = fixture_from_probe.render_profile_stub(device, guesses)
    assert "SCUBA_V3_STATUS_SEMANTICS = StatusSemantics(" in stub
    assert "# TODO: verify on hardware" in stub
    assert "MODEL_STATUS_SEMANTICS['scuba_v3']" in stub

    # No fake secret may survive into the fixture dict or the printed stub.
    leak_surface = json.dumps(device) + stub
    for name, value in seed["secrets"].items():
        assert value not in leak_surface, f"{name} value leaked into fixture_from_probe output"


def test_fixture_from_probe_writes_named_file(tmp_path: Path) -> None:
    """write_fixture keys the output file by model_key."""
    seed = _fake_bundle_inputs()
    bundle = aiper_probe.build_bundle(
        sn="SEEDSN123456",
        device_identity=seed["device_info"],
        device_status=seed["device_status"],
        consumables=seed["consumables"],
        device_shadow=seed["shadow"],
        machine_report=None,
        mode_query=None,
        clean_path_query=None,
    )
    device, _ = fixture_from_probe.build_fixture_device(bundle)
    path = fixture_from_probe.write_fixture(device, tmp_path)
    assert path.name == "scuba_v3.json"
    assert json.loads(path.read_text(encoding="utf-8"))["model"] == "Scuba_V3"
