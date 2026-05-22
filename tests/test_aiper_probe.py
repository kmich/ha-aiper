"""Tests for the Aiper probe utility's non-live behavior."""

from __future__ import annotations

from argparse import Namespace
from typing import Any, cast

import pytest

from tools import aiper_probe


def test_load_discovery_flow() -> None:
    """Discovery flows are declarative YAML files."""
    flow = aiper_probe._load_discovery_flow("surfer-s2")

    assert flow["name"] == "Surfer S2"
    assert flow["steps"]
    assert flow["steps"][0]["id"] == "baseline_idle"


@pytest.mark.asyncio
async def test_at_command_requires_explicit_control_permission() -> None:
    """The probe should not send control commands by default."""
    args = Namespace(allow_control=False)

    with pytest.raises(SystemExit, match="--allow-control"):
        await aiper_probe.cmd_at(args)


def test_device_sn_preserves_serial_value() -> None:
    """The probe should use real serial numbers for correlation."""
    assert aiper_probe._device_sn({"serialNumber": "S2SERIAL123"}) == "S2SERIAL123"


def test_credentials_use_region_environment_when_cli_region_missing(monkeypatch: pytest.MonkeyPatch) -> None:
    """The parser default should not mask AIPER_REGION."""
    monkeypatch.setenv("AIPER_USERNAME", "user@example.com")
    monkeypatch.setenv("AIPER_PASSWORD", "secret")
    monkeypatch.setenv("AIPER_REGION", "asia")

    username, password, region = aiper_probe._credentials(Namespace(username=None, password=None, region=None))

    assert username == "user@example.com"
    assert password == "secret"
    assert region == "asia"


def test_region_from_iot_endpoint() -> None:
    """MQTT auth probe should derive AWS region from AWS IoT endpoint hosts."""
    assert aiper_probe._region_from_iot_endpoint("abc.iot.eu-central-1.amazonaws.com") == "eu-central-1"
    assert aiper_probe._region_from_iot_endpoint("iot.aiper.com") is None


def test_effective_aws_region_prefers_api_region() -> None:
    """The API-provided region should beat endpoint inference and fallback defaults."""

    class FakeApi:
        _aws_region = "ap-southeast-1"
        _iot_endpoint = "abc.iot.eu-central-1.amazonaws.com"

    assert aiper_probe._effective_aws_region(cast(Any, FakeApi())) == "ap-southeast-1"


def test_effective_aws_region_falls_back_to_endpoint_region() -> None:
    """Endpoint inference should be used when the API response has no region field."""

    class FakeApi:
        _aws_region = None
        _iot_endpoint = "abc.iot.eu-central-1.amazonaws.com"

    assert aiper_probe._effective_aws_region(cast(Any, FakeApi())) == "eu-central-1"


def test_machine_at_message_builds_plain_and_encrypted_payloads() -> None:
    """The AT format probe should build the same payload shape as the API client."""

    class FakeApi:
        def _timezone_string_for_sn(self, sn: str) -> str:
            return "UTC+10"

        def _crc16(self, data: str) -> int:
            return 123

        def _encrypt(self, data: str) -> str:
            return "encrypted:" + data

    plain, encrypted = aiper_probe._machine_at_message(cast(Any, FakeApi()), "SN123", "AT+MODE=1")

    assert plain == (
        '{"type":"Machine","data":{"sn":"SN123","timeZone":"UTC+10","cmd":"AT+MODE=1"},"res":0,"chksum":123}'
    )
    assert encrypted == "encrypted:" + plain


def test_clean_path_query_candidates_cover_legacy_variants() -> None:
    """The contract verifier should exercise the legacy clean-path matrix."""
    candidates = aiper_probe.clean_path_query_candidates({"equipmentId": "E123"}, "SN123")

    assert {
        "path": "/equipmentCleanPathSetting/getCleanPathSetting",
        "body": {"sn": "SN123", "equipmentId": "E123"},
        "envelope": "encrypted",
    } in candidates
    assert {
        "path": "/swimming/v2/getCleanPathSettingBySn",
        "body": {"sn": "SN123"},
        "envelope": "plain",
    } in candidates
    assert all(not candidate["path"].startswith("/surfer/") for candidate in candidates)


def test_clean_path_at_commands_match_legacy_control_variants() -> None:
    """The contract verifier should test the legacy clean-path AT commands."""
    assert aiper_probe.clean_path_at_commands(0) == [
        "AT+AUTO=0",
        "AUTO 0",
        "AT+CPATH=0",
        "AT+CLEANPATH=0",
        "AT+SETPATH=0",
    ]
