#!/usr/bin/env python3
"""Aiper discovery utility.

This tool intentionally reuses the integration's AiperApi implementation. It
adds only orchestration, capture, redaction, and reporting around the same REST
and MQTT code Home Assistant uses.
"""

from __future__ import annotations

import argparse
import asyncio
import getpass
import json
import os
import sys
from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import asynccontextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import aiohttp

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

try:
    import yaml
except ImportError:  # pragma: no cover - exercised only in incomplete dev envs
    yaml = None  # type: ignore[assignment]

from custom_components.aiper.api import AiperApi  # noqa: E402
from custom_components.aiper.const import MqttTopic  # noqa: E402
from custom_components.aiper.redaction import redact, redact_str  # noqa: E402

DEFAULT_OUTPUT_DIR = Path("probe-output")
DISCOVERY_FLOWS_DIR = REPO_ROOT / "tools" / "discovery_flows"
DEFAULT_DISCOVERY_FLOW = "generic"


def _utc_now() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds")


def _json_default(value: Any) -> str:
    if isinstance(value, datetime):
        return value.isoformat()
    return repr(value)


def _write_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(redact(data), indent=2, sort_keys=True, default=_json_default) + "\n",
        encoding="utf-8",
    )


def _append_ndjson(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as file:
        file.write(json.dumps(redact(data), sort_keys=True, default=_json_default) + "\n")


def _run_dir(base_dir: Path, prefix: str) -> Path:
    stamp = datetime.now(UTC).strftime("%Y%m%d-%H%M%S")
    path = base_dir / f"{stamp}-{prefix}"
    path.mkdir(parents=True, exist_ok=False)
    return path


def _device_sn(device: dict[str, Any]) -> str | None:
    for key in ("sn", "deviceSn", "serialNumber", "equipmentSn", "deviceSN"):
        value = device.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return None


def _device_label(device: dict[str, Any]) -> str:
    return str(
        device.get("name")
        or device.get("deviceName")
        or device.get("productName")
        or device.get("model")
        or "Aiper device"
    )


def _load_discovery_flow(profile: str) -> dict[str, Any]:
    if yaml is None:
        raise RuntimeError("PyYAML is required for guided discovery flows")

    path = DISCOVERY_FLOWS_DIR / f"{profile}.yaml"
    if not path.exists():
        available = ", ".join(sorted(p.stem for p in DISCOVERY_FLOWS_DIR.glob("*.yaml")))
        raise FileNotFoundError(f"Unknown discovery profile '{profile}'. Available profiles: {available}")

    flow = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    if not isinstance(flow, dict):
        raise ValueError(f"Discovery profile {path} must contain a mapping")
    steps = flow.get("steps")
    if not isinstance(steps, list) or not steps:
        raise ValueError(f"Discovery profile {path} must define at least one step")
    return flow


def _credentials(args: argparse.Namespace) -> tuple[str, str, str]:
    username = args.username or os.environ.get("AIPER_USERNAME")
    password = args.password or os.environ.get("AIPER_PASSWORD")
    region = args.region or os.environ.get("AIPER_REGION") or "eu"

    if not username:
        raise SystemExit("Provide --username or AIPER_USERNAME")
    if not password:
        password = getpass.getpass("Aiper password: ")
    if not password:
        raise SystemExit("Provide --password or AIPER_PASSWORD")
    return username, password, region


@asynccontextmanager
async def _make_api(args: argparse.Namespace) -> AsyncIterator[AiperApi]:
    username, password, region = _credentials(args)
    async with aiohttp.ClientSession() as session:
        api = AiperApi(username=username, password=password, region=region, async_session=session)
        api.mqtt_debug = bool(getattr(args, "mqtt_debug", False))
        if not await api.login():
            raise SystemExit("Aiper login failed")
        try:
            yield api
        finally:
            await api.disconnect()


async def _get_devices(api: AiperApi) -> list[dict[str, Any]]:
    devices = await api.get_devices()
    if not devices:
        raise SystemExit("No Aiper devices found")
    return devices


def _select_sn(devices: list[dict[str, Any]], sn: str | None) -> str:
    if sn:
        return sn
    first_sn = _device_sn(devices[0])
    if not first_sn:
        raise SystemExit("Could not infer a serial number from the first device; pass --sn")
    return first_sn


async def _capture_call(name: str, fn: Callable[[], Awaitable[Any]]) -> dict[str, Any]:
    started = _utc_now()
    try:
        return {
            "name": name,
            "started": started,
            "ok": True,
            "data": await fn(),
        }
    except Exception as err:
        return {
            "name": name,
            "started": started,
            "ok": False,
            "error": f"{type(err).__name__}: {err}",
        }


async def capture_rest_snapshot(api: AiperApi, sn: str) -> dict[str, Any]:
    """Capture read-only REST state for a device."""
    return {
        "captured_at": _utc_now(),
        "sn": sn,
        "calls": {
            "status": await _capture_call("get_device_status", lambda: api.get_device_status(sn)),
            "info": await _capture_call("get_device_info", lambda: api.get_device_info(sn)),
            "consumables": await _capture_call("get_consumables", lambda: api.get_consumables(sn)),
            "clean_path": await _capture_call("query_clean_path_setting", lambda: api.query_clean_path_setting(sn)),
        },
    }


def _region_from_iot_endpoint(endpoint: str | None) -> str | None:
    """Extract AWS region from an AWS IoT endpoint host."""
    if not endpoint or ".iot." not in endpoint:
        return None
    try:
        return endpoint.split(".iot.", 1)[1].split(".", 1)[0] or None
    except Exception:
        return None


def _region_prefix(value: str | None) -> str | None:
    """Extract the region prefix from Cognito values like eu-central-1:abc."""
    if not value or ":" not in value:
        return None
    return value.split(":", 1)[0] or None


def _effective_aws_region(api: AiperApi) -> str:
    """Return the region the API client will use for Cognito and AWS IoT."""
    api_region = getattr(api, "_aws_region", None)
    if isinstance(api_region, str) and api_region:
        return api_region
    endpoint_region = _region_from_iot_endpoint(getattr(api, "_iot_endpoint", None))
    return endpoint_region or "eu-central-1"


async def probe_mqtt_auth(api: AiperApi) -> dict[str, Any]:
    """Capture non-secret AWS IoT/Cognito region evidence."""
    started = _utc_now()
    await api.get_openid_token()

    openid = {
        "started": started,
        "ok": bool(getattr(api, "_identity_id", None) and getattr(api, "_openid_token", None)),
        "api_region": getattr(api, "_aws_region", None),
        "iot_endpoint_redacted": redact_str(str(getattr(api, "_iot_endpoint", "") or "")),
        "iot_endpoint_region": _region_from_iot_endpoint(getattr(api, "_iot_endpoint", None)),
        "cognito_id_region": _region_prefix(getattr(api, "_identity_id", None)),
        "cognito_pool_region": _region_prefix(getattr(api, "_identity_pool_id", None)),
        "token_present": bool(getattr(api, "_openid_token", None)),
    }

    credential_region = _effective_aws_region(api)
    try:
        creds = await api.get_aws_credentials()
        credentials = {
            "ok": bool(creds and creds.get("AccessKeyId")),
            "request_region": credential_region,
            "credential_keys": sorted(str(key) for key in (creds or {})),
        }
    except Exception as err:
        credentials = {
            "ok": False,
            "request_region": credential_region,
            "error": f"{type(err).__name__}: {err}",
        }

    return {
        "captured_at": _utc_now(),
        "openid": openid,
        "credentials": credentials,
        "effective_region": credential_region,
    }


def clean_path_query_candidates(device: dict[str, Any], sn: str) -> list[dict[str, Any]]:
    """Return the legacy clean-path query variants still present in api.py."""
    equip_id = device.get("equipmentId") or device.get("deviceId") or device.get("id")

    base_paths = [
        "/equipmentCleanPathSetting/getCleanPathSetting",
        "/equipmentCleanPathSetting/getCleanPathSettingBySn",
        "/equipmentCleanPathSetting/queryCleanPathSetting",
        "/network/clean_path_setting",
        "/network/cleanPathSetting",
        "/swimming/v2/queryCleanPathSetting",
        "/swimming/v2/getCleanPathSetting",
        "/swimming/v2/getCleanPathSettingBySn",
    ]
    bodies: list[dict[str, Any]] = [{"sn": sn}]
    if equip_id is not None:
        bodies = [
            {"sn": sn, "id": equip_id},
            {"sn": sn, "equipmentId": equip_id},
            {"sn": sn, "deviceId": equip_id},
            {"sn": sn},
        ]

    candidates: list[dict[str, Any]] = []
    for path in base_paths:
        for body in bodies:
            for envelope in ("encrypted", "plain"):
                candidates.append({"path": path, "body": body, "envelope": envelope})
    return candidates


def clean_path_at_commands(value: int) -> list[str]:
    """Return the legacy clean-path AT variants still present in api.py."""
    return [
        f"AT+AUTO={int(value)}",
        f"AUTO {int(value)}",
        f"AT+CPATH={int(value)}",
        f"AT+CLEANPATH={int(value)}",
        f"AT+SETPATH={int(value)}",
    ]


def _payload_summary(payload: Any) -> dict[str, Any]:
    """Summarize a REST payload without requiring readers to inspect the full body."""
    if not isinstance(payload, dict):
        return {"payload_type": type(payload).__name__}

    data = payload.get("data")
    summary: dict[str, Any] = {
        "code": payload.get("code"),
        "successful": payload.get("successful"),
        "message": payload.get("message") or payload.get("msg"),
        "data_type": type(data).__name__,
    }

    if isinstance(data, dict):
        summary["data_keys"] = sorted(str(key) for key in data)
        for key in ("pageNum", "pageNo", "page", "pageSize", "size", "total"):
            if key in data:
                summary[key] = data.get(key)
        records = data.get("list")
        if isinstance(records, list):
            summary["record_key"] = "list"
            summary["record_count"] = len(records)
    elif isinstance(data, list):
        summary["record_count"] = len(data)

    return summary


async def probe_consumables(api: AiperApi, sn: str) -> dict[str, Any]:
    """Call the consumables endpoint and capture the outcome."""
    body = {"sn": sn}
    started = _utc_now()
    try:
        payload = await api._call_with_zoneid(
            sn,
            lambda: api._call_encrypted("POST", "/poolRobot/getConsumableList", body),
        )
        attempt = {
            "started": started,
            "request_body": body,
            "ok": api._is_success(payload),
            "summary": _payload_summary(payload),
            "response": payload,
        }
    except Exception as err:
        attempt = {
            "started": started,
            "request_body": body,
            "ok": False,
            "error": f"{type(err).__name__}: {err}",
        }

    return {
        "captured_at": _utc_now(),
        "sn": sn,
        "endpoint": "/poolRobot/getConsumableList",
        "attempts": [attempt],
    }


async def probe_clean_path_query(api: AiperApi, device: dict[str, Any], sn: str) -> dict[str, Any]:
    """Try legacy clean-path query variants and capture each outcome."""
    attempts: list[dict[str, Any]] = []

    for candidate in clean_path_query_candidates(device, sn):
        path = str(candidate["path"])
        body = dict(candidate["body"])
        envelope = str(candidate["envelope"])
        started = _utc_now()
        try:
            if envelope == "plain":

                async def plain_query(
                    path: str = path,
                    body: dict[str, Any] = body,
                ) -> Any:
                    return await api._call_plain("POST", path, body)

                payload = await api._call_with_zoneid(
                    sn,
                    plain_query,
                )
            else:

                async def encrypted_query(
                    path: str = path,
                    body: dict[str, Any] = body,
                ) -> Any:
                    return await api._call_encrypted("POST", path, body)

                payload = await api._call_with_zoneid(
                    sn,
                    encrypted_query,
                )
            attempts.append(
                {
                    "started": started,
                    "path": path,
                    "request_body": body,
                    "envelope": envelope,
                    "ok": api._is_success(payload),
                    "summary": _payload_summary(payload),
                    "response": payload,
                }
            )
        except Exception as err:
            attempts.append(
                {
                    "started": started,
                    "path": path,
                    "request_body": body,
                    "envelope": envelope,
                    "ok": False,
                    "error": f"{type(err).__name__}: {err}",
                }
            )

    return {
        "captured_at": _utc_now(),
        "sn": sn,
        "attempts": attempts,
    }


async def probe_at_commands(
    api: AiperApi,
    sn: str,
    commands: list[str],
    timeout: float,
    between_seconds: float,
) -> list[dict[str, Any]]:
    """Send AT commands sequentially and capture their acknowledgements."""
    results: list[dict[str, Any]] = []
    for command in commands:
        started = _utc_now()
        result = await api.send_machine_at(sn, command, timeout=timeout)
        results.append(
            {
                "started": started,
                "sn": sn,
                "command": command,
                "acknowledged": result,
            }
        )
        await asyncio.sleep(between_seconds)
    return results


def _machine_at_message(api: AiperApi, sn: str, command: str) -> tuple[str, str]:
    """Build the compact plain and encrypted downChan payloads for one AT command."""
    data_obj = {
        "sn": sn,
        "timeZone": api._timezone_string_for_sn(sn),
        "cmd": command,
    }
    payload: dict[str, Any] = {
        "type": "Machine",
        "data": data_obj,
        "res": 0,
    }
    data_json = json.dumps(data_obj, separators=(",", ":"))
    payload["chksum"] = api._crc16(data_json)
    plain = json.dumps(payload, separators=(",", ":"))
    return plain, api._encrypt(plain)


async def publish_machine_at_format(
    api: AiperApi,
    sn: str,
    command: str,
    payload_format: str,
    timeout: float,
) -> dict[str, Any]:
    """Publish one AT command using only one payload format and wait for an ack."""
    plain, encrypted = _machine_at_message(api, sn, command)
    message = encrypted if payload_format == "encrypted" else plain
    topic = MqttTopic.WRITE.format(sn=sn)
    started = _utc_now()

    api._clear_ack_fifo(sn)
    published = await api._mqtt_client.async_publish(topic, message, 1) if api.is_mqtt_connected() else False
    ack = await api._wait_for_ack(sn, timeout=timeout) if published else None
    return {
        "started": started,
        "sn": sn,
        "command": command,
        "format": payload_format,
        "topic": topic,
        "published": bool(published),
        "ack": ack,
        "ack_ok": isinstance(ack, str) and "+OK" in ack.upper(),
        "ack_error": isinstance(ack, str) and "+ERROR" in ack.upper(),
    }


class EventRecorder:
    """Record MQTT events to an ndjson file."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self.count = 0

    def __call__(self, *args: Any) -> None:
        if len(args) == 2:
            sn, payload = args
        elif len(args) == 1:
            payload = args[0]
            sn = payload.get("_sn") if isinstance(payload, dict) else None
        else:
            sn = None
            payload = {"args": list(args)}

        event = {
            "ts": _utc_now(),
            "kind": "mqtt",
            "sn": sn,
            "topic": payload.get("_topic") if isinstance(payload, dict) else None,
            "payload": payload,
        }
        _append_ndjson(self.path, event)
        self.count += 1


async def _connect_and_subscribe(api: AiperApi, sn: str, recorder: EventRecorder) -> None:
    if not await api.connect_mqtt():
        raise SystemExit("MQTT connection failed")
    if not await api.subscribe_device(sn, recorder):
        raise SystemExit(f"MQTT subscription failed for {sn}")


def _write_manifest(
    path: Path, args: argparse.Namespace, command: str, sn: str | None, devices: list[dict[str, Any]]
) -> None:
    _write_json(
        path / "manifest.json",
        {
            "tool": "aiper_probe",
            "command": command,
            "created_at": _utc_now(),
            "region": getattr(args, "region", None) or os.environ.get("AIPER_REGION") or "eu",
            "sn": sn,
            "devices": devices,
        },
    )


async def cmd_list(args: argparse.Namespace) -> int:
    async with _make_api(args) as api:
        devices = await _get_devices(api)
        print(json.dumps(redact(devices), indent=2, sort_keys=True, default=_json_default))
        return 0


async def cmd_snapshot(args: argparse.Namespace) -> int:
    async with _make_api(args) as api:
        devices = await _get_devices(api)
        sn = _select_sn(devices, args.sn)
        out_dir = _run_dir(args.output_dir, "snapshot")
        _write_manifest(out_dir, args, "snapshot", sn, devices)
        _write_json(out_dir / "devices.json", devices)
        _write_json(out_dir / "rest-snapshot.json", await capture_rest_snapshot(api, sn))
        _write_summary(out_dir, "snapshot", sn, 0)
        print(out_dir)
        return 0


async def cmd_consumables_probe(args: argparse.Namespace) -> int:
    async with _make_api(args) as api:
        devices = await _get_devices(api)
        sn = _select_sn(devices, args.sn)
        out_dir = _run_dir(args.output_dir, "consumables")
        _write_manifest(out_dir, args, "consumables", sn, devices)
        result = await probe_consumables(api, sn)
        _write_json(out_dir / "consumables.json", result)
        _write_summary(out_dir, "consumables", sn, 0)

        for idx, attempt in enumerate(result["attempts"], start=1):
            summary = attempt.get("summary") or {}
            print(
                f"{idx}. body={attempt['request_body']} ok={attempt['ok']} "
                f"code={summary.get('code')} successful={summary.get('successful')} "
                f"records={summary.get('record_count')}"
            )
        print(out_dir)
        return 0


async def cmd_mqtt_auth(args: argparse.Namespace) -> int:
    async with _make_api(args) as api:
        devices = await _get_devices(api)
        sn = _select_sn(devices, args.sn)
        out_dir = _run_dir(args.output_dir, "mqtt-auth")
        _write_manifest(out_dir, args, "mqtt-auth", sn, devices)
        result = await probe_mqtt_auth(api)
        _write_json(out_dir / "mqtt-auth.json", result)
        _write_summary(out_dir, "mqtt-auth", sn, 0)

        openid = result["openid"]
        credentials = result["credentials"]
        print(
            "openid: "
            f"ok={openid['ok']} api_region={openid['api_region']} "
            f"endpoint_region={openid['iot_endpoint_region']} "
            f"cognito_id_region={openid['cognito_id_region']} "
            f"pool_region={openid['cognito_pool_region']}"
        )
        print(f"credentials: ok={credentials['ok']} request_region={credentials['request_region']}")
        print(out_dir)
        return 0


async def cmd_observe(args: argparse.Namespace) -> int:
    async with _make_api(args) as api:
        devices = await _get_devices(api)
        sn = _select_sn(devices, args.sn)
        out_dir = _run_dir(args.output_dir, "observe")
        _write_manifest(out_dir, args, "observe", sn, devices)
        recorder = EventRecorder(out_dir / "mqtt.ndjson")
        await _connect_and_subscribe(api, sn, recorder)
        await api.request_shadow(sn)
        await asyncio.sleep(args.seconds)
        _write_summary(out_dir, "observe", sn, recorder.count)
        print(out_dir)
        return 0


async def cmd_shadow(args: argparse.Namespace) -> int:
    args.seconds = max(args.seconds, 5)
    return await cmd_observe(args)


async def cmd_at(args: argparse.Namespace) -> int:
    if not args.allow_control:
        raise SystemExit("Refusing to send control command without --allow-control")

    async with _make_api(args) as api:
        devices = await _get_devices(api)
        sn = _select_sn(devices, args.sn)
        out_dir = _run_dir(args.output_dir, "at")
        _write_manifest(out_dir, args, "at", sn, devices)
        recorder = EventRecorder(out_dir / "mqtt.ndjson")
        await _connect_and_subscribe(api, sn, recorder)
        await api.request_shadow(sn)
        result = await api.send_machine_at(sn, args.command, timeout=args.timeout)
        _write_json(
            out_dir / "command-result.json",
            {
                "ts": _utc_now(),
                "sn": sn,
                "command": args.command,
                "acknowledged": result,
            },
        )
        await asyncio.sleep(args.observe_seconds)
        _write_summary(out_dir, "at", sn, recorder.count)
        print(out_dir)
        return 0


async def cmd_at_format(args: argparse.Namespace) -> int:
    if not args.allow_control:
        raise SystemExit("Refusing to send control command without --allow-control")

    async with _make_api(args) as api:
        devices = await _get_devices(api)
        sn = _select_sn(devices, args.sn)
        out_dir = _run_dir(args.output_dir, "at-format")
        _write_manifest(out_dir, args, "at-format", sn, devices)
        recorder = EventRecorder(out_dir / "mqtt.ndjson")
        await _connect_and_subscribe(api, sn, recorder)
        await api.request_shadow(sn)

        command = args.command
        if not command.upper().startswith("AT+"):
            command = "AT+" + command

        results = []
        for payload_format in ("plain", "encrypted"):
            result = await publish_machine_at_format(api, sn, command, payload_format, args.timeout)
            results.append(result)
            print(
                f"{payload_format}: published={result['published']} "
                f"ack={result['ack']!r} ok={result['ack_ok']} error={result['ack_error']}"
            )
            await asyncio.sleep(args.between_seconds)

        await asyncio.sleep(args.observe_seconds)
        _write_json(
            out_dir / "at-format.json",
            {
                "ts": _utc_now(),
                "sn": sn,
                "command": command,
                "results": results,
            },
        )
        _write_summary(out_dir, "at-format", sn, recorder.count)
        print(out_dir)
        return 0


async def cmd_contract_verify(args: argparse.Namespace) -> int:
    if not args.allow_control:
        raise SystemExit("Refusing to send control commands without --allow-control")

    async with _make_api(args) as api:
        devices = await _get_devices(api)
        sn = _select_sn(devices, args.sn)
        device = next((dev for dev in devices if _device_sn(dev) == sn), {})
        out_dir = _run_dir(args.output_dir, "contract-verify")
        _write_manifest(out_dir, args, "contract-verify", sn, devices)

        consumables = await probe_consumables(api, sn)
        clean_path_query = await probe_clean_path_query(api, device, sn)

        recorder = EventRecorder(out_dir / "mqtt.ndjson")
        await _connect_and_subscribe(api, sn, recorder)
        await api.request_shadow(sn)
        await asyncio.sleep(args.observe_seconds)

        mode_commands = ["AT+MODE=1", "AT+WORKMODE=1"]
        clean_path_commands = clean_path_at_commands(args.clean_path_value)
        command_results = {
            "mode": await probe_at_commands(api, sn, mode_commands, args.timeout, args.between_seconds),
            "clean_path": await probe_at_commands(api, sn, clean_path_commands, args.timeout, args.between_seconds),
        }

        await api.request_shadow(sn)
        await asyncio.sleep(args.observe_seconds)

        result = {
            "captured_at": _utc_now(),
            "sn": sn,
            "device": device,
            "rest": {
                "consumables": consumables,
                "clean_path_query": clean_path_query,
            },
            "mqtt_command_results": command_results,
        }
        _write_json(out_dir / "contract-verify.json", result)
        _write_summary(out_dir, "contract-verify", sn, recorder.count)

        consumables_ok = [a for a in consumables["attempts"] if a.get("ok")]
        clean_path_ok = [a for a in clean_path_query["attempts"] if a.get("ok")]
        print(f"consumables_ok={len(consumables_ok)} clean_path_query_ok={len(clean_path_ok)}")
        for group, results in command_results.items():
            for item in results:
                print(f"{group}: {item['command']} acknowledged={item['acknowledged']}")
        print(out_dir)
        return 0


async def cmd_guided(args: argparse.Namespace) -> int:
    flow = _load_discovery_flow(args.profile)
    async with _make_api(args) as api:
        devices = await _get_devices(api)
        sn = _select_sn(devices, args.sn)
        out_dir = _run_dir(args.output_dir, f"guided-{args.profile}")
        _write_manifest(out_dir, args, "guided", sn, devices)
        _write_json(out_dir / "flow.json", flow)
        recorder = EventRecorder(out_dir / "mqtt.ndjson")
        await _connect_and_subscribe(api, sn, recorder)

        for step in flow["steps"]:
            if not isinstance(step, dict):
                continue
            step_id = str(step.get("id") or f"step-{flow['steps'].index(step) + 1}")
            prompt = str(step.get("prompt") or f"Ready for {step_id}.")
            raw_capture = step.get("capture")
            capture: dict[str, Any] = raw_capture if isinstance(raw_capture, dict) else {}
            observe_seconds = int(capture.get("observe_seconds", args.seconds))

            print(f"\n[{step_id}] {prompt}")
            input("Press Enter to start capture...")

            step_dir = out_dir / "steps" / step_id
            if capture.get("rest", True):
                _write_json(step_dir / "rest-before.json", await capture_rest_snapshot(api, sn))
            if capture.get("shadow", True):
                await api.request_shadow(sn)

            await asyncio.sleep(observe_seconds)

            if capture.get("rest", True):
                _write_json(step_dir / "rest-after.json", await capture_rest_snapshot(api, sn))
            if capture.get("shadow", True):
                await api.request_shadow(sn)

            _write_json(
                step_dir / "step.json",
                {
                    "id": step_id,
                    "prompt": prompt,
                    "observe_seconds": observe_seconds,
                    "completed_at": _utc_now(),
                },
            )

        _write_summary(out_dir, f"guided:{args.profile}", sn, recorder.count)
        print(out_dir)
        return 0


def _write_summary(out_dir: Path, command: str, sn: str, mqtt_events: int) -> None:
    summary = (
        f"# Aiper Probe Summary\n\n"
        f"- Command: `{command}`\n"
        f"- Serial number: `{sn}`\n"
        f"- MQTT events captured: {mqtt_events}\n"
        f"- Created at: {_utc_now()}\n\n"
        "Attach this directory when reporting discovery results. Review it first; "
        "the tool redacts sensitive keys but intentionally keeps serial numbers.\n"
    )
    (out_dir / "summary.md").write_text(summary, encoding="utf-8")


def build_parser() -> argparse.ArgumentParser:
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--username", help="Aiper account username, or AIPER_USERNAME")
    common.add_argument("--password", help="Aiper account password, or AIPER_PASSWORD")
    common.add_argument("--region", choices=("eu", "us", "asia", "au"), help="Aiper API region")
    common.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT_DIR)
    common.add_argument("--mqtt-debug", action="store_true", help="Enable verbose MQTT logging in AiperApi")

    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    list_parser = subparsers.add_parser("list", parents=[common], help="List account devices")
    list_parser.set_defaults(func=cmd_list)

    snapshot_parser = subparsers.add_parser("snapshot", parents=[common], help="Capture read-only REST state")
    snapshot_parser.add_argument("--sn", help="Device serial number; defaults to the first discovered device")
    snapshot_parser.set_defaults(func=cmd_snapshot)

    consumables_parser = subparsers.add_parser(
        "consumables",
        parents=[common],
        help="Call the consumables endpoint and record the result",
    )
    consumables_parser.add_argument("--sn", help="Device serial number; defaults to the first discovered device")
    consumables_parser.set_defaults(func=cmd_consumables_probe)

    mqtt_auth_parser = subparsers.add_parser(
        "mqtt-auth",
        parents=[common],
        help="Capture non-secret Cognito/AWS IoT region evidence",
    )
    mqtt_auth_parser.add_argument("--sn", help="Device serial number; defaults to the first discovered device")
    mqtt_auth_parser.set_defaults(func=cmd_mqtt_auth)

    observe_parser = subparsers.add_parser("observe", parents=[common], help="Observe MQTT events")
    observe_parser.add_argument("--sn", help="Device serial number; defaults to the first discovered device")
    observe_parser.add_argument("--seconds", type=int, default=120)
    observe_parser.set_defaults(func=cmd_observe)

    shadow_parser = subparsers.add_parser("shadow", parents=[common], help="Request shadow and observe responses")
    shadow_parser.add_argument("--sn", help="Device serial number; defaults to the first discovered device")
    shadow_parser.add_argument("--seconds", type=int, default=15)
    shadow_parser.set_defaults(func=cmd_shadow)

    at_parser = subparsers.add_parser("at", parents=[common], help="Send one AT command and capture responses")
    at_parser.add_argument("--sn", help="Device serial number; defaults to the first discovered device")
    at_parser.add_argument("--command", required=True, help="AT command to send")
    at_parser.add_argument("--timeout", type=float, default=4.0, help="Ack wait timeout")
    at_parser.add_argument("--observe-seconds", type=int, default=15)
    at_parser.add_argument("--allow-control", action="store_true", help="Allow commands that can affect a real device")
    at_parser.set_defaults(func=cmd_at)

    at_format_parser = subparsers.add_parser(
        "at-format",
        parents=[common],
        help="Send one AT command as plain-only and encrypted-only MQTT payloads",
    )
    at_format_parser.add_argument("--sn", help="Device serial number; defaults to the first discovered device")
    at_format_parser.add_argument("--command", required=True, help="AT command to send")
    at_format_parser.add_argument("--timeout", type=float, default=4.0, help="Ack wait timeout")
    at_format_parser.add_argument("--between-seconds", type=float, default=1.0)
    at_format_parser.add_argument("--observe-seconds", type=int, default=10)
    at_format_parser.add_argument(
        "--allow-control", action="store_true", help="Allow commands that can affect a real device"
    )
    at_format_parser.set_defaults(func=cmd_at_format)

    contract_verify_parser = subparsers.add_parser(
        "contract-verify",
        parents=[common],
        help="Run REST-contract and legacy-control verification probes",
    )
    contract_verify_parser.add_argument("--sn", help="Device serial number; defaults to the first discovered device")
    contract_verify_parser.add_argument("--timeout", type=float, default=4.0, help="Ack wait timeout")
    contract_verify_parser.add_argument("--between-seconds", type=float, default=1.0)
    contract_verify_parser.add_argument("--observe-seconds", type=int, default=5)
    contract_verify_parser.add_argument("--clean-path-value", type=int, default=0)
    contract_verify_parser.add_argument(
        "--allow-control", action="store_true", help="Allow commands that can affect a real device"
    )
    contract_verify_parser.set_defaults(func=cmd_contract_verify)

    guided_parser = subparsers.add_parser("guided", parents=[common], help="Run a guided discovery flow")
    guided_parser.add_argument("--sn", help="Device serial number; defaults to the first discovered device")
    guided_parser.add_argument(
        "--profile",
        default=DEFAULT_DISCOVERY_FLOW,
        help="Discovery flow name from tools/discovery_flows",
    )
    guided_parser.add_argument("--seconds", type=int, default=30, help="Default observe seconds per step")
    guided_parser.set_defaults(func=cmd_guided)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return int(asyncio.run(args.func(args)))


if __name__ == "__main__":
    raise SystemExit(main())
