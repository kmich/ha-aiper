#!/usr/bin/env python3
"""Turn a probe bundle into a model fixture plus a profiles.py stub.

Input: a JSON bundle produced by ``tools/aiper_probe.py bundle``.

Outputs:

* ``tests/fixtures/models/<model_key>.json`` -- a normalized device dict that
  ``custom_components.aiper.profiles.derive_device_profile`` accepts.
* a ready-to-paste ``StatusSemantics(...)`` + profile-stub snippet printed to
  stdout, with ``# TODO: verify on hardware`` markers on any guessed field.

The bundle is already redacted by the emitter; this tool never performs live
network calls.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from custom_components.aiper.profiles import (  # noqa: E402
    DeviceFamily,
    derive_device_profile,
    model_key,
)

DEFAULT_FIXTURES_DIR = REPO_ROOT / "tests" / "fixtures" / "models"

_MODEL_KEYS = ("model", "deviceModel", "productModel", "modelName", "equipmentModel")
_NAME_KEYS = ("name", "deviceName", "productName", "nickName")
_SN_KEYS = ("sn", "deviceSn", "serialNumber", "equipmentSn", "deviceSN")
_FW_KEYS = ("fw_main", "mainVersion", "firmwareVersion", "softwareVersion", "version")


def load_bundle(path: str | Path) -> dict[str, Any]:
    """Load and minimally validate a probe bundle JSON file."""
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError(f"{path}: bundle root must be a JSON object")
    return data


def _capture_data(value: Any) -> Any:
    """Unwrap a ``_capture_call`` result ({"ok": ..., "data": ...}) if present."""
    if isinstance(value, dict) and "ok" in value and ("data" in value or "error" in value):
        return value.get("data")
    return value


def _identity(bundle: dict[str, Any]) -> dict[str, Any]:
    info = _capture_data(bundle.get("rest", {}).get("get_device_info"))
    if isinstance(info, dict):
        # get_device_info() nests the raw envelope under "payload"; drop it.
        return {key: val for key, val in info.items() if key != "payload"}
    return {}


def _status(bundle: dict[str, Any]) -> dict[str, Any]:
    data = _capture_data(bundle.get("rest", {}).get("get_device_status"))
    return data if isinstance(data, dict) else {}


def _shadow_machine(bundle: dict[str, Any]) -> dict[str, Any]:
    shadow = bundle.get("mqtt", {}).get("device_shadow")
    if not isinstance(shadow, dict):
        return {}
    for container in (
        shadow.get("Machine"),
        shadow.get("machine"),
        shadow.get("data"),
        (shadow.get("state") or {}).get("reported") if isinstance(shadow.get("state"), dict) else None,
        shadow,
    ):
        if isinstance(container, dict) and any(
            key in container for key in ("status", "mode", "temp", "in_water", "cap")
        ):
            return container
    return {}


def _first(mapping: dict[str, Any], keys: tuple[str, ...]) -> Any:
    for key in keys:
        value = mapping.get(key)
        if value not in (None, ""):
            return value
    return None


def build_fixture_device(bundle: dict[str, Any]) -> tuple[dict[str, Any], list[str]]:
    """Build a normalized device dict and a list of human-readable guess notes."""
    identity = _identity(bundle)
    status = _status(bundle)
    machine = _shadow_machine(bundle)
    guesses: list[str] = []

    model = _first(identity, _MODEL_KEYS)
    if not model:
        raise ValueError(
            "bundle rest.get_device_info carries no model string; cannot key a fixture. "
            "Capture a fresh bundle once the device-info call succeeds."
        )

    device: dict[str, Any] = {
        "sn": _first(identity, _SN_KEYS) or bundle.get("sn") or "REDACTED",
        "model": str(model),
        # profiles.model_key() falls back to deviceModel; keep both aligned so a
        # fixture stays recognized even if a consumer only reads deviceModel.
        "deviceModel": str(model),
    }

    name = _first(identity, _NAME_KEYS)
    device["name"] = str(name) if name else str(model)

    device_type = identity.get("deviceType")
    if device_type is not None:
        device["deviceType"] = str(device_type)
    else:
        guesses.append("deviceType: absent from bundle; family inferred from model/name only")

    fw = _first(identity, _FW_KEYS)
    if fw is not None:
        device["fw_main"] = str(fw)

    temp = identity.get("temp") if identity.get("temp") is not None else machine.get("temp")
    if temp is not None:
        device["temp"] = temp

    in_water = identity.get("in_water") if identity.get("in_water") is not None else machine.get("in_water")
    if in_water is not None:
        device["in_water"] = in_water

    online = _first(status, ("online", "onlineStatus", "isOnline"))
    if online is not None:
        device["online"] = online

    supported = identity.get("supported_mode_ids")
    if isinstance(supported, list) and supported:
        device["supported_mode_ids"] = [int(mode_id) for mode_id in supported]
        device["supported_modes_explicit"] = bool(identity.get("supported_modes_explicit"))
    else:
        guesses.append("supported_mode_ids: no payload mode evidence; mode_map uses family defaults")

    mode_query = _capture_data(bundle.get("queries", {}).get("mode"))
    if isinstance(mode_query, int):
        device["selected_mode"] = mode_query

    device["_bundle_provenance"] = {
        "bundle_schema_version": bundle.get("bundle_schema_version"),
        "integration_version": bundle.get("integration_version"),
        "captured_at": bundle.get("captured_at"),
        "generated_by": "tools/fixture_from_probe.py",
    }
    return device, guesses


def _const_prefix(key: str) -> str:
    return "".join(ch if ch.isalnum() else "_" for ch in key).upper().strip("_")


def render_profile_stub(device: dict[str, Any], guesses: list[str]) -> str:
    """Render a paste-ready profiles.py stub for the device."""
    key = model_key(device)
    profile = derive_device_profile(device)
    prefix = _const_prefix(key)
    provenance = device.get("_bundle_provenance", {})

    caps = ", ".join(f"Capability.{cap.name}" for cap in sorted(profile.capabilities, key=lambda c: c.name))
    mode_lines = "\n".join(f"#     {mode_id}: {label!r}," for mode_id, label in sorted(profile.mode_map.items()))

    notes = list(guesses)
    if profile.family is DeviceFamily.UNKNOWN:
        notes.append("family: derive_device_profile() returned DeviceFamily.UNKNOWN")
    notes.append("status labels/charging/running: no charge or park cycle captured in the bundle")

    todo_block = "\n".join(f"# TODO: verify on hardware -- {note}" for note in notes)

    return f"""\
# ---------------------------------------------------------------------------
# profiles.py onboarding stub for model_key = {key!r}
# Generated by tools/fixture_from_probe.py
# bundle_schema_version={provenance.get("bundle_schema_version")} \
integration_version={provenance.get("integration_version")} \
captured_at={provenance.get("captured_at")}
# ---------------------------------------------------------------------------
{todo_block}

{prefix}_MODEL = {key!r}

# derive_device_profile() currently classifies this device as:
#   family       = DeviceFamily.{profile.family.name}
#   capabilities = frozenset({{{caps}}})
#   mode_map     = {{
{mode_lines or "#     (empty -- no selectable cleaning modes inferred)"}
#   }}

{prefix}_STATUS_SEMANTICS = StatusSemantics(
    labels={{
        # int(Status.RETURNING): "Charging",  # TODO: verify on hardware
    }},
    charging=frozenset({{int(Status.CHARGING)}}),  # TODO: verify on hardware
    running=frozenset({{int(Status.CLEANING)}}),  # TODO: verify on hardware
)

# Register once verified on hardware:
#     MODEL_STATUS_SEMANTICS[{key!r}] = {prefix}_STATUS_SEMANTICS
"""


def write_fixture(device: dict[str, Any], fixtures_dir: str | Path = DEFAULT_FIXTURES_DIR) -> Path:
    """Write the normalized device dict to ``<fixtures_dir>/<model_key>.json``."""
    key = model_key(device)
    if not key:
        raise ValueError("device has no resolvable model_key")
    out_dir = Path(fixtures_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    path = out_dir / f"{key}.json"
    path.write_text(json.dumps(device, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return path


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("bundle", help="Path to a bundle JSON emitted by 'aiper_probe.py bundle'")
    parser.add_argument(
        "--fixtures-dir",
        type=Path,
        default=DEFAULT_FIXTURES_DIR,
        help="Directory to write <model_key>.json into",
    )
    parser.add_argument(
        "--print-fixture",
        action="store_true",
        help="Also echo the fixture JSON to stdout",
    )
    args = parser.parse_args(argv)

    bundle = load_bundle(args.bundle)
    device, guesses = build_fixture_device(bundle)
    path = write_fixture(device, args.fixtures_dir)
    print(f"# wrote {path}", file=sys.stderr)

    if args.print_fixture:
        print(json.dumps(device, indent=2, sort_keys=True))
    print(render_profile_stub(device, guesses))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
