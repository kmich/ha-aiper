"""Tests for integration translation assets."""

from __future__ import annotations

import json
import re
from pathlib import Path

INTEGRATION_DIR = Path("custom_components/aiper")


def test_strings_and_english_translation_stay_in_sync() -> None:
    """The source strings and generated English translation should match."""
    strings = json.loads((INTEGRATION_DIR / "strings.json").read_text(encoding="utf-8"))
    translation = json.loads((INTEGRATION_DIR / "translations/en.json").read_text(encoding="utf-8"))

    assert translation == strings


def test_config_flow_abort_reasons_are_translated() -> None:
    """Every abort reason the config flow can produce needs a string."""
    strings = json.loads((INTEGRATION_DIR / "strings.json").read_text(encoding="utf-8"))
    aborts = strings["config"]["abort"]

    for reason in ("already_configured", "reauth_successful"):
        assert reason in aborts


def _flatten(data: dict, prefix: str = "") -> dict[str, str]:
    out: dict[str, str] = {}
    for key, value in data.items():
        if isinstance(value, dict):
            out.update(_flatten(value, f"{prefix}{key}."))
        else:
            out[f"{prefix}{key}"] = value
    return out


def test_every_language_translates_every_english_key() -> None:
    """Non-English translations must cover the same keys and placeholders as English."""
    import re

    english = _flatten(json.loads((INTEGRATION_DIR / "translations/en.json").read_text(encoding="utf-8")))
    placeholder = re.compile(r"{(\w+)}")
    for path in sorted((INTEGRATION_DIR / "translations").glob("*.json")):
        translated = _flatten(json.loads(path.read_text(encoding="utf-8")))
        assert set(translated) == set(english), path.name
        for key, text in english.items():
            assert set(placeholder.findall(translated[key])) == set(placeholder.findall(text)), (path.name, key)


def test_entity_translation_keys_exist() -> None:
    """Every entity translation key and exception key used in code has a string."""
    from custom_components.aiper import binary_sensor, button, sensor

    strings = json.loads((INTEGRATION_DIR / "strings.json").read_text(encoding="utf-8"))
    entity = strings["entity"]
    for platform, descriptions in (
        ("sensor", (*sensor.SENSOR_DESCRIPTIONS, sensor.ESTIMATED_CLEANING_TIME_DESCRIPTION)),
        ("binary_sensor", binary_sensor.BINARY_SENSOR_DESCRIPTIONS),
        ("button", button.BUTTON_DESCRIPTIONS),
    ):
        for description in descriptions:
            assert description.translation_key in entity[platform], (platform, description.key)
            # A hard-coded name would override the translation.
            assert not isinstance(description.name, str), (platform, description.key)

    assert "running" in entity["switch"]
    assert {"mode_selection", "clean_path"} <= set(entity["select"])
    assert {"connection_state", "last_cloud_update"} <= set(entity["sensor"])
    assert "cloud_connected" in entity["binary_sensor"]

    source = "".join(p.read_text(encoding="utf-8") for p in INTEGRATION_DIR.glob("*.py"))
    used = (
        set(re.findall(r'translation_key="(\w+)"', source))
        - {key for platform in entity.values() for key in platform}
        - set(strings["issues"])
    )
    assert used <= set(strings["exceptions"]), used - set(strings["exceptions"])
