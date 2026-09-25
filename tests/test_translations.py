"""Tests for integration translation assets."""

from __future__ import annotations

import json
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
