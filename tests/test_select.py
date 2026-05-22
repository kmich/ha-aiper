"""Tests for Aiper select capability gating."""

from __future__ import annotations

from custom_components.aiper.select import _supports_clean_path, _supports_mode_control
from custom_components.aiper.state import normalize_device_state


def test_surfer_s2_does_not_expose_select_controls() -> None:
    """Surfer S2 exposes on/off running control through switch, not selects."""
    dev = normalize_device_state(
        {
            "model": "Surfer_S2",
            "capabilities": ["battery", "online", "running_control"],
            "supported_mode_ids": [1, 2, 3, 4, 5],
            "supported_modes_explicit": False,
        }
    )

    assert _supports_clean_path(dev) is False
    assert _supports_mode_control(dev) is False


def test_mode_capability_allows_mode_control() -> None:
    """The select helper follows the normalized profile capability."""
    dev = normalize_device_state(
        {
            "model": "Shark_X",
            "capabilities": ["mode_select"],
            "supported_mode_ids": [1, 5],
            "supported_modes_explicit": True,
        }
    )

    assert _supports_mode_control(dev) is True
