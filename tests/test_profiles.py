"""Tests for device profile and capability discovery."""

from __future__ import annotations

from custom_components.aiper.profiles import Capability, DeviceFamily, derive_device_profile


def test_surfer_profile_does_not_inherit_scuba_controls() -> None:
    """Surfer models should remain read mostly until capabilities are proven."""
    profile = derive_device_profile(
        {
            "model": "Surfer_S2",
            "_ha_supported_mode_ids": [1, 2, 3, 4, 5],
            "_ha_supported_modes_explicit": False,
            "_ha_consumables": [{"name": "Propeller"}],
        }
    )

    assert profile.family is DeviceFamily.SURFER
    assert Capability.PROPELLER_MAINTENANCE in profile.capabilities
    assert Capability.CLEAN_PATH not in profile.capabilities
    assert Capability.MODE_SELECT not in profile.capabilities
    assert profile.mode_map[5] == "Mode 5"


def test_scuba_profile_gets_scuba_controls_and_labels() -> None:
    """Scuba models can expose Scuba controls and Scuba-specific mode labels."""
    profile = derive_device_profile(
        {
            "model": "Scuba_X1",
            "_ha_supported_mode_ids": [1, 2, 3, 4, 5],
            "_ha_supported_modes_explicit": False,
        }
    )

    assert profile.family is DeviceFamily.SCUBA
    assert Capability.CLEAN_PATH in profile.capabilities
    assert Capability.MODE_SELECT in profile.capabilities
    assert profile.mode_map[1] == "Smart"
    assert profile.mode_map[5] == "Scheduled"


def test_explicit_mode_evidence_enables_non_scuba_mode_control() -> None:
    """A non-Scuba model can expose mode select when payloads prove support."""
    profile = derive_device_profile(
        {
            "model": "Surfer_S2",
            "_ha_supported_mode_ids": [1, 5],
            "_ha_supported_modes_explicit": True,
        }
    )

    assert Capability.MODE_SELECT in profile.capabilities
    assert profile.mode_map == {1: "Mode 1", 5: "Mode 5"}
