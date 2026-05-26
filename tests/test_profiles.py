"""Tests for device profile and capability discovery."""

from __future__ import annotations

from custom_components.aiper.profiles import Capability, DeviceFamily, derive_device_profile


def test_surfer_profile_exposes_verified_controls_without_mode_select() -> None:
    """Surfer models expose verified controls without Scuba mode selection."""
    profile = derive_device_profile(
        {
            "model": "Surfer_S2",
            "supported_mode_ids": [1, 2, 3, 4, 5],
            "supported_modes_explicit": False,
            "consumables": [
                {"name": "Propeller"},
                {"name": "Roller Brush"},
                {"name": "MicroMesh Filter"},
                {"name": "Caterpillar Tread"},
            ],
        }
    )

    assert profile.family is DeviceFamily.SURFER
    assert Capability.RUNNING_CONTROL in profile.capabilities
    assert Capability.CLEAN_PATH not in profile.capabilities
    assert Capability.CLEANING_MODE_SELECT not in profile.capabilities
    assert profile.mode_map[0] == "Off"
    assert profile.mode_map[1] == "Manual"
    assert profile.mode_map[5] == "Scheduled"


def test_scuba_profile_gets_scuba_controls_and_labels() -> None:
    """Scuba models can expose Scuba controls and Scuba-specific mode labels."""
    profile = derive_device_profile(
        {
            "model": "Scuba_X1",
            "supported_mode_ids": [1, 2, 3, 4, 5],
            "supported_modes_explicit": False,
        }
    )

    assert profile.family is DeviceFamily.SCUBA
    assert Capability.CLEAN_PATH in profile.capabilities
    assert Capability.CLEANING_MODE_SELECT in profile.capabilities
    assert profile.mode_map[1] == "Smart"
    assert profile.mode_map[5] == "Scheduled"


def test_scuba_profile_defaults_modes_by_family() -> None:
    """Scuba defaults are family-specific, not a coordinator fallback."""
    profile = derive_device_profile({"model": "Scuba_X1"})

    assert Capability.CLEANING_MODE_SELECT in profile.capabilities
    assert profile.mode_map == {
        1: "Smart",
        2: "Floor",
        3: "Wall",
        4: "Waterline",
        5: "Scheduled",
    }


def test_surfer_mode_evidence_stays_read_only() -> None:
    """Surfer mode IDs describe cleaning context, not selectable cleaning modes."""
    profile = derive_device_profile(
        {
            "model": "Surfer_S2",
            "supported_mode_ids": [1, 5],
            "supported_modes_explicit": True,
        }
    )

    assert Capability.CLEANING_MODE_SELECT not in profile.capabilities
    assert profile.mode_map == {0: "Off", 1: "Manual", 5: "Scheduled"}


def test_shark_explicit_mode_evidence_enables_cleaning_mode_control() -> None:
    """Shark can join cleaning-mode control when payloads provide mode IDs."""
    profile = derive_device_profile(
        {
            "model": "Shark_X",
            "supported_mode_ids": [1, 2],
            "supported_modes_explicit": True,
        }
    )

    assert profile.family is DeviceFamily.SHARK
    assert Capability.CLEANING_MODE_SELECT in profile.capabilities
    assert profile.mode_map == {1: "Mode 1", 2: "Mode 2"}


def test_explicit_device_mode_ids_can_be_outside_known_cleaning_mode_labels() -> None:
    """Profiles preserve explicit device IDs even when the label enum is incomplete."""
    profile = derive_device_profile(
        {
            "model": "Shark_X",
            "supported_mode_ids": [7],
            "supported_modes_explicit": True,
        }
    )

    assert Capability.CLEANING_MODE_SELECT in profile.capabilities
    assert profile.mode_map == {7: "Mode 7"}


def test_unknown_profile_does_not_invent_modes() -> None:
    """Unknown models stay read-only until payload evidence identifies modes."""
    profile = derive_device_profile({"model": "Mystery"})

    assert Capability.CLEANING_MODE_SELECT not in profile.capabilities
    assert profile.mode_map == {}


def test_hydrocomm_detected_via_device_type() -> None:
    """HydroComm is identified when deviceType is 4, regardless of model string."""
    profile = derive_device_profile({"deviceType": "4", "model": ""})

    assert profile.family is DeviceFamily.HYDROCOMM
    assert Capability.CLEANING_MODE_SELECT not in profile.capabilities
    assert Capability.STATUS in profile.capabilities
    assert Capability.WATER_QUALITY in profile.capabilities
    assert profile.mode_map == {}


def test_hydrocomm_detected_via_model_string() -> None:
    """HydroComm is identified when the model field contains hydrocomm."""
    profile = derive_device_profile({"model": "HydroComm"})

    assert profile.family is DeviceFamily.HYDROCOMM
    assert Capability.ONLINE in profile.capabilities
    assert Capability.BATTERY in profile.capabilities
    assert Capability.WIFI in profile.capabilities
    assert Capability.FIRMWARE in profile.capabilities
    assert Capability.STATUS in profile.capabilities
    assert Capability.WARNING in profile.capabilities
    assert Capability.WATER_TEMPERATURE in profile.capabilities
    assert Capability.WATER_QUALITY in profile.capabilities
    assert Capability.PROBE_STATUS in profile.capabilities
    assert Capability.CLEANING_MODE_SELECT not in profile.capabilities
    assert Capability.RUNNING_CONTROL not in profile.capabilities
    assert Capability.CLEAN_PATH not in profile.capabilities
    assert Capability.IN_WATER not in profile.capabilities
    assert profile.mode_map == {}


def test_hydrocomm_detected_via_bt_name_fallback() -> None:
    """HydroComm is identified via btName when model field is absent."""
    profile = derive_device_profile({"model": "", "btName": "Aiper-HydroComm-W2X60601424"})

    assert profile.family is DeviceFamily.HYDROCOMM
    assert Capability.CLEANING_MODE_SELECT not in profile.capabilities
    assert Capability.STATUS in profile.capabilities
    assert profile.mode_map == {}


def test_hydrocomm_profile_exposes_water_quality_capabilities() -> None:
    """HydroComm exposes monitor sensors without cleaner controls."""
    profile = derive_device_profile({"model": "HydroComm", "temp": 28.5})

    assert profile.family is DeviceFamily.HYDROCOMM
    assert Capability.WATER_TEMPERATURE in profile.capabilities
    assert Capability.WATER_QUALITY in profile.capabilities
    assert Capability.RUNNING_CONTROL not in profile.capabilities


def test_hydrohub_and_bare_w2_map_to_hydrocomm_family() -> None:
    """The APK's W2 family includes HydroHub and bare W2 monitor models."""
    assert derive_device_profile({"model": "HydroHub Pro"}).family is DeviceFamily.HYDROCOMM
    assert derive_device_profile({"model": "W2"}).family is DeviceFamily.HYDROCOMM
