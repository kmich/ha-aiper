"""Tests for pure value helpers: coercion, status/clean-path parsing, redaction."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import timedelta

import pytest

from custom_components.aiper.connection import ConnectionStatus
from custom_components.aiper.const import (
    Status,
    clean_path_value,
    status_label,
    status_running,
    status_value,
)
from custom_components.aiper.redaction import redact, redact_known_values, redact_serial, redact_topic
from custom_components.aiper.state_common import (
    _centihours_to_hours,
    _coerce_bool,
    _coerce_float,
    _coerce_int,
    _hours,
)


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        (None, None),
        (True, True),
        (1, True),
        (0, False),
        (2, True),
        (0.0, False),
        (" Online ", True),
        ("disconnected", False),
        ("7", True),
        ("0", False),
        ("maybe", None),
        ([1], True),
        ([], False),
    ],
)
def test_coerce_bool(value, expected) -> None:
    assert _coerce_bool(value) is expected


@pytest.mark.parametrize(
    ("value", "expected"),
    [(True, None), (None, None), (5, 5), (5.9, 5), (" -3 ", -3), ("3.5", None), ([], None)],
)
def test_coerce_int(value, expected) -> None:
    assert _coerce_int(value) == expected


@pytest.mark.parametrize(
    ("value", "expected"),
    [(False, None), (None, None), (2, 2.0), (" 2.5 ", 2.5), ("x", None), ({}, None)],
)
def test_coerce_float(value, expected) -> None:
    assert _coerce_float(value) == expected


@pytest.mark.parametrize(
    ("value", "expected"),
    [(True, None), (None, None), (250, 2.5), (250.0, 2.5), (" 125 ", 1.25), ("1.5", None), (2.5, None)],
)
def test_centihours_to_hours(value, expected) -> None:
    assert _centihours_to_hours(value) == expected


@pytest.mark.parametrize(
    ("value", "expected"),
    [(True, None), (None, None), (1.234, 1.23), ("2.345", 2.35), ("x", None), ([], None)],
)
def test_hours(value, expected) -> None:
    assert _hours(value) == expected


def test_status_helpers_handle_unknown_and_invalid_values() -> None:
    assert status_value(None) is None
    assert status_value("bad") is None  # type: ignore[arg-type]
    assert status_value(0x81) == Status.CLEANING
    assert status_running(None) is False
    assert status_running(0x82) is True
    assert status_label(None) == "Status None"
    assert status_label(0x7F) == "Status 127"
    assert status_label(Status.CHARGED) == "Charged"


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        (None, None),
        (-1, 0),
        (1, 1),
        (-1.0, 0),
        (1.0, 1),
        ("", None),
        ("-1", 0),
        ("S-shaped", 0),
        ("adaptive_mode", 1),
        ("s shape", 0),
        ("S", 0),
        ("random", None),
        (object(), None),
    ],
)
def test_clean_path_value(value, expected) -> None:
    assert clean_path_value(value) == expected


def test_clean_path_value_never_raises() -> None:
    class Weird(float):
        def __int__(self) -> int:
            raise ValueError("nope")

    assert clean_path_value(Weird(1.0)) is None


def test_redaction_edge_cases() -> None:
    assert redact_serial("") == ""
    assert redact_topic(None) == "None"
    assert redact_topic("aiper/things/SN1234567890/upChan") == "aiper/things/SN1...890/upChan"
    assert redact_topic("no/serial/here") == "no/serial/here"

    long_text = "x" * 600
    out = redact(
        {"tuple": ("a", {"token": "t"}), "set": {"a"}, "frozen": frozenset({"b"}), "long": long_text},
    )
    assert out["tuple"] == ("a", {"token": "***"})
    assert out["set"] == {"a"}
    assert out["frozen"] == frozenset({"b"})
    assert len(out["long"]) == 256 + 3 + 64
    assert redact(long_text, truncate_strings=False) == long_text


def test_redact_known_values_walks_nested_containers() -> None:
    @dataclass
    class Holder:
        value: str

    data = [("SN1234567890", Holder("id SN1234567890")), 5]

    assert redact_known_values(data, {"SN1234567890", ""}) == [("SN1...890", {"value": "id SN1...890"}), 5]
    assert redact_known_values(data, set()) is data


def test_connection_seconds_in_state() -> None:
    status = ConnectionStatus()
    later = status.last_state_change + timedelta(seconds=30)

    assert status.seconds_in_state(now=later) == 30
    assert status.seconds_in_state() >= 0
