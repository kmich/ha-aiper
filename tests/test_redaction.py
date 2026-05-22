"""Tests for shared redaction helpers."""

from __future__ import annotations

from custom_components.aiper.redaction import redact, redact_str


def test_redact_keeps_serial_numbers_but_redacts_sensitive_keys() -> None:
    """Serial numbers remain visible while credentials are masked."""
    payload = {
        "sn": "S2SERIAL123",
        "serialNumber": "S2SERIAL123",
        "token": "runtime-token",
        "SecretKey": "aws-secret",
        "nested": {"identityId": "eu-central-1:abc"},
    }

    redacted = redact(payload)

    assert redacted["sn"] == "S2SERIAL123"
    assert redacted["serialNumber"] == "S2SERIAL123"
    assert redacted["token"] == "***"
    assert redacted["SecretKey"] == "***"
    assert redacted["nested"]["identityId"] == "***"


def test_redact_str_shortens_identifiers() -> None:
    """Identifier redaction keeps enough context for diagnostics."""
    assert redact_str("person@example.com") == "per...com"
    assert redact_str("short") == "***"
