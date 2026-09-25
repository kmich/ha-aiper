"""Tests for the Aiper AES/RSA request envelope."""

from __future__ import annotations

import base64
import json

from custom_components.aiper.crypto import AiperEncryption


def test_request_round_trips_through_the_envelope() -> None:
    """A request encrypted with a session key decrypts back with the same key."""
    enc = AiperEncryption()

    envelope = json.loads(enc.encrypt_request({"sn": "SN1"}))
    plaintext = json.loads(enc.decrypt_response(envelope["data"]))

    assert plaintext["sn"] == "SN1"
    assert len(plaintext["nonce"]) == 4
    assert isinstance(plaintext["timestamp"], int)


def test_key_header_is_rsa_encrypted_per_session() -> None:
    """Each client instance uses a fresh AES key/IV, wrapped for the server's RSA key."""
    first, second = AiperEncryption(), AiperEncryption()

    assert len(base64.b64decode(first.encrypt_key_header)) == 128  # 1024-bit RSA
    assert (first.aes_key, first.iv) != (second.aes_key, second.iv)
    assert all(40 <= b <= 126 for b in first.aes_key + first.iv)


def test_plain_json_and_empty_responses_pass_through() -> None:
    enc = AiperEncryption()

    assert enc.decrypt_response('{"code": "0"}') == '{"code": "0"}'
    assert enc.decrypt_response("") == ""


def test_zero_padding_keeps_block_aligned_data() -> None:
    assert AiperEncryption._zero_pad(b"x" * 16) == b"x" * 16
    assert AiperEncryption._zero_pad(b"x") == b"x" + b"\x00" * 15


def test_non_rsa_public_key_is_rejected(monkeypatch) -> None:
    import pytest

    from custom_components.aiper import crypto

    monkeypatch.setattr(crypto, "load_der_public_key", lambda der: object())
    with pytest.raises(TypeError):
        AiperEncryption()
