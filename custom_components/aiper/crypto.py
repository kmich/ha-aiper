"""Cryptographic helpers for the Aiper cloud API.

The Aiper mobile apps wrap most REST calls in an AES-CBC encrypted `data` field.
The AES key + IV are transported in an RSA-encrypted `encryptKey` header.

This module uses `cryptography`, which is already bundled with Home Assistant.
"""

from __future__ import annotations

import base64
import json
import secrets
import time

from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.serialization import load_der_public_key


# RSA Public Key used by the official mobile app (DER, base64-encoded)
PUBLIC_KEY_STRING = (
    "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCIKoKPqwq1f60hm/2lpHDF/DT4J9YaptuTq78nsxdgnSBAvkIZ3E8d"
    "qbEBT/VETjJ9Yr28QtHX13E8QGByYxLzYPldHNXChgOWfSemTEC3TxPvlaSuM9eFUuhqSeGbgoKG7JJNlgjvsPO2cH"
    "EhPXJE4qWtKEZVOZBxEeCgAaLZxwIDAQAB"
)


class AiperEncryption:
    """Implements the AES/RSA envelope used by Aiper REST endpoints."""

    def __init__(self) -> None:
        # The Android app generates random 16-byte ASCII-ish key/IV.
        # We emulate that by sampling printable bytes (40..126 in their code).
        alphabet = bytes(range(40, 127))
        self.aes_key = bytes(secrets.choice(alphabet) for _ in range(16))
        self.iv = bytes(secrets.choice(alphabet) for _ in range(16))
        self.encrypt_key_header = self._create_encrypt_key_header()

    @staticmethod
    def _nonce() -> str:
        chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()-_=+[]{}"
        return "".join(secrets.choice(chars) for _ in range(4))

    def _create_encrypt_key_header(self) -> str:
        key_data = json.dumps(
            {
                "key": self.aes_key.decode("utf-8", errors="replace"),
                "iv": self.iv.decode("utf-8", errors="replace"),
            },
            separators=(",", ":"),
        ).encode("utf-8")

        der = base64.b64decode(PUBLIC_KEY_STRING)
        pub = load_der_public_key(der)
        encrypted = pub.encrypt(key_data, padding.PKCS1v15())
        return base64.b64encode(encrypted).decode("utf-8")

    @staticmethod
    def _zero_pad(data: bytes, block_size: int = 16) -> bytes:
        pad_len = block_size - (len(data) % block_size)
        if pad_len == block_size:
            return data
        return data + (b"\x00" * pad_len)

    @staticmethod
    def _zero_unpad(data: bytes) -> bytes:
        return data.rstrip(b"\x00")

    def encrypt_request(self, body: dict) -> str:
        body = dict(body)
        body["nonce"] = self._nonce()
        body["timestamp"] = int(time.time() * 1000)

        raw = json.dumps(body, separators=(",", ":")).encode("utf-8")
        raw = self._zero_pad(raw)

        cipher = Cipher(algorithms.AES(self.aes_key), modes.CBC(self.iv))
        encryptor = cipher.encryptor()
        ct = encryptor.update(raw) + encryptor.finalize()
        return json.dumps({"data": base64.b64encode(ct).decode("utf-8")})

    def decrypt_response(self, response_text: str) -> str:
        # If it's already JSON, return as-is.
        try:
            json.loads(response_text)
            return response_text
        except Exception:
            pass

        if not response_text:
            return response_text

        encrypted = base64.b64decode(response_text)
        cipher = Cipher(algorithms.AES(self.aes_key), modes.CBC(self.iv))
        decryptor = cipher.decryptor()
        pt = decryptor.update(encrypted) + decryptor.finalize()
        return self._zero_unpad(pt).decode("utf-8", errors="replace")
