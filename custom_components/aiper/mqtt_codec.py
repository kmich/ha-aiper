"""Pure-Python AWS IoT SigV4 WebSocket signer and MQTT 3.1.1 wire codec."""

from __future__ import annotations

import hashlib
import hmac
from dataclasses import dataclass
from datetime import UTC, datetime
from urllib.parse import quote

PACKET_CONNECT = 1
PACKET_CONNACK = 2
PACKET_PUBLISH = 3
PACKET_PUBACK = 4
PACKET_SUBSCRIBE = 8
PACKET_SUBACK = 9
PACKET_PINGREQ = 12
PACKET_PINGRESP = 13
PACKET_DISCONNECT = 14

_EMPTY_SHA256 = hashlib.sha256(b"").hexdigest()


@dataclass(frozen=True, kw_only=True)
class AwsIotCredentials:
    """Temporary AWS credentials returned by Cognito."""

    access_key_id: str
    secret_access_key: str
    session_token: str | None = None


@dataclass(frozen=True)
class ConnAckPacket:
    """Decoded MQTT CONNACK packet."""

    session_present: bool
    return_code: int


@dataclass(frozen=True)
class PublishPacket:
    """Decoded MQTT PUBLISH packet."""

    topic: str
    payload: bytes
    qos: int
    packet_id: int | None


@dataclass(frozen=True)
class PubAckPacket:
    """Decoded MQTT PUBACK packet."""

    packet_id: int


@dataclass(frozen=True)
class SubAckPacket:
    """Decoded MQTT SUBACK packet."""

    packet_id: int
    return_codes: tuple[int, ...]


@dataclass(frozen=True)
class PingRespPacket:
    """Decoded MQTT PINGRESP packet."""


MqttPacket = ConnAckPacket | PublishPacket | PubAckPacket | SubAckPacket | PingRespPacket


def _hmac_sha256(key: bytes, data: bytes) -> bytes:
    return hmac.new(key, data, hashlib.sha256).digest()


def sign_aws_iot_websocket_url(
    endpoint: str,
    region: str,
    credentials: AwsIotCredentials,
    *,
    now: datetime | None = None,
) -> str:
    """Return a SigV4-presigned ``wss://.../mqtt`` URL for AWS IoT Core.

    AWS IoT's ``iotdevicegateway`` service signs only ``X-Amz-Algorithm``,
    ``X-Amz-Credential``, ``X-Amz-Date``, and ``X-Amz-SignedHeaders`` in the
    canonical query string and appends ``X-Amz-Security-Token`` afterwards
    (matching ``awsiotsdk`` / ``awscrt`` with ``omit_session_token=True``).
    """
    host = endpoint.strip().lower()
    for prefix in ("wss://", "https://"):
        if host.startswith(prefix):
            host = host[len(prefix) :]
            break
    host = host.rstrip("/")

    timestamp = (now or datetime.now(UTC)).astimezone(UTC)
    amz_date = timestamp.strftime("%Y%m%dT%H%M%SZ")
    date_stamp = timestamp.strftime("%Y%m%d")
    service = "iotdevicegateway"
    scope = f"{date_stamp}/{region}/{service}/aws4_request"

    canonical_query = "&".join(
        (
            "X-Amz-Algorithm=AWS4-HMAC-SHA256",
            f"X-Amz-Credential={quote(f'{credentials.access_key_id}/{scope}', safe='-_.~')}",
            f"X-Amz-Date={amz_date}",
            "X-Amz-SignedHeaders=host",
        )
    )
    canonical_request = f"GET\n/mqtt\n{canonical_query}\nhost:{host}\n\nhost\n{_EMPTY_SHA256}"
    canonical_hash = hashlib.sha256(canonical_request.encode("utf-8")).hexdigest()
    string_to_sign = f"AWS4-HMAC-SHA256\n{amz_date}\n{scope}\n{canonical_hash}"

    k_date = _hmac_sha256(f"AWS4{credentials.secret_access_key}".encode(), date_stamp.encode("utf-8"))
    k_region = _hmac_sha256(k_date, region.encode("utf-8"))
    k_service = _hmac_sha256(k_region, service.encode("utf-8"))
    k_signing = _hmac_sha256(k_service, b"aws4_request")
    signature = hmac.new(k_signing, string_to_sign.encode("utf-8"), hashlib.sha256).hexdigest()

    query = canonical_query
    if credentials.session_token:
        query += f"&X-Amz-Security-Token={quote(credentials.session_token, safe='-_.~')}"
    query += f"&X-Amz-Signature={signature}"
    return f"wss://{host}/mqtt?{query}"


def encode_remaining_length(length: int) -> bytes:
    """Encode an MQTT 3.1.1 variable-byte remaining length."""
    if length < 0 or length > 268_435_455:
        raise ValueError(f"Invalid MQTT remaining length: {length}")
    out = bytearray()
    while True:
        byte = length % 128
        length //= 128
        if length > 0:
            byte |= 0x80
        out.append(byte)
        if length == 0:
            break
    return bytes(out)


def decode_remaining_length(buf: bytes | bytearray, offset: int = 1) -> tuple[int, int] | None:
    """Decode an MQTT 3.1.1 remaining length starting at ``offset``.

    Returns ``(length, next_offset)`` or ``None`` if more bytes are needed.
    """
    multiplier = 1
    value = 0
    pos = offset
    for _ in range(4):
        if pos >= len(buf):
            return None
        encoded = buf[pos]
        pos += 1
        value += (encoded & 0x7F) * multiplier
        if (encoded & 0x80) == 0:
            return value, pos
        multiplier *= 128
    raise ValueError("Malformed MQTT remaining length (>4 bytes)")


def encode_utf8(text: str) -> bytes:
    """Encode a length-prefixed MQTT UTF-8 string."""
    raw = text.encode("utf-8")
    if len(raw) > 0xFFFF:
        raise ValueError(f"MQTT string too long: {len(raw)} bytes")
    return len(raw).to_bytes(2, "big") + raw


def decode_utf8(data: bytes, offset: int) -> tuple[str, int]:
    """Decode a length-prefixed MQTT UTF-8 string starting at ``offset``."""
    if offset + 2 > len(data):
        raise ValueError("Truncated MQTT UTF-8 length prefix")
    length = int.from_bytes(data[offset : offset + 2], "big")
    end = offset + 2 + length
    if end > len(data):
        raise ValueError("Truncated MQTT UTF-8 string")
    return data[offset + 2 : end].decode("utf-8"), end


def _build_packet(fixed_header: int, body: bytes) -> bytes:
    return bytes((fixed_header,)) + encode_remaining_length(len(body)) + body


def encode_connect(client_id: str, *, keep_alive: int = 60, clean_session: bool = False) -> bytes:
    """Encode an MQTT 3.1.1 CONNECT packet."""
    flags = 0x02 if clean_session else 0x00
    body = b"\x00\x04MQTT\x04" + bytes((flags,)) + int(keep_alive).to_bytes(2, "big") + encode_utf8(client_id)
    return _build_packet(PACKET_CONNECT << 4, body)


def encode_subscribe(packet_id: int, topic: str, qos: int = 1) -> bytes:
    """Encode an MQTT 3.1.1 SUBSCRIBE packet for one topic."""
    body = int(packet_id).to_bytes(2, "big") + encode_utf8(topic) + bytes((int(qos) & 0x03,))
    return _build_packet((PACKET_SUBSCRIBE << 4) | 0x02, body)


def encode_publish(topic: str, payload: bytes, *, qos: int = 1, packet_id: int | None = None) -> bytes:
    """Encode an MQTT 3.1.1 PUBLISH packet."""
    qos_val = int(qos) & 0x03
    if qos_val > 0 and packet_id is None:
        raise ValueError("packet_id is required for QoS > 0 PUBLISH")
    body = encode_utf8(topic)
    if qos_val > 0 and packet_id is not None:
        body += int(packet_id).to_bytes(2, "big")
    body += payload
    fixed_header = (PACKET_PUBLISH << 4) | (qos_val << 1)
    return _build_packet(fixed_header, body)


def encode_puback(packet_id: int) -> bytes:
    """Encode an MQTT 3.1.1 PUBACK packet."""
    return _build_packet(PACKET_PUBACK << 4, int(packet_id).to_bytes(2, "big"))


def encode_pingreq() -> bytes:
    """Encode an MQTT 3.1.1 PINGREQ packet."""
    return b"\xc0\x00"


def encode_disconnect() -> bytes:
    """Encode an MQTT 3.1.1 DISCONNECT packet."""
    return b"\xe0\x00"


def topic_matches(topic_filter: str, topic_name: str) -> bool:
    """Return True if an MQTT topic name matches a subscription filter."""
    if topic_filter == topic_name:
        return True
    if topic_name.startswith("$") and topic_filter[:1] in ("+", "#"):
        return False

    filter_parts = topic_filter.split("/")
    name_parts = topic_name.split("/")
    for idx, f_part in enumerate(filter_parts):
        if f_part == "#":
            return idx == len(filter_parts) - 1
        if idx >= len(name_parts):
            return False
        if f_part != "+" and f_part != name_parts[idx]:
            return False
    return len(filter_parts) == len(name_parts)


class MqttStreamDecoder:
    """Incremental MQTT 3.1.1 packet decoder over WebSocket binary chunks."""

    def __init__(self) -> None:
        """Initialize an empty receive buffer."""
        self._buf = bytearray()

    def feed(self, chunk: bytes) -> list[MqttPacket]:
        """Append ``chunk`` and decode all complete MQTT packets."""
        self._buf.extend(chunk)
        packets: list[MqttPacket] = []

        while len(self._buf) >= 2:
            header = self._buf[0]
            decoded = decode_remaining_length(self._buf, 1)
            if decoded is None:
                break
            rem_len, body_start = decoded
            total_len = body_start + rem_len
            if len(self._buf) < total_len:
                break
            body = bytes(self._buf[body_start:total_len])
            del self._buf[:total_len]
            packet = self._parse_packet(header, body)
            if packet is not None:
                packets.append(packet)

        return packets

    @staticmethod
    def _parse_packet(header: int, body: bytes) -> MqttPacket | None:
        packet_type = header >> 4
        if packet_type == PACKET_CONNACK:
            if len(body) != 2:
                raise ValueError(f"Invalid CONNACK length: {len(body)}")
            return ConnAckPacket(session_present=bool(body[0] & 0x01), return_code=body[1])

        if packet_type == PACKET_PUBLISH:
            qos = (header >> 1) & 0x03
            topic, pos = decode_utf8(body, 0)
            packet_id: int | None = None
            if qos > 0:
                if pos + 2 > len(body):
                    raise ValueError("Truncated QoS PUBLISH packet identifier")
                packet_id = int.from_bytes(body[pos : pos + 2], "big")
                pos += 2
            return PublishPacket(topic=topic, payload=body[pos:], qos=qos, packet_id=packet_id)

        if packet_type == PACKET_PUBACK:
            if len(body) != 2:
                raise ValueError(f"Invalid PUBACK length: {len(body)}")
            return PubAckPacket(packet_id=int.from_bytes(body, "big"))

        if packet_type == PACKET_SUBACK:
            if len(body) < 3:
                raise ValueError(f"Invalid SUBACK length: {len(body)}")
            return SubAckPacket(packet_id=int.from_bytes(body[:2], "big"), return_codes=tuple(body[2:]))

        if packet_type == PACKET_PINGRESP:
            return PingRespPacket()

        return None
