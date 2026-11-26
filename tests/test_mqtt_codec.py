"""Tests for the pure-Python AWS IoT SigV4 signer and MQTT 3.1.1 codec."""

from __future__ import annotations

from datetime import UTC, datetime
from urllib.parse import urlparse

import pytest

from custom_components.aiper.mqtt_codec import (
    PACKET_CONNACK,
    PACKET_PUBACK,
    PACKET_SUBACK,
    AwsIotCredentials,
    ConnAckPacket,
    MqttStreamDecoder,
    PingRespPacket,
    PubAckPacket,
    PublishPacket,
    SubAckPacket,
    decode_remaining_length,
    decode_utf8,
    encode_connect,
    encode_disconnect,
    encode_pingreq,
    encode_puback,
    encode_publish,
    encode_remaining_length,
    encode_subscribe,
    encode_utf8,
    sign_aws_iot_websocket_url,
    topic_matches,
)


def test_sigv4_websocket_url_matches_awscrt_golden_vector() -> None:
    """The SigV4 presigner must match awscrt's iotdevicegateway signing byte-for-byte."""
    creds = AwsIotCredentials(
        access_key_id="AKIAEXAMPLE",
        secret_access_key="secret-key-example",
        session_token="session-token+with/special=chars",
    )
    url = sign_aws_iot_websocket_url(
        "wss://EXAMPLE.iot.eu-central-1.amazonaws.com/",
        "eu-central-1",
        creds,
        now=datetime(2026, 11, 26, 12, 0, 0, tzinfo=UTC),
    )

    parsed = urlparse(url)
    assert parsed.scheme == "wss"
    assert parsed.netloc == "example.iot.eu-central-1.amazonaws.com"
    assert f"{parsed.path}?{parsed.query}" == (
        "/mqtt?X-Amz-Algorithm=AWS4-HMAC-SHA256"
        "&X-Amz-Credential=AKIAEXAMPLE%2F20261126%2Feu-central-1%2Fiotdevicegateway%2Faws4_request"
        "&X-Amz-Date=20261126T120000Z"
        "&X-Amz-SignedHeaders=host"
        "&X-Amz-Security-Token=session-token%2Bwith%2Fspecial%3Dchars"
        "&X-Amz-Signature=135b79248480576a9b04766ad078a67bc364518d447b8fae01862baab56d5438"
    )


def test_sigv4_websocket_url_without_session_token() -> None:
    """Static IAM credentials omit X-Amz-Security-Token while keeping the same signature."""
    creds = AwsIotCredentials(access_key_id="AKIAEXAMPLE", secret_access_key="secret-key-example")
    url = sign_aws_iot_websocket_url(
        "example.iot.eu-central-1.amazonaws.com",
        "eu-central-1",
        creds,
        now=datetime(2026, 11, 26, 12, 0, 0, tzinfo=UTC),
    )
    assert "X-Amz-Security-Token" not in url
    assert "X-Amz-Signature=135b79248480576a9b04766ad078a67bc364518d447b8fae01862baab56d5438" in url


@pytest.mark.parametrize("length", [0, 127, 128, 16_383, 16_384, 2_097_151, 2_097_152, 268_435_455])
def test_remaining_length_round_trip(length: int) -> None:
    encoded = encode_remaining_length(length)
    assert decode_remaining_length(b"\x00" + encoded, 1) == (length, 1 + len(encoded))


def test_remaining_length_and_utf8_validation_errors() -> None:
    with pytest.raises(ValueError):
        encode_remaining_length(-1)
    with pytest.raises(ValueError):
        encode_remaining_length(268_435_456)
    with pytest.raises(ValueError, match=">4 bytes"):
        decode_remaining_length(b"\x00\x80\x80\x80\x80", 1)
    assert decode_remaining_length(b"\x00\x80", 1) is None

    with pytest.raises(ValueError, match="too long"):
        encode_utf8("a" * 65_536)
    with pytest.raises(ValueError, match="length prefix"):
        decode_utf8(b"\x00", 0)
    with pytest.raises(ValueError, match="UTF-8 string"):
        decode_utf8(b"\x00\x05abc", 0)


def test_encoders_and_stream_decoder_handle_fragmentation_and_coalescing() -> None:
    connect_bytes = encode_connect("cid-1", keep_alive=45, clean_session=True)
    assert connect_bytes[0] == 0x10
    assert b"MQTT\x04\x02\x00\x2d" in connect_bytes

    sub_bytes = encode_subscribe(7, "aiper/things/SN1/upChan", qos=1)
    assert sub_bytes[0] == 0x82

    with pytest.raises(ValueError, match="packet_id is required"):
        encode_publish("t", b"p", qos=1, packet_id=None)

    pub_q0 = encode_publish("aiper/things/SN1/upChan", b'{"ok":1}', qos=0)
    pub_q1 = encode_publish("aiper/things/SN1/shadow/report", b"hello", qos=1, packet_id=42)
    puback = encode_puback(42)
    pingreq = encode_pingreq()
    disconnect = encode_disconnect()
    assert pingreq == b"\xc0\x00"
    assert disconnect == b"\xe0\x00"

    connack_raw = bytes((PACKET_CONNACK << 4, 2, 0x01, 0x00))
    suback_raw = bytes((PACKET_SUBACK << 4, 3)) + (7).to_bytes(2, "big") + b"\x01"
    pingresp_raw = b"\xd0\x00"
    unknown_raw = b"\xf0\x01\x00"

    stream = connack_raw + suback_raw + pub_q0 + pub_q1 + puback + pingresp_raw + unknown_raw
    decoder = MqttStreamDecoder()
    decoded: list[object] = []
    # Feed 1 byte at a time to exercise incomplete-header and incomplete-body buffering.
    for idx in range(len(stream)):
        decoded.extend(decoder.feed(stream[idx : idx + 1]))

    assert decoded == [
        ConnAckPacket(session_present=True, return_code=0),
        SubAckPacket(packet_id=7, return_codes=(1,)),
        PublishPacket(topic="aiper/things/SN1/upChan", payload=b'{"ok":1}', qos=0, packet_id=None),
        PublishPacket(topic="aiper/things/SN1/shadow/report", payload=b"hello", qos=1, packet_id=42),
        PubAckPacket(packet_id=42),
        PingRespPacket(),
    ]


def test_stream_decoder_rejects_malformed_packets() -> None:
    with pytest.raises(ValueError, match="CONNACK"):
        MqttStreamDecoder().feed(bytes((PACKET_CONNACK << 4, 1, 0)))
    with pytest.raises(ValueError, match="PUBACK"):
        MqttStreamDecoder().feed(bytes((PACKET_PUBACK << 4, 1, 0)))
    with pytest.raises(ValueError, match="SUBACK"):
        MqttStreamDecoder().feed(bytes((PACKET_SUBACK << 4, 2, 0, 1)))
    with pytest.raises(ValueError, match="PUBLISH"):
        MqttStreamDecoder().feed(b"\x32\x04\x00\x01a\x00")


def test_topic_matches_wildcards_and_dollar_rules() -> None:
    assert topic_matches("aiper/things/SN1/upChan", "aiper/things/SN1/upChan") is True
    assert topic_matches("aiper/things/+/upChan", "aiper/things/SN1/upChan") is True
    assert topic_matches("aiper/#", "aiper/things/SN1/upChan") is True
    assert topic_matches("aiper/things/SN1/#", "aiper/things/SN1") is True
    assert topic_matches("aiper/things/+/extra", "aiper/things/SN1") is False
    assert topic_matches("aiper/things/SN1", "aiper/things/SN1/upChan") is False
    assert topic_matches("aiper/things/SN1/upChan", "aiper/things/SN2/upChan") is False
    assert topic_matches("#", "$aws/things/SN1/shadow/get/accepted") is False
    assert topic_matches("+/things/SN1", "$aws/things/SN1") is False
    assert topic_matches("$aws/things/+/shadow/get/accepted", "$aws/things/SN1/shadow/get/accepted") is True
