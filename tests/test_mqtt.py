"""Tests for Aiper MQTT integration boundaries."""

from __future__ import annotations

import json
from typing import Any, cast

import pytest

from custom_components.aiper.api import AiperApi
from custom_components.aiper.const import MqttTopic


class FakeMqttTransport:
    """Small fake for the AWS IoT MQTT transport."""

    def __init__(self) -> None:
        self.subscriptions: dict[str, Any] = {}
        self.published: list[tuple[str, str | bytes, int]] = []

    def is_connected(self) -> bool:
        return True

    async def async_subscribe(self, topic: str, callback, qos: int = 1) -> bool:
        self.subscriptions[topic] = callback
        return True

    async def async_publish(self, topic: str, payload: str | bytes, qos: int = 1) -> bool:
        self.published.append((topic, payload, qos))
        return True

    async def async_disconnect(self) -> None:
        return None


def _api_with_fake_mqtt() -> tuple[AiperApi, FakeMqttTransport]:
    api = AiperApi("user@example.com", "secret", "asia", async_session=cast(Any, object()))
    transport = FakeMqttTransport()
    api._mqtt_client = transport
    api._mqtt_connected = True
    return api, transport


@pytest.mark.asyncio
async def test_subscribe_device_normalizes_transport_messages() -> None:
    """MQTT callbacks should preserve SN/topic metadata and ack handling."""
    api, transport = _api_with_fake_mqtt()
    events: list[tuple[str, dict[str, Any]]] = []

    assert await api.subscribe_device("SN123", lambda sn, payload: events.append((sn, payload))) is True

    topic = MqttTopic.READ.format(sn="SN123")
    message = {
        "type": "Machine",
        "data": {
            "sn": "SN123",
            "timeZone": "UTC+10",
            "ack": "+OK\r\n",
        },
    }
    transport.subscriptions[topic](topic, api._encrypt(json.dumps(message)).encode())

    assert events == [
        (
            "SN123",
            {
                "type": "Machine",
                "data": {
                    "sn": "SN123",
                    "timeZone": "UTC+10",
                    "ack": "+OK\r\n",
                },
                "_sn": "SN123",
                "_topic": topic,
            },
        )
    ]
    assert api._timezone_string_for_sn("SN123") == "UTC+10"
    assert await api._wait_for_ack("SN123", timeout=0.01) == "+OK\r\n"


@pytest.mark.asyncio
async def test_shadow_publish_uses_transport() -> None:
    """Shadow request/update helpers should publish through the transport wrapper."""
    api, transport = _api_with_fake_mqtt()

    assert await api.request_shadow("SN123") is True
    assert await api.publish_shadow_desired("SN123", {"Machine": {"status": 1}}) is True

    assert transport.published[0] == (MqttTopic.SHADOW_GET_REQUEST.format(sn="SN123"), "", 1)
    assert transport.published[1] == (
        MqttTopic.SHADOW_UPDATE.format(sn="SN123"),
        '{"state":{"desired":{"Machine":{"status":1}}}}',
        1,
    )


@pytest.mark.asyncio
async def test_downchan_command_publishes_plain_payload() -> None:
    """Command publishing should use the plain JSON payload accepted by current firmware."""
    api, transport = _api_with_fake_mqtt()

    assert await api.send_command("SN123", "Machine", {"status": 1}) is True

    assert len(transport.published) == 1
    assert transport.published[0][0] == MqttTopic.WRITE.format(sn="SN123")
    assert '"status":1' in str(transport.published[0][1])


@pytest.mark.asyncio
async def test_mqtt_paths_use_transport() -> None:
    """Shadow and command helpers should use async transport methods."""
    api, transport = _api_with_fake_mqtt()

    assert await api.request_shadow("SN123") is True
    assert await api.publish_shadow_desired("SN123", {"Machine": {"status": 1}}) is True
    assert await api.send_command("SN123", "Machine", {"status": 1}) is True

    assert transport.published[0] == (MqttTopic.SHADOW_GET_REQUEST.format(sn="SN123"), "", 1)
    assert transport.published[1] == (
        MqttTopic.SHADOW_UPDATE.format(sn="SN123"),
        '{"state":{"desired":{"Machine":{"status":1}}}}',
        1,
    )
    assert transport.published[2][0] == MqttTopic.WRITE.format(sn="SN123")
    assert '"status":1' in str(transport.published[2][1])
