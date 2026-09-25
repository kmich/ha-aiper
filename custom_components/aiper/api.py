"""Aiper cloud API client for REST and MQTT communication.

The client is layered across modules, each building on the one below:

- ``api_rest.AiperRestClient``: account session, encrypted REST requests,
  device discovery and the Cognito exchange for AWS credentials.
- ``api_mqtt.AiperMqttClient``: AWS IoT MQTT transport lifecycle,
  subscriptions, message decoding and AT-command acknowledgement.
- ``api_commands.AiperCommandClient``: model-aware settings commands
  (cleaning mode, running state, clean path).
- ``AiperApi`` (here): the facade the integration uses, plus diagnostics.

Names that callers import from this module are re-exported below.
"""

from __future__ import annotations

import time
from typing import Any

from .api_commands import AiperCommandClient
from .api_mqtt import MQTT_CREDENTIALS_REFRESH_MARGIN_SECONDS, ShadowCallback
from .api_rest import (
    AWS_CREDENTIALS_COOLDOWN_SECONDS,
    AWS_CREDENTIALS_TTL_DEBUG_SECONDS,
    AWS_CREDENTIALS_TTL_SECONDS,
    DEFAULT_ZONE_ID,
    RETRYABLE_HTTP_STATUSES,
    SESSION_CONFLICT_CODE,
    SESSION_CONFLICT_COOLDOWN_SECONDS,
    AiperApiError,
    AiperAuthenticationError,
    AiperConnectionError,
    AiperResponseError,
    AiperSessionConflict,
)
from .redaction import redact_str

__all__ = [
    "AWS_CREDENTIALS_COOLDOWN_SECONDS",
    "AWS_CREDENTIALS_TTL_DEBUG_SECONDS",
    "AWS_CREDENTIALS_TTL_SECONDS",
    "DEFAULT_ZONE_ID",
    "MQTT_CREDENTIALS_REFRESH_MARGIN_SECONDS",
    "RETRYABLE_HTTP_STATUSES",
    "SESSION_CONFLICT_CODE",
    "SESSION_CONFLICT_COOLDOWN_SECONDS",
    "AiperApi",
    "AiperApiError",
    "AiperAuthenticationError",
    "AiperConnectionError",
    "AiperResponseError",
    "AiperSessionConflict",
    "ShadowCallback",
]


class AiperApi(AiperCommandClient):
    """Client for Aiper cloud API and MQTT."""

    def diagnostics(self) -> dict[str, Any]:
        """Return a JSON-safe snapshot of client/connection state for diagnostics.

        Identifiers are partially redacted here; the diagnostics platform also
        redacts sensitive keys and device serials over the whole payload.
        """
        client = self._mqtt_client
        return {
            "base_url": self.base_url,
            "region": self.region,
            "time_zone": self._headers.get("zoneId"),
            "mqtt_connected": self.is_mqtt_connected(),
            "connection": self.connection.as_diagnostics(),
            "iot_endpoint": redact_str(self._iot_endpoint) if self._iot_endpoint else None,
            "identity_id": redact_str(self._identity_id) if self._identity_id else None,
            "aws_region": self._aws_region,
            "mqtt_client": type(client).__name__ if client is not None else None,
            "mqtt_last_error": getattr(client, "last_error", None),
            "mqtt_last_connected_at": getattr(client, "last_connected_at", None),
            "mqtt_last_disconnected_at": getattr(client, "last_disconnected_at", None),
            "mqtt_reconnect_count": getattr(client, "reconnect_count", None),
            # Non-zero and rising across reconnects means the SDK really is
            # re-asking us to sign, which is what keeps a reconnect from
            # retrying forever with expired Cognito credentials.
            "mqtt_credential_signing_count": getattr(client, "credential_signing_count", None),
            "mqtt_disconnected_seconds": self.mqtt_disconnected_seconds(),
            "seconds_since_mqtt_rebuild": self.seconds_since_mqtt_rebuild(),
            "aws_credentials_ttl": self.aws_credentials_ttl,
            "aws_credentials_expires_in": (
                round(self._aws_credentials_exp - time.time()) if self._aws_credentials_exp else None
            ),
            "session_conflict_cooldown_seconds": max(0, round(self._session_conflict_until - time.time())),
        }
