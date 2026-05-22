"""Aiper API Client for REST and MQTT communication."""

from __future__ import annotations

import asyncio
import base64
import json
import logging
import random
import threading
import time
from collections import defaultdict, deque
from collections.abc import Awaitable, Callable
from contextlib import suppress
from datetime import datetime
from typing import Any

import aiohttp

try:
    from zoneinfo import ZoneInfo
except Exception:  # pragma: no cover
    ZoneInfo = None  # type: ignore

from .const import (
    X9_SERIES_PREFIXES,
    XOR_KEY,
    ApiEndpoint,
    CleaningMode,
    MqttTopic,
)
from .crypto import AiperEncryption
from .mqtt import AwsIotCredentials, AwsIotMqttTransport
from .profiles import DeviceFamily, device_family

_LOGGER = logging.getLogger(__name__)

SESSION_CONFLICT_CODE = "402"
SESSION_CONFLICT_COOLDOWN_SECONDS = 180
RETRYABLE_HTTP_STATUSES = (429, 500, 502, 503, 504)


class AiperApiError(Exception):
    """Base exception for Aiper API failures."""


class AiperAuthenticationError(AiperApiError):
    """Raised when Aiper rejects supplied login credentials."""


class AiperConnectionError(AiperApiError):
    """Raised when Aiper cloud services cannot be reached."""


class AiperResponseError(AiperApiError):
    """Raised when Aiper returns an unexpected response shape."""


class AiperSessionConflict(AiperApiError):
    """Raised when Aiper rejects a request because another session is active."""


class AiperApi:
    """Client for Aiper cloud API and MQTT."""

    def __init__(
        self,
        username: str,
        password: str,
        region: str = ApiEndpoint.eu,
        *,
        async_session: aiohttp.ClientSession,
    ) -> None:
        """Initialize the API client."""
        self.username = username
        self.password = password
        self.region = region
        self.base_url = ApiEndpoint[region].value
        self._async_session = async_session
        self._session_conflict_until = 0.0

        self._token: str | None = None
        self._user_id: str | None = None
        self._identity_id: str | None = None
        self._identity_pool_id: str | None = None
        self._developer_provider_name: str | None = None
        self._openid_token: str | None = None
        self._openid_token_exp: float | None = None
        self._aws_credentials: dict[str, Any] | None = None
        self._aws_credentials_exp: float | None = None
        self._iot_endpoint: str | None = None
        self._aws_region: str | None = None
        self._mqtt_client: Any = None
        self._mqtt_connected = False
        self.mqtt_debug = False
        self._devices: dict[str, dict] = {}
        # Convenience lookup tables derived from device discovery / MQTT telemetry
        self._device_zone_id_by_sn: dict[str, str] = {}
        self._last_timezone_by_sn: dict[str, str] = {}
        self._shadow_callbacks: dict[str, list[Callable]] = {}
        self._lock = threading.Lock()

        # DownChan AT command acknowledgements (received on upChan as "+OK" / "+ERROR").
        # We keep a small per-device FIFO so we can wait for the next ack after a publish.
        self._ack_lock = threading.Lock()
        self._ack_fifo: dict[str, deque[str]] = defaultdict(lambda: deque(maxlen=10))
        self._async_ack_events: dict[str, asyncio.Event] = {}
        self._async_loop: asyncio.AbstractEventLoop | None = None

        # Serialize command sends per device SN so that ack correlation is reliable.
        self._cmd_locks: dict[str, asyncio.Lock] = {}

        # Headers from RetrofitFactory interceptor
        # REST call pacing to avoid triggering cloud throttling
        self._async_rest_lock: asyncio.Lock | None = None
        self._rest_min_interval = 0.8  # seconds between REST calls
        self._rest_next_allowed = 0.0
        self._headers: dict[str, str] = {
            "Content-Type": "application/json",
            "version": "3.0.0",  # App version
            "os": "android",
            "charset": "UTF-8",
            "Accept-Language": "en",
            "zoneId": "Europe/Athens",
            "token": "",  # Will be set after login
        }

    @staticmethod
    def _is_success(payload: dict) -> bool:
        code = payload.get("code")
        successful = payload.get("successful")
        return str(code) in ("0", "200") or successful is True

    @staticmethod
    def _is_session_conflict(payload: dict[str, Any]) -> bool:
        """Return whether Aiper says this account is active in another session."""
        return str(payload.get("code")) == SESSION_CONFLICT_CODE

    @staticmethod
    def _payload_message(payload: dict[str, Any]) -> str:
        """Return the best available human-readable API error message."""
        return str(payload.get("msg") or payload.get("message") or payload.get("mess") or "Unknown error")

    def _raise_if_session_conflict_active(self, path: str) -> None:
        """Avoid repeatedly fighting the mobile app after a confirmed conflict."""
        if path == "/login":
            return
        remaining = self._session_conflict_until - time.time()
        if remaining > 0:
            raise AiperSessionConflict(
                f"Aiper account is active in another session; retrying after {int(remaining)} seconds"
            )

    def _mark_session_conflict(self, payload: dict[str, Any]) -> None:
        self._session_conflict_until = time.time() + SESSION_CONFLICT_COOLDOWN_SECONDS
        raise AiperSessionConflict(self._payload_message(payload))

    def _device_family_for_sn(self, sn: str) -> DeviceFamily:
        """Return the discovered family for a device serial number."""
        return device_family(self._devices.get(sn) or {})

    @staticmethod
    def _clean_path_value_from_payload(payload: dict[str, Any]) -> int | None:
        """Normalize a clean-path value from known REST response shapes."""
        data = payload.get("data")
        val: Any = None
        if isinstance(data, dict):
            for key in ("cleanPath", "cleanPathSetting", "clean_path_setting", "path", "value"):
                if key in data:
                    val = data.get(key)
                    break

        if val is None:
            for key in ("cleanPath", "cleanPathSetting", "clean_path_setting"):
                if isinstance(payload.get(key), (int, str)):
                    val = payload.get(key)
                    break

        if isinstance(val, str):
            s = val.strip()
            if s.lstrip("-").isdigit():
                try:
                    val = int(s)
                except Exception:
                    val = None

        if isinstance(val, int):
            # Aiper's app treats -1 as the default path preference.
            return 0 if val == -1 else int(val)

        if isinstance(val, str):
            norm = " ".join(val.lower().replace("_", " ").replace("-", " ").split())
            if "adaptive" in norm:
                return 1
            if "shape" in norm or norm.startswith("s ") or norm == "s":
                return 0

        return None

    async def _call_encrypted(
        self,
        method: str,
        path: str,
        body: dict[str, Any] | None = None,
        *,
        base_url: str | None = None,
        token: str | None = None,
        timeout: int = 30,
        retry_login: bool = True,
    ) -> dict[str, Any]:
        """Call an Aiper REST endpoint using the AES/RSA envelope."""
        self._raise_if_session_conflict_active(path)
        enc = AiperEncryption()

        headers = dict(self._headers)
        headers["encryptKey"] = enc.encrypt_key_header
        headers["token"] = token or (self._token or "")

        url_base = (base_url or self.base_url).rstrip("/")
        url = f"{url_base}{path}"

        data = enc.encrypt_request(body) if body is not None else None
        _status, text = await self._request_with_backoff(method, url, headers=headers, data=data, timeout=timeout)
        decrypted = enc.decrypt_response(text)

        try:
            payload = json.loads(decrypted)
        except Exception as err:
            raise AiperResponseError(f"Failed to parse decrypted response from {path}: {decrypted[:200]}") from err

        if not isinstance(payload, dict):
            raise AiperResponseError(f"Unexpected decrypted response from {path}: {type(payload).__name__}")

        if retry_login and path != "/login" and self._is_session_conflict(payload):
            _LOGGER.info("Aiper account session conflict; re-authenticating once before backing off")
            try:
                if await self.login():
                    retry_payload = await self._call_encrypted(
                        method,
                        path,
                        body,
                        base_url=base_url,
                        token=self._token,
                        timeout=timeout,
                        retry_login=False,
                    )
                    if not self._is_session_conflict(retry_payload):
                        self._session_conflict_until = 0.0
                        return retry_payload
                    payload = retry_payload
            except AiperSessionConflict:
                raise
            except Exception as err:
                _LOGGER.debug("Session-conflict re-authentication failed: %s", err)
            self._mark_session_conflict(payload)

        if retry_login and str(payload.get("code")) in ("401", "403"):
            _LOGGER.info("Token appears expired; attempting refresh")
            try:
                if await self.refresh_token():
                    return await self._call_encrypted(
                        method,
                        path,
                        body,
                        base_url=base_url,
                        token=self._token,
                        timeout=timeout,
                        retry_login=False,
                    )
            except Exception:
                pass

            _LOGGER.info("Token refresh failed; re-authenticating")
            if await self.login():
                return await self._call_encrypted(
                    method,
                    path,
                    body,
                    base_url=base_url,
                    token=self._token,
                    timeout=timeout,
                    retry_login=False,
                )

        return payload

    async def _rest_wait(self) -> None:
        """Throttle REST calls to reduce cloud load and avoid rate limits."""
        if self._async_rest_lock is None:
            self._async_rest_lock = asyncio.Lock()
        async with self._async_rest_lock:
            now = time.time()
            if now < self._rest_next_allowed:
                await asyncio.sleep(self._rest_next_allowed - now)
            self._rest_next_allowed = time.time() + self._rest_min_interval

    async def _request_with_backoff(
        self,
        method: str,
        url: str,
        *,
        headers: dict,
        json_body: dict | None = None,
        data: Any = None,
        timeout: int = 30,
    ) -> tuple[int, str]:
        """Perform an async REST request with limited retries/backoff on 429/5xx."""
        max_attempts = 4
        delay = 1.0
        last_exc: Exception | None = None
        for attempt in range(1, max_attempts + 1):
            await self._rest_wait()
            try:
                async with self._async_session.request(
                    method.upper(),
                    url,
                    headers=headers,
                    json=json_body,
                    data=data,
                    timeout=aiohttp.ClientTimeout(total=timeout),
                ) as resp:
                    text = await resp.text()
                    if resp.status in RETRYABLE_HTTP_STATUSES:
                        raise AiperConnectionError(f"HTTP {resp.status}")
                    resp.raise_for_status()
                    return resp.status, text
            except Exception as err:
                last_exc = err
                msg = str(err).lower()
                transient = any(
                    key in msg
                    for key in (
                        "429",
                        "500",
                        "502",
                        "503",
                        "504",
                        "timeout",
                        "tempor",
                        "connection",
                        "reset",
                        "refused",
                    )
                )
                if attempt >= max_attempts or not transient:
                    break
                await asyncio.sleep(delay + random.uniform(0, 0.3))
                delay = min(delay * 2.0, 8.0)
        if isinstance(last_exc, (AiperConnectionError, aiohttp.ClientConnectionError, TimeoutError)):
            raise AiperConnectionError(f"Aiper request failed: {last_exc}") from last_exc
        raise last_exc if last_exc else AiperConnectionError("Aiper request failed")

    async def _call_plain(
        self,
        method: str,
        path: str,
        body: dict[str, Any] | None = None,
        *,
        base_url: str | None = None,
        token: str | None = None,
        timeout: int = 30,
    ) -> dict[str, Any]:
        """Call an Aiper REST endpoint without the AES/RSA envelope."""
        headers = dict(self._headers)
        headers["token"] = token or (self._token or "")

        url_base = (base_url or self.base_url).rstrip("/")
        url = f"{url_base}{path}"

        status, text = await self._request_with_backoff(
            method,
            url,
            headers=headers,
            json_body=body,
            timeout=timeout,
        )

        if not text:
            return {}
        try:
            return json.loads(text)
        except Exception:
            return {"code": status, "successful": False, "message": text[:500]}

    def _encrypt(self, data: str) -> str:
        """Encrypt message using XOR + Base64."""
        data_bytes = data.encode("utf-8")
        xored = bytes([b ^ XOR_KEY[i % 4] for i, b in enumerate(data_bytes)])
        return base64.b64encode(xored).decode("utf-8") + "\n"

    def _decrypt(self, data: bytes) -> str:
        """Decrypt message using Base64 + XOR."""
        try:
            decoded = base64.b64decode(data)
            return bytes([b ^ XOR_KEY[i % 4] for i, b in enumerate(decoded)]).decode("utf-8")
        except Exception:
            # May be unencrypted JSON
            return data.decode("utf-8") if isinstance(data, bytes) else data

    async def login(self) -> bool:
        """Authenticate with Aiper API."""
        _LOGGER.debug("Logging in to Aiper API")

        login_data = {"email": self.username, "password": self.password}

        try:
            _LOGGER.debug("Logging in with email: %s", self.username)
            payload = await self._call_encrypted(
                "POST",
                "/login",
                login_data,
                base_url=self.base_url,
                token="",
            )

            if not self._is_success(payload):
                msg = payload.get("msg") or payload.get("message") or payload.get("mess") or "Unknown error"
                raise AiperAuthenticationError(f"Login failed: {msg}")

            result = payload.get("data", {}) or {}

            self._token = result.get("token")
            self._user_id = result.get("serialNumber")
            self._token_expires = result.get("tokenExpires", 0)
            domains = result.get("domain") or []
            if domains:
                self.base_url = str(domains[0]).rstrip("/")

            if not self._token:
                raise AiperResponseError(f"No token in login response: {result}")

            self._headers["token"] = self._token
            _LOGGER.info("Successfully logged in to Aiper API (base_url=%s)", self.base_url)

            await self.get_openid_token()
            return True

        except (aiohttp.ClientError, TimeoutError) as err:
            _LOGGER.error("Login request failed: %s", err)
            raise AiperConnectionError(f"Login request failed: {err}") from err

    def _zone_id_for_sn(self, sn: str) -> str | None:
        """Return the best-known zoneId for a device.

        Aiper REST endpoints commonly key off the `zoneId` header (timezone).
        The mobile app sets this to the phone timezone; device discovery also
        exposes a per-device `zoneId` field. We use that when available.
        """
        zid = self._device_zone_id_by_sn.get(sn)
        if isinstance(zid, str) and zid:
            return zid
        zid = self._last_timezone_by_sn.get(sn)
        if isinstance(zid, str) and zid:
            return zid
        # Fall back to whatever is already configured on the session.
        header_zid = self._headers.get("zoneId")
        return header_zid if isinstance(header_zid, str) and header_zid else None

    async def _call_with_zoneid(self, sn: str, fn: Callable[[], Awaitable[Any]]) -> Any:
        """Invoke async `fn` while temporarily setting the zoneId header for `sn`."""
        zid = self._zone_id_for_sn(sn)
        prev_value = self._headers.get("zoneId")
        prev = prev_value if isinstance(prev_value, str) else None
        if zid:
            self._headers["zoneId"] = zid
        try:
            return await fn()
        finally:
            if prev is not None:
                self._headers["zoneId"] = prev
            else:
                self._headers.pop("zoneId", None)

    async def refresh_token(self) -> bool:
        """Refresh the authentication token."""
        try:
            payload = await self._call_encrypted(
                "POST",
                "/users/token/refresh",
                {},
                retry_login=False,
            )
            if self._is_success(payload):
                result = payload.get("data", {}) or {}
                new_token = result.get("token")
                if isinstance(new_token, str) and new_token:
                    self._token = new_token
                    self._headers["token"] = self._token
                    _LOGGER.info("Token refreshed successfully")
                    return True
            try:
                code = payload.get("code") if isinstance(payload, dict) else None
                msg = None
                if isinstance(payload, dict):
                    msg = payload.get("msg") or payload.get("message")
                _LOGGER.warning("Token refresh failed (code=%s, message=%s)", code, msg)
            except Exception:
                _LOGGER.warning("Token refresh failed")
            return False
        except Exception as err:
            _LOGGER.error("Token refresh error: %s", err)
            return False

    async def get_openid_token(self) -> None:
        """Fetch Cognito Identity/OpenID data used for AWS IoT MQTT."""
        try:
            payload = await self._call_encrypted("POST", "/users/getOpenIdToken", {})
            if not self._is_success(payload):
                try:
                    code = payload.get("code") if isinstance(payload, dict) else None
                    msg = None
                    if isinstance(payload, dict):
                        msg = payload.get("msg") or payload.get("message")
                    _LOGGER.warning("OpenID token fetch failed (code=%s, message=%s)", code, msg)
                except Exception:
                    _LOGGER.warning("OpenID token fetch failed")
                return

            data = payload.get("data", {}) or {}
            self._developer_provider_name = data.get("developerProviderName")
            self._identity_id = data.get("identityId")
            self._identity_pool_id = data.get("identityPoolId")
            self._iot_endpoint = data.get("iotEndpoint")
            self._aws_region = data.get("region")
            self._openid_token = data.get("token")

            dur = data.get("tokenDuration")
            if dur:
                self._openid_token_exp = time.time() + float(dur)

            _LOGGER.debug(
                "Got OpenID token data identity_id=%s pool_id=%s iot_endpoint=%s",
                (self._identity_id[:8] + "...") if isinstance(self._identity_id, str) else None,
                (self._identity_pool_id[:8] + "...") if isinstance(self._identity_pool_id, str) else None,
                self._iot_endpoint,
            )

        except Exception as err:
            _LOGGER.warning("Failed to get OpenID token data: %s", err)

    async def get_aws_credentials(self) -> dict[str, Any] | None:
        """Exchange the OpenID token for temporary AWS credentials asynchronously."""
        if not self._identity_id or not self._openid_token:
            return None

        if self._openid_token_exp and (self._openid_token_exp - time.time()) < 120:
            await self.get_openid_token()

        if self._aws_credentials_exp and (self._aws_credentials_exp - time.time()) > 120:
            return self._aws_credentials

        region = self._aws_region
        if not region and self._iot_endpoint and ".iot." in self._iot_endpoint:
            try:
                region = self._iot_endpoint.split(".iot.", 1)[1].split(".", 1)[0]
            except Exception:
                region = None
        region = region or "eu-central-1"

        url = f"https://cognito-identity.{region}.amazonaws.com/"
        headers = {
            "Content-Type": "application/x-amz-json-1.1",
            "X-Amz-Target": "AWSCognitoIdentityService.GetCredentialsForIdentity",
        }
        body = {
            "IdentityId": self._identity_id,
            "Logins": {"cognito-identity.amazonaws.com": self._openid_token},
        }

        _status, text = await self._request_with_backoff("POST", url, headers=headers, json_body=body, timeout=30)
        out = json.loads(text)

        creds = out.get("Credentials") or {}
        if not creds.get("AccessKeyId"):
            _LOGGER.warning("Unexpected Cognito credentials response: %s", out)
            return None

        self._aws_credentials = creds
        self._aws_credentials_exp = time.time() + 3300
        return creds

    async def get_devices(self) -> list[dict]:
        """Get list of devices from API without blocking the event loop."""
        try:
            payload = await self._call_encrypted("POST", "/equipment/getEquipment", {})
            _LOGGER.debug("Get devices response: %s", payload)

            if not self._is_success(payload):
                _LOGGER.warning("Get devices failed: %s", payload)
                return []

            devices = payload.get("data", [])
            if isinstance(devices, dict):
                devices = devices.get("list", devices.get("equipments", []))
            if not isinstance(devices, list) or not all(isinstance(device, dict) for device in devices):
                raise AiperResponseError(f"Unexpected device list response: {type(devices).__name__}")

            for device in devices:
                sn = device.get("sn")
                if sn:
                    self._devices[sn] = device
                    zone_id = device.get("zoneId") or device.get("zone_id")
                    if isinstance(zone_id, str) and zone_id:
                        self._device_zone_id_by_sn[sn] = zone_id
                    _LOGGER.debug("Found device: %s (%s)", device.get("name", "Unknown"), sn)

            return devices

        except aiohttp.ClientError as err:
            _LOGGER.error("Failed to get devices: %s", err)
            return []

    async def get_device_info(self, sn: str) -> dict | None:
        """Get detailed info for a specific device without blocking the event loop."""
        try:
            payload = await self._call_encrypted("POST", "/equipment/getEquipmentInfo", {"sn": sn})
            _LOGGER.info("Device info for %s: %s", sn, payload)

            if not self._is_success(payload):
                return None

            data = payload.get("data")
            if isinstance(data, dict):
                out = dict(data)
                out["payload"] = payload
                return out
            return {"data": data, "payload": payload}

        except aiohttp.ClientError as err:
            _LOGGER.error("Failed to get device info for %s: %s", sn, err)
            return None

    async def get_device_status(self, sn: str) -> dict | None:
        """Get online status for a device without blocking the event loop."""
        try:
            payload = await self._call_encrypted("POST", "/equipment/checkEquipmentOnlineStatus", {"sn": sn})
            _LOGGER.info("Device status for %s: %s", sn, payload)

            if self._is_success(payload):
                return payload.get("data")
            return None

        except aiohttp.ClientError as err:
            _LOGGER.error("Failed to get status for %s: %s", sn, err)
            return None

    async def get_consumables(self, sn: str) -> Any:
        """Get consumable status without blocking the event loop."""

        try:
            payload = await self._call_with_zoneid(
                sn,
                lambda: self._call_encrypted("POST", "/poolRobot/getConsumableList", {"sn": sn}),
            )
            if self._is_success(payload):
                return payload

            return None

        except Exception as err:
            _LOGGER.error("Failed to get consumables: %s", err)
            return None

    # --- Clean path preference (REST) ---

    async def query_clean_path_setting(self, sn: str) -> int | None:
        """Query the clean-path preference without blocking the event loop."""
        if self._device_family_for_sn(sn) == DeviceFamily.SURFER:
            try:
                payload = await self._call_with_zoneid(
                    sn,
                    lambda: self._call_encrypted(
                        "POST",
                        "/equipmentCleanPathSetting/getCleanPathSetting",
                        {"sn": sn},
                    ),
                )
            except Exception as err:
                _LOGGER.debug("Surfer clean path query failed: %s", err)
                return None

            if payload and self._is_success(payload):
                return self._clean_path_value_from_payload(payload)
            return None

        dev = self._devices.get(sn) or {}
        equip_id = dev.get("equipmentId") or dev.get("deviceId") or dev.get("id")

        if equip_id is None:
            with suppress(Exception):
                await self.get_devices()
            dev = self._devices.get(sn) or {}
            equip_id = dev.get("equipmentId") or dev.get("deviceId") or dev.get("id")

        # Async mirror of the legacy non-Surfer clean-path discovery code above.
        # Keep until Scuba verification proves the current backend contract.
        base_paths = [
            "/equipmentCleanPathSetting/getCleanPathSetting",
            "/equipmentCleanPathSetting/getCleanPathSettingBySn",
            "/equipmentCleanPathSetting/queryCleanPathSetting",
            "/network/clean_path_setting",
            "/network/cleanPathSetting",
            "/swimming/v2/queryCleanPathSetting",
            "/swimming/v2/getCleanPathSetting",
            "/swimming/v2/getCleanPathSettingBySn",
        ]

        bodies: list[dict[str, Any]] = [{"sn": sn}]
        if equip_id is not None:
            bodies.insert(0, {"sn": sn, "id": equip_id})
            bodies.insert(1, {"sn": sn, "equipmentId": equip_id})
            bodies.insert(2, {"sn": sn, "deviceId": equip_id})

        for path in base_paths:
            for body in bodies:
                payload = None
                try:

                    async def encrypted_query(
                        path: str = path,
                        body: dict[str, Any] = body,
                    ) -> Any:
                        return await self._call_encrypted("POST", path, body)

                    payload = await self._call_with_zoneid(
                        sn,
                        encrypted_query,
                    )
                except Exception as err:
                    _LOGGER.debug("Clean path query encrypted call failed (%s): %s", path, err)

                if not payload or not self._is_success(payload):
                    try:

                        async def plain_query(
                            path: str = path,
                            body: dict[str, Any] = body,
                        ) -> Any:
                            return await self._call_plain("POST", path, body)

                        payload = await self._call_with_zoneid(
                            sn,
                            plain_query,
                        )
                    except Exception as err:
                        _LOGGER.debug("Clean path query plain call failed (%s): %s", path, err)

                if not payload or not self._is_success(payload):
                    continue

                val = self._clean_path_value_from_payload(payload)
                if val is not None:
                    return val

        return None

    async def update_clean_path_setting(self, sn: str, value: int) -> bool:
        """Update clean-path preference and apply it to the device asynchronously."""
        if self._device_family_for_sn(sn) == DeviceFamily.SURFER:
            rest_ok = False
            try:
                payload = await self._call_with_zoneid(
                    sn,
                    lambda: self._call_encrypted(
                        "POST",
                        "/equipmentCleanPathSetting/updateCleanPathSetting",
                        {"sn": sn, "cleanPath": int(value)},
                    ),
                )
                rest_ok = bool(payload and self._is_success(payload))
            except Exception as err:
                _LOGGER.debug("Surfer clean path REST update failed: %s", err)

            mqtt_ok = False
            if self.is_mqtt_connected():
                try:
                    # Surfer S2 accepts AT+AUTO=<value>. Other AT and structured
                    # downChan variants were rejected or unacknowledged in live probes.
                    mqtt_ok = await self.send_machine_at(sn, f"AT+AUTO={int(value)}") is True
                except Exception as err:
                    _LOGGER.debug("Surfer clean path AT update failed: %s", err)

            with suppress(Exception):
                await self.request_shadow(sn)

            return bool(rest_ok or mqtt_ok)

        # Async mirror of the legacy non-Surfer clean-path control code above.
        # Keep until Scuba verification proves the current backend contract.
        dev = self._devices.get(sn) or {}
        equip_id = dev.get("equipmentId") or dev.get("deviceId") or dev.get("id")

        if equip_id is None:
            with suppress(Exception):
                await self.get_devices()
            dev = self._devices.get(sn) or {}
            equip_id = dev.get("equipmentId") or dev.get("deviceId") or dev.get("id")

        base_paths = [
            "/equipmentCleanPathSetting/updateCleanPathSetting",
            "/equipmentCleanPathSetting/updateCleanPathSettingBySn",
            "/network/clean_path_setting",
            "/network/cleanPathSetting",
            "/swimming/v2/updateCleanPathSetting",
            "/swimming/v2/setCleanPathSetting",
        ]

        key_variants = ("cleanPath", "cleanPathSetting", "clean_path_setting")
        base_bodies: list[dict[str, Any]] = [{"sn": sn, k: int(value)} for k in key_variants]

        bodies: list[dict[str, Any]] = []
        if equip_id is not None:
            for bb in base_bodies:
                for idk in ("id", "equipmentId", "deviceId"):
                    b = dict(bb)
                    b[idk] = equip_id
                    bodies.append(b)
        bodies.extend(base_bodies)

        rest_ok = False
        for path in base_paths:
            for body in bodies:
                payload = None
                try:

                    async def encrypted_update(
                        path: str = path,
                        body: dict[str, Any] = body,
                    ) -> Any:
                        return await self._call_encrypted("POST", path, body)

                    payload = await self._call_with_zoneid(
                        sn,
                        encrypted_update,
                    )
                except Exception as err:
                    _LOGGER.debug("Clean path update encrypted call failed (%s): %s", path, err)

                if not payload or not self._is_success(payload):
                    try:

                        async def plain_update(
                            path: str = path,
                            body: dict[str, Any] = body,
                        ) -> Any:
                            return await self._call_plain("POST", path, body)

                        payload = await self._call_with_zoneid(
                            sn,
                            plain_update,
                        )
                    except Exception as err:
                        _LOGGER.debug("Clean path update plain call failed (%s): %s", path, err)

                if payload and self._is_success(payload):
                    rest_ok = True
                    _LOGGER.debug(
                        "Clean path REST OK via %s (code=%s successful=%s message=%s) keys=%s",
                        path,
                        payload.get("code"),
                        payload.get("successful"),
                        payload.get("message"),
                        list(body.keys()),
                    )
                    break
            if rest_ok:
                break

        mqtt_published = False
        if self.is_mqtt_connected():
            machine_payloads = (
                {"cleanPath": int(value)},
                {"cleanPathSetting": int(value)},
                {"clean_path_setting": int(value)},
                {"cmd": "AUTO", "param": [int(value)]},
                {"cmd": "AUTO", "params": [int(value)]},
                {"cmd": f"AUTO {int(value)}"},
            )
            for mp in machine_payloads:
                try:
                    if await self.send_command(sn, "Machine", mp):
                        mqtt_published = True
                        _LOGGER.debug("Clean path downChan published: %s", mp)
                except Exception as err:
                    _LOGGER.debug("Clean path downChan publish failed (%s): %s", mp, err)

            for at_cmd in (
                f"AT+AUTO={int(value)}",
                f"AUTO {int(value)}",
                f"AT+CPATH={int(value)}",
                f"AT+CLEANPATH={int(value)}",
                f"AT+SETPATH={int(value)}",
            ):
                try:
                    res = await self.send_machine_at(sn, at_cmd)
                    if res is True:
                        mqtt_published = True
                        _LOGGER.debug("Clean path AT confirmed: %s", at_cmd)
                        break
                    if res is False:
                        mqtt_published = True
                        _LOGGER.debug("Clean path AT rejected: %s", at_cmd)
                        continue
                    mqtt_published = True
                    _LOGGER.debug("Clean path AT published (no ack): %s", at_cmd)
                except Exception as err:
                    _LOGGER.debug("Clean path AT failed (%s): %s", at_cmd, err)

        try:
            shadow_ok = bool(
                await self.publish_shadow_update(
                    sn,
                    {
                        "Machine": {
                            "cleanPath": int(value),
                            "cleanPathSetting": int(value),
                            "clean_path_setting": int(value),
                        }
                    },
                )
            )
        except Exception:
            shadow_ok = False

        with suppress(Exception):
            await self.request_shadow(sn)

        return bool(rest_ok or mqtt_published or shadow_ok)

    async def connect_mqtt(self) -> bool:
        """Connect to AWS IoT MQTT broker."""
        if not self._identity_id or not self._iot_endpoint:
            _LOGGER.error("No IoT identity/endpoint available")
            return False

        try:
            self._async_loop = asyncio.get_running_loop()
            creds = await self.get_aws_credentials()
            if not creds:
                _LOGGER.error("Unable to obtain AWS credentials for MQTT")
                return False

            client_id = self._identity_id
            region = self._aws_region
            if not region and self._iot_endpoint and ".iot." in self._iot_endpoint:
                region = self._iot_endpoint.split(".iot.", 1)[1].split(".", 1)[0]
            region = region or "eu-central-1"

            self._mqtt_client = AwsIotMqttTransport(
                endpoint=self._iot_endpoint,
                region=region,
                client_id=client_id,
                credentials=AwsIotCredentials(
                    access_key_id=creds["AccessKeyId"],
                    secret_access_key=creds["SecretKey"],
                    session_token=creds.get("SessionToken", ""),
                ),
                connect_timeout=10.0,
                operation_timeout=5.0,
            )

            if await self._mqtt_client.async_connect():
                self._mqtt_connected = True
                _LOGGER.info("Connected to AWS IoT MQTT using AWS IoT Device SDK v2")
                return True

            self._mqtt_connected = False
            return False

        except Exception as err:
            _LOGGER.error("MQTT connection failed: %s", err)
            self._mqtt_connected = False
            return False

    def is_mqtt_connected(self) -> bool:
        """Return True if the AWS IoT MQTT client is connected.

        Exposed for entity availability and diagnostics.
        """
        return bool(self._mqtt_connected and self._mqtt_client and self._mqtt_client.is_connected())

    async def request_shadow(self, sn: str) -> bool:
        """Request the current AWS IoT thing shadow."""
        if not self.is_mqtt_connected():
            return False
        try:
            topic = MqttTopic.SHADOW_GET_REQUEST.format(sn=sn)
            if not await self._mqtt_client.async_publish(topic, "", 1):
                return False
            _LOGGER.debug("Published shadow get request to %s", topic)
            return True
        except Exception as err:
            _LOGGER.debug("Failed to request shadow for %s: %s", sn, err)
            return False

    async def publish_shadow_update(self, sn: str, desired: dict[str, Any]) -> bool:
        """Backward-compatible alias for desired-state publishing."""
        return await self.publish_shadow_desired(sn, desired)

    async def publish_shadow_desired(self, sn: str, desired: dict[str, Any]) -> bool:
        """Publish a desired-state update to the AWS IoT device shadow."""
        if not self.is_mqtt_connected():
            return False
        try:
            topic = MqttTopic.SHADOW_UPDATE.format(sn=sn)
            payload = {"state": {"desired": desired}}
            message = json.dumps(payload, separators=(",", ":"))
            if not await self._mqtt_client.async_publish(topic, message, 1):
                return False
            _LOGGER.debug("Published shadow update to %s: %s", topic, message)
            return True
        except Exception as err:
            _LOGGER.debug("Failed to publish shadow update for %s: %s", sn, err)
            return False

    def _register_shadow_callback(self, sn: str, callback: Callable[..., None]) -> None:
        """Register a callback for normalized MQTT shadow/report payloads."""
        with self._lock:
            if sn not in self._shadow_callbacks:
                self._shadow_callbacks[sn] = []
            self._shadow_callbacks[sn].append(callback)

    def _subscription_topics_for_sn(self, sn: str) -> tuple[str, ...]:
        """Return MQTT topics to subscribe for a device."""
        is_x9 = any(sn.upper().startswith(prefix) for prefix in X9_SERIES_PREFIXES)
        report_topic = MqttTopic.SHADOW_REPORT_X9 if is_x9 else MqttTopic.SHADOW_REPORT
        return (
            report_topic.format(sn=sn),
            MqttTopic.READ.format(sn=sn),
            MqttTopic.SHADOW_GET.format(sn=sn),
            MqttTopic.SHADOW_UPDATE_ACCEPTED.format(sn=sn),
            MqttTopic.SHADOW_UPDATE_DELTA.format(sn=sn),
            MqttTopic.SHADOW_UPDATE_DOCUMENTS.format(sn=sn),
            MqttTopic.SHADOW_REPORT_X9.format(sn=sn),
        )

    def _handle_device_message(self, sn: str, topic: str, payload_bytes: bytes) -> None:
        """Normalize one MQTT payload and dispatch it to registered callbacks."""
        try:
            payload = self._decrypt(payload_bytes)
            data = json.loads(payload)

            if (
                isinstance(data, dict)
                and isinstance(data.get("data"), dict)
                and isinstance(data["data"].get("sn"), str)
                and isinstance(data["data"].get("timeZone"), str)
            ):
                self._last_timezone_by_sn[data["data"]["sn"]] = data["data"]["timeZone"]

            if (
                isinstance(data, dict)
                and data.get("type") == "Machine"
                and isinstance(data.get("data"), dict)
                and isinstance(data["data"].get("ack"), str)
            ):
                self._record_ack(sn, data["data"]["ack"])

            if isinstance(data, dict) and "_sn" not in data:
                data["_sn"] = sn

            if isinstance(data, dict) and "_topic" not in data:
                data["_topic"] = topic

            if self.mqtt_debug:
                _LOGGER.debug("MQTT message topic=%s payload=%s", topic, payload[:800])

            with self._lock:
                for cb in self._shadow_callbacks.get(sn, []):
                    try:
                        try:
                            cb(sn, data)
                        except TypeError:
                            cb(data)
                    except Exception as err:
                        _LOGGER.error("Callback error: %s", err)

        except Exception as err:
            _LOGGER.error("Failed to process message: %s", err)

    async def subscribe_device(self, sn: str, callback: Callable[..., None]) -> bool:
        """Subscribe to device shadow updates."""
        if not self.is_mqtt_connected():
            _LOGGER.warning("MQTT not connected, cannot subscribe")
            return False

        self._async_loop = asyncio.get_running_loop()
        self._register_shadow_callback(sn, callback)

        def on_message(topic: str, payload_bytes: bytes) -> None:
            self._handle_device_message(sn, topic, payload_bytes)

        try:
            for sub_topic in self._subscription_topics_for_sn(sn):
                if not await self._mqtt_client.async_subscribe(sub_topic, on_message, 1):
                    return False
                _LOGGER.debug("Subscribed to %s", sub_topic)

            return True

        except Exception as err:
            _LOGGER.error("Failed to subscribe to %s: %s", sn, err)
            return False

    def _timezone_string_for_sn(self, sn: str) -> str:
        """Return a timezone string in the device's expected format (e.g. "UTC+3").

        Preference order:
          1) Last value observed from `shadow/report` messages.
          2) Derive from the device's `zoneId` (when available) using zoneinfo.
          3) Fallback to "UTC+0".
        """
        last = self._last_timezone_by_sn.get(sn)
        if isinstance(last, str) and last:
            return last

        zone_id = self._device_zone_id_by_sn.get(sn)
        if ZoneInfo is not None and isinstance(zone_id, str) and zone_id:
            try:
                offset = datetime.now(ZoneInfo(zone_id)).utcoffset()
                if offset is not None:
                    hours = int(offset.total_seconds() / 3600)
                    sign = "+" if hours >= 0 else "-"
                    return f"UTC{sign}{abs(hours)}"
            except Exception:
                pass

        return "UTC+0"

    def _record_ack(self, sn: str, ack: str) -> None:
        """Record an AT command acknowledgement received on upChan."""
        with self._ack_lock:
            self._ack_fifo[sn].append(ack)
        if self._async_loop is not None and sn in self._async_ack_events:
            self._async_loop.call_soon_threadsafe(self._async_ack_events[sn].set)

    def _clear_ack_fifo(self, sn: str) -> None:
        with self._ack_lock:
            self._ack_fifo[sn].clear()
        event = self._async_ack_events.get(sn)
        if event is not None:
            event.clear()

    def _async_ack_event(self, sn: str) -> asyncio.Event:
        event = self._async_ack_events.get(sn)
        if event is None:
            event = asyncio.Event()
            self._async_ack_events[sn] = event
        return event

    async def _wait_for_ack(self, sn: str, timeout: float = 4.0) -> str | None:
        """Wait for the next ack for this device SN without blocking."""
        with self._ack_lock:
            if self._ack_fifo[sn]:
                return self._ack_fifo[sn].popleft()

        event = self._async_ack_event(sn)
        try:
            await asyncio.wait_for(event.wait(), timeout=timeout)
        except TimeoutError:
            return None

        with self._ack_lock:
            if not self._ack_fifo[sn]:
                return None
            ack = self._ack_fifo[sn].popleft()
            if not self._ack_fifo[sn]:
                event.clear()
            return ack

    def _cmd_lock(self, sn: str) -> asyncio.Lock:
        lock = self._cmd_locks.get(sn)
        if lock is None:
            lock = asyncio.Lock()
            self._cmd_locks[sn] = lock
        return lock

    async def send_machine_at(self, sn: str, at_cmd: str, timeout: float = 4.0) -> bool | None:
        """Send an AT command via downChan and wait for an upChan ack."""
        self._async_loop = asyncio.get_running_loop()
        tz = self._timezone_string_for_sn(sn)
        payload = {"sn": sn, "timeZone": tz, "cmd": at_cmd}

        async with self._cmd_lock(sn):
            self._async_ack_event(sn)
            self._clear_ack_fifo(sn)
            published = await self.send_command(sn, "Machine", payload)
            if not published:
                return None

            ack = await self._wait_for_ack(sn, timeout=timeout)
            if ack is None:
                return None

            ack_u = ack.upper()
            if "+OK" in ack_u:
                return True
            if "+ERROR" in ack_u:
                return False
            return None

    async def send_command(self, sn: str, cmd_type: str, data: dict | None = None) -> bool:
        """Send a command to the device."""
        is_x9 = any(sn.upper().startswith(prefix) for prefix in X9_SERIES_PREFIXES)

        data_obj: dict[str, Any] = dict(data or {})

        if not is_x9:
            cmd_sn = data_obj.get("sn") if isinstance(data_obj.get("sn"), str) else sn
            tz = (
                data_obj.get("timeZone")
                if isinstance(data_obj.get("timeZone"), str)
                else self._timezone_string_for_sn(sn)
            )

            ordered: dict[str, Any] = {
                "sn": cmd_sn,
                "timeZone": tz,
            }

            for k, v in data_obj.items():
                if k in ("sn", "timeZone"):
                    continue
                ordered[k] = v

            data_obj = ordered

        if is_x9:
            payload: dict[str, Any] = {cmd_type: data_obj}
        else:
            payload = {
                "type": cmd_type,
                "data": data_obj,
            }

        if not is_x9:
            payload["res"] = 0

        data_json = json.dumps(data_obj, separators=(",", ":"))
        payload["chksum"] = self._crc16(data_json)

        message = json.dumps(payload, separators=(",", ":"))
        topic = MqttTopic.WRITE.format(sn=sn)

        try:
            if self.is_mqtt_connected():
                if not await self._mqtt_client.async_publish(topic, message, 1):
                    return False
                _LOGGER.debug(
                    "Sent command to %s: %s data=%s",
                    sn,
                    cmd_type,
                    data_json,
                )
                return True
            _LOGGER.warning("MQTT not connected, cannot send command")
            return False
        except Exception as err:
            _LOGGER.error("Failed to send command: %s", err)
            return False

    async def set_cleaning_mode(self, sn: str, mode: int | CleaningMode) -> bool:
        """Set a selectable cleaning mode."""
        _LOGGER.info("Setting cleaning mode for %s: %s", sn, mode)

        cmd_result = await self.send_machine_at(sn, f"AT+PLAN={int(mode)}")

        with suppress(Exception):
            await self.request_shadow(sn)

        return cmd_result is True

    async def set_running(self, sn: str, running: bool) -> bool:
        """Start or stop running."""
        mode = 1 if running else 0
        _LOGGER.info("Setting running mode for %s: %s", sn, mode)

        cmd_result = await self.send_machine_at(sn, f"AT+MODE={mode}")

        with suppress(Exception):
            await self.request_shadow(sn)

        return cmd_result is True

    def _crc16(self, data: str) -> int:
        """Calculate CRC16 checksum."""
        crc = 0x9966
        for byte in data.encode("utf-8"):
            crc ^= byte
            for _ in range(8):
                if crc & 1:
                    crc = (crc >> 1) ^ 0xA001
                else:
                    crc >>= 1
        return crc

    async def disconnect(self) -> None:
        """Disconnect from MQTT and cleanup."""
        if self._mqtt_client:
            with suppress(Exception):
                await self._mqtt_client.async_disconnect()
        self._mqtt_connected = False
        self._mqtt_client = None

        _LOGGER.info("Disconnected from Aiper API")
