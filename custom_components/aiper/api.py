"""Aiper API Client for REST and MQTT communication."""
from __future__ import annotations

import base64
import json
import logging
import threading
import time
import random
from typing import Any, Callable

from collections import defaultdict, deque

from datetime import datetime

try:
    from zoneinfo import ZoneInfo
except Exception:  # pragma: no cover
    ZoneInfo = None  # type: ignore

import requests

from .const import (
    API_ENDPOINTS,
    XOR_KEY,
    TOPIC_READ,
    TOPIC_WRITE,
    TOPIC_SHADOW_GET,
    TOPIC_SHADOW_GET_REQUEST,
    TOPIC_SHADOW_UPDATE,
    TOPIC_SHADOW_UPDATE_ACCEPTED,
    TOPIC_SHADOW_UPDATE_DELTA,
    TOPIC_SHADOW_UPDATE_DOCUMENTS,
    TOPIC_SHADOW_REPORT,
    TOPIC_SHADOW_REPORT_X9,
    X9_SERIES_PREFIXES,
)

from .crypto import AiperEncryption

_LOGGER = logging.getLogger(__name__)


class AiperApi:
    """Client for Aiper cloud API and MQTT."""

    def __init__(
        self,
        username: str,
        password: str,
        region: str = "eu",
    ) -> None:
        """Initialize the API client."""
        self.username = username
        self.password = password
        self.region = region
        self.base_url = API_ENDPOINTS.get(region, API_ENDPOINTS["eu"])
        
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
        self._ack_events: dict[str, threading.Event] = defaultdict(threading.Event)
        self._ack_fifo: dict[str, deque[str]] = defaultdict(lambda: deque(maxlen=10))

        # Serialize command sends per device SN so that ack correlation is reliable.
        self._cmd_locks: dict[str, threading.Lock] = defaultdict(threading.Lock)
        
        # Session for REST API
        # Headers from RetrofitFactory interceptor
        self._session = requests.Session()
        # REST call pacing to avoid triggering cloud throttling
        self._rest_lock = threading.Lock()
        self._rest_min_interval = 0.8  # seconds between REST calls
        self._rest_next_allowed = 0.0
        self._session.headers.update({
            "Content-Type": "application/json",
            "version": "3.0.0",  # App version
            "os": "android",
            "charset": "UTF-8",
            "Accept-Language": "en",
            "zoneId": "Europe/Athens",
            "token": "",  # Will be set after login
        })

    @staticmethod
    def _is_success(payload: dict) -> bool:
        code = payload.get("code")
        successful = payload.get("successful")
        return str(code) in ("0", "200") or successful is True

    def _call_encrypted(
        self,
        method: str,
        path: str,
        body: dict | None = None,
        *,
        base_url: str | None = None,
        token: str | None = None,
        timeout: int = 30,
        retry_login: bool = True,
    ) -> dict:
        """Call an Aiper REST endpoint using the AES/RSA envelope.

        Most endpoints expect:
          - Header: encryptKey = RSA(key+iv)
          - Body: {"data": base64(AES_CBC_ZeroPad(json_with_nonce_ts))}
          - Response: base64(AES(...)) which we then decrypt.
        """

        enc = AiperEncryption()

        headers = dict(self._session.headers)
        headers["encryptKey"] = enc.encrypt_key_header
        headers["token"] = token or (self._token or "")

        url_base = (base_url or self.base_url).rstrip("/")
        url = f"{url_base}{path}"

        data = None
        if body is not None:
            data = enc.encrypt_request(body)

        resp = self._request_with_backoff(method, url, headers=headers, data=data, timeout=timeout)
        # Aiper returns HTTP 200 for most application-level errors.
        # Decrypt first, then evaluate code/message.
        decrypted = enc.decrypt_response(resp.text)

        try:
            payload = json.loads(decrypted)
        except Exception as err:
            raise Exception(f"Failed to parse decrypted response from {path}: {decrypted[:200]}") from err

        # If token expired, some stacks return code 401/403 inside JSON.
        # Prefer token refresh (less disruptive) before performing a full login.
        if retry_login and str(payload.get("code")) in ("401", "403"):
            _LOGGER.info("Token appears expired; attempting refresh")
            try:
                if self.refresh_token():
                    return self._call_encrypted(
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
            if self.login():
                return self._call_encrypted(
                    method,
                    path,
                    body,
                    base_url=base_url,
                    token=self._token,
                    timeout=timeout,
                    retry_login=False,
                )

        return payload

def _rest_wait(self) -> None:
    """Throttle REST calls to reduce cloud load and avoid rate limits."""
    with self._rest_lock:
        now = time.time()
        if now < self._rest_next_allowed:
            time.sleep(self._rest_next_allowed - now)
        self._rest_next_allowed = time.time() + self._rest_min_interval

def _request_with_backoff(self, method: str, url: str, *, headers: dict, json_body: dict | None = None, data: Any = None, timeout: int = 30):
    """Perform a REST request with limited retries/backoff on 429/5xx."""
    max_attempts = 4
    delay = 1.0
    last_exc = None
    for attempt in range(1, max_attempts + 1):
        self._rest_wait()
        try:
            resp = self._session.request(
                method.upper(),
                url,
                headers=headers,
                json=json_body,
                data=data,
                timeout=timeout,
            )
            # Only raise for HTTP-level failures; app-level errors are often HTTP 200
            if resp.status_code in (429, 500, 502, 503, 504):
                raise Exception(f"HTTP {resp.status_code}")
            resp.raise_for_status()
            return resp
        except Exception as err:
            last_exc = err
            # Backoff only for likely transient / throttling errors
            msg = str(err).lower()
            transient = any(k in msg for k in ("429", "500", "502", "503", "504", "timeout", "tempor", "connection", "reset", "refused"))
            if attempt >= max_attempts or not transient:
                break
            # jitter
            time.sleep(delay + random.uniform(0, 0.3))
            delay = min(delay * 2.0, 8.0)
    raise last_exc if last_exc else Exception("Request failed")

    def _call_plain(
        self,
        method: str,
        path: str,
        body: dict | None = None,
        *,
        base_url: str | None = None,
        token: str | None = None,
        timeout: int = 30,
    ) -> dict:
        """Call an Aiper REST endpoint without the AES/RSA envelope.

        Some endpoints in the Aiper app ecosystem appear to accept (or require)
        plain JSON rather than the encrypted request body used by most of the
        public API. We keep this as a fallback for a small set of features.
        """

        headers = dict(self._session.headers)
        headers["token"] = token or (self._token or "")

        url_base = (base_url or self.base_url).rstrip("/")
        url = f"{url_base}{path}"

        resp = self._request_with_backoff(method, url, headers=headers, json_body=body, timeout=timeout)
        resp.raise_for_status()

        if not resp.text:
            return {}

        try:
            return resp.json()
        except Exception:
            # Best-effort fallback when server returns non-JSON error bodies.
            return {"code": resp.status_code, "successful": False, "message": resp.text[:500]}

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

    def login(self) -> bool:
        """Authenticate with Aiper API."""
        _LOGGER.debug("Logging in to Aiper API")
        
        # Confirmed from MineApi: POST /login with email and password
        # @o("/login")
        # Object login(@JsonKey("email") String, @JsonKey("password") String, ...)
        login_data = {"email": self.username, "password": self.password}

        try:
            _LOGGER.debug("Logging in with email: %s", self.username)
            payload = self._call_encrypted("POST", "/login", login_data, base_url=self.base_url, token="")

            if not self._is_success(payload):
                msg = payload.get("msg") or payload.get("message") or payload.get("mess") or "Unknown error"
                raise Exception(f"Login failed: {msg}")

            result = payload.get("data", {}) or {}

            # TokenIdInfo fields observed: token, serialNumber, tokenExpires, domain
            self._token = result.get("token")
            self._user_id = result.get("serialNumber")
            self._token_expires = result.get("tokenExpires", 0)
            domains = result.get("domain") or []
            if domains:
                # This is authoritative for the account; use it for subsequent calls.
                self.base_url = str(domains[0]).rstrip("/")

            if not self._token:
                raise Exception(f"No token in login response: {result}")

            self._session.headers["token"] = self._token
            _LOGGER.info("Successfully logged in to Aiper API (base_url=%s)", self.base_url)

            # Pre-fetch OpenID token for AWS IoT
            self._get_openid_token()

            return True

        except requests.RequestException as err:
            _LOGGER.error("Login request failed: %s", err)
            raise Exception(f"Login request failed: {err}")

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
        zid = self._session.headers.get("zoneId")
        return str(zid) if isinstance(zid, str) and zid else None

    def _call_with_zoneid(self, sn: str, fn: Callable[[], Any]) -> Any:
        """Invoke `fn` while temporarily setting the zoneId header for `sn`."""
        zid = self._zone_id_for_sn(sn)
        prev = self._session.headers.get("zoneId")
        if zid:
            self._session.headers["zoneId"] = zid
        try:
            return fn()
        finally:
            if prev is not None:
                self._session.headers["zoneId"] = prev
            else:
                # Remove if it did not exist before.
                self._session.headers.pop("zoneId", None)
    
    def _verify_token(self) -> bool:
        """Verify the authentication token is valid."""
        try:
            payload = self._call_encrypted("GET", "/users/verificationToken", None)
            if self._is_success(payload):
                _LOGGER.debug("Token verification successful")
                return True
            # Do not log full payload because it may include authentication details.
            try:
                code = payload.get("code") if isinstance(payload, dict) else None
                msg = None
                if isinstance(payload, dict):
                    msg = payload.get("msg") or payload.get("message")
                _LOGGER.warning("Token verification returned (code=%s, message=%s)", code, msg)
            except Exception:
                _LOGGER.warning("Token verification returned an unexpected response")
            return False
        except Exception as err:
            _LOGGER.warning("Token verification failed: %s", err)
            return False
    
    def refresh_token(self) -> bool:
        """Refresh the authentication token."""
        try:
            payload = self._call_encrypted("POST", "/users/token/refresh", {})
            if self._is_success(payload):
                result = payload.get("data", {}) or {}
                new_token = result.get("token")
                if new_token:
                    self._token = new_token
                    self._session.headers["token"] = self._token
                    _LOGGER.info("Token refreshed successfully")
                    return True
            # Do not log full payload because it may include credentials/tokens.
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

    def _get_openid_token(self) -> None:
        """Fetch Cognito Identity/OpenID data used for AWS IoT MQTT."""
        try:
            payload = self._call_encrypted("POST", "/users/getOpenIdToken", {})
            if not self._is_success(payload):
                # Do not log full payload because it may contain credentials/tokens.
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

            # tokenDuration is in seconds
            dur = data.get("tokenDuration")
            if dur:
                self._openid_token_exp = time.time() + float(dur)

            _LOGGER.debug(
                "Got OpenID token data identity_id=%s pool_id=%s iot_endpoint=%s",
                (self._identity_id[:8] + "…") if isinstance(self._identity_id, str) else None,
                (self._identity_pool_id[:8] + "…") if isinstance(self._identity_pool_id, str) else None,
                self._iot_endpoint,
            )

        except Exception as err:
            _LOGGER.warning("Failed to get OpenID token data: %s", err)

    def _get_aws_credentials(self) -> dict[str, Any] | None:
        """Exchange the OpenID token for temporary AWS credentials.

        Uses Cognito Identity GetCredentialsForIdentity with Logins set to
        cognito-identity.amazonaws.com.
        """

        if not self._identity_id or not self._openid_token:
            return None

        # Refresh OpenID token if close to expiry (or missing expiry info)
        if self._openid_token_exp and (self._openid_token_exp - time.time()) < 120:
            self._get_openid_token()

        if self._aws_credentials_exp and (self._aws_credentials_exp - time.time()) > 120:
            return self._aws_credentials

        # Infer region from the IoT endpoint, e.g. "...iot.eu-central-1.amazonaws.com"
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

        resp = requests.post(url, headers=headers, json=body, timeout=30)
        resp.raise_for_status()
        out = resp.json()

        creds = out.get("Credentials") or {}
        if not creds.get("AccessKeyId"):
            _LOGGER.warning("Unexpected Cognito credentials response: %s", out)
            return None

        self._aws_credentials = creds
        # Expiration may be ISO8601 string; keep a conservative cache window.
        self._aws_credentials_exp = time.time() + 3300  # ~55 minutes
        return creds

    def get_devices(self) -> list[dict]:
        """Get list of devices from API."""
        try:
            payload = self._call_encrypted("POST", "/equipment/getEquipment", {})
            _LOGGER.debug("Get devices response: %s", payload)

            if not self._is_success(payload):
                _LOGGER.warning("Get devices failed: %s", payload)
                return []

            devices = payload.get("data", [])
            if isinstance(devices, dict):
                devices = devices.get("list", devices.get("equipments", []))

            for device in devices:
                sn = device.get("sn")
                if sn:
                    self._devices[sn] = device
                    zone_id = device.get("zoneId") or device.get("zone_id")
                    if isinstance(zone_id, str) and zone_id:
                        self._device_zone_id_by_sn[sn] = zone_id
                    _LOGGER.debug("Found device: %s (%s)", device.get("name", "Unknown"), sn)

            return devices
            
        except requests.RequestException as err:
            _LOGGER.error("Failed to get devices: %s", err)
            return []

    def get_device_info(self, sn: str) -> dict | None:
        """Get detailed info for a specific device."""
        try:
            payload = self._call_encrypted("POST", "/equipment/getEquipmentInfo", {"sn": sn})
            _LOGGER.info("Device info for %s: %s", sn, payload)

            if not self._is_success(payload):
                return None

            data = payload.get("data")
            if isinstance(data, dict):
                out = dict(data)
                out["_payload"] = payload
                return out
            # Some regions return a non-dict under `data` (e.g., list/scalar).
            return {"data": data, "_payload": payload}

        except requests.RequestException as err:
            _LOGGER.error("Failed to get device info for %s: %s", sn, err)
            return None

    def get_device_status(self, sn: str) -> dict | None:
        """Get online status for a device."""
        try:
            payload = self._call_encrypted("POST", "/equipment/checkEquipmentOnlineStatus", {"sn": sn})
            _LOGGER.info("Device status for %s: %s", sn, payload)

            if self._is_success(payload):
                return payload.get("data")
            return None
            
        except requests.RequestException as err:
            _LOGGER.error("Failed to get status for %s: %s", sn, err)
            return None
    
    def get_cleaning_history(self, sn: str) -> Any:
        """Get cleaning history/totals for a device.

        We return the full decrypted payload because some regions/firmwares
        place totals (counts/time) at the root level instead of under `data`.
        """

        def _do(body: dict) -> Any:
            payload = self._call_encrypted("POST", "/swimming/v2/getCleanTimeBySn", body)
            if self._is_success(payload):
                return payload
            return None

        try:
            # Try a couple of common pagination payload shapes.
            data = self._call_with_zoneid(sn, lambda: _do({"sn": sn}))
            if not data:
                data = self._call_with_zoneid(sn, lambda: _do({"sn": sn, "pageNo": 1, "pageSize": 20}))
            if not data:
                data = self._call_with_zoneid(sn, lambda: _do({"sn": sn, "pageNum": 1, "pageSize": 20}))
            if not data:
                data = self._call_with_zoneid(sn, lambda: _do({"sn": sn, "page": 1, "size": 20}))
            return data or {}

        except Exception as err:
            _LOGGER.error("Failed to get cleaning history: %s", err)
            return {}

    def get_consumables(self, sn: str) -> Any:
        """Get consumable status (filter, brush, etc.).

        Similar to other Aiper endpoints, parameter names vary by region.
        We try multiple request shapes and return the full decrypted payload.
        """

        def _do(body: dict) -> Any:
            payload = self._call_encrypted("POST", "/poolRobot/getConsumableList", body)
            if self._is_success(payload):
                return payload
            return None

        try:
            dev = self._devices.get(sn) or {}
            equip_id = dev.get("equipmentId") or dev.get("deviceId") or dev.get("id") or dev.get("eid")

            bodies: list[dict] = []
            # Common shapes
            bodies.extend([
                {"sn": sn},
                {"sn": sn, "type": 0},
                {"sn": sn, "type": 1},
                {"equipmentSn": sn},
                {"equipmentSn": sn, "type": 0},
                {"equipmentSn": sn, "type": 1},
                {"serialNumber": sn},
            ])

            if equip_id is not None:
                bodies[:0] = [
                    {"equipmentId": equip_id},
                    {"equipmentId": equip_id, "type": 0},
                    {"equipmentId": equip_id, "type": 1},
                    {"id": equip_id},
                    {"deviceId": equip_id},
                ]

            # Try each body until we get a non-empty payload
            for body in bodies:
                data = self._call_with_zoneid(sn, lambda b=body: _do(b))
                if data:
                    return data

            return None

        except Exception as err:
            _LOGGER.error("Failed to get consumables: %s", err)
            return None

    # --- Clean path preference (REST) ---
    def query_clean_path_setting(self, sn: str) -> int | None:
        """Query the clean-path preference.

        We observe multiple backend stacks depending on region/device family.
        For EU Scuba_X1, /equipmentCleanPathSetting/* endpoints exist while
        older /network/* and /swimming/v2/* endpoints may return 404.

        Returns:
            int | None: preference value (0/1 typical), or None if not available.
        """

        dev = self._devices.get(sn) or {}
        equip_id = dev.get("equipmentId") or dev.get("deviceId") or dev.get("id")

        # Ensure we have an equipment id (some accounts/devices only populate it after discovery).
        if equip_id is None:
            try:
                self.get_devices()
            except Exception:
                pass
            dev = self._devices.get(sn) or {}
            equip_id = dev.get("equipmentId") or dev.get("deviceId") or dev.get("id")

        base_paths = [
            # Newer backend (EU)
            "/equipmentCleanPathSetting/getCleanPathSetting",
            "/equipmentCleanPathSetting/getCleanPathSettingBySn",
            "/equipmentCleanPathSetting/queryCleanPathSetting",
            # Older backends
            "/network/clean_path_setting",
            "/network/cleanPathSetting",
            "/swimming/v2/queryCleanPathSetting",
            "/swimming/v2/getCleanPathSetting",
            "/swimming/v2/getCleanPathSettingBySn",
        ]

        candidate_paths: list[str] = []
        for p in base_paths:
            if p not in candidate_paths:
                candidate_paths.append(p)
        # Some environments mount APIs under /surfer
        for p in list(candidate_paths):
            sp = f"/surfer{p}" if not p.startswith("/surfer/") else p
            if sp not in candidate_paths:
                candidate_paths.append(sp)

        # Try a few common payload shapes.
        bodies: list[dict] = [{"sn": sn}]
        if equip_id is not None:
            bodies.insert(0, {"sn": sn, "id": equip_id})
            bodies.insert(1, {"sn": sn, "equipmentId": equip_id})
            bodies.insert(2, {"sn": sn, "deviceId": equip_id})

        for path in candidate_paths:
            for body in bodies:
                payload = None
                try:
                    payload = self._call_with_zoneid(sn, lambda p=path, b=body: self._call_encrypted("POST", p, b))
                except Exception as err:
                    _LOGGER.debug("Clean path query encrypted call failed (%s): %s", path, err)

                if not payload or not self._is_success(payload):
                    try:
                        payload = self._call_with_zoneid(sn, lambda p=path, b=body: self._call_plain("POST", p, b))
                    except Exception as err:
                        _LOGGER.debug("Clean path query plain call failed (%s): %s", path, err)

                if not payload or not self._is_success(payload):
                    continue

                data = payload.get("data")
                val = None
                if isinstance(data, dict):
                    for k in ("cleanPath", "cleanPathSetting", "clean_path_setting", "path", "value"):
                        if k in data:
                            val = data.get(k)
                            break
                # Some backends may return the value at the top level
                if val is None:
                    for k in ("cleanPath", "cleanPathSetting", "clean_path_setting"):
                        if isinstance(payload.get(k), (int, str)):
                            val = payload.get(k)
                            break

                # Normalize to numeric values. Some firmwares return labels.
                if isinstance(val, str):
                    s = val.strip()
                    if s.lstrip("-").isdigit():
                        try:
                            val = int(s)
                        except Exception:
                            val = None

                if isinstance(val, int):
                    # App treats -1 as default.
                    return 0 if val == -1 else int(val)

                if isinstance(val, str):
                    # Labels like "S-shaped" / "Adaptive"
                    norm = " ".join(val.lower().replace("_", " ").replace("-", " ").split())
                    if "adaptive" in norm:
                        return 1
                    if "shape" in norm or norm.startswith("s ") or norm == "s":
                        return 0

        return None

    def update_clean_path_setting(self, sn: str, value: int) -> bool:
        """Update clean-path preference and apply it to the device.

        On some models (e.g. Scuba_X1), updating the cloud preference alone may
        not immediately affect device behavior; the mobile app appears to also
        send a downChan (MQTT) command to apply the setting. We therefore:

          1) Persist preference via REST (best-effort across known stacks)
          2) If MQTT is connected, publish downChan variants (structured + AT)
          3) Nudge shadow desired so HA converges quickly
        """

        dev = self._devices.get(sn) or {}
        equip_id = dev.get("equipmentId") or dev.get("deviceId") or dev.get("id")

        # Ensure we have an equipment id (some accounts/devices only populate it after discovery).
        if equip_id is None:
            try:
                self.get_devices()
            except Exception:
                pass
            dev = self._devices.get(sn) or {}
            equip_id = dev.get("equipmentId") or dev.get("deviceId") or dev.get("id")

        base_paths = [
            # Newer backend (EU)
            "/equipmentCleanPathSetting/updateCleanPathSetting",
            "/equipmentCleanPathSetting/updateCleanPathSettingBySn",
            # Older backends
            "/network/clean_path_setting",
            "/network/cleanPathSetting",
            "/swimming/v2/updateCleanPathSetting",
            "/swimming/v2/setCleanPathSetting",
        ]

        candidate_paths: list[str] = []
        for p in base_paths:
            if p not in candidate_paths:
                candidate_paths.append(p)
        for p in list(candidate_paths):
            sp = f"/surfer{p}" if not p.startswith("/surfer/") else p
            if sp not in candidate_paths:
                candidate_paths.append(sp)

        # Try multiple key variants; some backends expect cleanPathSetting.
        key_variants = ("cleanPath", "cleanPathSetting", "clean_path_setting")
        base_bodies: list[dict] = []
        for k in key_variants:
            base_bodies.append({"sn": sn, k: int(value)})

        bodies: list[dict] = []
        if equip_id is not None:
            for bb in base_bodies:
                for idk in ("id", "equipmentId", "deviceId"):
                    b = dict(bb)
                    b[idk] = equip_id
                    bodies.append(b)
        bodies.extend(base_bodies)

        rest_ok = False
        for path in candidate_paths:
            for body in bodies:
                payload = None
                try:
                    payload = self._call_with_zoneid(sn, lambda p=path, b=body: self._call_encrypted("POST", p, b))
                except Exception as err:
                    _LOGGER.debug("Clean path update encrypted call failed (%s): %s", path, err)

                if not payload or not self._is_success(payload):
                    try:
                        payload = self._call_with_zoneid(sn, lambda p=path, b=body: self._call_plain("POST", p, b))
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
            # 2a) Structured downChan variants (best-effort)
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
                    if self.send_command(sn, "Machine", mp):
                        mqtt_published = True
                        _LOGGER.debug("Clean path downChan published: %s", mp)
                except Exception as err:
                    _LOGGER.debug("Clean path downChan publish failed (%s): %s", mp, err)

            # 2b) AT command variants with ack observation (stop early on +OK)
            for at_cmd in (
                f"AT+AUTO={int(value)}",
                f"AUTO {int(value)}",
                f"AT+CPATH={int(value)}",
                f"AT+CLEANPATH={int(value)}",
                f"AT+SETPATH={int(value)}",
            ):
                try:
                    res = self.send_machine_at(sn, at_cmd)
                    if res is True:
                        mqtt_published = True
                        _LOGGER.debug("Clean path AT confirmed: %s", at_cmd)
                        break
                    if res is False:
                        mqtt_published = True
                        _LOGGER.debug("Clean path AT rejected: %s", at_cmd)
                        continue
                    # None: published but no ack observed
                    mqtt_published = True
                    _LOGGER.debug("Clean path AT published (no ack): %s", at_cmd)
                except Exception as err:
                    _LOGGER.debug("Clean path AT failed (%s): %s", at_cmd, err)

        shadow_ok = False
        try:
            shadow_ok = bool(
                self.publish_shadow_update(
                    sn,
                    {"Machine": {"cleanPath": int(value), "cleanPathSetting": int(value), "clean_path_setting": int(value)}},
                )
            )
        except Exception:
            shadow_ok = False

        try:
            self.request_shadow(sn)
        except Exception:
            pass

        return bool(rest_ok or mqtt_published or shadow_ok)

    def connect_mqtt(self) -> bool:
        """Connect to AWS IoT MQTT broker."""
        if not self._identity_id or not self._iot_endpoint:
            _LOGGER.error("No IoT identity/endpoint available")
            return False
            
        try:
            from AWSIoTPythonSDK.MQTTLib import AWSIoTMQTTClient
            import certifi

            creds = self._get_aws_credentials()
            if not creds:
                _LOGGER.error("Unable to obtain AWS credentials for MQTT")
                return False
            
            client_id = f"aiper-ha-{self._identity_id[:8]}"
            self._mqtt_client = AWSIoTMQTTClient(client_id, useWebsocket=True)
            self._mqtt_client.configureEndpoint(self._iot_endpoint, 443)
            # Root CA bundle is required for TLS. certifi works well inside HA containers.
            self._mqtt_client.configureCredentials(certifi.where())
            # WebSocket SigV4 requires IAM creds.
            self._mqtt_client.configureIAMCredentials(
                creds["AccessKeyId"],
                creds["SecretKey"],
                creds.get("SessionToken", ""),
            )

            # Some SDK builds support explicit region configuration.
            if hasattr(self._mqtt_client, "configureAWSRegion"):
                try:
                    region = self._aws_region
                    if not region and self._iot_endpoint and ".iot." in self._iot_endpoint:
                        region = self._iot_endpoint.split(".iot.", 1)[1].split(".", 1)[0]
                    if region:
                        self._mqtt_client.configureAWSRegion(region)
                except Exception:
                    pass
            
            # Configure connection parameters - use short timeouts
            self._mqtt_client.configureAutoReconnectBackoffTime(1, 8, 5)
            self._mqtt_client.configureOfflinePublishQueueing(-1)
            self._mqtt_client.configureDrainingFrequency(2)
            self._mqtt_client.configureConnectDisconnectTimeout(5)  # 5 second timeout
            self._mqtt_client.configureMQTTOperationTimeout(3)
            
            if self._mqtt_client.connect():
                self._mqtt_connected = True
                _LOGGER.info("Connected to AWS IoT MQTT")
                return True
            
            return False
            
        except ImportError:
            _LOGGER.error("AWSIoTPythonSDK not installed")
            return False
        except Exception as err:
            _LOGGER.error("MQTT connection failed: %s", err)
            return False

    def is_mqtt_connected(self) -> bool:
        """Return True if the AWS IoT MQTT client is connected.

        Exposed for entity availability and diagnostics.
        """
        return bool(self._mqtt_connected and self._mqtt_client)


    def request_shadow(self, sn: str) -> bool:
        """Request the current AWS IoT thing shadow."""
        if not self._mqtt_connected or not self._mqtt_client:
            return False
        try:
            topic = TOPIC_SHADOW_GET_REQUEST.format(sn=sn)
            self._mqtt_client.publish(topic, "", 1)
            _LOGGER.debug("Published shadow get request to %s", topic)
            return True
        except Exception as err:
            _LOGGER.debug("Failed to request shadow for %s: %s", sn, err)
            return False


    def publish_shadow_update(self, sn: str, desired: dict[str, Any]) -> bool:
        """Backward-compatible alias for publishing a shadow desired-state update.

        Earlier builds referenced `publish_shadow_update`; the implementation is
        provided by `publish_shadow_desired`.
        """
        return self.publish_shadow_desired(sn, desired)


    def publish_shadow_desired(self, sn: str, desired: dict[str, Any]) -> bool:
        """Publish a desired-state update to the AWS IoT device shadow.

        Some Aiper models appear to act on desired-state deltas rather than
        processing app/downChan packets. We therefore publish desired-state
        updates as an additional control path.

        Parameters
        ----------
        sn: str
            Device serial number
        desired: dict
            Desired state fragment, e.g. {"Machine": {"mode": 0}}
        """
        if not self._mqtt_connected or not self._mqtt_client:
            return False
        try:
            topic = TOPIC_SHADOW_UPDATE.format(sn=sn)
            payload = {"state": {"desired": desired}}
            message = json.dumps(payload, separators=(",", ":"))
            self._mqtt_client.publish(topic, message, 1)
            _LOGGER.debug("Published shadow update to %s: %s", topic, message)
            return True
        except Exception as err:
            _LOGGER.debug("Failed to publish shadow update for %s: %s", sn, err)
            return False

    def subscribe_device(self, sn: str, callback: Callable[[dict], None]) -> bool:
        """Subscribe to device shadow updates."""
        if not self._mqtt_connected:
            _LOGGER.warning("MQTT not connected, cannot subscribe")
            return False
            
        with self._lock:
            if sn not in self._shadow_callbacks:
                self._shadow_callbacks[sn] = []
            self._shadow_callbacks[sn].append(callback)
        
        # Determine topic based on device type
        is_x9 = any(sn.upper().startswith(prefix) for prefix in X9_SERIES_PREFIXES)
        report_topic = TOPIC_SHADOW_REPORT_X9 if is_x9 else TOPIC_SHADOW_REPORT
        
        def on_message(client, userdata, message):
            try:
                payload = self._decrypt(message.payload)
                data = json.loads(payload)

                # Track the device's reported timezone string (e.g. "UTC+3")
                # so that we can include it when sending downlink commands.
                if (
                    isinstance(data, dict)
                    and isinstance(data.get("data"), dict)
                    and isinstance(data["data"].get("sn"), str)
                    and isinstance(data["data"].get("timeZone"), str)
                ):
                    self._last_timezone_by_sn[data["data"]["sn"]] = data["data"]["timeZone"]

                # Capture acknowledgements for downlink AT commands.
                # Example upChan payload:
                #   {"type":"Machine","data":{"sn":"...","timeZone":"UTC+3","ack":"+OK\r\n"}, ...}
                if (
                    isinstance(data, dict)
                    and data.get("type") == "Machine"
                    and isinstance(data.get("data"), dict)
                    and isinstance(data["data"].get("ack"), str)
                ):
                    self._record_ack(sn, data["data"]["ack"])

                # Always attach the serial number so downstream handlers can
                # process updates even if they were registered with a
                # single-argument callback.
                if isinstance(data, dict) and "_sn" not in data:
                    data["_sn"] = sn

                # Attach the MQTT topic so downstream handlers can distinguish
                # between shadow/report, shadow/update/delta, and documents.
                if isinstance(data, dict) and "_topic" not in data:
                    try:
                        data["_topic"] = getattr(message, "topic", "")
                    except Exception:
                        data["_topic"] = ""

                if self.mqtt_debug:
                    _LOGGER.debug("MQTT message topic=%s payload=%s", getattr(message, "topic", "?"), payload[:800])
                
                with self._lock:
                    for cb in self._shadow_callbacks.get(sn, []):
                        try:
                            # Support both callback styles:
                            #   cb(sn, data)
                            #   cb(data)
                            try:
                                cb(sn, data)
                            except TypeError:
                                cb(data)
                        except Exception as err:
                            _LOGGER.error("Callback error: %s", err)
                            
            except Exception as err:
                _LOGGER.error("Failed to process message: %s", err)
        
        try:
            # Subscribe to shadow report topic
            topic = report_topic.format(sn=sn)
            self._mqtt_client.subscribe(topic, 1, on_message)
            _LOGGER.debug("Subscribed to %s", topic)

            # Subscribe to additional topics (AWS IoT shadow and device uplink)
            self._mqtt_client.subscribe(TOPIC_READ.format(sn=sn), 1, on_message)
            self._mqtt_client.subscribe(TOPIC_SHADOW_GET.format(sn=sn), 1, on_message)
            self._mqtt_client.subscribe(TOPIC_SHADOW_UPDATE_ACCEPTED.format(sn=sn), 1, on_message)
            self._mqtt_client.subscribe(TOPIC_SHADOW_UPDATE_DELTA.format(sn=sn), 1, on_message)
            self._mqtt_client.subscribe(TOPIC_SHADOW_UPDATE_DOCUMENTS.format(sn=sn), 1, on_message)

            # Some models publish to app/report
            self._mqtt_client.subscribe(TOPIC_SHADOW_REPORT_X9.format(sn=sn), 1, on_message)
            
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
            self._ack_events[sn].set()

    def _clear_ack_fifo(self, sn: str) -> None:
        with self._ack_lock:
            self._ack_fifo[sn].clear()
            self._ack_events[sn].clear()

    def _wait_for_ack(self, sn: str, timeout: float = 4.0) -> str | None:
        """Wait for the next ack for this device SN.

        Returns the ack string (e.g. "+OK\r\n" / "+ERROR\r\n") or None on timeout.
        """
        ev = self._ack_events[sn]
        if not ev.wait(timeout=timeout):
            return None
        with self._ack_lock:
            if not self._ack_fifo[sn]:
                return None
            ack = self._ack_fifo[sn].popleft()
            # If more acks remain, keep the event set; otherwise clear.
            if not self._ack_fifo[sn]:
                ev.clear()
            return ack

    def send_machine_at(self, sn: str, at_cmd: str, timeout: float = 4.0) -> bool | None:
        """Send an AT command via downChan and wait for an upChan ack.

        Returns:
          True  -> ack indicates OK
          False -> ack indicates ERROR
          None  -> no ack observed (published, but cannot confirm)
        """
        tz = self._timezone_string_for_sn(sn)
        payload = {"sn": sn, "timeZone": tz, "cmd": at_cmd}

        with self._cmd_locks[sn]:
            self._clear_ack_fifo(sn)
            published = self.send_command(sn, "Machine", payload)
            if not published:
                return None

            ack = self._wait_for_ack(sn, timeout=timeout)
            if ack is None:
                return None

            ack_u = ack.upper()
            if "+OK" in ack_u:
                return True
            if "+ERROR" in ack_u:
                return False
            return None

    def send_command(self, sn: str, cmd_type: str, data: dict | None = None) -> bool:
        """Send a command to the device.

        IMPORTANT: The device validates a CRC16 checksum over a *compact* JSON
        rendering of the `data` object (no spaces). Using Python's default
        `json.dumps()` (which inserts spaces) yields a different checksum and
        commands are silently ignored.

        We therefore:
          1) Serialize `data` with `separators=(",", ":")`
          2) Compute CRC16 over that exact string
          3) Serialize the full payload with the same compact separators
        """
        is_x9 = any(sn.upper().startswith(prefix) for prefix in X9_SERIES_PREFIXES)

        data_obj: dict[str, Any] = dict(data or {})

        # Most devices include `sn` and `timeZone` inside the `data` object.
        # Including them (and keeping a stable key order) improves interoperability
        # and matches what we see in `shadow/report` payloads.
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
            # X9 format: {"Machine": {...}, "chksum": 12345}
            payload: dict[str, Any] = {cmd_type: data_obj}
        else:
            # Standard format: {"type": "Machine", "data": {...}, "chksum": 12345}
            payload = {
                "type": cmd_type,
                "data": data_obj,
            }

        # Include a result field to mirror telemetry...
        if not is_x9:
            payload["res"] = 0

        # Compute checksum over compact JSON of the *data* object.
        data_json = json.dumps(data_obj, separators=(",", ":"))
        payload["chksum"] = self._crc16(data_json)

        # Send compact JSON overall (matches the mobile app behavior more closely).
        message = json.dumps(payload, separators=(",", ":"))
        encrypted = self._encrypt(message)

        topic = TOPIC_WRITE.format(sn=sn)

        try:
            if self._mqtt_connected and self._mqtt_client:
                # Some firmware revisions accept plaintext JSON on downChan;
                # others use the XOR+base64 encoded form. To maximize compatibility
                # we publish both.
                self._mqtt_client.publish(topic, message, 1)
                self._mqtt_client.publish(topic, encrypted, 1)
                _LOGGER.debug(
                    "Sent command to %s: %s data=%s (plain+encrypted)",
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

    def start_cleaning(self, sn: str, mode: int = 1) -> bool:
        """Start cleaning cycle."""
        # Prefer direct downChan commands. Writing AWS IoT shadow desired-state can
        # cause UI oscillation via /shadow/update/delta even when the device ignores it.
        ok = self.send_command(sn, "Machine", {"status": 1, "mode": mode})
        self.request_shadow(sn)
        return ok

    def stop_cleaning(self, sn: str) -> bool:
        """Stop cleaning and return to dock."""
        ok = self.send_command(sn, "Machine", {"status": 2})
        self.request_shadow(sn)
        return ok

    def pause_cleaning(self, sn: str) -> bool:
        """Pause cleaning."""
        ok = self.send_command(sn, "Machine", {"status": 0})
        self.request_shadow(sn)
        return ok

    def set_mode(self, sn: str, mode: int) -> bool:
        """Set the cleaning mode.

        For Scuba X1, we treat all modes (including "Scheduled") as ``AT+MODE=<n>``.
        Some firmwares expose ``AT+WORKMODE=<n>`` instead, so we try it as a fallback.

        Note: Earlier experiments used ``AT+PLAN`` for "Scheduled", but the device
        often responds ``+ERROR``. We therefore avoid ``AT+PLAN`` unless we have
        hard evidence it is required.

        The integration is intentionally optimistic: if the command is published but no ack
        is received within the timeout, we still treat it as success to avoid the UI
        snapping back while you validate device behavior.
        """

        _LOGGER.info("Setting mode for %s: %s", sn, mode)

        # Some accounts/devices expose a REST setter. Keep it best-effort.
        rest_ok = False
        try:
            rest_ok = bool(self._try_rest_set_mode(sn, mode))
        except Exception as err:  # pragma: no cover
            _LOGGER.debug("REST set_mode failed for %s: %s", sn, err)

        candidates = [
            f"AT+MODE={mode}",
            f"AT+WORKMODE={mode}",
        ]

        cmd_result: bool | None = False
        for at_cmd in candidates:
            cmd_result = self.send_machine_at(sn, at_cmd)
            if cmd_result is True or cmd_result is None:
                break

        # Pull fresh shadow state (non-blocking).
        try:
            self.request_shadow(sn)
        except Exception:
            pass

        cmd_ok = cmd_result is True or cmd_result is None
        return rest_ok or cmd_ok

    def _send_mode_commands(self, sn: str, mode: int) -> bool:
        """Try different command formats for setting mode."""
        results = []
        
        # Format 1: Standard Machine command (reported field)
        r1 = self.send_command(sn, "Machine", {"mode": mode})
        results.append(("Machine.mode", r1))

        # Format 1b: AT-style commands (used heavily by the Android app)
        # These are best-effort guesses; different firmware revisions use different names.
        for at_name in ("WORKMODE", "MODE", "WMODE", "PLAN"):
            r = self.send_command(sn, "Machine", {"cmd": f"AT+{at_name}={mode}"})
            results.append((f"Machine.cmd AT+{at_name}=", r))
        
        # Format 2: SetMode command type (seen on some models)
        r2 = self.send_command(sn, "SetMode", {"mode": mode})
        results.append(("SetMode", r2))
        
        # Format 3: Control command type (seen on some models)
        r3 = self.send_command(sn, "Control", {"cmd": "setMode", "mode": mode})
        results.append(("Control", r3))
        
        # Format 4: GetWorkMode with mode (some devices use this to set)
        r4 = self.send_command(sn, "GetWorkMode", {"mode": mode})
        results.append(("GetWorkMode", r4))
        
        _LOGGER.info("Mode command results: %s", results)
        return any(r for _, r in results)

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

    def disconnect(self) -> None:
        """Disconnect from MQTT and cleanup."""
        if self._mqtt_client and self._mqtt_connected:
            try:
                self._mqtt_client.disconnect()
            except Exception:
                pass
            self._mqtt_connected = False
        
        self._session.close()
        _LOGGER.info("Disconnected from Aiper API")
