"""Aiper API Client for REST and MQTT communication.

This module replaces the legacy api.py import path used by the integration.
The legacy file currently has an indentation regression that leaves most
AiperApi methods nested below a helper function, so the config flow cannot
instantiate/login correctly on current Home Assistant installs.
"""
from __future__ import annotations

import base64
import json
import logging
import random
import threading
import time
from collections import defaultdict, deque
from datetime import datetime
from typing import Any, Callable

try:
    from zoneinfo import ZoneInfo
except Exception:  # pragma: no cover
    ZoneInfo = None  # type: ignore[assignment]

import requests

from .const import (
    API_ENDPOINTS,
    TOPIC_READ,
    TOPIC_SHADOW_GET,
    TOPIC_SHADOW_GET_REQUEST,
    TOPIC_SHADOW_REPORT,
    TOPIC_SHADOW_REPORT_X9,
    TOPIC_SHADOW_UPDATE,
    TOPIC_SHADOW_UPDATE_ACCEPTED,
    TOPIC_SHADOW_UPDATE_DELTA,
    TOPIC_SHADOW_UPDATE_DOCUMENTS,
    TOPIC_WRITE,
    XOR_KEY,
    X9_SERIES_PREFIXES,
)
from .crypto import AiperEncryption

_LOGGER = logging.getLogger(__name__)


class AiperApi:
    """Client for the Aiper REST API and AWS IoT MQTT transport."""

    def __init__(self, username: str, password: str, region: str = "eu") -> None:
        self.username = username
        self.password = password
        self.region = region
        self.base_url = API_ENDPOINTS.get(region, API_ENDPOINTS["eu"])

        self._token: str | None = None
        self._user_id: str | None = None
        self._token_expires: Any = None
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

        self._devices: dict[str, dict[str, Any]] = {}
        self._device_zone_id_by_sn: dict[str, str] = {}
        self._last_timezone_by_sn: dict[str, str] = {}
        self._shadow_callbacks: dict[str, list[Callable[..., None]]] = {}
        self._lock = threading.Lock()

        self._ack_lock = threading.Lock()
        self._ack_events: dict[str, threading.Event] = defaultdict(threading.Event)
        self._ack_fifo: dict[str, deque[str]] = defaultdict(lambda: deque(maxlen=10))
        self._cmd_locks: dict[str, threading.Lock] = defaultdict(threading.Lock)

        self._session = requests.Session()
        self._rest_lock = threading.Lock()
        self._rest_min_interval = 0.8
        self._rest_next_allowed = 0.0
        self._session.headers.update(
            {
                "Content-Type": "application/json",
                "version": "3.0.0",
                "os": "android",
                "charset": "UTF-8",
                "Accept-Language": "en",
                "zoneId": "Europe/Athens",
                "token": "",
            }
        )

    @staticmethod
    def _is_success(payload: dict[str, Any]) -> bool:
        code = payload.get("code")
        successful = payload.get("successful")
        return str(code) in ("0", "200") or successful is True

    def _rest_wait(self) -> None:
        """Throttle REST calls to reduce cloud load and avoid rate limits."""
        with self._rest_lock:
            now = time.time()
            if now < self._rest_next_allowed:
                time.sleep(self._rest_next_allowed - now)
            self._rest_next_allowed = time.time() + self._rest_min_interval

    def _request_with_backoff(
        self,
        method: str,
        url: str,
        *,
        headers: dict[str, Any],
        json_body: dict[str, Any] | None = None,
        data: Any = None,
        timeout: int = 30,
    ) -> requests.Response:
        """Perform a REST request with limited retry/backoff on transient errors."""
        max_attempts = 4
        delay = 1.0
        last_exc: Exception | None = None

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
                if resp.status_code in (429, 500, 502, 503, 504):
                    raise requests.HTTPError(f"HTTP {resp.status_code}", response=resp)
                resp.raise_for_status()
                return resp
            except Exception as err:
                last_exc = err
                transient = any(
                    key in str(err).lower()
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
                time.sleep(delay + random.uniform(0, 0.3))
                delay = min(delay * 2.0, 8.0)

        raise last_exc if last_exc else RuntimeError("Request failed")

    def _call_encrypted(
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
        """Call an Aiper endpoint using the AES/RSA envelope used by the app."""
        enc = AiperEncryption()

        headers = dict(self._session.headers)
        headers["encryptKey"] = enc.encrypt_key_header
        headers["token"] = token or (self._token or "")

        url = f"{(base_url or self.base_url).rstrip('/')}{path}"
        encrypted_body = enc.encrypt_request(body) if body is not None else None
        resp = self._request_with_backoff(
            method,
            url,
            headers=headers,
            data=encrypted_body,
            timeout=timeout,
        )

        decrypted = enc.decrypt_response(resp.text)
        try:
            payload = json.loads(decrypted)
        except Exception as err:
            raise RuntimeError(f"Failed to parse decrypted response from {path}: {decrypted[:200]}") from err

        if retry_login and str(payload.get("code")) in ("401", "403"):
            _LOGGER.info("Aiper token appears expired; attempting refresh")
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

            _LOGGER.info("Aiper token refresh failed; re-authenticating")
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

    def _call_plain(
        self,
        method: str,
        path: str,
        body: dict[str, Any] | None = None,
        *,
        base_url: str | None = None,
        token: str | None = None,
        timeout: int = 30,
    ) -> dict[str, Any]:
        """Call an Aiper endpoint without the encrypted app envelope."""
        headers = dict(self._session.headers)
        headers["token"] = token or (self._token or "")
        url = f"{(base_url or self.base_url).rstrip('/')}{path}"
        resp = self._request_with_backoff(
            method,
            url,
            headers=headers,
            json_body=body,
            timeout=timeout,
        )
        if not resp.text:
            return {}
        try:
            return resp.json()
        except Exception:
            return {"code": resp.status_code, "successful": False, "message": resp.text[:500]}

    def _encrypt(self, data: str) -> str:
        data_bytes = data.encode("utf-8")
        xored = bytes([byte ^ XOR_KEY[index % 4] for index, byte in enumerate(data_bytes)])
        return base64.b64encode(xored).decode("utf-8") + "\n"

    def _decrypt(self, data: bytes | str) -> str:
        try:
            raw = data if isinstance(data, bytes) else data.encode("utf-8")
            decoded = base64.b64decode(raw)
            return bytes([byte ^ XOR_KEY[index % 4] for index, byte in enumerate(decoded)]).decode("utf-8")
        except Exception:
            return data.decode("utf-8") if isinstance(data, bytes) else str(data)

    def login(self) -> bool:
        """Authenticate with the Aiper cloud."""
        payload = self._call_encrypted(
            "POST",
            "/login",
            {"email": self.username, "password": self.password},
            base_url=self.base_url,
            token="",
        )
        if not self._is_success(payload):
            msg = payload.get("msg") or payload.get("message") or payload.get("mess") or "Unknown error"
            raise RuntimeError(f"Login failed: {msg}")

        result = payload.get("data", {}) or {}
        self._token = result.get("token")
        self._user_id = result.get("serialNumber")
        self._token_expires = result.get("tokenExpires", 0)
        domains = result.get("domain") or []
        if domains:
            self.base_url = str(domains[0]).rstrip("/")

        if not self._token:
            raise RuntimeError(f"No token in login response: {result}")

        self._session.headers["token"] = self._token
        self._get_openid_token()
        return True

    def refresh_token(self) -> bool:
        try:
            payload = self._call_encrypted("POST", "/users/token/refresh", {})
            if self._is_success(payload):
                result = payload.get("data", {}) or {}
                token = result.get("token")
                if token:
                    self._token = token
                    self._session.headers["token"] = token
                    return True
        except Exception as err:
            _LOGGER.debug("Aiper token refresh failed: %s", err)
        return False

    def _get_openid_token(self) -> None:
        try:
            payload = self._call_encrypted("POST", "/users/getOpenIdToken", {})
            if not self._is_success(payload):
                _LOGGER.debug("OpenID token fetch failed: %s", payload.get("message") or payload.get("msg"))
                return

            data = payload.get("data", {}) or {}
            self._developer_provider_name = data.get("developerProviderName")
            self._identity_id = data.get("identityId")
            self._identity_pool_id = data.get("identityPoolId")
            self._iot_endpoint = data.get("iotEndpoint")
            self._aws_region = data.get("region")
            self._openid_token = data.get("token")
            duration = data.get("tokenDuration")
            if duration:
                self._openid_token_exp = time.time() + float(duration)
        except Exception as err:
            _LOGGER.warning("Failed to get Aiper OpenID token data: %s", err)

    def _get_aws_credentials(self) -> dict[str, Any] | None:
        if not self._identity_id or not self._openid_token:
            return None

        if self._openid_token_exp and self._openid_token_exp - time.time() < 120:
            self._get_openid_token()
        if self._aws_credentials_exp and self._aws_credentials_exp - time.time() > 120:
            return self._aws_credentials

        region = self._aws_region
        if not region and self._iot_endpoint and ".iot." in self._iot_endpoint:
            region = self._iot_endpoint.split(".iot.", 1)[1].split(".", 1)[0]
        region = region or "eu-central-1"

        resp = requests.post(
            f"https://cognito-identity.{region}.amazonaws.com/",
            headers={
                "Content-Type": "application/x-amz-json-1.1",
                "X-Amz-Target": "AWSCognitoIdentityService.GetCredentialsForIdentity",
            },
            json={
                "IdentityId": self._identity_id,
                "Logins": {"cognito-identity.amazonaws.com": self._openid_token},
            },
            timeout=30,
        )
        resp.raise_for_status()
        out = resp.json()
        creds = out.get("Credentials") or {}
        if not creds.get("AccessKeyId"):
            _LOGGER.warning("Unexpected Aiper Cognito credentials response: %s", out)
            return None

        self._aws_credentials = creds
        self._aws_credentials_exp = time.time() + 3300
        return creds

    def _zone_id_for_sn(self, sn: str) -> str | None:
        for value in (
            self._device_zone_id_by_sn.get(sn),
            self._last_timezone_by_sn.get(sn),
            self._session.headers.get("zoneId"),
        ):
            if isinstance(value, str) and value:
                return value
        return None

    def _call_with_zoneid(self, sn: str, fn: Callable[[], Any]) -> Any:
        zone_id = self._zone_id_for_sn(sn)
        previous = self._session.headers.get("zoneId")
        if zone_id:
            self._session.headers["zoneId"] = zone_id
        try:
            return fn()
        finally:
            if previous is not None:
                self._session.headers["zoneId"] = previous
            else:
                self._session.headers.pop("zoneId", None)

    def get_devices(self) -> list[dict[str, Any]]:
        try:
            payload = self._call_encrypted("POST", "/equipment/getEquipment", {})
            if not self._is_success(payload):
                _LOGGER.warning("Aiper get devices failed: %s", payload.get("message") or payload.get("msg"))
                return []

            devices: Any = payload.get("data", [])
            if isinstance(devices, dict):
                devices = devices.get("list") or devices.get("equipments") or []
            if not isinstance(devices, list):
                return []

            for device in devices:
                if not isinstance(device, dict):
                    continue
                sn = device.get("sn") or device.get("serialNumber")
                if not sn:
                    continue
                sn = str(sn)
                self._devices[sn] = device
                zone_id = device.get("zoneId") or device.get("zone_id")
                if isinstance(zone_id, str) and zone_id:
                    self._device_zone_id_by_sn[sn] = zone_id
            return devices
        except Exception as err:
            _LOGGER.error("Failed to get Aiper devices: %s", err)
            return []

    def get_device_info(self, sn: str) -> dict[str, Any] | None:
        try:
            payload = self._call_encrypted("POST", "/equipment/getEquipmentInfo", {"sn": sn})
            if not self._is_success(payload):
                return None
            data = payload.get("data")
            if isinstance(data, dict):
                out = dict(data)
                out["_payload"] = payload
                return out
            return {"data": data, "_payload": payload}
        except Exception as err:
            _LOGGER.debug("Failed to get Aiper device info for %s: %s", sn, err)
            return None

    def get_device_status(self, sn: str) -> Any:
        try:
            payload = self._call_encrypted("POST", "/equipment/checkEquipmentOnlineStatus", {"sn": sn})
            if self._is_success(payload):
                return payload.get("data")
        except Exception as err:
            _LOGGER.debug("Failed to get Aiper online status for %s: %s", sn, err)
        return None

    def get_cleaning_history(self, sn: str) -> Any:
        def _do(body: dict[str, Any]) -> Any:
            payload = self._call_encrypted("POST", "/swimming/v2/getCleanTimeBySn", body)
            return payload if self._is_success(payload) else None

        for body in (
            {"sn": sn},
            {"sn": sn, "pageNo": 1, "pageSize": 20},
            {"sn": sn, "pageNum": 1, "pageSize": 20},
            {"sn": sn, "page": 1, "size": 20},
        ):
            try:
                data = self._call_with_zoneid(sn, lambda b=body: _do(b))
                if data:
                    return data
            except Exception as err:
                _LOGGER.debug("Cleaning history query failed for %s with %s: %s", sn, body, err)
        return {}

    def get_consumables(self, sn: str) -> Any:
        dev = self._devices.get(sn) or {}
        equip_id = dev.get("equipmentId") or dev.get("deviceId") or dev.get("id") or dev.get("eid")

        bodies: list[dict[str, Any]] = []
        if equip_id is not None:
            bodies.extend(
                [
                    {"equipmentId": equip_id},
                    {"equipmentId": equip_id, "type": 0},
                    {"equipmentId": equip_id, "type": 1},
                    {"id": equip_id},
                    {"deviceId": equip_id},
                ]
            )
        bodies.extend(
            [
                {"sn": sn},
                {"sn": sn, "type": 0},
                {"sn": sn, "type": 1},
                {"equipmentSn": sn},
                {"equipmentSn": sn, "type": 0},
                {"equipmentSn": sn, "type": 1},
                {"serialNumber": sn},
            ]
        )

        for body in bodies:
            try:
                payload = self._call_with_zoneid(
                    sn,
                    lambda b=body: self._call_encrypted("POST", "/poolRobot/getConsumableList", b),
                )
                if self._is_success(payload):
                    return payload
            except Exception as err:
                _LOGGER.debug("Consumables query failed for %s with %s: %s", sn, body, err)
        return None

    def query_clean_path_setting(self, sn: str) -> int | None:
        dev = self._devices.get(sn) or {}
        equip_id = dev.get("equipmentId") or dev.get("deviceId") or dev.get("id")
        paths = (
            "/equipmentCleanPathSetting/getCleanPathSetting",
            "/equipmentCleanPathSetting/getCleanPathSettingBySn",
            "/equipmentCleanPathSetting/queryCleanPathSetting",
            "/network/clean_path_setting",
            "/network/cleanPathSetting",
            "/swimming/v2/queryCleanPathSetting",
            "/swimming/v2/getCleanPathSetting",
            "/swimming/v2/getCleanPathSettingBySn",
        )
        candidate_paths = list(dict.fromkeys([*paths, *[f"/surfer{p}" for p in paths]]))
        bodies = [{"sn": sn}]
        if equip_id is not None:
            bodies[:0] = [
                {"sn": sn, "id": equip_id},
                {"sn": sn, "equipmentId": equip_id},
                {"sn": sn, "deviceId": equip_id},
            ]

        for path in candidate_paths:
            for body in bodies:
                payload: dict[str, Any] | None = None
                try:
                    payload = self._call_with_zoneid(
                        sn,
                        lambda p=path, b=body: self._call_encrypted("POST", p, b),
                    )
                except Exception:
                    pass
                if not payload or not self._is_success(payload):
                    try:
                        payload = self._call_with_zoneid(
                            sn,
                            lambda p=path, b=body: self._call_plain("POST", p, b),
                        )
                    except Exception:
                        payload = None
                if not payload or not self._is_success(payload):
                    continue

                value = self._extract_clean_path_value(payload)
                if value is not None:
                    return value
        return None

    @staticmethod
    def _extract_clean_path_value(payload: dict[str, Any]) -> int | None:
        data = payload.get("data")
        for source in (data, payload):
            if not isinstance(source, dict):
                continue
            for key in ("cleanPath", "cleanPathSetting", "clean_path_setting", "path", "value"):
                val = source.get(key)
                if val is None:
                    continue
                if isinstance(val, int):
                    return 0 if val == -1 else int(val)
                if isinstance(val, str):
                    clean = val.strip()
                    if clean.lstrip("-").isdigit():
                        num = int(clean)
                        return 0 if num == -1 else num
                    norm = clean.lower().replace("_", " ").replace("-", " ")
                    if "adaptive" in norm:
                        return 1
                    if "shape" in norm or norm.strip() == "s":
                        return 0
        return None

    def update_clean_path_setting(self, sn: str, value: int) -> bool:
        dev = self._devices.get(sn) or {}
        equip_id = dev.get("equipmentId") or dev.get("deviceId") or dev.get("id")
        paths = (
            "/equipmentCleanPathSetting/updateCleanPathSetting",
            "/equipmentCleanPathSetting/updateCleanPathSettingBySn",
            "/network/clean_path_setting",
            "/network/cleanPathSetting",
            "/swimming/v2/updateCleanPathSetting",
            "/swimming/v2/setCleanPathSetting",
        )
        candidate_paths = list(dict.fromkeys([*paths, *[f"/surfer{p}" for p in paths]]))
        base_bodies = [{"sn": sn, key: int(value)} for key in ("cleanPath", "cleanPathSetting", "clean_path_setting")]
        bodies: list[dict[str, Any]] = []
        if equip_id is not None:
            for base in base_bodies:
                for id_key in ("id", "equipmentId", "deviceId"):
                    body = dict(base)
                    body[id_key] = equip_id
                    bodies.append(body)
        bodies.extend(base_bodies)

        rest_ok = False
        for path in candidate_paths:
            for body in bodies:
                payload = None
                try:
                    payload = self._call_with_zoneid(
                        sn,
                        lambda p=path, b=body: self._call_encrypted("POST", p, b),
                    )
                except Exception:
                    pass
                if not payload or not self._is_success(payload):
                    try:
                        payload = self._call_with_zoneid(
                            sn,
                            lambda p=path, b=body: self._call_plain("POST", p, b),
                        )
                    except Exception:
                        payload = None
                if payload and self._is_success(payload):
                    rest_ok = True
                    break
            if rest_ok:
                break

        mqtt_ok = False
        if self.is_mqtt_connected():
            for data in (
                {"cleanPath": int(value)},
                {"cleanPathSetting": int(value)},
                {"clean_path_setting": int(value)},
                {"cmd": "AUTO", "param": [int(value)]},
                {"cmd": f"AUTO {int(value)}"},
            ):
                try:
                    mqtt_ok = self.send_command(sn, "Machine", data) or mqtt_ok
                except Exception:
                    pass
            for at_cmd in (
                f"AT+AUTO={int(value)}",
                f"AUTO {int(value)}",
                f"AT+CPATH={int(value)}",
                f"AT+CLEANPATH={int(value)}",
            ):
                try:
                    result = self.send_machine_at(sn, at_cmd)
                    mqtt_ok = mqtt_ok or result is not False
                    if result is True:
                        break
                except Exception:
                    pass

        shadow_ok = self.publish_shadow_update(
            sn,
            {"Machine": {"cleanPath": int(value), "cleanPathSetting": int(value), "clean_path_setting": int(value)}},
        )
        self.request_shadow(sn)
        return bool(rest_ok or mqtt_ok or shadow_ok)

    def _try_rest_set_mode(self, sn: str, mode: int) -> bool:
        dev = self._devices.get(sn) or {}
        equip_id = dev.get("equipmentId") or dev.get("deviceId") or dev.get("id")
        paths = (
            "/equipment/setWorkMode",
            "/equipment/updateWorkMode",
            "/poolRobot/setWorkMode",
            "/swimming/v2/setWorkMode",
            "/network/setWorkMode",
        )
        bodies: list[dict[str, Any]] = [{"sn": sn, "mode": int(mode)}, {"sn": sn, "workMode": int(mode)}]
        if equip_id is not None:
            bodies.extend(
                [
                    {"sn": sn, "equipmentId": equip_id, "mode": int(mode)},
                    {"sn": sn, "deviceId": equip_id, "mode": int(mode)},
                    {"equipmentId": equip_id, "mode": int(mode)},
                ]
            )
        for path in paths:
            for body in bodies:
                try:
                    payload = self._call_with_zoneid(
                        sn,
                        lambda p=path, b=body: self._call_encrypted("POST", p, b),
                    )
                    if self._is_success(payload):
                        return True
                except Exception:
                    pass
        return False

    def connect_mqtt(self) -> bool:
        if not self._identity_id or not self._iot_endpoint:
            _LOGGER.error("No Aiper IoT identity/endpoint available")
            return False
        try:
            import certifi
            from AWSIoTPythonSDK.MQTTLib import AWSIoTMQTTClient

            creds = self._get_aws_credentials()
            if not creds:
                return False

            client_id = f"aiper-ha-{self._identity_id[:8]}"
            client = AWSIoTMQTTClient(client_id, useWebsocket=True)
            client.configureEndpoint(self._iot_endpoint, 443)
            client.configureCredentials(certifi.where())
            client.configureIAMCredentials(
                creds["AccessKeyId"],
                creds["SecretKey"],
                creds.get("SessionToken", ""),
            )
            if hasattr(client, "configureAWSRegion"):
                region = self._aws_region
                if not region and ".iot." in self._iot_endpoint:
                    region = self._iot_endpoint.split(".iot.", 1)[1].split(".", 1)[0]
                if region:
                    client.configureAWSRegion(region)
            client.configureAutoReconnectBackoffTime(1, 8, 5)
            client.configureOfflinePublishQueueing(-1)
            client.configureDrainingFrequency(2)
            client.configureConnectDisconnectTimeout(5)
            client.configureMQTTOperationTimeout(3)
            if client.connect():
                self._mqtt_client = client
                self._mqtt_connected = True
                return True
        except Exception as err:
            _LOGGER.warning("Aiper MQTT connection failed: %s", err)
        return False

    def is_mqtt_connected(self) -> bool:
        return bool(self._mqtt_connected and self._mqtt_client)

    def request_shadow(self, sn: str) -> bool:
        if not self.is_mqtt_connected():
            return False
        try:
            self._mqtt_client.publish(TOPIC_SHADOW_GET_REQUEST.format(sn=sn), "", 1)
            return True
        except Exception as err:
            _LOGGER.debug("Failed to request Aiper shadow for %s: %s", sn, err)
            return False

    def publish_shadow_update(self, sn: str, desired: dict[str, Any]) -> bool:
        return self.publish_shadow_desired(sn, desired)

    def publish_shadow_desired(self, sn: str, desired: dict[str, Any]) -> bool:
        if not self.is_mqtt_connected():
            return False
        try:
            payload = json.dumps({"state": {"desired": desired}}, separators=(",", ":"))
            self._mqtt_client.publish(TOPIC_SHADOW_UPDATE.format(sn=sn), payload, 1)
            return True
        except Exception as err:
            _LOGGER.debug("Failed to publish Aiper shadow update for %s: %s", sn, err)
            return False

    def subscribe_device(self, sn: str, callback: Callable[..., None]) -> bool:
        if not self.is_mqtt_connected():
            return False
        with self._lock:
            self._shadow_callbacks.setdefault(sn, []).append(callback)

        is_x9 = any(sn.upper().startswith(prefix) for prefix in X9_SERIES_PREFIXES)
        report_topic = TOPIC_SHADOW_REPORT_X9 if is_x9 else TOPIC_SHADOW_REPORT

        def on_message(client: Any, userdata: Any, message: Any) -> None:
            del client, userdata
            try:
                payload = self._decrypt(message.payload)
                data = json.loads(payload)
                if isinstance(data, dict):
                    data.setdefault("_sn", sn)
                    data.setdefault("_topic", getattr(message, "topic", ""))
                    body = data.get("data")
                    if isinstance(body, dict):
                        msg_sn = body.get("sn")
                        tz = body.get("timeZone")
                        ack = body.get("ack")
                        if isinstance(msg_sn, str) and isinstance(tz, str):
                            self._last_timezone_by_sn[msg_sn] = tz
                        if data.get("type") == "Machine" and isinstance(ack, str):
                            self._record_ack(sn, ack)
                if self.mqtt_debug:
                    _LOGGER.debug("Aiper MQTT message topic=%s payload=%s", getattr(message, "topic", "?"), payload[:800])
                with self._lock:
                    callbacks = list(self._shadow_callbacks.get(sn, []))
                for cb in callbacks:
                    try:
                        try:
                            cb(sn, data)
                        except TypeError:
                            cb(data)
                    except Exception as err:
                        _LOGGER.error("Aiper MQTT callback error: %s", err)
            except Exception as err:
                _LOGGER.error("Failed to process Aiper MQTT message: %s", err)

        topics = {
            report_topic.format(sn=sn),
            TOPIC_READ.format(sn=sn),
            TOPIC_SHADOW_GET.format(sn=sn),
            TOPIC_SHADOW_UPDATE_ACCEPTED.format(sn=sn),
            TOPIC_SHADOW_UPDATE_DELTA.format(sn=sn),
            TOPIC_SHADOW_UPDATE_DOCUMENTS.format(sn=sn),
            TOPIC_SHADOW_REPORT_X9.format(sn=sn),
        }
        try:
            for topic in topics:
                self._mqtt_client.subscribe(topic, 1, on_message)
            return True
        except Exception as err:
            _LOGGER.error("Failed to subscribe to Aiper device %s: %s", sn, err)
            return False

    def _timezone_string_for_sn(self, sn: str) -> str:
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
        with self._ack_lock:
            self._ack_fifo[sn].append(ack)
            self._ack_events[sn].set()

    def _clear_ack_fifo(self, sn: str) -> None:
        with self._ack_lock:
            self._ack_fifo[sn].clear()
            self._ack_events[sn].clear()

    def _wait_for_ack(self, sn: str, timeout: float = 4.0) -> str | None:
        event = self._ack_events[sn]
        if not event.wait(timeout=timeout):
            return None
        with self._ack_lock:
            if not self._ack_fifo[sn]:
                event.clear()
                return None
            ack = self._ack_fifo[sn].popleft()
            if not self._ack_fifo[sn]:
                event.clear()
            return ack

    def send_machine_at(self, sn: str, at_cmd: str, timeout: float = 4.0) -> bool | None:
        payload = {"sn": sn, "timeZone": self._timezone_string_for_sn(sn), "cmd": at_cmd}
        with self._cmd_locks[sn]:
            self._clear_ack_fifo(sn)
            if not self.send_command(sn, "Machine", payload):
                return None
            ack = self._wait_for_ack(sn, timeout=timeout)
            if ack is None:
                return None
            ack_upper = ack.upper()
            if "+OK" in ack_upper:
                return True
            if "+ERROR" in ack_upper:
                return False
            return None

    def send_command(self, sn: str, cmd_type: str, data: dict[str, Any] | None = None) -> bool:
        if not self.is_mqtt_connected():
            _LOGGER.warning("Aiper MQTT not connected; cannot send command")
            return False

        is_x9 = any(sn.upper().startswith(prefix) for prefix in X9_SERIES_PREFIXES)
        data_obj = dict(data or {})
        if not is_x9:
            command_sn = data_obj.get("sn") if isinstance(data_obj.get("sn"), str) else sn
            timezone_value = (
                data_obj.get("timeZone")
                if isinstance(data_obj.get("timeZone"), str)
                else self._timezone_string_for_sn(sn)
            )
            ordered: dict[str, Any] = {"sn": command_sn, "timeZone": timezone_value}
            for key, value in data_obj.items():
                if key not in ("sn", "timeZone"):
                    ordered[key] = value
            data_obj = ordered

        if is_x9:
            payload: dict[str, Any] = {cmd_type: data_obj}
        else:
            payload = {"type": cmd_type, "data": data_obj, "res": 0}

        data_json = json.dumps(data_obj, separators=(",", ":"))
        payload["chksum"] = self._crc16(data_json)
        message = json.dumps(payload, separators=(",", ":"))
        encrypted = self._encrypt(message)
        try:
            topic = TOPIC_WRITE.format(sn=sn)
            self._mqtt_client.publish(topic, message, 1)
            self._mqtt_client.publish(topic, encrypted, 1)
            return True
        except Exception as err:
            _LOGGER.error("Failed to send Aiper command: %s", err)
            return False

    def start_cleaning(self, sn: str, mode: int = 1) -> bool:
        ok = self.send_command(sn, "Machine", {"status": 1, "mode": mode})
        self.request_shadow(sn)
        return ok

    def stop_cleaning(self, sn: str) -> bool:
        ok = self.send_command(sn, "Machine", {"status": 2})
        self.request_shadow(sn)
        return ok

    def pause_cleaning(self, sn: str) -> bool:
        ok = self.send_command(sn, "Machine", {"status": 0})
        self.request_shadow(sn)
        return ok

    def set_mode(self, sn: str, mode: int) -> bool:
        rest_ok = False
        try:
            rest_ok = self._try_rest_set_mode(sn, mode)
        except Exception as err:
            _LOGGER.debug("Aiper REST mode update failed for %s: %s", sn, err)

        result: bool | None = False
        for at_cmd in (f"AT+MODE={int(mode)}", f"AT+WORKMODE={int(mode)}"):
            result = self.send_machine_at(sn, at_cmd)
            if result is True or result is None:
                break
        self.request_shadow(sn)
        return bool(rest_ok or result is True or result is None)

    def _send_mode_commands(self, sn: str, mode: int) -> bool:
        results = [
            self.send_command(sn, "Machine", {"mode": mode}),
            self.send_command(sn, "SetMode", {"mode": mode}),
            self.send_command(sn, "Control", {"cmd": "setMode", "mode": mode}),
            self.send_command(sn, "GetWorkMode", {"mode": mode}),
        ]
        for at_name in ("WORKMODE", "MODE", "WMODE", "PLAN"):
            results.append(self.send_command(sn, "Machine", {"cmd": f"AT+{at_name}={mode}"}))
        return any(results)

    def _crc16(self, data: str) -> int:
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
        if self._mqtt_client and self._mqtt_connected:
            try:
                self._mqtt_client.disconnect()
            except Exception:
                pass
        self._mqtt_connected = False
        self._session.close()
