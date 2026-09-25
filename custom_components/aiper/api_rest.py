"""Aiper cloud REST client: login, encrypted requests and Cognito credentials.

Lowest layer of the API client stack (see ``api.py``). Owns the account
session, the AES/RSA request envelope, REST pacing/backoff, device discovery
and the Cognito exchange that yields AWS credentials for MQTT.
"""

from __future__ import annotations

import asyncio
import json
import logging
import random
import time
from collections.abc import Awaitable, Callable
from contextvars import ContextVar
from datetime import tzinfo
from typing import Any
from zoneinfo import ZoneInfo

import aiohttp

from .connection import ConnectionStatus
from .const import ApiEndpoint
from .crypto import AiperEncryption
from .profiles import SCUBA_S1_2025_MODEL, DeviceFamily, device_family, model_key
from .redaction import redact_serial, redact_str

_LOGGER = logging.getLogger(__name__)

SESSION_CONFLICT_CODE = "402"
SESSION_CONFLICT_COOLDOWN_SECONDS = 180
RETRYABLE_HTTP_STATUSES = (429, 500, 502, 503, 504)

# If Cognito still rejects the AWS credentials exchange after a bounded
# OpenID-token refresh-and-retry, back off for this long before trying
# again, rather than repeating the same doomed 2-3 round trips on every
# coordinator poll for a permanently broken account.
AWS_CREDENTIALS_COOLDOWN_SECONDS = 180

# Cognito hands out ~1 hour credentials; cache just under that. Overridable
# per-instance (see `AiperRestClient.aws_credentials_ttl`) so the
# expiry/refresh path can be exercised in minutes instead of an hour when
# validating on a device.
AWS_CREDENTIALS_TTL_SECONDS = 3300

# Used instead of the above when MQTT debug is enabled, so a full
# expire-refresh-resign cycle happens every few minutes and can actually be
# observed in a log rather than waiting out the real ~55 minute lifetime.
AWS_CREDENTIALS_TTL_DEBUG_SECONDS = 300

# Default `zoneId` header when Home Assistant does not supply a time zone.
DEFAULT_ZONE_ID = "UTC"

# Per-request `zoneId` override. A ContextVar (rather than mutating the shared
# header dict) keeps concurrent requests for devices in different time zones
# from overwriting each other's header or leaving it stuck on another device's
# zone after they finish.
_REQUEST_ZONE_ID: ContextVar[str | None] = ContextVar("aiper_request_zone_id", default=None)


def _load_zone_info(zone_id: str) -> tzinfo | None:
    """Load a time zone from tzdata (blocking file I/O; run in an executor)."""
    try:
        return ZoneInfo(zone_id)
    except Exception:
        return None


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


class AiperRestClient:
    """Aiper account session and REST/Cognito requests."""

    def __init__(
        self,
        username: str,
        password: str,
        region: str = ApiEndpoint.eu,
        *,
        async_session: aiohttp.ClientSession,
        time_zone: str | None = None,
    ) -> None:
        """Initialize the REST client."""
        self.username = username
        self.password = password
        self.region = region
        self.base_url = ApiEndpoint[region].value
        self._async_session = async_session
        self._session_conflict_until = 0.0

        self._token: str | None = None
        self._token_expires: Any = None
        self._user_id: str | None = None
        self._identity_id: str | None = None
        self._identity_pool_id: str | None = None
        self._developer_provider_name: str | None = None
        self._openid_token: str | None = None
        self._openid_token_exp: float | None = None
        self._aws_credentials: dict[str, Any] | None = None
        self._aws_credentials_exp: float | None = None
        self._aws_credentials_cooldown_until: float = 0.0
        # Serializes get_aws_credentials(): it can be entered concurrently
        # from the coordinator's poll-driven refresh and the MQTT signing
        # delegate's CRT-triggered background refresh, which otherwise race
        # on self._identity_id/_openid_token/_aws_credentials and duplicate
        # Cognito/Aiper network calls.
        self._aws_credentials_lock = asyncio.Lock()
        self._iot_endpoint: str | None = None
        self._aws_region: str | None = None
        self.aws_credentials_ttl = AWS_CREDENTIALS_TTL_SECONDS
        # Single authoritative record of MQTT/credential connection health,
        # read by diagnostics and the connection-status entities.
        self.connection = ConnectionStatus()
        self._devices: dict[str, dict] = {}
        # Convenience lookup tables derived from device discovery / MQTT telemetry
        self._device_zone_id_by_sn: dict[str, str] = {}
        self._last_timezone_by_sn: dict[str, str] = {}
        # zoneId -> tzinfo, loaded off the event loop (see _async_cache_zone_info).
        self._zone_info_cache: dict[str, tzinfo | None] = {}

        # REST call pacing to avoid triggering cloud throttling
        self._async_rest_lock: asyncio.Lock | None = None
        self._rest_min_interval = 0.8  # seconds between REST calls
        self._rest_next_allowed = 0.0
        # Headers from the Android app's RetrofitFactory interceptor.
        self._headers: dict[str, str] = {
            "Content-Type": "application/json",
            "version": "3.0.0",  # App version
            "os": "android",
            "charset": "UTF-8",
            "Accept-Language": "en",
            "zoneId": time_zone or DEFAULT_ZONE_ID,
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

        headers = self._request_headers(token)
        headers["encryptKey"] = enc.encrypt_key_header

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

        # Never re-login from the login request itself: a 401/403 there means
        # the credentials are bad, and re-entering login() would recurse until
        # RecursionError while hammering the login endpoint.
        if retry_login and path != "/login" and str(payload.get("code")) in ("401", "403"):
            _LOGGER.debug("Token appears expired; attempting refresh")
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

            _LOGGER.debug("Token refresh failed; re-authenticating")
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

    def _request_headers(self, token: str | None) -> dict[str, str]:
        """Return a per-request copy of the session headers."""
        headers = dict(self._headers)
        headers["token"] = token or (self._token or "")
        zone_id = _REQUEST_ZONE_ID.get()
        if zone_id:
            headers["zoneId"] = zone_id
        return headers

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
        """Perform an async REST request with limited retries/backoff.

        Retries only transient failures, classified by type rather than by
        error text: retryable HTTP statuses (429/5xx), connection errors,
        truncated payloads and timeouts. Those become AiperConnectionError
        once retries are exhausted. Any other HTTP error status is raised
        immediately as ``aiohttp.ClientResponseError`` so callers can inspect
        the status (e.g. Cognito 4xx handling).
        """
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
            except (
                AiperConnectionError,
                aiohttp.ClientConnectionError,
                aiohttp.ClientPayloadError,
                TimeoutError,
            ) as err:
                last_exc = err
            if attempt < max_attempts:
                await asyncio.sleep(delay + random.uniform(0, 0.3))
                delay = min(delay * 2.0, 8.0)
        raise AiperConnectionError(f"Aiper request failed: {last_exc}") from last_exc

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
        headers = self._request_headers(token)

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

    async def login(self) -> bool:
        """Authenticate with Aiper API."""
        _LOGGER.debug("Logging in to Aiper API")

        login_data = {"email": self.username, "password": self.password}

        try:
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
            _LOGGER.debug("Successfully logged in to Aiper API (base_url=%s)", self.base_url)

            # retry_login=False: a 401/402 here must not re-enter login().
            await self.get_openid_token(retry_login=False)
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
        """Invoke async `fn` with the zoneId header set for `sn`.

        The override lives in a ContextVar, so it applies only to requests made
        by this task and never touches the shared session headers.
        """
        reset_token = _REQUEST_ZONE_ID.set(self._zone_id_for_sn(sn))
        try:
            return await fn()
        finally:
            _REQUEST_ZONE_ID.reset(reset_token)

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
                    _LOGGER.debug("Token refreshed successfully")
                    return True
            _LOGGER.warning(
                "Token refresh failed (code=%s, message=%s)", payload.get("code"), self._payload_message(payload)
            )
            return False
        except Exception as err:
            _LOGGER.error("Token refresh error: %s", err)
            return False

    async def get_openid_token(self, *, retry_login: bool = True) -> None:
        """Fetch Cognito Identity/OpenID data used for AWS IoT MQTT."""
        try:
            payload = await self._call_encrypted("POST", "/users/getOpenIdToken", {}, retry_login=retry_login)
            if not self._is_success(payload):
                _LOGGER.warning(
                    "OpenID token fetch failed (code=%s, message=%s)",
                    payload.get("code"),
                    self._payload_message(payload),
                )
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
                redact_str(self._iot_endpoint) if self._iot_endpoint else None,
            )

        except Exception as err:
            _LOGGER.warning("Failed to get OpenID token data: %s", err)

    def _resolve_aws_region(self) -> str:
        """Return the AWS region to use for Cognito/IoT calls.

        Prefers the region Aiper's backend reported, falls back to parsing
        it out of the IoT endpoint hostname, and finally to a hardcoded
        default. Shared by get_aws_credentials and connect_mqtt so the two
        can't silently drift out of sync on how region is derived.
        """
        region = self._aws_region
        if not region and self._iot_endpoint and ".iot." in self._iot_endpoint:
            region = self._iot_endpoint.split(".iot.", 1)[1].split(".", 1)[0] or None
        return region or "eu-central-1"

    async def _exchange_openid_token(self) -> tuple[int, str]:
        """Exchange the current OpenID token for temporary AWS credentials."""
        headers = {
            "Content-Type": "application/x-amz-json-1.1",
            "X-Amz-Target": "AWSCognitoIdentityService.GetCredentialsForIdentity",
        }
        url = f"https://cognito-identity.{self._resolve_aws_region()}.amazonaws.com/"
        body = {
            "IdentityId": self._identity_id,
            "Logins": {"cognito-identity.amazonaws.com": self._openid_token},
        }
        return await self._request_with_backoff("POST", url, headers=headers, json_body=body, timeout=30)

    async def get_aws_credentials(self) -> dict[str, Any] | None:
        """Exchange the OpenID token for temporary AWS credentials asynchronously.

        Serialized by _aws_credentials_lock: this can be entered concurrently
        from the coordinator's poll-driven refresh and the MQTT signing
        delegate's CRT-triggered background refresh, and without a lock they
        can interleave awaits and duplicate network calls, or clobber each
        other's writes to self._identity_id/_openid_token.
        """
        async with self._aws_credentials_lock:
            return await self._get_aws_credentials_locked()

    async def _get_aws_credentials_locked(self) -> dict[str, Any] | None:
        """Body of get_aws_credentials(); must only be called holding the lock."""
        if not self._identity_id or not self._openid_token:
            return None

        if self._aws_credentials_cooldown_until and time.time() < self._aws_credentials_cooldown_until:
            # A recent attempt was rejected and refreshing the OpenID token
            # didn't produce new credentials to retry with -- back off
            # instead of repeating the same doomed exchange on every poll.
            return None

        if self._openid_token_exp and (self._openid_token_exp - time.time()) < 120:
            await self.get_openid_token()

        if self._aws_credentials_exp and (self._aws_credentials_exp - time.time()) > 120:
            return self._aws_credentials

        try:
            _status, text = await self._exchange_openid_token()
        except aiohttp.ClientResponseError as err:
            if not 400 <= err.status < 500:
                raise
            # Some Aiper regions omit tokenDuration, so the proactive expiry
            # check above cannot know when the OpenID token has gone stale.
            # A Cognito 4xx is authoritative evidence: refresh once and retry
            # the exchange with the new token/identity values. The retry is
            # deliberately bounded so invalid accounts cannot create a loop.
            self.connection.mark_credentials_stale(f"Cognito {err.status} on credentials exchange")
            _LOGGER.info("Cognito rejected the cached OpenID token; refreshing it once")
            prior_identity, prior_token = self._identity_id, self._openid_token
            await self.get_openid_token()
            refreshed = (
                self._identity_id
                and self._openid_token
                and (self._identity_id, self._openid_token) != (prior_identity, prior_token)
            )
            if not refreshed:
                # get_openid_token() swallows its own failures and leaves the
                # already-rejected identity/token in place on error, so
                # retrying here would just resend the identical payload
                # Cognito already rejected. Back off instead.
                _LOGGER.warning(
                    "OpenID token refresh did not produce new credentials; backing off AWS credential exchange for %ss",
                    AWS_CREDENTIALS_COOLDOWN_SECONDS,
                )
                self._aws_credentials_cooldown_until = time.time() + AWS_CREDENTIALS_COOLDOWN_SECONDS
                return None
            try:
                _status, text = await self._exchange_openid_token()
            except aiohttp.ClientResponseError as err2:
                if not 400 <= err2.status < 500:
                    raise
                _LOGGER.warning(
                    "Cognito rejected the AWS credentials exchange again after refreshing "
                    "the OpenID token; backing off for %ss",
                    AWS_CREDENTIALS_COOLDOWN_SECONDS,
                )
                self._aws_credentials_cooldown_until = time.time() + AWS_CREDENTIALS_COOLDOWN_SECONDS
                return None
        out = json.loads(text)

        creds = out.get("Credentials") or {}
        if not creds.get("AccessKeyId"):
            _LOGGER.warning(
                "Unexpected Cognito credentials response (keys=%s)",
                sorted(out) if isinstance(out, dict) else type(out).__name__,
            )
            return None

        self._aws_credentials = creds
        self._aws_credentials_exp = time.time() + self.aws_credentials_ttl
        self._aws_credentials_cooldown_until = 0.0
        return creds

    async def get_devices(self) -> list[dict]:
        """Get the account's device list.

        Raises AiperApiError subclasses on failure rather than returning an
        empty list, so callers can tell "no devices" from "request failed".
        """
        try:
            payload = await self._call_encrypted("POST", "/equipment/getEquipment", {})
            _LOGGER.debug("Get devices response code=%s", payload.get("code"))

            if not self._is_success(payload):
                raise AiperResponseError(
                    f"Get devices failed (code={payload.get('code')}, message={self._payload_message(payload)})"
                )

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
                    _LOGGER.debug("Found device: %s (%s)", device.get("name", "Unknown"), redact_serial(sn))

            await self._async_cache_zone_info(set(self._device_zone_id_by_sn.values()))
            return devices

        except aiohttp.ClientError as err:
            raise AiperConnectionError(f"Failed to get devices: {err}") from err

    async def get_device_info(self, sn: str) -> dict | None:
        """Get detailed info for a specific device without blocking the event loop."""
        try:
            payload = await self._call_encrypted("POST", "/equipment/getEquipmentInfo", {"sn": sn})
            _LOGGER.debug("Device info response code=%s keys=%s", payload.get("code"), sorted(payload))

            if not self._is_success(payload):
                return None

            data = payload.get("data")
            if isinstance(data, dict):
                out = dict(data)
                out["payload"] = payload
                return out
            return {"data": data, "payload": payload}

        except aiohttp.ClientError as err:
            _LOGGER.error("Failed to get device info for %s: %s", redact_serial(sn), err)
            return None

    async def get_device_status(self, sn: str) -> dict | None:
        """Get online status for a device without blocking the event loop."""
        try:
            payload = await self._call_encrypted("POST", "/equipment/checkEquipmentOnlineStatus", {"sn": sn})
            _LOGGER.debug("Device status response code=%s", payload.get("code"))

            if self._is_success(payload):
                return payload.get("data")
            return None

        except aiohttp.ClientError as err:
            _LOGGER.error("Failed to get status for %s: %s", redact_serial(sn), err)
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

    async def get_cleaning_history(self, sn: str) -> Any:
        """Get cleaning history/totals for a device.

        Return the full decrypted payload because regional backends place
        totals at different levels of the response body.
        """

        bodies = (
            {"sn": sn},
            {"sn": sn, "pageNo": 1, "pageSize": 20},
            {"sn": sn, "pageNum": 1, "pageSize": 20},
            {"sn": sn, "page": 1, "size": 20},
        )

        for body in bodies:
            try:

                async def request_history(body: dict[str, Any] = body) -> dict[str, Any]:
                    return await self._call_encrypted("POST", "/swimming/v2/getCleanTimeBySn", body)

                payload = await self._call_with_zoneid(
                    sn,
                    request_history,
                )
            except Exception as err:
                _LOGGER.debug(
                    "Cleaning history request failed for %s with keys %s: %s", redact_serial(sn), sorted(body), err
                )
                continue

            if isinstance(payload, dict) and self._is_success(payload):
                return payload

        return {}

    # --- Clean path preference (REST) ---

    async def _async_cache_zone_info(self, zone_ids: set[str]) -> None:
        """Load tzdata for newly seen zone IDs in an executor.

        ``ZoneInfo()`` reads tzdata from disk on first use, which must not
        happen on the event loop; the sync lookup above only reads this cache.
        """
        missing = {zone_id for zone_id in zone_ids if zone_id not in self._zone_info_cache}
        if not missing:
            return
        loop = asyncio.get_running_loop()
        for zone_id in missing:
            self._zone_info_cache[zone_id] = await loop.run_in_executor(None, _load_zone_info, zone_id)

    def _is_scuba_s1_2025(self, sn: str) -> bool:
        """Return whether the serial belongs to the verified Scuba S1 profile."""
        dev = self._devices.get(sn) or {}
        return model_key(dev) == SCUBA_S1_2025_MODEL
