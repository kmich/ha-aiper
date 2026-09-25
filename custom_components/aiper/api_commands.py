"""Aiper device settings commands: cleaning mode, running state and clean path.

Top layer of the API client stack (see ``api.py``). Chooses between verified
per-model contracts (REST, AT commands) and, for unverified models, bounded
discovery sweeps over the REST/MQTT variants observed across firmwares.
"""

from __future__ import annotations

import logging
import time
from collections.abc import Awaitable, Callable, Sequence
from contextlib import suppress
from typing import Any

from .api_mqtt import AiperMqttClient
from .api_rest import AiperAuthenticationError, AiperSessionConflict
from .const import CleaningMode, clean_path_value
from .profiles import DeviceFamily, model_key
from .redaction import redact_serial

_LOGGER = logging.getLogger(__name__)

# How long a failed full discovery sweep is not repeated for a model.
ROUTE_MISS_COOLDOWN_SECONDS = 6 * 3600

# Discovery candidates for models without a verified contract, in the order
# they are tried. Observed across regional backends and firmware variants.
CLEAN_PATH_QUERY_PATHS = (
    "/equipmentCleanPathSetting/getCleanPathSetting",
    "/equipmentCleanPathSetting/getCleanPathSettingBySn",
    "/equipmentCleanPathSetting/queryCleanPathSetting",
    "/network/clean_path_setting",
    "/network/cleanPathSetting",
    "/swimming/v2/queryCleanPathSetting",
    "/swimming/v2/getCleanPathSetting",
    "/swimming/v2/getCleanPathSettingBySn",
)
CLEAN_PATH_UPDATE_PATHS = (
    "/equipmentCleanPathSetting/updateCleanPathSetting",
    "/equipmentCleanPathSetting/updateCleanPathSettingBySn",
    "/network/clean_path_setting",
    "/network/cleanPathSetting",
    "/swimming/v2/updateCleanPathSetting",
    "/swimming/v2/setCleanPathSetting",
)
CLEAN_PATH_VALUE_KEYS = ("cleanPath", "cleanPathSetting", "clean_path_setting")
CLEAN_PATH_AT_TEMPLATES = (
    "AT+AUTO={value}",
    "AUTO {value}",
    "AT+CPATH={value}",
    "AT+CLEANPATH={value}",
    "AT+SETPATH={value}",
)
MODE_UPDATE_PATHS = (
    "/equipmentCleanMode/updateCleanMode",
    "/equipmentCleanMode/setCleanMode",
    "/equipmentCleanMode/updateCleanModeBySn",
    "/swimming/v2/updateCleanMode",
    "/swimming/v2/setCleanMode",
    "/network/cleanMode",
    "/network/clean_mode",
)
MODE_VALUE_KEYS = ("cleanMode", "mode", "workMode", "cleaningMode")


class AiperCommandClient(AiperMqttClient):
    """Model-aware device settings commands."""

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        """Initialize the learned-route caches."""
        super().__init__(*args, **kwargs)
        # "<operation>:<model>" -> the request/command variant that last worked
        # for that model. JSON-safe so the coordinator can persist it.
        self._learned_routes: dict[str, dict[str, Any]] = {}
        # "<operation>:<model>" -> monotonic time until which a failed full
        # discovery sweep is not repeated.
        self._route_miss_until: dict[str, float] = {}
        # Called after a new route is learned (e.g. to persist it).
        self.on_learned_routes_changed: Callable[[], None] | None = None

    @property
    def learned_routes(self) -> dict[str, dict[str, Any]]:
        """Return a copy of the learned request/command variants."""
        return {key: dict(route) for key, route in self._learned_routes.items()}

    def restore_learned_routes(self, routes: Any) -> None:
        """Restore persisted learned routes, ignoring malformed entries."""
        if not isinstance(routes, dict):
            return
        for key, route in routes.items():
            if isinstance(key, str) and isinstance(route, dict):
                self._learned_routes[key] = dict(route)

    def _route_key(self, operation: str, sn: str) -> str:
        return f"{operation}:{model_key(self._devices.get(sn) or {}) or 'unknown'}"

    def _learn_route(self, key: str, route: dict[str, Any]) -> None:
        self._route_miss_until.pop(key, None)
        if self._learned_routes.get(key) == route:
            return
        self._learned_routes[key] = route
        _LOGGER.debug("Learned Aiper route %s: %s", key, route)
        if self.on_learned_routes_changed is not None:
            self.on_learned_routes_changed()

    async def _equipment_id(self, sn: str) -> Any:
        """Return the cloud equipment ID for a device, refreshing discovery once if missing."""
        dev = self._devices.get(sn) or {}
        equip_id = dev.get("equipmentId") or dev.get("deviceId") or dev.get("id")
        if equip_id is None:
            with suppress(Exception):
                await self.get_devices()
            dev = self._devices.get(sn) or {}
            equip_id = dev.get("equipmentId") or dev.get("deviceId") or dev.get("id")
        return equip_id

    async def _sweep_rest(
        self,
        sn: str,
        operation: str,
        paths: Sequence[str],
        bodies: Sequence[dict[str, Any]],
        accept: Callable[[dict[str, Any]], bool] = lambda _payload: True,
    ) -> dict[str, Any] | None:
        """Try REST path/body variants until one returns an accepted success payload.

        Each (path, body) pair is tried encrypted, then plain if the encrypted
        call did not succeed. The winning variant is remembered per model and
        tried first next time. When a full sweep finds nothing, the sweep is
        not repeated for ROUTE_MISS_COOLDOWN_SECONDS (only a learned variant,
        if any, is retried), so a model without a working contract does not
        replay 100+ paced requests on every command.
        """
        key = self._route_key(operation, sn)
        learned = self._learned_routes.get(key)

        def _matches(path: str, body: dict[str, Any]) -> bool:
            return bool(learned and learned.get("path") == path and learned.get("body_keys") == sorted(body))

        pairs = [(path, body) for path in paths for body in bodies]
        preferred = [pair for pair in pairs if _matches(*pair)]
        in_cooldown = self._route_miss_until.get(key, 0.0) > time.monotonic()
        if in_cooldown:
            if not preferred:
                _LOGGER.debug("Skipping %s discovery sweep; nothing worked recently", key)
                return None
            candidates = preferred
        else:
            candidates = preferred + [pair for pair in pairs if not _matches(*pair)]

        for path, body in candidates:
            encrypted_first = not (learned and _matches(path, body) and learned.get("encrypted") is False)
            for encrypted in (encrypted_first, not encrypted_first):
                call = self._call_encrypted if encrypted else self._call_plain

                async def request(
                    call: Callable[..., Awaitable[dict[str, Any]]] = call,
                    path: str = path,
                    body: dict[str, Any] = body,
                ) -> dict[str, Any]:
                    return await call("POST", path, body)

                try:
                    payload = await self._call_with_zoneid(sn, request)
                except (AiperAuthenticationError, AiperSessionConflict):
                    raise
                except Exception as err:
                    _LOGGER.debug("%s request failed (%s, encrypted=%s): %s", operation, path, encrypted, err)
                    continue
                if not payload or not self._is_success(payload):
                    continue
                if accept(payload):
                    _LOGGER.debug("%s REST OK via %s keys=%s encrypted=%s", operation, path, sorted(body), encrypted)
                    self._learn_route(key, {"path": path, "body_keys": sorted(body), "encrypted": encrypted})
                    return payload
                # A success without a usable value: try the next path/body
                # rather than the other envelope.
                break

        self._route_miss_until[key] = time.monotonic() + ROUTE_MISS_COOLDOWN_SECONDS
        return None

    @staticmethod
    def _id_variant_bodies(sn: str, equip_id: Any, value_keys: Sequence[str], value: int) -> list[dict[str, Any]]:
        """Build request bodies for every value key, with and without each ID key."""
        base_bodies: list[dict[str, Any]] = [{"sn": sn, key: value} for key in value_keys]
        bodies: list[dict[str, Any]] = []
        if equip_id is not None:
            for base in base_bodies:
                for id_key in ("id", "equipmentId", "deviceId"):
                    bodies.append({**base, id_key: equip_id})
        bodies.extend(base_bodies)
        return bodies

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

        return clean_path_value(val)

    async def query_clean_path_setting(self, sn: str) -> int | None:
        """Query the clean-path preference without blocking the event loop."""
        if self._is_scuba_s1_2025(sn):
            # Aiper Android 3.5.0 routes this model through its X5ProMax/X6
            # clean-path screen. That screen queries the cleaner directly with
            # AT+AUTO?; the REST endpoint returns -1 and device shadow does not
            # report this setting.
            if not self.is_mqtt_connected():
                return None
            return await self.query_machine_at_int(sn, "AUTO")

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

        # Unverified models: discover the query contract. Kept until Scuba
        # verification proves the current backend contract.
        equip_id = await self._equipment_id(sn)
        bodies: list[dict[str, Any]] = [{"sn": sn}]
        if equip_id is not None:
            bodies[:0] = [
                {"sn": sn, "id": equip_id},
                {"sn": sn, "equipmentId": equip_id},
                {"sn": sn, "deviceId": equip_id},
            ]

        payload = await self._sweep_rest(
            sn,
            "clean_path_query",
            CLEAN_PATH_QUERY_PATHS,
            bodies,
            accept=lambda payload: self._clean_path_value_from_payload(payload) is not None,
        )
        return self._clean_path_value_from_payload(payload) if payload else None

    async def update_clean_path_setting(self, sn: str, value: int) -> bool:
        """Update clean-path preference and apply it to the device asynchronously."""
        if self._is_scuba_s1_2025(sn):
            # Verified against Aiper Android 3.5.0 and a physical
            # Scuba_S1_2025: 0=S-shaped, 1=Adaptive, acknowledged with +OK.
            if value not in (0, 1) or not self.is_mqtt_connected():
                return False
            return await self.send_machine_at(sn, f"AT+AUTO={value}") is True

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

        # Unverified models: discover the REST/MQTT contract. Kept until Scuba
        # verification proves the current backend contract.
        equip_id = await self._equipment_id(sn)
        bodies = self._id_variant_bodies(sn, equip_id, CLEAN_PATH_VALUE_KEYS, int(value))
        rest_ok = await self._sweep_rest(sn, "clean_path_update", CLEAN_PATH_UPDATE_PATHS, bodies) is not None

        mqtt_published = False
        if self.is_mqtt_connected():
            mqtt_published = await self._send_clean_path_mqtt(sn, int(value))

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

    async def _send_clean_path_mqtt(self, sn: str, value: int) -> bool:
        """Send clean-path variants over MQTT for models without a verified contract.

        Once an AT variant is acknowledged with +OK for a model, only that
        variant is sent next time; otherwise every structured downChan payload
        (which the device never acknowledges) and AT variant is tried.
        """
        key = self._route_key("clean_path_at", sn)
        learned = self._learned_routes.get(key)
        if learned and isinstance(learned.get("command"), str):
            try:
                if await self.send_machine_at(sn, learned["command"].format(value=value)) is True:
                    return True
            except Exception as err:
                _LOGGER.debug("Learned clean path AT failed (%s): %s", learned["command"], err)

        published = False
        for machine_payload in (
            {"cleanPath": value},
            {"cleanPathSetting": value},
            {"clean_path_setting": value},
            {"cmd": "AUTO", "param": [value]},
            {"cmd": "AUTO", "params": [value]},
            {"cmd": f"AUTO {value}"},
        ):
            try:
                if await self.send_command(sn, "Machine", machine_payload):
                    published = True
                    _LOGGER.debug("Clean path downChan published: %s", machine_payload)
            except Exception as err:
                _LOGGER.debug("Clean path downChan publish failed (%s): %s", machine_payload, err)

        for template in CLEAN_PATH_AT_TEMPLATES:
            at_cmd = template.format(value=value)
            try:
                res = await self.send_machine_at(sn, at_cmd)
            except Exception as err:
                _LOGGER.debug("Clean path AT failed (%s): %s", at_cmd, err)
                continue
            published = True
            if res is True:
                _LOGGER.debug("Clean path AT confirmed: %s", at_cmd)
                self._learn_route(key, {"command": template})
                break
            _LOGGER.debug("Clean path AT %s: %s", "rejected" if res is False else "published (no ack)", at_cmd)
        return published

    async def query_cleaning_mode_setting(self, sn: str) -> int | None:
        """Query the configured cleaning mode for models with a verified contract."""
        if not self._is_scuba_s1_2025(sn) or not self.is_mqtt_connected():
            return None
        return await self.query_machine_at_int(sn, "MODE")

    async def set_cleaning_mode(self, sn: str, mode: int | CleaningMode) -> bool:
        """Set a selectable cleaning mode."""
        mode_id = int(mode)
        _LOGGER.debug("Setting cleaning mode for %s: %s", redact_serial(sn), mode_id)

        if self._is_scuba_s1_2025(sn):
            # Verified from Aiper Android 3.5.0's X5ProMax implementation.
            # This model supports Auto/Floor/Wall/Scheduled as 1/2/3/5 and
            # uses only AT+MODE. Do not fall through to speculative variants.
            if mode_id not in (1, 2, 3, 5) or not self.is_mqtt_connected():
                return False
            return await self.send_machine_at(sn, f"AT+MODE={mode_id}") is True

        # Try MQTT AT commands first (preferred — low latency, confirmed by ack).
        # X1 firmware rejects AT+PLAN for normal mode selection. Earlier
        # releases used AT+MODE with AT+WORKMODE fallback, which matches the
        # app-observed command surface across Scuba firmware variants.
        cmd_result: bool | None = False
        if self.is_mqtt_connected():
            for at_cmd in (f"AT+MODE={mode_id}", f"AT+WORKMODE={mode_id}"):
                cmd_result = await self.send_machine_at(sn, at_cmd)
                if cmd_result is True or cmd_result is None:
                    break

        if cmd_result is True or cmd_result is None:
            with suppress(Exception):
                await self.request_shadow(sn)
            return True

        # MQTT unavailable or rejected — fall back to REST endpoints.
        # Probe path/body combinations; the working one varies by firmware.
        equip_id = await self._equipment_id(sn)
        bodies = self._id_variant_bodies(sn, equip_id, MODE_VALUE_KEYS, mode_id)
        rest_ok = await self._sweep_rest(sn, "cleaning_mode_update", MODE_UPDATE_PATHS, bodies) is not None

        with suppress(Exception):
            await self.request_shadow(sn)

        return rest_ok

    async def set_running(self, sn: str, running: bool) -> bool:
        """Start or stop running."""
        mode = 1 if running else 0
        _LOGGER.debug("Setting running mode for %s: %s", redact_serial(sn), mode)

        cmd_result = await self.send_machine_at(sn, f"AT+MODE={mode}")

        with suppress(Exception):
            await self.request_shadow(sn)

        return cmd_result is True
