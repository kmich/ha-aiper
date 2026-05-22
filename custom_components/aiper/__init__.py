"""Aiper Pool Cleaner Integration for Home Assistant."""

from __future__ import annotations

import logging
from contextlib import suppress
from typing import Any

from homeassistant.config_entries import ConfigEntry
from homeassistant.const import Platform
from homeassistant.core import HomeAssistant
from homeassistant.exceptions import ConfigEntryNotReady
from homeassistant.helpers import config_validation as cv
from homeassistant.helpers import device_registry as dr
from homeassistant.helpers import entity_registry as er
from homeassistant.helpers.aiohttp_client import async_get_clientsession

from .api import AiperApi
from .const import (
    CONF_METADATA_REFRESH_HOURS,
    CONF_MQTT_DEBUG,
    DEFAULT_METADATA_REFRESH_HOURS,
    DOMAIN,
)
from .controller import AiperDeviceController
from .coordinator import AiperDataUpdateCoordinator

_LOGGER = logging.getLogger(__name__)

CONFIG_SCHEMA = cv.config_entry_only_config_schema(DOMAIN)

PLATFORMS: list[Platform] = [
    Platform.SENSOR,
    Platform.BINARY_SENSOR,
    Platform.SELECT,
    Platform.SWITCH,
]


async def async_setup(hass: HomeAssistant, config: dict[str, Any]) -> bool:
    """Set up the Aiper integration."""
    hass.data.setdefault(DOMAIN, {})
    return True


async def _options_update_listener(hass: HomeAssistant, entry: ConfigEntry) -> None:
    """Handle options updates by reloading the config entry."""
    await hass.config_entries.async_reload(entry.entry_id)


async def async_remove_config_entry_device(
    hass: HomeAssistant,
    config_entry: ConfigEntry,
    device_entry: dr.DeviceEntry,
) -> bool:
    """Allow HA to remove stale Aiper device-registry entries."""
    device_serials = {
        identifier
        for domain, identifier in device_entry.identifiers
        if domain == DOMAIN and isinstance(identifier, str)
    }

    runtime_data = hass.data.get(DOMAIN, {}).get(config_entry.entry_id) or {}
    coordinator = runtime_data.get("coordinator")
    current_serials: set[str] = set()
    coordinator_data = getattr(coordinator, "data", None)
    if isinstance(coordinator_data, dict):
        current_serials = {str(sn) for sn in coordinator_data}

    if device_serials and device_serials & current_serials:
        _LOGGER.info(
            "Refusing to remove active Aiper device %s; serial is still present in coordinator data",
            device_entry.name or device_entry.id,
        )
        return False

    ent_reg = er.async_get(hass)
    entities = er.async_entries_for_device(
        ent_reg,
        device_entry.id,
        include_disabled_entities=True,
    )
    _LOGGER.info(
        "Allowing removal of stale Aiper device %s with %d registered entities",
        device_entry.name or device_entry.id,
        len(entities),
    )
    return True


async def _cleanup_legacy_entities(
    hass: HomeAssistant,
    entry: ConfigEntry,
    serial_numbers: list[str],
) -> None:
    """Remove legacy entities that are no longer provided.

    Earlier test builds exposed entities that are now intentionally removed:
    - Legacy switch/vacuum controls from before model-specific cleaning support
    - A duplicate "cleaning mode" sensor (superseded by the select)

    Home Assistant keeps orphaned entities in the entity registry, so we
    explicitly remove them when detected.
    """
    ent_reg = er.async_get(hass)
    entries = er.async_entries_for_config_entry(ent_reg, entry.entry_id)

    # Remove switch/vacuum entities from earlier builds while preserving the
    # verified model-specific running switch.
    for ent in entries:
        uid = ent.unique_id or ""
        if ent.domain == "vacuum" or (ent.domain == "switch" and not uid.endswith("_running")):
            _LOGGER.info("Removing legacy Aiper %s entity: %s", ent.domain, ent.entity_id)
            ent_reg.async_remove(ent.entity_id)

    # Remove legacy "Warning Active" binary sensor from earlier builds.
    # Some test versions used unique_id "<sn>_warning" for a binary_sensor.
    # We now expose only a single sensor "Warning" using that unique_id.
    legacy_warning_binary_uids = {f"{sn}_warning" for sn in serial_numbers}
    for ent in list(entries):
        if ent.domain != "binary_sensor":
            continue
        uid = ent.unique_id or ""
        if uid in legacy_warning_binary_uids or ent.entity_id.endswith("_warning_active"):
            _LOGGER.info("Removing legacy Aiper warning binary sensor entity: %s", ent.entity_id)
            ent_reg.async_remove(ent.entity_id)

    # Remove legacy sensors by unique_id / entity_id patterns.
    legacy_unique_ids: set[str] = set()
    for sn in serial_numbers:
        legacy_unique_ids.update(
            {
                f"{sn}_mode",
                f"{sn}_cleaning_mode",
                f"{sn}_start_stop",
                f"{sn}_power",
            }
        )

    for ent in list(entries):
        if ent.domain != "sensor":
            continue
        uid = ent.unique_id or ""
        if uid in legacy_unique_ids or ent.entity_id.endswith("_cleaning_mode"):
            _LOGGER.info("Removing legacy Aiper sensor entity: %s", ent.entity_id)
            ent_reg.async_remove(ent.entity_id)


async def _migrate_select_unique_ids(
    hass: HomeAssistant,
    entry: ConfigEntry,
    serial_numbers: list[str],
) -> None:
    """Normalize select unique_ids and remove duplicates deterministically.

    Goal: preserve the legacy entity_id (dashboard compatibility) while ensuring
    the active entities are actually provided by the integration.

    Canonical unique_ids:
      - <sn>_clean_path
      - <sn>_mode_selection

    If multiple select entities exist for the same device/kind, we keep the
    preferred legacy entity_id when present:
      - mode: prefer *_mode_selection over *_cleaning_mode
      - path: prefer *_clean_path
    """

    ent_reg = er.async_get(hass)
    entries = er.async_entries_for_config_entry(ent_reg, entry.entry_id)

    # Map device_id -> serial number (sn) from the device registry for robustness.
    sn_by_device_id: dict[str, str] = {}
    try:
        from homeassistant.helpers import device_registry as dr

        dev_reg = dr.async_get(hass)
        for e in entries:
            if not e.device_id or e.device_id in sn_by_device_id:
                continue
            dev = dev_reg.async_get(e.device_id)
            if not dev:
                continue
            for dom, ident in dev.identifiers:
                if dom == DOMAIN:
                    sn_by_device_id[e.device_id] = ident
                    break
    except Exception:
        sn_by_device_id = {}

    targets = {sn: {"mode": f"{sn}_mode_selection", "path": f"{sn}_clean_path"} for sn in serial_numbers}

    def _sn_for_entry(e: er.RegistryEntry) -> str | None:
        if e.device_id and e.device_id in sn_by_device_id:
            return sn_by_device_id[e.device_id]
        uid = e.unique_id or ""
        for sn in serial_numbers:
            if uid.startswith(f"{sn}_"):
                return sn
        return None

    def _kind_for_entry(e: er.RegistryEntry) -> str | None:
        uid = (e.unique_id or "").lower()
        eid = (e.entity_id or "").lower()
        if "clean_path" in uid or "clean_path" in eid:
            return "path"
        if (
            "mode_selection" in uid
            or "cleaning_mode" in uid
            or "mode_select" in uid
            or "_mode_selection" in eid
            or "_cleaning_mode" in eid
            or "_mode_select" in eid
        ):
            return "mode"
        return None

    def _preference(e: er.RegistryEntry, kind: str) -> tuple[int, str]:
        eid = (e.entity_id or "").lower()

        # Prefer stable (non-suffixed) entity_ids when duplicates exist (e.g., *_2, *_3).
        # This preserves dashboards that reference the unsuffixed entity_id.
        suffixed = False
        try:
            import re as _re

            suffixed = bool(_re.search(r"_\d+$", eid))
        except Exception:
            suffixed = False

        score = 9
        if kind == "mode":
            if eid.endswith("_mode_selection"):
                score = 0
            elif eid.endswith("_cleaning_mode"):
                score = 1
        elif kind == "path" and eid.endswith("clean_path"):
            score = 0

        if suffixed:
            score += 5

        return (score, eid)

    # Index by unique_id for duplicate detection.
    by_uid: dict[str, er.RegistryEntry] = {(e.unique_id or ""): e for e in entries if e.unique_id}

    # Group select entries per (sn, kind)
    groups: dict[tuple[str, str], list[er.RegistryEntry]] = {}
    for e in entries:
        if e.domain != "select":
            continue
        sn = _sn_for_entry(e)
        if not sn or sn not in targets:
            continue
        kind = _kind_for_entry(e)
        if kind is None:
            continue
        groups.setdefault((sn, kind), []).append(e)

    for (sn, group_kind), ents in groups.items():
        if not ents:
            continue
        ents_sorted = sorted(ents, key=lambda x: _preference(x, group_kind))
        primary = ents_sorted[0]
        target_uid = targets[sn][group_kind]

        # Remove any entity already using the target unique_id that isn't our primary.
        dup = by_uid.get(target_uid)
        if dup and dup.entity_id != primary.entity_id:
            # Prefer keeping primary if it has the legacy entity_id.
            ent_reg.async_remove(dup.entity_id)
            by_uid.pop(target_uid, None)

        # Migrate primary unique_id if needed.
        if (primary.unique_id or "") != target_uid:
            ent_reg.async_update_entity(primary.entity_id, new_unique_id=target_uid)
            by_uid.pop(primary.unique_id or "", None)
            by_uid[target_uid] = primary

        # Remove all other duplicates for this sn/kind.
        for extra in ents_sorted[1:]:
            if extra.entity_id == primary.entity_id:
                continue
            ent_reg.async_remove(extra.entity_id)


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Set up Aiper from a config entry."""
    hass.data.setdefault(DOMAIN, {})

    api = AiperApi(
        username=entry.data["username"],
        password=entry.data["password"],
        region=entry.data.get("region", "eu"),
        async_session=async_get_clientsession(hass),
    )

    try:
        _LOGGER.debug("Attempting login to Aiper API...")
        await api.login()
        _LOGGER.info("Login successful")
    except Exception as err:
        _LOGGER.error("Failed to login to Aiper: %s", err)
        raise ConfigEntryNotReady from err

    coordinator = AiperDataUpdateCoordinator(
        hass,
        api,
        metadata_refresh_hours=entry.options.get(CONF_METADATA_REFRESH_HOURS, DEFAULT_METADATA_REFRESH_HOURS),
        config_entry=entry,
    )

    _LOGGER.debug("Performing first data refresh...")
    await coordinator.async_config_entry_first_refresh()
    _LOGGER.info("First refresh complete, data: %s", list(coordinator.data.keys()) if coordinator.data else "None")

    # Keep slow metadata refresh scheduled even if HA delays entity listener
    # registration.
    def _keepalive_listener() -> None:
        return

    unsub_keepalive = coordinator.async_add_listener(_keepalive_listener)

    # Remove legacy/orphaned entities from earlier test builds.
    serials = list(coordinator.data.keys()) if coordinator.data else []
    await _migrate_select_unique_ids(hass, entry, serials)
    await _cleanup_legacy_entities(hass, entry, serials)

    hass.data[DOMAIN][entry.entry_id] = {
        "api": api,
        "controller": AiperDeviceController(api, coordinator),
        "coordinator": coordinator,
        "_unsub_keepalive": unsub_keepalive,
    }

    entry.async_on_unload(entry.add_update_listener(_options_update_listener))

    await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)

    mqtt_debug = bool(entry.options.get(CONF_MQTT_DEBUG, False))
    api.mqtt_debug = mqtt_debug

    _LOGGER.info("Attempting AWS IoT MQTT connection")
    if mqtt_debug:
        _LOGGER.warning("MQTT debug logging is enabled; raw topics/payloads will be logged at DEBUG")

    try:
        connected = await api.connect_mqtt()
        if not connected:
            raise ConfigEntryNotReady("MQTT connection could not be established")
        if coordinator.data:
            for sn in coordinator.data:
                # AWS IoT callbacks arrive on a background thread.
                # Ensure coordinator updates happen on the HA event loop.
                cb = coordinator.make_shadow_callback(sn)
                await api.subscribe_device(sn, cb)
                # Ask for a current shadow snapshot; many stacks publish only on change.
                await api.request_shadow(sn)
        _LOGGER.info("MQTT connected and subscriptions registered")
    except ConfigEntryNotReady:
        raise
    except Exception as err:
        _LOGGER.warning("MQTT setup failed: %s", err)
        raise ConfigEntryNotReady from err

    _LOGGER.info("Aiper integration setup complete")

    return True


async def async_unload_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Unload a config entry."""
    if unload_ok := await hass.config_entries.async_unload_platforms(entry, PLATFORMS):
        data = hass.data[DOMAIN].pop(entry.entry_id)
        unsub = data.get("_unsub_keepalive")
        if callable(unsub):
            with suppress(Exception):
                unsub()
        api: AiperApi = data["api"]
        await api.disconnect()

    return unload_ok
