"""Aiper Pool Cleaner Integration for Home Assistant."""
from __future__ import annotations

import logging

from homeassistant.config_entries import ConfigEntry
from homeassistant.const import Platform
from homeassistant.core import HomeAssistant
from homeassistant.exceptions import ConfigEntryNotReady
from homeassistant.helpers import entity_registry as er
from homeassistant.helpers.entity_registry import RegistryEntryDisabler

from .const import DOMAIN, CONF_ENABLE_MQTT, CONF_MQTT_DEBUG, CONF_POLL_INTERVAL, DEFAULT_SCAN_INTERVAL, CONF_HISTORY_REFRESH_HOURS, CONF_CONSUMABLES_REFRESH_HOURS, CONF_CLEAN_PATH_REFRESH_HOURS, DEFAULT_HISTORY_REFRESH_HOURS, DEFAULT_CONSUMABLES_REFRESH_HOURS, DEFAULT_CLEAN_PATH_REFRESH_HOURS
from .coordinator import AiperDataUpdateCoordinator
from .api import AiperApi

_LOGGER = logging.getLogger(__name__)

PLATFORMS: list[Platform] = [
    Platform.SENSOR,
    Platform.BINARY_SENSOR,
    Platform.SELECT,
]

SERVICE_SEND_AT = "send_at_command"



def _mqtt_enabled(entry: ConfigEntry) -> bool:
    """Return whether MQTT is enabled.

    Backwards-compatible default: if the option has never been set, we assume
    MQTT is enabled. This preserves behavior from earlier versions where MQTT
    was always used for control/state.
    """
    if CONF_ENABLE_MQTT in entry.options:
        return bool(entry.options.get(CONF_ENABLE_MQTT))
    return True


async def _options_update_listener(hass: HomeAssistant, entry: ConfigEntry) -> None:
    """Handle options updates by reloading the config entry.

    Polling interval changes require a coordinator restart. Reloading the
    entry is the most reliable approach, and also re-applies MQTT enable/
    debug options consistently.
    """
    await hass.config_entries.async_reload(entry.entry_id)


def _is_mqtt_only_unique_id(unique_id: str) -> bool:
    """Return True if a unique_id corresponds to an MQTT-only entity."""
    mqtt_only_suffixes = (
        "_in_water",
        "_warning",
        "_solar_charging",
        "_bluetooth",
        "_linked",
        "_temperature",
    )
    return unique_id.endswith(mqtt_only_suffixes)


async def _disable_mqtt_only_entities(hass: HomeAssistant, entry: ConfigEntry) -> None:
    """Disable MQTT-only entities to avoid clutter when MQTT is not enabled."""
    if _mqtt_enabled(entry):
        return
    ent_reg = er.async_get(hass)
    entries = er.async_entries_for_config_entry(ent_reg, entry.entry_id)

    for ent in entries:
        mqtt_only = _is_mqtt_only_unique_id(ent.unique_id or "")

        if mqtt_only and ent.disabled_by is None:
            ent_reg.async_update_entity(
                ent.entity_id,
                disabled_by=RegistryEntryDisabler.INTEGRATION,
            )


async def _cleanup_legacy_entities(
    hass: HomeAssistant,
    entry: ConfigEntry,
    serial_numbers: list[str],
) -> None:
    """Remove legacy entities that are no longer provided.

    Earlier test builds exposed entities that are now intentionally removed:
    - An on/off switch (no functional value for Scuba X1)
    - A duplicate "cleaning mode" sensor (superseded by the select)

    Home Assistant keeps orphaned entities in the entity registry, so we
    explicitly remove them when detected.
    """
    ent_reg = er.async_get(hass)
    entries = er.async_entries_for_config_entry(ent_reg, entry.entry_id)

    # Remove any switch/vacuum entities from earlier builds.
    for ent in entries:
        if ent.domain in ("switch", "vacuum"):
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
        if "clean_path" in uid or "_clean_path" in eid:
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
        elif kind == "path":
            if eid.endswith("_clean_path"):
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
        if not kind:
            continue
        groups.setdefault((sn, kind), []).append(e)

    for (sn, kind), ents in groups.items():
        if not ents:
            continue
        ents_sorted = sorted(ents, key=lambda x: _preference(x, kind))
        primary = ents_sorted[0]
        target_uid = targets[sn][kind]

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



async def _enable_previously_disabled_entities(
    hass: HomeAssistant,
    entry: ConfigEntry,
    serial_numbers: list[str],
) -> None:
    """Enable entities that were shipped as disabled-by-default in earlier builds.

    Home Assistant keeps the disabled/enabled choice in the entity registry.
    If a previous test build created entities with `entity_registry_enabled_default=False`,
    they will remain disabled even if we later flip the default.

    We only re-enable entities that were disabled by the integration itself,
    not ones the user explicitly disabled.
    """
    ent_reg = er.async_get(hass)
    entries = er.async_entries_for_config_entry(ent_reg, entry.entry_id)

    # Keys we now want enabled by default.
    keys_to_enable = {
        "last_cleaning_mode",
        "last_cleaning_start",
        "last_cleaning_duration",
        "ip_address",
        "ap_hotspot",
        "bluetooth_name",
        "roller_brush_remaining",
        "roller_brush_percent",
        "micromesh_remaining",
        "micromesh_percent",
        "tread_remaining",
        "tread_percent",
    }

    want_uids = {f"{sn}_{k}" for sn in serial_numbers for k in keys_to_enable}

    for ent in entries:
        uid = ent.unique_id or ""
        if uid in want_uids and ent.disabled_by == RegistryEntryDisabler.INTEGRATION:
            _LOGGER.info("Enabling Aiper entity (was disabled-by-default in earlier build): %s", ent.entity_id)
            ent_reg.async_update_entity(ent.entity_id, disabled_by=None)


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Set up Aiper from a config entry."""
    hass.data.setdefault(DOMAIN, {})

    api = AiperApi(
        username=entry.data["username"],
        password=entry.data["password"],
        region=entry.data.get("region", "eu"),
    )

    try:
        _LOGGER.debug("Attempting login to Aiper API...")
        await hass.async_add_executor_job(api.login)
        _LOGGER.info("Login successful")
    except Exception as err:
        _LOGGER.error("Failed to login to Aiper: %s", err)
        raise ConfigEntryNotReady from err

    scan_interval = int(entry.options.get(CONF_POLL_INTERVAL, DEFAULT_SCAN_INTERVAL))
    coordinator = AiperDataUpdateCoordinator(
        hass,
        api,
        scan_interval=scan_interval,
        history_refresh_hours=entry.options.get(CONF_HISTORY_REFRESH_HOURS, DEFAULT_HISTORY_REFRESH_HOURS),
        consumables_refresh_hours=entry.options.get(CONF_CONSUMABLES_REFRESH_HOURS, DEFAULT_CONSUMABLES_REFRESH_HOURS),
        clean_path_refresh_hours=entry.options.get(CONF_CLEAN_PATH_REFRESH_HOURS, DEFAULT_CLEAN_PATH_REFRESH_HOURS),
    )
    
    _LOGGER.debug("Performing first data refresh...")
    await coordinator.async_config_entry_first_refresh()
    _LOGGER.info("First refresh complete, data: %s", list(coordinator.data.keys()) if coordinator.data else "None")

    # Ensure periodic polling continues even if no entities are currently
    # attached as listeners (or if HA delays entity listener registration).
    # Without at least one listener, DataUpdateCoordinator will not schedule
    # timed refreshes.
    def _keepalive_listener() -> None:
        return

    unsub_keepalive = coordinator.async_add_listener(_keepalive_listener)

    # Remove legacy/orphaned entities from earlier test builds.
    serials = list(coordinator.data.keys()) if coordinator.data else []
    await _migrate_select_unique_ids(hass, entry, serials)
    await _cleanup_legacy_entities(hass, entry, serials)
    await _enable_previously_disabled_entities(hass, entry, serials)

    hass.data[DOMAIN][entry.entry_id] = {
        "api": api,
        "coordinator": coordinator,
        "_unsub_keepalive": unsub_keepalive,
    }

    # Reload the entry on options updates so polling interval/MQTT toggles
    # take effect immediately and safely.
    entry.async_on_unload(entry.add_update_listener(_options_update_listener))

    await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)

    await _disable_mqtt_only_entities(hass, entry)

    # Optional: enable AWS IoT MQTT for near real-time updates.
    enable_mqtt = _mqtt_enabled(entry)
    mqtt_debug = bool(entry.options.get(CONF_MQTT_DEBUG, False))

    api.mqtt_debug = mqtt_debug

    if enable_mqtt:
        _LOGGER.info("MQTT is enabled in options; attempting AWS IoT connection")
        if mqtt_debug:
            _LOGGER.warning("MQTT debug logging is enabled; raw topics/payloads will be logged at DEBUG")

        try:
            connected = await hass.async_add_executor_job(api.connect_mqtt)
            if connected and coordinator.data:
                for sn in coordinator.data.keys():
                    # AWS IoT callbacks arrive on a background thread.
                    # Ensure coordinator updates happen on the HA event loop.
                    cb = coordinator.make_shadow_callback(sn)
                    await hass.async_add_executor_job(api.subscribe_device, sn, cb)
                    # Ask for a current shadow snapshot; many stacks publish only on change.
                    await hass.async_add_executor_job(api.request_shadow, sn)
                _LOGGER.info("MQTT connected and subscriptions registered")
            else:
                _LOGGER.warning("MQTT connection could not be established; continuing in REST polling mode")
        except Exception as err:
            _LOGGER.warning("MQTT setup failed; continuing in REST polling mode: %s", err)

    _LOGGER.info("Aiper integration setup complete")

    # Debug/engineering service: send a raw AT command over MQTT.
    async def _svc_send_at(call):
        api: AiperApi = hass.data[DOMAIN][entry.entry_id]["api"]
        coordinator: AiperDataUpdateCoordinator = hass.data[DOMAIN][entry.entry_id]["coordinator"]

        sn = call.data.get("sn")
        if not sn and coordinator.data:
            sn = next(iter(coordinator.data.keys()))
        if not sn:
            _LOGGER.warning("send_at_command called but no device SN is available")
            return

        cmd = str(call.data.get("command", "")).strip()
        if not cmd:
            _LOGGER.warning("send_at_command called with empty command")
            return

        if not cmd.upper().startswith("AT+"):
            cmd = "AT+" + cmd

        await hass.async_add_executor_job(api.send_machine_at, sn, cmd)
        await hass.async_add_executor_job(api.request_shadow, sn)

    # Register once per config entry.
    hass.services.async_register(DOMAIN, SERVICE_SEND_AT, _svc_send_at)

    return True


async def async_unload_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Unload a config entry."""
    if unload_ok := await hass.config_entries.async_unload_platforms(entry, PLATFORMS):
        if hass.services.has_service(DOMAIN, SERVICE_SEND_AT):
            hass.services.async_remove(DOMAIN, SERVICE_SEND_AT)
        data = hass.data[DOMAIN].pop(entry.entry_id)
        unsub = data.get("_unsub_keepalive")
        if callable(unsub):
            try:
                unsub()
            except Exception:
                pass
        api: AiperApi = data["api"]
        await hass.async_add_executor_job(api.disconnect)

    return unload_ok
