"""Diagnostics support for the Aiper integration.

The diagnostics output is intended to be safe to attach to GitHub issues.
Credentials, tokens and AWS secrets are removed; the account username and
device serial numbers are partially redacted (``abc...xyz``) so entries can
still be correlated within one report.
"""

from __future__ import annotations

from typing import Any

from homeassistant.components.diagnostics import async_redact_data
from homeassistant.config_entries import ConfigEntry
from homeassistant.const import CONF_PASSWORD, CONF_USERNAME
from homeassistant.core import HomeAssistant

from .redaction import redact, redact_known_values, redact_str

TO_REDACT = {CONF_PASSWORD}


async def async_get_config_entry_diagnostics(hass: HomeAssistant, entry: ConfigEntry) -> dict[str, Any]:
    """Return diagnostics for a config entry."""

    # `runtime_data` is unset if diagnostics are requested before setup has
    # assigned it, e.g. while the entry is stuck retrying setup -- degrade to
    # an empty api/coordinator rather than raising.
    runtime_data = getattr(entry, "runtime_data", None)
    api = getattr(runtime_data, "api", None)
    coordinator = getattr(runtime_data, "coordinator", None)

    entry_data = async_redact_data(dict(entry.data), TO_REDACT)
    username = entry.data.get(CONF_USERNAME)
    if username:
        entry_data[CONF_USERNAME] = redact_str(str(username))
    entry_data.pop(CONF_PASSWORD, None)

    diag: dict[str, Any] = {
        "entry": {
            "title": entry.title,
            "version": f"{entry.version}.{entry.minor_version}",
            "data": entry_data,
            "options": dict(entry.options),
        },
        "api": api.diagnostics() if api is not None else {"base_url": None, "region": None, "mqtt_connected": False},
    }

    if coordinator is not None:
        diag.update(coordinator.diagnostics())

    # Pseudonymize identifiers that key-name redaction does not catch: device
    # serial numbers (keys and values, including MQTT topics) and the account
    # username, which is also embedded in the entry title.
    identifiers: set[str] = set()
    if coordinator is not None and isinstance(coordinator.data, dict):
        identifiers.update(str(sn) for sn in coordinator.data)
    if isinstance(username, str) and username:
        identifiers.add(username)
    return redact_known_values(redact(diag), identifiers)
