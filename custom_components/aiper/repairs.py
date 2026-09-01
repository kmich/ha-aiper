"""Repair issues surfaced in Home Assistant's Repairs dashboard.

Currently one issue type: a device whose model family the integration cannot
identify. It runs on a minimal generic profile, and the fix is community
help -- the issue links the model-onboarding guide.
"""

from __future__ import annotations

from typing import Any

from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers import issue_registry as ir

from .const import DOMAIN
from .profiles import DeviceFamily, device_family, device_model_string

UNKNOWN_MODEL_ISSUE_PREFIX = "unknown_model_"
DISCOVERY_DOC_URL = "https://github.com/kmich/ha-aiper/blob/main/docs/discovery.md"


def unknown_model_issue_id(sn: str) -> str:
    """Stable per-device issue id."""
    return f"{UNKNOWN_MODEL_ISSUE_PREFIX}{sn}"


@callback
def async_update_unknown_model_issues(hass: HomeAssistant, devices: dict[str, dict[str, Any]]) -> None:
    """Raise an issue for every unidentifiable device and clear it for the rest.

    Safe to call on every coordinator poll: ``async_create_issue`` de-dupes and
    ``async_delete_issue`` is a no-op when the issue is absent.
    """
    for sn, raw in devices.items():
        issue_id = unknown_model_issue_id(sn)
        if device_family(raw) is DeviceFamily.UNKNOWN:
            ir.async_create_issue(
                hass,
                DOMAIN,
                issue_id,
                is_fixable=False,
                severity=ir.IssueSeverity.WARNING,
                translation_key="unknown_model",
                translation_placeholders={
                    "model": device_model_string(raw) or "unknown",
                    "serial": sn,
                },
                learn_more_url=DISCOVERY_DOC_URL,
            )
        else:
            ir.async_delete_issue(hass, DOMAIN, issue_id)
