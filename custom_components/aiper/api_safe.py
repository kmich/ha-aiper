"""Runtime-safe wrapper around the fixed Aiper API client."""
from __future__ import annotations

import logging
from typing import Any

from .api_fixed import AiperApi as _FixedAiperApi

_LOGGER = logging.getLogger(__name__)


class AiperApi(_FixedAiperApi):
    """Aiper API client with defensive return-shape normalization."""

    @staticmethod
    def _as_dict(value: Any) -> dict[str, Any]:
        return value if isinstance(value, dict) else {}

    @staticmethod
    def _as_list(value: Any) -> list[dict[str, Any]]:
        if not isinstance(value, list):
            return []
        return [item for item in value if isinstance(item, dict)]

    def get_devices(self) -> list[dict[str, Any]]:
        try:
            return self._as_list(super().get_devices())
        except Exception as err:  # noqa: BLE001
            _LOGGER.warning("Aiper device list failed; returning empty list: %s", err)
            return []

    def get_device_info(self, sn: str) -> dict[str, Any]:
        try:
            return self._as_dict(super().get_device_info(sn))
        except Exception as err:  # noqa: BLE001
            _LOGGER.debug("Aiper device info failed for %s: %s", sn, err)
            return {}

    def get_device_status(self, sn: str) -> dict[str, Any]:
        try:
            value = super().get_device_status(sn)
            if isinstance(value, dict):
                return value
            if isinstance(value, (bool, int, float, str)):
                return {"online": value}
            return {}
        except Exception as err:  # noqa: BLE001
            _LOGGER.debug("Aiper status failed for %s: %s", sn, err)
            return {}

    def get_cleaning_history(self, sn: str) -> dict[str, Any]:
        try:
            value = super().get_cleaning_history(sn)
            if isinstance(value, dict):
                return value
            if isinstance(value, list):
                return {"data": value}
            return {}
        except Exception as err:  # noqa: BLE001
            _LOGGER.debug("Aiper cleaning history failed for %s: %s", sn, err)
            return {}

    def get_consumables(self, sn: str) -> dict[str, Any]:
        try:
            value = super().get_consumables(sn)
            if isinstance(value, dict):
                return value
            if isinstance(value, list):
                return {"data": value}
            return {}
        except Exception as err:  # noqa: BLE001
            _LOGGER.debug("Aiper consumables failed for %s: %s", sn, err)
            return {}

    def query_clean_path_setting(self, sn: str) -> int | None:
        try:
            return super().query_clean_path_setting(sn)
        except Exception as err:  # noqa: BLE001
            _LOGGER.debug("Aiper clean path query failed for %s: %s", sn, err)
            return None
