"""Pending command tracking and confirmation for Aiper devices."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from homeassistant.util import dt as dt_util

from .const import clean_path_value, status_running
from .state_common import _coerce_int

PENDING_TIMEOUT_SECONDS = 8
# Scuba_S1_2025-only: async_confirm_clean_path_selection retries with
# sleeps summing to 10s, plus up to four more query_clean_path_setting
# calls that can each take up to their own ~4s ack timeout — a slow-ack
# worst case reaches ~26s. This must stay comfortably above that so the
# pending "hint" doesn't expire (and the UI flicker back to a stale
# value) while a legitimate confirmation is still in flight.
CLEAN_PATH_PENDING_TIMEOUT_SECONDS = 30


class CommandTracker:
    """Track in-flight commands and confirm them against device reports.

    Structure of ``state``:
        ``{sn: {"pending": {kind: {...}}, "last": {kind: {...}}}}``
    """

    def __init__(self) -> None:
        """Initialize empty per-device command tracking state."""
        self.state: dict[str, dict[str, dict[str, Any]]] = {}

    def _ensure(self, sn: str) -> dict[str, dict[str, Any]]:
        st = self.state.get(sn)
        if st is None:
            st = {"pending": {}, "last": {}}
            self.state[sn] = st
        st.setdefault("pending", {})
        st.setdefault("last", {})
        return st

    def note_sent(self, sn: str, kind: str, target: Any, *, source: str = "select") -> None:
        """Record that a command was sent and mark it pending until confirmed."""
        now = dt_util.utcnow()
        st = self._ensure(sn)
        st["pending"][kind] = {
            "target": target,
            "since": now.isoformat(),
            "source": source,
        }
        st["last"][kind] = {
            "target": target,
            "time": now.isoformat(),
            "source": source,
            "result": "sent",
            "confirmed": False,
        }

    def note_failed(
        self,
        sn: str,
        kind: str,
        target: Any,
        *,
        reason: str | None = None,
        source: str = "select",
    ) -> None:
        """Record a command failure and clear any matching pending entry."""
        now = dt_util.utcnow()
        st = self._ensure(sn)
        pend = st.get("pending", {})
        if kind in pend and isinstance(pend.get(kind), dict) and pend[kind].get("target") == target:
            pend.pop(kind, None)
        st["last"][kind] = {
            "target": target,
            "time": now.isoformat(),
            "source": source,
            "result": "failed",
            "reason": reason,
            "confirmed": False,
        }

    def get_state(self, sn: str) -> dict[str, Any]:
        """Return a shallow copy of pending/last command state for entities."""
        st = self.state.get(sn) or {"pending": {}, "last": {}}
        return {
            "pending": dict(st.get("pending", {})),
            "last": dict(st.get("last", {})),
        }

    def clear(self, sn: str) -> bool:
        """Clear pending/last command tracking for one device; return True if removed."""
        return self.state.pop(sn, None) is not None

    def get_pending_target(self, sn: str, kind: str) -> Any:
        """Return a pending command target without expiring entries."""
        st = self.state.get(sn) or {}
        pending = st.get("pending") or {}
        info = pending.get(kind) if isinstance(pending, dict) else None
        if info is None and kind == "mode" and isinstance(pending, dict):
            info = pending.get("cleaning_mode")
        elif info is None and kind == "cleaning_mode" and isinstance(pending, dict):
            info = pending.get("mode")
        return info.get("target") if isinstance(info, dict) else None

    def expire(self, sn: str, *, is_s1: bool = False) -> bool:
        """Expire pending commands past their timeout; return True if any expired."""
        st = self.state.get(sn)
        if not st:
            return False
        pend = st.get("pending", {})
        if not isinstance(pend, dict) or not pend:
            return False
        now = dt_util.utcnow()
        expired: list[str] = []
        for kind, info in pend.items():
            if not isinstance(info, dict):
                continue
            since_raw = info.get("since")
            try:
                since = dt_util.parse_datetime(since_raw) if isinstance(since_raw, str) else None
            except Exception:
                since = None
            if since is None:
                continue
            # The extended clean_path timeout exists specifically for
            # Scuba_S1_2025's slow AT+AUTO? confirmation; other clean-path
            # capable models (Scuba S2/S3) confirm quickly and should keep
            # the standard timeout so a genuinely failed command doesn't
            # leave a stale optimistic value on screen for longer than
            # necessary.
            timeout = (
                CLEAN_PATH_PENDING_TIMEOUT_SECONDS if (kind == "clean_path" and is_s1) else PENDING_TIMEOUT_SECONDS
            )
            if (now - since).total_seconds() >= timeout:
                expired.append(kind)
        for kind in expired:
            info = pend.pop(kind, None) or {}
            st.setdefault("last", {})[kind] = {
                "target": info.get("target"),
                "time": now.isoformat(),
                "source": info.get("source"),
                "result": "timeout",
                "confirmed": False,
            }
        return bool(expired)

    def confirm(
        self,
        sn: str,
        machine: dict[str, Any],
        *,
        running_fn: Callable[[int], bool] = status_running,
    ) -> bool:
        """Mark pending commands confirmed when reported state matches targets."""
        st = self.state.get(sn)
        if not st:
            return False
        pend = st.get("pending", {})
        if not isinstance(pend, dict) or not pend:
            return False

        reported_mode = _coerce_int(machine.get("mode"))
        reported_status = _coerce_int(machine.get("status"))
        reported_running = running_fn(reported_status) if reported_status is not None else None
        # Clean path is especially inconsistent across firmwares; normalize.
        reported_clean_path = clean_path_value(machine.get("cleanPath"))

        now = dt_util.utcnow().isoformat()
        changed = False

        for mode_kind in ("mode", "cleaning_mode"):
            if mode_kind not in pend:
                continue
            tgt = _coerce_int((pend.get(mode_kind) or {}).get("target"))
            if tgt is not None and reported_mode is not None and tgt == reported_mode:
                pend.pop(mode_kind, None)
                st.setdefault("last", {})[mode_kind] = {
                    "target": tgt,
                    "time": now,
                    "source": "device_report",
                    "result": "confirmed",
                    "confirmed": True,
                }
                changed = True

        if "running" in pend:
            tgt = (pend.get("running") or {}).get("target")
            if isinstance(tgt, bool) and reported_running is not None and tgt == reported_running:
                pend.pop("running", None)
                st.setdefault("last", {})["running"] = {
                    "target": tgt,
                    "time": now,
                    "source": "device_report",
                    "result": "confirmed",
                    "confirmed": True,
                }
                changed = True

        if "clean_path" in pend:
            tgt = clean_path_value((pend.get("clean_path") or {}).get("target"))
            if tgt is not None and reported_clean_path is not None and tgt == reported_clean_path:
                pend.pop("clean_path", None)
                st.setdefault("last", {})["clean_path"] = {
                    "target": tgt,
                    "time": now,
                    "source": "device_report",
                    "result": "confirmed",
                    "confirmed": True,
                }
                changed = True

        return changed
