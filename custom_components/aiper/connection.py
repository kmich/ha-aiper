"""Explicit MQTT / cloud-credential connection status tracking.

A single object the API client reports connection transitions into, so
diagnostics and entities read one authoritative source instead of scraping
scattered private attributes. (That scraping is exactly what broke in v1.3.1,
where diagnostics read a storage location the runtime had stopped writing.)

This tracker only *records*. The reconnect / watchdog / back-off policy still
lives in ``api.py`` and ``coordinator.py`` -- this module deliberately holds no
timers and makes no network calls, so it stays trivially testable.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any


def _now() -> datetime:
    return datetime.now(UTC)


class ConnectionState(StrEnum):
    """Coarse lifecycle state of the AWS IoT MQTT connection."""

    INITIALIZING = "initializing"
    CONNECTING = "connecting"
    CONNECTED = "connected"
    DISCONNECTED = "disconnected"
    RECONNECTING = "reconnecting"
    CREDENTIALS_STALE = "credentials_stale"
    FATAL = "fatal"


# States that represent "not currently carrying traffic".
DOWN_STATES = frozenset(
    {
        ConnectionState.DISCONNECTED,
        ConnectionState.RECONNECTING,
        ConnectionState.CREDENTIALS_STALE,
        ConnectionState.FATAL,
    }
)


@dataclass
class ConnectionStatus:
    """Mutable, in-memory record of MQTT connection health.

    Instances are owned by a single :class:`AiperApi` and mutated from both the
    event loop and AWS CRT callback threads; every mutation is a single
    attribute write or counter bump, which CPython executes atomically, so no
    lock is taken here.
    """

    state: ConnectionState = ConnectionState.INITIALIZING
    last_state_change: datetime = field(default_factory=_now)
    last_connected_at: datetime | None = None
    last_disconnected_at: datetime | None = None
    last_error: str | None = None
    connect_attempts: int = 0
    reconnect_count: int = 0
    credential_refresh_count: int = 0
    credential_reject_count: int = 0

    # -- transitions -------------------------------------------------------

    def _transition(self, new_state: ConnectionState) -> None:
        if new_state != self.state:
            self.state = new_state
            self.last_state_change = _now()

    def mark_connecting(self) -> None:
        """A fresh connect attempt has started."""
        self.connect_attempts += 1
        self._transition(ConnectionState.CONNECTING)

    def mark_connected(self) -> None:
        """The transport reports an established session."""
        self.last_connected_at = _now()
        self.last_error = None
        self._transition(ConnectionState.CONNECTED)

    def mark_disconnected(self, error: object | None = None) -> None:
        """The connection dropped (or a connect attempt failed).

        ``last_disconnected_at`` is only stamped on the edge out of a
        connected/connecting state so it keeps marking the start of the
        current outage across repeated calls while already down.
        """
        if self.state not in DOWN_STATES:
            self.last_disconnected_at = _now()
        if error is not None:
            self.last_error = str(error)
        self._transition(ConnectionState.DISCONNECTED)

    def mark_reconnecting(self) -> None:
        """A forced rebuild (full disconnect -> connect -> resubscribe) began."""
        self.reconnect_count += 1
        self._transition(ConnectionState.RECONNECTING)

    def mark_credentials_stale(self, error: object | None = None) -> None:
        """Cognito rejected the cached credentials / OpenID token."""
        self.credential_reject_count += 1
        if error is not None:
            self.last_error = str(error)
        self._transition(ConnectionState.CREDENTIALS_STALE)

    def mark_credentials_refreshed(self) -> None:
        """A new AWS credential snapshot was obtained. State is left unchanged;
        the caller decides whether that clears a stale condition."""
        self.credential_refresh_count += 1

    def mark_fatal(self, error: object | None = None) -> None:
        """Unrecoverable without user action (e.g. persistent auth failure)."""
        if error is not None:
            self.last_error = str(error)
        self._transition(ConnectionState.FATAL)

    # -- reads -----------------------------------------------------------

    @property
    def is_connected(self) -> bool:
        return self.state is ConnectionState.CONNECTED

    def seconds_in_state(self, *, now: datetime | None = None) -> float:
        return ((now or _now()) - self.last_state_change).total_seconds()

    def as_diagnostics(self) -> dict[str, Any]:
        """JSON-safe snapshot for the diagnostics download."""
        return {
            "state": str(self.state),
            "last_state_change": self.last_state_change.isoformat(),
            "last_connected_at": self.last_connected_at.isoformat() if self.last_connected_at else None,
            "last_disconnected_at": self.last_disconnected_at.isoformat() if self.last_disconnected_at else None,
            "last_error": self.last_error,
            "connect_attempts": self.connect_attempts,
            "reconnect_count": self.reconnect_count,
            "credential_refresh_count": self.credential_refresh_count,
            "credential_reject_count": self.credential_reject_count,
        }
