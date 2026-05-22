"""Pytest configuration for the Aiper custom integration."""

from __future__ import annotations

import sys
from collections.abc import Generator

import pytest

if sys.platform == "win32":
    import pytest_socket

    @pytest.hookimpl(hookwrapper=True, tryfirst=True)
    def pytest_fixture_setup(
        fixturedef: pytest.FixtureDef[object],
    ) -> Generator[None, object, None]:
        """Keep Windows asyncio loop sockets available during tests."""
        if fixturedef.argname == "event_loop":
            pytest_socket.enable_socket()
            pytest_socket.socket_allow_hosts(["127.0.0.1"])
        yield
