"""Cassette-based replay harness for ``AiperApi`` REST / credential flows.

This lets us regression-test Aiper's regional API variance without any live
network. The motivating case is the v1.3.1 fix: some regions'
``getOpenIdToken`` response omits ``tokenDuration``, so the client cannot tell
its cached OpenID token has gone stale until Cognito rejects it -- and a
Cognito 4xx must then trigger exactly one bounded OpenID refresh + retry.

A *cassette* is a hand-authored JSON file under ``tests/cassettes/<name>.json``
holding an ordered list of entries::

    [
      {"request":  {"method": "POST", "path_contains": "/login"},
       "response": {"status": 200, "json": {...}}},
      ...
    ]

Entries are consumed strictly in order. ``AiperApi._request_with_backoff`` is
patched to pop the next entry, assert the HTTP ``method`` matches and
``path_contains`` is a substring of the request URL, and return
``(status, json.dumps(entry["response"]["json"]))`` -- mirroring the real
method's ``tuple[int, str]`` contract. A ``status`` of 400-499 is raised as
``aiohttp.ClientResponseError`` instead, exactly as the real
``_request_with_backoff`` does through ``resp.raise_for_status()``; the Cognito
error-handling path in ``_get_aws_credentials_locked`` depends on that shape.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from pathlib import Path
from typing import Any, cast

import aiohttp
import pytest

from custom_components.aiper import api as api_module
from custom_components.aiper.api import AiperApi

CASSETTE_DIR = Path(__file__).parent / "cassettes"

# Region each named cassette was authored against, so that
# ``replay_api("us_happy_path")`` builds the client with the matching
# ``ApiEndpoint`` base URL and AWS region.
_REGION_BY_CASSETTE: dict[str, str] = {
    "eu_happy_path": "eu",
    "us_happy_path": "us",
    "asia_happy_path": "asia",
    "openid_no_token_duration": "eu",
    "cognito_4xx_then_recover": "eu",
}


class FakeEncryption:
    """No-op stand-in for ``AiperEncryption`` so cassettes hold plain JSON.

    Matches the seam already used by ``tests/test_api_session.py``: the AES/RSA
    envelope is bypassed, request bodies pass through untouched and responses
    are returned verbatim.
    """

    encrypt_key_header = "test-key"

    def encrypt_request(self, body: dict[str, Any] | None) -> dict[str, Any] | None:
        return body

    def decrypt_response(self, text: str) -> str:
        return text


class CassettePlayer:
    """Replays a single cassette in order, in place of ``_request_with_backoff``."""

    def __init__(self, name: str, entries: list[dict[str, Any]]) -> None:
        self.name = name
        self._entries = entries
        self._index = 0
        # (method, url) for every intercepted request, in order, for assertions.
        self.calls: list[tuple[str, str]] = []

    @property
    def remaining(self) -> int:
        """How many cassette entries have not been consumed yet."""
        return len(self._entries) - self._index

    def count_calls(self, url_substring: str) -> int:
        """Number of intercepted requests whose URL contains ``url_substring``."""
        return sum(1 for _method, url in self.calls if url_substring in url)

    async def request(
        self,
        method: str,
        url: str,
        *,
        headers: dict[str, Any] | None = None,
        json_body: dict[str, Any] | None = None,
        data: Any = None,
        timeout: int = 30,
        **_kwargs: Any,
    ) -> tuple[int, str]:
        """Drop-in replacement for ``AiperApi._request_with_backoff``."""
        self.calls.append((method.upper(), url))

        if self._index >= len(self._entries):
            raise AssertionError(
                f"cassette {self.name!r} is exhausted: nothing left to answer "
                f"{method.upper()} {url} (all {len(self._entries)} entries already consumed)"
            )

        entry = self._entries[self._index]
        position = self._index
        self._index += 1

        want = entry["request"]
        want_method = str(want["method"]).upper()
        if method.upper() != want_method:
            raise AssertionError(
                f"cassette {self.name!r} entry {position}: expected a {want_method} request "
                f"but the client sent {method.upper()} {url}"
            )

        needle = str(want["path_contains"])
        if needle not in url:
            raise AssertionError(
                f"cassette {self.name!r} entry {position}: expected {needle!r} to appear in the "
                f"request URL but the client sent {url!r}"
            )

        response = entry["response"]
        status = int(response["status"])
        body = json.dumps(response.get("json", {}))

        if status >= 400:
            # The real _request_with_backoff surfaces a 4xx as ClientResponseError
            # via resp.raise_for_status(); _get_aws_credentials_locked catches
            # exactly that and reads err.status.
            message = str(response.get("message") or f"cassette {self.name!r} returned HTTP {status}")
            raise aiohttp.ClientResponseError(cast(Any, None), (), status=status, message=message)

        return status, body


def load_cassette(name: str) -> list[dict[str, Any]]:
    """Load and lightly validate a named cassette file."""
    path = CASSETTE_DIR / f"{name}.json"
    if not path.is_file():
        raise FileNotFoundError(f"no cassette named {name!r} under {CASSETTE_DIR}")

    entries = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(entries, list) or not entries:
        raise ValueError(f"cassette {name!r} must be a non-empty JSON list")

    for i, entry in enumerate(entries):
        if not isinstance(entry, dict) or "request" not in entry or "response" not in entry:
            raise ValueError(f"cassette {name!r} entry {i} must have 'request' and 'response' keys")
        req = entry["request"]
        if "method" not in req or "path_contains" not in req:
            raise ValueError(f"cassette {name!r} entry {i} 'request' needs 'method' and 'path_contains'")
        if "status" not in entry["response"]:
            raise ValueError(f"cassette {name!r} entry {i} 'response' needs a 'status'")

    return entries


def build_replay_api(
    monkeypatch: pytest.MonkeyPatch,
    name: str,
    *,
    region: str | None = None,
) -> AiperApi:
    """Construct an ``AiperApi`` wired to the named cassette.

    Installs :class:`FakeEncryption` on ``api_module.AiperEncryption`` and
    patches the instance's ``_request_with_backoff`` with a :class:`CassettePlayer`.
    The player is attached as ``api.replay`` so a test can inspect the call log,
    the count of unused entries, and how often a given endpoint was hit.
    """
    resolved_region = region or _REGION_BY_CASSETTE.get(name, "eu")
    monkeypatch.setattr(api_module, "AiperEncryption", FakeEncryption)

    api = AiperApi("user@example.com", "secret", resolved_region, async_session=cast(Any, object()))
    player = CassettePlayer(name, load_cassette(name))
    monkeypatch.setattr(api, "_request_with_backoff", player.request)
    # Test-only handle. AiperApi itself never reads this attribute.
    api.replay = player  # type: ignore[attr-defined]
    return api


@pytest.fixture
def replay_api(monkeypatch: pytest.MonkeyPatch) -> Callable[..., AiperApi]:
    """Factory fixture: ``replay_api("eu_happy_path")`` -> a configured ``AiperApi``.

    Pass ``region=`` to override the cassette's default region. The returned
    client has its REST/credential transport backed entirely by the cassette;
    no network access occurs.
    """

    def _factory(name: str, *, region: str | None = None) -> AiperApi:
        return build_replay_api(monkeypatch, name, region=region)

    return _factory
