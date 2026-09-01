"""Cassette-replay regression tests for ``AiperApi`` REST / credential flows.

These exercise the full ``login -> get_devices -> get_openid_token ->
get_aws_credentials`` chain against hand-authored cassettes (see
``tests/cassettes/``), with no live network. The interesting cassettes model
Aiper's regional variance behind the v1.3.1 fix: a region whose
``getOpenIdToken`` omits ``tokenDuration`` (so the client has no expiry hint),
and a Cognito 4xx that must trigger exactly one bounded OpenID refresh + retry.
"""

from __future__ import annotations

import time
from collections.abc import Callable

import pytest

from custom_components.aiper.api import AiperApi

# (cassette, aws_region baked into the responses, expected AccessKeyId, device sn)
_HAPPY_PATHS = [
    ("eu_happy_path", "eu-central-1", "ASIAEUHAPPYPATH00001", "1000000000000001"),
    ("us_happy_path", "us-east-1", "ASIAUSHAPPYPATH00002", "2000000000000002"),
    ("asia_happy_path", "ap-southeast-1", "ASIAASIAHAPPYPATH003", "3000000000000003"),
]


@pytest.mark.parametrize(("cassette", "aws_region", "access_key", "sn"), _HAPPY_PATHS)
async def test_happy_path_login_devices_openid_credentials(
    replay_api: Callable[..., AiperApi],
    cassette: str,
    aws_region: str,
    access_key: str,
    sn: str,
) -> None:
    """Each regional happy-path cassette drives the whole chain to success."""
    api = replay_api(cassette)

    assert await api.login() is True
    assert api._token
    assert api._identity_id
    assert api._iot_endpoint and aws_region in api._iot_endpoint
    assert api._openid_token
    # tokenDuration is present in these cassettes, so the expiry is known.
    assert api._openid_token_exp is not None and api._openid_token_exp > time.time()

    devices = await api.get_devices()
    assert isinstance(devices, list) and len(devices) == 1
    assert devices[0]["sn"] == sn
    assert api._devices[sn]["sn"] == sn

    # Explicit second OpenID fetch: returns None by contract, keeps state populated.
    assert await api.get_openid_token() is None
    assert api._openid_token

    creds = await api.get_aws_credentials()
    assert creds is not None
    assert creds["AccessKeyId"] == access_key
    assert api._aws_credentials is creds
    assert api._aws_credentials_exp is not None and api._aws_credentials_exp > time.time()
    assert api._aws_credentials_cooldown_until == 0.0

    # The region Aiper reported must have flowed into the Cognito endpoint.
    assert api._resolve_aws_region() == aws_region
    player = api.replay
    assert player.count_calls(f"cognito-identity.{aws_region}.amazonaws.com") == 1
    assert player.remaining == 0


async def test_openid_without_token_duration_does_not_crash_and_refreshes_on_reject(
    replay_api: Callable[..., AiperApi],
) -> None:
    """A region that omits ``tokenDuration`` must not crash the client, and the
    only staleness signal it has -- a Cognito 4xx -- must drive one refresh."""
    api = replay_api("openid_no_token_duration")

    assert await api.login() is True
    assert api._openid_token == "openid-token-eu-nodur-1"
    # No expiry hint anywhere: the client cannot proactively refresh the token.
    assert api._openid_token_exp is None
    # No AWS credentials fetched yet + no expiry hint => derived MQTT
    # credentials are treated as due for refresh.
    assert api._mqtt_credentials_due_for_refresh() is True

    devices = await api.get_devices()
    assert [d["sn"] for d in devices] == ["1000000000000009"]

    assert await api.get_openid_token() is None
    assert api._openid_token == "openid-token-eu-nodur-2"
    assert api._openid_token_exp is None

    # The exchange gets a Cognito 4xx; the client must refresh OpenID once and
    # retry, then succeed -- without ever tripping over the missing tokenDuration.
    creds = await api.get_aws_credentials()
    assert creds is not None
    assert creds["AccessKeyId"] == "ASIAEUNODURRECOVERED1"
    assert api._identity_id == "eu-central-1:aaaaaaaa-0002-0002-0002-000000000002"
    assert api._openid_token == "openid-token-eu-nodur-refreshed"
    assert api._aws_credentials_cooldown_until == 0.0
    assert api._aws_credentials_exp is not None

    player = api.replay
    assert player.remaining == 0
    # One rejected exchange + one successful retry.
    assert player.count_calls("cognito-identity.") == 2
    # login + explicit fetch + exactly one reactive refresh inside get_aws_credentials.
    assert player.count_calls("/users/getOpenIdToken") == 3


async def test_cognito_4xx_triggers_exactly_one_bounded_openid_refresh_and_retry(
    replay_api: Callable[..., AiperApi],
) -> None:
    """A Cognito 4xx on the credentials exchange must cause one bounded OpenID
    refresh + retry that then succeeds -- consistent with test_mqtt_credentials."""
    api = replay_api("cognito_4xx_then_recover")

    assert await api.login() is True
    assert await api.get_openid_token() is None

    identity_before = api._identity_id
    token_before = api._openid_token
    assert identity_before == "eu-central-1:bbbbbbbb-0001-0001-0001-000000000001"
    assert token_before == "openid-token-eu-4xx-2"

    creds = await api.get_aws_credentials()
    assert creds is not None
    assert creds["AccessKeyId"] == "ASIAEU4XXRECOVERED01"

    # Exactly one refresh: identity and token each rolled forward once.
    assert api._identity_id == "eu-central-1:bbbbbbbb-0002-0002-0002-000000000002"
    assert api._identity_id != identity_before
    assert api._openid_token == "openid-token-eu-4xx-refreshed"
    assert api._openid_token != token_before

    # The successful retry must persist to the instance cache.
    assert api._aws_credentials is creds
    assert api._aws_credentials_exp is not None and api._aws_credentials_exp > time.time()
    assert api._aws_credentials_cooldown_until == 0.0

    player = api.replay
    assert player.count_calls("cognito-identity.") == 2  # 1 rejected + 1 retry
    assert player.count_calls("/users/getOpenIdToken") == 3  # login + explicit + 1 reactive
    assert player.remaining == 0

    # A follow-up call stays inside the cached window: no further round trips,
    # and no cassette entries are needed.
    creds_again = await api.get_aws_credentials()
    assert creds_again is api._aws_credentials
    assert player.count_calls("cognito-identity.") == 2
    assert player.remaining == 0
