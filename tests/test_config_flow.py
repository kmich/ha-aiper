"""Tests for the Aiper config flow helpers."""

from __future__ import annotations

from collections.abc import Iterator
from typing import Any, cast

import pytest
from homeassistant import config_entries
from homeassistant.const import CONF_PASSWORD, CONF_USERNAME
from homeassistant.core import HomeAssistant
from pytest_homeassistant_custom_component.common import (
    MockConfigEntry,
    MockModule,
    mock_config_flow,
    mock_integration,
    mock_platform,
)

from custom_components.aiper import config_flow as aiper_config_flow
from custom_components.aiper.api import AiperConnectionError, AiperResponseError
from custom_components.aiper.config_flow import (
    CONF_REGION,
    CannotConnect,
    InvalidAuth,
    InvalidResponse,
    validate_input,
)
from custom_components.aiper.const import (
    CONF_METADATA_REFRESH_HOURS,
    CONF_MQTT_DEBUG,
    DOMAIN,
)


class FakeAiperApi:
    """Fake Aiper API client used by validate_input tests."""

    instances: list[FakeAiperApi] = []
    login_result = True
    login_error: Exception | None = None
    devices = [{"sn": "SN1"}, {"sn": "SN2"}]

    def __init__(self, username: str, password: str, region: str, async_session=None) -> None:
        self.username = username
        self.password = password
        self.region = region
        self.async_session = async_session
        self.disconnected = False
        self.__class__.instances.append(self)

    async def login(self) -> bool:
        if self.login_error is not None:
            raise self.login_error
        return self.login_result

    async def get_devices(self) -> list[dict[str, str]]:
        return self.devices

    async def disconnect(self) -> None:
        self.disconnected = True


@pytest.fixture(autouse=True)
def fake_api(monkeypatch: pytest.MonkeyPatch) -> type[FakeAiperApi]:
    """Patch the config flow to use a fake API client."""
    FakeAiperApi.instances = []
    FakeAiperApi.login_result = True
    FakeAiperApi.login_error = None
    FakeAiperApi.devices = [{"sn": "SN1"}, {"sn": "SN2"}]
    monkeypatch.setattr("custom_components.aiper.config_flow.AiperApi", FakeAiperApi)
    monkeypatch.setattr("custom_components.aiper.config_flow.async_get_clientsession", lambda hass: "session")
    return FakeAiperApi


@pytest.fixture
def aiper_flow_handler(hass: HomeAssistant) -> Iterator[None]:
    """Register the custom integration and config flow with HA's flow manager."""
    mock_integration(
        hass,
        MockModule(DOMAIN, partial_manifest={"config_flow": True}),
        built_in=False,
    )
    mock_platform(hass, f"{DOMAIN}.config_flow", cast(Any, aiper_config_flow), built_in=False)
    with mock_config_flow(DOMAIN, aiper_config_flow.ConfigFlow):
        yield


@pytest.mark.asyncio
async def test_validate_input_returns_title_and_device_count(hass: HomeAssistant) -> None:
    """Successful validation returns display info and disconnects the client."""
    data = {
        CONF_USERNAME: "user@example.com",
        CONF_PASSWORD: "secret",
        CONF_REGION: "eu",
    }

    result = await validate_input(hass, data)

    assert result == {
        "title": "Aiper (user@example.com)",
        "device_count": 2,
    }
    assert FakeAiperApi.instances[0].region == "eu"
    assert FakeAiperApi.instances[0].disconnected is True


@pytest.mark.asyncio
async def test_validate_input_raises_invalid_auth_when_login_fails(
    hass: HomeAssistant,
    fake_api: type[FakeAiperApi],
) -> None:
    """A false login result is treated as invalid credentials."""
    fake_api.login_result = False
    data = {
        CONF_USERNAME: "user@example.com",
        CONF_PASSWORD: "bad-secret",
        CONF_REGION: "eu",
    }

    with pytest.raises(InvalidAuth):
        await validate_input(hass, data)

    assert FakeAiperApi.instances[0].disconnected is True


@pytest.mark.asyncio
async def test_validate_input_raises_cannot_connect_for_connection_error(
    hass: HomeAssistant,
    fake_api: type[FakeAiperApi],
) -> None:
    """Cloud transport failures should not be reported as bad credentials."""
    fake_api.login_error = AiperConnectionError("network down")
    data = {
        CONF_USERNAME: "user@example.com",
        CONF_PASSWORD: "secret",
        CONF_REGION: "eu",
    }

    with pytest.raises(CannotConnect):
        await validate_input(hass, data)

    assert FakeAiperApi.instances[0].disconnected is True


@pytest.mark.asyncio
async def test_validate_input_raises_invalid_response_for_unexpected_payload(
    hass: HomeAssistant,
    fake_api: type[FakeAiperApi],
) -> None:
    """Unexpected cloud payloads should not be reported as bad credentials."""
    fake_api.login_error = AiperResponseError("missing token")
    data = {
        CONF_USERNAME: "user@example.com",
        CONF_PASSWORD: "secret",
        CONF_REGION: "eu",
    }

    with pytest.raises(InvalidResponse):
        await validate_input(hass, data)

    assert FakeAiperApi.instances[0].disconnected is True


@pytest.mark.asyncio
async def test_user_step_success_creates_entry(hass: HomeAssistant, aiper_flow_handler: None) -> None:
    """The real user config-flow step should validate and create an entry."""
    user_input = {
        CONF_USERNAME: "user@example.com",
        CONF_PASSWORD: "secret",
        CONF_REGION: "asia",
    }

    result = cast(
        dict[str, Any],
        await hass.config_entries.flow.async_init(
            DOMAIN,
            context={"source": config_entries.SOURCE_USER},
            data=user_input,
        ),
    )

    assert result["type"] == "create_entry"
    assert result["title"] == "Aiper (user@example.com)"
    assert result["data"] == user_input
    assert FakeAiperApi.instances[0].async_session == "session"
    assert FakeAiperApi.instances[0].disconnected is True


@pytest.mark.asyncio
async def test_user_step_invalid_auth_returns_form_error(
    hass: HomeAssistant,
    aiper_flow_handler: None,
    fake_api: type[FakeAiperApi],
) -> None:
    """Invalid credentials should keep the user on the form with invalid_auth."""
    fake_api.login_result = False

    result = cast(
        dict[str, Any],
        await hass.config_entries.flow.async_init(
            DOMAIN,
            context={"source": config_entries.SOURCE_USER},
            data={
                CONF_USERNAME: "user@example.com",
                CONF_PASSWORD: "bad-secret",
                CONF_REGION: "eu",
            },
        ),
    )

    assert result["type"] == "form"
    assert result["step_id"] == "user"
    assert result["errors"] == {"base": "invalid_auth"}


@pytest.mark.asyncio
async def test_user_step_connection_error_returns_form_error(
    hass: HomeAssistant,
    aiper_flow_handler: None,
    fake_api: type[FakeAiperApi],
) -> None:
    """Connection failures should keep the user on the form with cannot_connect."""
    fake_api.login_error = AiperConnectionError("network down")

    result = cast(
        dict[str, Any],
        await hass.config_entries.flow.async_init(
            DOMAIN,
            context={"source": config_entries.SOURCE_USER},
            data={
                CONF_USERNAME: "user@example.com",
                CONF_PASSWORD: "secret",
                CONF_REGION: "eu",
            },
        ),
    )

    assert result["type"] == "form"
    assert result["step_id"] == "user"
    assert result["errors"] == {"base": "cannot_connect"}


@pytest.mark.asyncio
async def test_user_step_invalid_response_returns_form_error(
    hass: HomeAssistant,
    aiper_flow_handler: None,
    fake_api: type[FakeAiperApi],
) -> None:
    """Unexpected cloud payloads should use the invalid_response form error."""
    fake_api.login_error = AiperResponseError("missing token")

    result = cast(
        dict[str, Any],
        await hass.config_entries.flow.async_init(
            DOMAIN,
            context={"source": config_entries.SOURCE_USER},
            data={
                CONF_USERNAME: "user@example.com",
                CONF_PASSWORD: "secret",
                CONF_REGION: "eu",
            },
        ),
    )

    assert result["type"] == "form"
    assert result["step_id"] == "user"
    assert result["errors"] == {"base": "invalid_response"}


@pytest.mark.asyncio
async def test_user_step_duplicate_username_aborts(hass: HomeAssistant, aiper_flow_handler: None) -> None:
    """A second entry for the same Aiper username should abort."""
    existing = MockConfigEntry(
        domain=DOMAIN,
        unique_id="user@example.com",
        data={
            CONF_USERNAME: "user@example.com",
            CONF_PASSWORD: "old-secret",
            CONF_REGION: "eu",
        },
    )
    existing.add_to_hass(hass)

    result = cast(
        dict[str, Any],
        await hass.config_entries.flow.async_init(
            DOMAIN,
            context={"source": config_entries.SOURCE_USER},
            data={
                CONF_USERNAME: "user@example.com",
                CONF_PASSWORD: "secret",
                CONF_REGION: "asia",
            },
        ),
    )

    assert result["type"] == "abort"
    assert result["reason"] == "already_configured"


@pytest.mark.asyncio
async def test_reauth_success_updates_entry(hass: HomeAssistant, aiper_flow_handler: None) -> None:
    """Successful reauth should update the existing entry password."""
    entry = MockConfigEntry(
        domain=DOMAIN,
        entry_id="entry-1",
        unique_id="user@example.com",
        data={
            CONF_USERNAME: "user@example.com",
            CONF_PASSWORD: "old-secret",
            CONF_REGION: "asia",
        },
    )
    entry.add_to_hass(hass)

    result = cast(
        dict[str, Any],
        await hass.config_entries.flow.async_init(
            DOMAIN,
            context={
                "source": config_entries.SOURCE_REAUTH,
                "entry_id": entry.entry_id,
                "unique_id": "user@example.com",
            },
            data=entry.data,
        ),
    )
    assert result["type"] == "form"
    assert result["step_id"] == "reauth_confirm"
    assert result["description_placeholders"][CONF_USERNAME] == "user@example.com"

    result = cast(
        dict[str, Any],
        await hass.config_entries.flow.async_configure(
            result["flow_id"],
            user_input={CONF_PASSWORD: "new-secret"},
        ),
    )

    assert result["type"] == "abort"
    assert result["reason"] == "reauth_successful"
    assert entry.data[CONF_PASSWORD] == "new-secret"


@pytest.mark.asyncio
async def test_options_flow_defaults_and_updates(hass: HomeAssistant, aiper_flow_handler: None) -> None:
    """Options flow should expose current defaults and persist submitted options."""
    entry = MockConfigEntry(
        domain=DOMAIN,
        entry_id="entry-1",
        data={
            CONF_USERNAME: "user@example.com",
            CONF_PASSWORD: "secret",
            CONF_REGION: "asia",
        },
        options={
            CONF_METADATA_REFRESH_HOURS: 12,
            CONF_MQTT_DEBUG: True,
        },
    )
    entry.add_to_hass(hass)

    result = cast(dict[str, Any], await hass.config_entries.options.async_init(entry.entry_id))

    assert result["type"] == "form"
    assert result["step_id"] == "init"

    user_input = {
        CONF_METADATA_REFRESH_HOURS: 24,
        CONF_MQTT_DEBUG: False,
    }
    result = cast(
        dict[str, Any],
        await hass.config_entries.options.async_configure(
            result["flow_id"],
            user_input=user_input,
        ),
    )

    assert result["type"] == "create_entry"
    assert result["data"] == user_input
