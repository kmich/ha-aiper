"""Config flow for Aiper integration."""

from __future__ import annotations

import logging
from typing import Any

import aiohttp
import voluptuous as vol
from homeassistant import config_entries
from homeassistant.const import CONF_PASSWORD, CONF_USERNAME
from homeassistant.core import HomeAssistant, callback
from homeassistant.exceptions import HomeAssistantError
from homeassistant.helpers.aiohttp_client import async_get_clientsession

from .api import (
    AiperApi,
    AiperAuthenticationError,
    AiperConnectionError,
    AiperResponseError,
    AiperSessionConflict,
)
from .const import (
    CONF_METADATA_REFRESH_HOURS,
    CONF_MQTT_DEBUG,
    DEFAULT_METADATA_REFRESH_HOURS,
    DOMAIN,
)

_LOGGER = logging.getLogger(__name__)

CONF_REGION = "region"

REGION_SELECTOR = vol.In(
    {
        "us": "Americas",
        "eu": "Europe",
        "asia": "Asia/Pacific",
    }
)

STEP_USER_DATA_SCHEMA = vol.Schema(
    {
        vol.Required(CONF_USERNAME): str,
        vol.Required(CONF_PASSWORD): str,
        vol.Required(CONF_REGION, default="eu"): REGION_SELECTOR,
    }
)


async def validate_input(hass: HomeAssistant, data: dict[str, Any]) -> dict[str, Any]:
    """Validate the user input allows us to connect."""
    api = AiperApi(
        username=data[CONF_USERNAME],
        password=data[CONF_PASSWORD],
        region=data[CONF_REGION],
        async_session=async_get_clientsession(hass),
        time_zone=hass.config.time_zone,
    )

    try:
        result = await api.login()
        if not result:
            raise InvalidAuth

        # Get devices to show count
        devices = await api.get_devices()

    except AiperAuthenticationError as err:
        _LOGGER.debug("Aiper rejected login credentials during validation: %s", err)
        raise InvalidAuth from err
    except AiperSessionConflict as err:
        _LOGGER.error("Aiper session conflict: %s", err)
        raise SessionConflict from err
    except AiperConnectionError as err:
        _LOGGER.error("Aiper connection validation failed: %s", err)
        raise CannotConnect from err
    except AiperResponseError as err:
        _LOGGER.error("Aiper returned an unexpected validation response: %s", err)
        raise InvalidResponse from err
    except aiohttp.ClientResponseError as err:
        _LOGGER.error("Aiper returned HTTP %s during validation", err.status)
        if err.status in (401, 403):
            raise InvalidAuth from err
        raise InvalidResponse from err
    except aiohttp.ClientError as err:
        _LOGGER.error("Aiper connection validation failed: %s", err)
        raise CannotConnect from err
    finally:
        await api.disconnect()

    return {
        "title": f"Aiper ({data[CONF_USERNAME]})",
        "device_count": len(devices),
    }


def normalize_username(username: str) -> str:
    """Return the canonical account identifier used as the config entry unique ID.

    Aiper account emails are case-insensitive, so `User@Example.com` and
    `user@example.com` must not create two entries for the same account.
    """
    return username.strip().lower()


async def _async_validate_errors(hass: HomeAssistant, data: dict[str, Any]) -> tuple[dict[str, Any], dict[str, str]]:
    """Validate credentials and map failures to config-flow error keys."""
    try:
        info = await validate_input(hass, data)
    except CannotConnect:
        return {}, {"base": "cannot_connect"}
    except InvalidAuth:
        return {}, {"base": "invalid_auth"}
    except SessionConflict:
        return {}, {"base": "session_conflict"}
    except InvalidResponse:
        return {}, {"base": "invalid_response"}
    except Exception:
        _LOGGER.exception("Unexpected exception")
        return {}, {"base": "unknown"}
    return info, {}


class ConfigFlow(config_entries.ConfigFlow, domain=DOMAIN):
    """Handle a config flow for Aiper."""

    VERSION = 1
    # 1.2: unique ID normalized to the lower-cased username and legacy entity
    # registry cleanup moved into a one-time migration.
    MINOR_VERSION = 2

    async def async_step_user(self, user_input: dict[str, Any] | None = None) -> config_entries.ConfigFlowResult:
        """Handle the initial step."""
        errors: dict[str, str] = {}

        if user_input is not None:
            user_input = {**user_input, CONF_USERNAME: user_input[CONF_USERNAME].strip()}
            await self.async_set_unique_id(normalize_username(user_input[CONF_USERNAME]))
            self._abort_if_unique_id_configured()

            info, errors = await _async_validate_errors(self.hass, user_input)
            if not errors:
                return self.async_create_entry(title=info["title"], data=user_input)

        return self.async_show_form(
            step_id="user",
            data_schema=self.add_suggested_values_to_schema(
                STEP_USER_DATA_SCHEMA,
                {key: value for key, value in (user_input or {}).items() if key != CONF_PASSWORD},
            ),
            errors=errors,
        )

    async def async_step_reauth(self, entry_data: dict[str, Any]) -> config_entries.ConfigFlowResult:
        """Handle reauthorization request."""
        return await self.async_step_reauth_confirm()

    async def async_step_reauth_confirm(
        self, user_input: dict[str, Any] | None = None
    ) -> config_entries.ConfigFlowResult:
        """Handle reauthorization confirmation."""
        errors: dict[str, str] = {}
        entry = self._get_reauth_entry()

        if user_input is not None:
            _info, errors = await _async_validate_errors(self.hass, {**entry.data, **user_input})
            if not errors:
                return self.async_update_reload_and_abort(entry, data_updates=user_input)

        return self.async_show_form(
            step_id="reauth_confirm",
            data_schema=vol.Schema({vol.Required(CONF_PASSWORD): str}),
            errors=errors,
            description_placeholders={CONF_USERNAME: entry.data[CONF_USERNAME]},
        )

    async def async_step_reconfigure(self, user_input: dict[str, Any] | None = None) -> config_entries.ConfigFlowResult:
        """Change the region or password of an existing account."""
        errors: dict[str, str] = {}
        entry = self._get_reconfigure_entry()

        if user_input is not None:
            _info, errors = await _async_validate_errors(self.hass, {**entry.data, **user_input})
            if not errors:
                return self.async_update_reload_and_abort(entry, data_updates=user_input)

        schema = vol.Schema(
            {
                vol.Required(CONF_PASSWORD): str,
                vol.Required(CONF_REGION, default=entry.data.get(CONF_REGION, "eu")): REGION_SELECTOR,
            }
        )
        return self.async_show_form(
            step_id="reconfigure",
            data_schema=schema,
            errors=errors,
            description_placeholders={CONF_USERNAME: entry.data[CONF_USERNAME]},
        )

    @staticmethod
    @callback
    def async_get_options_flow(config_entry: config_entries.ConfigEntry) -> OptionsFlowHandler:
        return OptionsFlowHandler()


class OptionsFlowHandler(config_entries.OptionsFlow):
    """Handle options for the integration."""

    async def async_step_init(self, user_input: dict[str, Any] | None = None) -> config_entries.ConfigFlowResult:
        """Manage the options."""
        if user_input is not None:
            return self.async_create_entry(title="", data=user_input)

        current = self.config_entry.options
        schema = vol.Schema(
            {
                vol.Optional(CONF_MQTT_DEBUG, default=current.get(CONF_MQTT_DEBUG, False)): bool,
                vol.Optional(
                    CONF_METADATA_REFRESH_HOURS,
                    default=current.get(CONF_METADATA_REFRESH_HOURS, DEFAULT_METADATA_REFRESH_HOURS),
                ): vol.All(
                    vol.Coerce(int),
                    vol.Range(min=1, max=168),
                ),
            }
        )

        return self.async_show_form(step_id="init", data_schema=schema)


class CannotConnect(HomeAssistantError):
    """Error to indicate we cannot connect."""


class InvalidAuth(HomeAssistantError):
    """Error to indicate there is invalid auth."""


class InvalidResponse(HomeAssistantError):
    """Error to indicate Aiper returned an unexpected response."""


class SessionConflict(HomeAssistantError):
    """Error to indicate Aiper account is active in another session."""
