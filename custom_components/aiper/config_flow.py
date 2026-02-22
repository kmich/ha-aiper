"""Config flow for Aiper integration."""
from __future__ import annotations

import logging
from typing import Any

import voluptuous as vol

from homeassistant import config_entries
from homeassistant.const import CONF_PASSWORD, CONF_USERNAME
from homeassistant.core import HomeAssistant
from homeassistant.data_entry_flow import FlowResult
from homeassistant.exceptions import HomeAssistantError

from .api import AiperApi
from .const import DOMAIN, CONF_ENABLE_MQTT, CONF_MQTT_DEBUG, CONF_QUEUE_OFFLINE_COMMANDS, CONF_POLL_INTERVAL, DEFAULT_SCAN_INTERVAL, CONF_HISTORY_REFRESH_HOURS, CONF_CONSUMABLES_REFRESH_HOURS, CONF_CLEAN_PATH_REFRESH_HOURS, DEFAULT_HISTORY_REFRESH_HOURS, DEFAULT_CONSUMABLES_REFRESH_HOURS, DEFAULT_CLEAN_PATH_REFRESH_HOURS

_LOGGER = logging.getLogger(__name__)

CONF_REGION = "region"

STEP_USER_DATA_SCHEMA = vol.Schema(
    {
        vol.Required(CONF_USERNAME): str,
        vol.Required(CONF_PASSWORD): str,
        vol.Required(CONF_REGION, default="eu"): vol.In(
            {
                "us": "Americas",
                "eu": "Europe",
                "asia": "Asia/Pacific",
            }
        ),
    }
)


async def validate_input(hass: HomeAssistant, data: dict[str, Any]) -> dict[str, Any]:
    """Validate the user input allows us to connect."""
    api = AiperApi(
        username=data[CONF_USERNAME],
        password=data[CONF_PASSWORD],
        region=data[CONF_REGION],
    )

    try:
        result = await hass.async_add_executor_job(api.login)
        if not result:
            raise InvalidAuth

        # Get devices to show count
        devices = await hass.async_add_executor_job(api.get_devices)

    except Exception as err:
        _LOGGER.error("Login validation failed: %s", err)
        raise InvalidAuth from err
    finally:
        await hass.async_add_executor_job(api.disconnect)

    return {
        "title": f"Aiper ({data[CONF_USERNAME]})",
        "device_count": len(devices),
    }


class ConfigFlow(config_entries.ConfigFlow, domain=DOMAIN):
    """Handle a config flow for Aiper."""

    VERSION = 1

    async def async_step_user(
        self, user_input: dict[str, Any] | None = None
    ) -> FlowResult:
        """Handle the initial step."""
        errors: dict[str, str] = {}

        if user_input is not None:
            try:
                info = await validate_input(self.hass, user_input)
            except CannotConnect:
                errors["base"] = "cannot_connect"
            except InvalidAuth:
                errors["base"] = "invalid_auth"
            except Exception:
                _LOGGER.exception("Unexpected exception")
                errors["base"] = "unknown"
            else:
                # Check for existing entry with same username
                await self.async_set_unique_id(user_input[CONF_USERNAME])
                self._abort_if_unique_id_configured()

                return self.async_create_entry(
                    title=info["title"],
                    data=user_input,
                )

        return self.async_show_form(
            step_id="user",
            data_schema=STEP_USER_DATA_SCHEMA,
            errors=errors,
        )

    async def async_step_reauth(self, entry_data: dict[str, Any]) -> FlowResult:
        """Handle reauthorization request."""
        return await self.async_step_reauth_confirm()

    async def async_step_reauth_confirm(
        self, user_input: dict[str, Any] | None = None
    ) -> FlowResult:
        """Handle reauthorization confirmation."""
        errors: dict[str, str] = {}

        if user_input is not None:
            try:
                await validate_input(self.hass, {
                    **self._get_reauth_entry().data,
                    **user_input,
                })
            except InvalidAuth:
                errors["base"] = "invalid_auth"
            except Exception:
                _LOGGER.exception("Unexpected exception")
                errors["base"] = "unknown"
            else:
                return self.async_update_reload_and_abort(
                    self._get_reauth_entry(),
                    data_updates=user_input,
                )

        return self.async_show_form(
            step_id="reauth_confirm",
            data_schema=vol.Schema({vol.Required(CONF_PASSWORD): str}),
            errors=errors,
        )


    @staticmethod
    @config_entries.callback
    def async_get_options_flow(config_entry: config_entries.ConfigEntry):
        return OptionsFlowHandler(config_entry)


class OptionsFlowHandler(config_entries.OptionsFlow):
    """Handle options for the integration."""

    def __init__(self, config_entry: config_entries.ConfigEntry) -> None:
        # Home Assistant exposes a read-only `config_entry` property on OptionsFlow.
        # Internally, it reads from `_config_entry`, so set that attribute instead
        # of attempting to assign to the property.
        self._config_entry = config_entry

    async def async_step_init(self, user_input: dict[str, Any] | None = None) -> FlowResult:
        """Manage the options."""
        if user_input is not None:
            return self.async_create_entry(title="", data=user_input)

        current = self._config_entry.options
        schema = vol.Schema(
            {
                vol.Optional(CONF_ENABLE_MQTT, default=current.get(CONF_ENABLE_MQTT, True)): bool,
                vol.Optional(CONF_MQTT_DEBUG, default=current.get(CONF_MQTT_DEBUG, False)): bool,
                vol.Optional(CONF_QUEUE_OFFLINE_COMMANDS, default=current.get(CONF_QUEUE_OFFLINE_COMMANDS, False)): bool,
                vol.Optional(CONF_POLL_INTERVAL, default=current.get(CONF_POLL_INTERVAL, DEFAULT_SCAN_INTERVAL)): vol.All(
                    vol.Coerce(int),
                    vol.Range(min=5, max=3600),
                ),
            }
        )

        return self.async_show_form(step_id="init", data_schema=schema)


class CannotConnect(HomeAssistantError):
    """Error to indicate we cannot connect."""


class InvalidAuth(HomeAssistantError):
    """Error to indicate there is invalid auth."""
