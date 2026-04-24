"""Config flow for FordPass integration."""
import asyncio
import hashlib
import logging
import re
import time
from base64 import urlsafe_b64encode
from collections.abc import Mapping
from pathlib import Path
from secrets import token_urlsafe
from typing import Any, Final
from urllib.parse import urlparse, parse_qs

import aiohttp
import voluptuous as vol
from homeassistant import config_entries, exceptions
from homeassistant.config_entries import ConfigError, ConfigFlowResult, ConfigFlow, OptionsFlow
from homeassistant.const import CONF_URL, CONF_USERNAME, CONF_REGION
from homeassistant.core import callback, HomeAssistant
from homeassistant.helpers import selector
from homeassistant.helpers.aiohttp_client import async_create_clientsession
from homeassistant.helpers.config_entry_oauth2_flow import AbstractOAuth2FlowHandler, OAuth2Session
from homeassistant.helpers.storage import STORAGE_DIR

from .const import (
    DOMAIN,
    OAUTH_ID,
    CLIENT_ID,
    REGIONS,
    REGIONS_STRICT,
    LEGACY_REGION_KEYS,
    LEGACY_TO_ACTIVE_REGION_MAP,
    REGION_OPTIONS_FORD,
    DEFAULT_REGION_FORD,
    REGION_OPTIONS_LINCOLN,
    DEFAULT_REGION_LINCOLN,

    CONFIG_VERSION,
    CONFIG_MINOR_VERSION,
    CONF_IS_SUPPORTED,
    CONF_BRAND,
    CONF_VIN,
    CONF_FORCE_REMOTE_CLIMATE_CONTROL,
    BRAND_OPTIONS,

    UPDATE_INTERVAL,
    UPDATE_INTERVAL_DEFAULT,
)
from .const_shared import (
    CONF_PRESSURE_UNIT,
    CONF_LOG_TO_FILESYSTEM,
    PRESSURE_UNITS,
    DEFAULT_PRESSURE_UNIT,
)
from .fordpass_bridge import ConnectedFordPassVehicle
from .oauth2_handler import FordOAuth2Handler

_LOGGER = logging.getLogger(__name__)

VIN_SCHEME = vol.Schema(
    {
        vol.Required(CONF_VIN, default=""): str,
    }
)

CONF_TOKEN_STR: Final = "tokenstr"
CONF_SETUP_TYPE: Final = "setup_type"
CONF_ACCOUNT: Final = "account"

NEW_ACCOUNT: Final = "new_account"
ADD_VEHICLE: Final = "add_vehicle"

# OAuth2 token field names for config_entry
CONF_ACCESS_TOKEN: Final = "access_token"
CONF_REFRESH_TOKEN: Final = "refresh_token"
CONF_EXPIRY_DATE: Final = "expiry_date"
CONF_AUTO_ACCESS_TOKEN: Final = "auto_access_token"
CONF_AUTO_REFRESH_TOKEN: Final = "auto_refresh_token"
CONF_AUTO_EXPIRY_DATE: Final = "auto_expiry_date"

class CannotConnect(exceptions.HomeAssistantError):
    """Error to indicate we cannot connect."""


class InvalidToken(exceptions.HomeAssistantError):
    """Error to indicate there is invalid token."""


class InvalidAuth(exceptions.HomeAssistantError):
    """Error to indicate there is invalid auth."""


class InvalidVin(exceptions.HomeAssistantError):
    """Error to indicate the wrong vin"""


class InvalidMobile(exceptions.HomeAssistantError):
    """Error to no mobile specified for South African Account"""


class FordPassOAuth2Flow(AbstractOAuth2FlowHandler, domain=DOMAIN):
    """OAuth2 flow handler for FordPass with automatic redirect capture."""

    DOMAIN = DOMAIN
    VERSION = 1
    CONNECTION_CLASS = config_entries.SOURCE_USER

    @property
    def logger(self) -> logging.Logger:
        """Return logger."""
        return _LOGGER

    def __init__(self, *args, **kwargs):
        """Initialize the OAuth2 flow."""
        super().__init__(*args, **kwargs)
        self._session: aiohttp.ClientSession | None = None

    @property
    def oauth_authorize_url(self) -> str:
        """Return the authorization URL with PKCE."""
        region_key = self.flow_state.get(CONF_REGION, DEFAULT_REGION_FORD)
        if region_key not in REGIONS:
            region_key = DEFAULT_REGION_FORD
        
        region = REGIONS[region_key]
        sign_up = "B2C_1A_SignInSignUp_"
        if "sign_up_addon" in region:
            sign_up = f"{sign_up}{region['sign_up_addon']}"
        
        return (
            f"{region['login_url']}/{OAUTH_ID}/{sign_up}{region['locale']}/"
            f"oauth2/v2.0/authorize"
        )

    @property
    def oauth_token_url(self) -> str:
        """Return the token URL."""
        region_key = self.flow_state.get(CONF_REGION, DEFAULT_REGION_FORD)
        if region_key not in REGIONS:
            region_key = DEFAULT_REGION_FORD
        
        region = REGIONS[region_key]
        sign_up = "B2C_1A_SignInSignUp_"
        if "sign_up_addon" in region:
            sign_up = f"{sign_up}{region['sign_up_addon']}"
        
        return (
            f"{region['login_url']}/{OAUTH_ID}/{sign_up}{region['locale']}/"
            f"oauth2/v2.0/token"
        )

    @property
    def extra_authorize_params(self) -> dict[str, str]:
        """Return extra parameters for authorization URL."""
        region_key = self.flow_state.get(CONF_REGION, DEFAULT_REGION_FORD)
        if region_key not in REGIONS:
            region_key = DEFAULT_REGION_FORD
        
        region = REGIONS[region_key]
        return {
            "client_id": CLIENT_ID,
            "scope": f"{CLIENT_ID} openid",
            "response_type": "code",
            "max_age": "3600",
            "ui_locales": region['locale'],
            "language_code": region['locale'],
            "ford_application_id": region['app_id'],
            "country_code": region['countrycode'],
        }

    async def async_step_user(self, user_input=None) -> ConfigFlowResult:
        """Start the OAuth2 flow with brand selection."""
        if self.source == config_entries.SOURCE_USER:
            return await self.async_step_brand()
        return await self.async_step_oauth2_user()

    async def async_step_brand(self, user_input=None) -> ConfigFlowResult:
        """Choose Ford vs Lincoln."""
        if user_input is not None:
            self.flow_state[CONF_BRAND] = user_input[CONF_BRAND]
            return await self.async_step_region()

        return self.async_show_form(
            step_id="brand",
            data_schema=vol.Schema({
                vol.Required(CONF_BRAND, default="ford"): selector.SelectSelector(
                    selector.SelectSelectorConfig(
                        options=BRAND_OPTIONS,
                        mode=selector.SelectSelectorMode.LIST,
                        translation_key=CONF_BRAND,
                    )
                )
            }),
        )

    async def async_step_region(self, user_input=None) -> ConfigFlowResult:
        """Choose region/country."""
        brand = self.flow_state.get(CONF_BRAND, "ford")
        options = REGION_OPTIONS_FORD if brand == "ford" else REGION_OPTIONS_LINCOLN
        default = DEFAULT_REGION_FORD if brand == "ford" else DEFAULT_REGION_LINCOLN

        if user_input is not None:
            self.flow_state[CONF_REGION] = user_input[CONF_REGION]
            return await self.async_step_oauth2_user()

        return self.async_show_form(
            step_id="region",
            data_schema=vol.Schema({
                vol.Required(CONF_REGION, default=default): selector.SelectSelector(
                    selector.SelectSelectorConfig(
                        options=options,
                        mode=selector.SelectSelectorMode.DROPDOWN,
                        translation_key=CONF_REGION,
                    )
                )
            }),
        )

    async def async_step_oauth2_user(self, user_input=None) -> ConfigFlowResult:
        """Redirect to OAuth2 step."""
        return await self.async_step_oauth2()

    async def async_oauth_create_entry(self, data: dict[str, Any]) -> ConfigFlowResult:
        """Create entry from OAuth2 token exchange - handle two-stage flow."""
        try:
            region_key = self.flow_state.get(CONF_REGION, DEFAULT_REGION_FORD)
            
            # Initialize OAuth2 handler for two-stage token exchange
            oauth_handler = FordOAuth2Handler(self.hass, region_key)
            
            # data here contains the B2C tokens from Azure AD
            # We need to exchange the IDP token for Ford API tokens
            _LOGGER.debug(f"async_oauth_create_entry: Processing B2C tokens for region {region_key}")
            
            # Process the two-stage token exchange
            all_tokens = await oauth_handler.process_oauth2_tokens(data)
            
            if not all_tokens:
                _LOGGER.error("Failed to process OAuth2 tokens - cannot exchange for Ford tokens")
                return self.async_abort(reason="cannot_connect")
            
            # Store tokens and move to account info step
            self.flow_state["oauth_tokens"] = all_tokens
            return await self.async_step_account_info()
            
        except Exception as e:
            _LOGGER.error(f"Error in async_oauth_create_entry: {e}")
            return self.async_abort(reason="cannot_connect")

    async def async_step_account_info(self, user_input=None) -> ConfigFlowResult:
        """Get Ford account email/username."""
        if user_input is not None:
            self.flow_state[CONF_USERNAME] = user_input[CONF_USERNAME]
            return await self.async_step_vehicle()

        return self.async_show_form(
            step_id="account_info",
            data_schema=vol.Schema({
                vol.Required(CONF_USERNAME): str,
            }),
            description_placeholders={
                "info": "Enter your Ford account email/username for verification"
            },
        )

    async def async_step_vehicle(self, user_input=None) -> ConfigFlowResult:
        """Select vehicle to configure."""
        errors = {}
        region_key = self.flow_state.get(CONF_REGION, DEFAULT_REGION_FORD)
        oauth_tokens = self.flow_state.get("oauth_tokens", {})
        username = self.flow_state.get(CONF_USERNAME, "")

        if user_input is not None:
            vin = user_input[CONF_VIN]
            
            # Create config entry with all tokens stored in data
            config_data = {
                CONF_USERNAME: username,
                CONF_REGION: region_key,
                CONF_VIN: vin,
                CONF_IS_SUPPORTED: True,
                # B2C tokens (for refresh)
                "b2c_access_token": oauth_tokens.get("b2c_access_token"),
                "b2c_refresh_token": oauth_tokens.get("b2c_refresh_token"),
                "b2c_expiry_date": oauth_tokens.get("b2c_expiry_date"),
                # Ford API tokens
                CONF_ACCESS_TOKEN: oauth_tokens.get("access_token"),
                CONF_AUTO_ACCESS_TOKEN: oauth_tokens.get("auto_access_token"),
                CONF_REFRESH_TOKEN: oauth_tokens.get("refresh_token"),
                CONF_AUTO_REFRESH_TOKEN: oauth_tokens.get("auto_refresh_token"),
                CONF_EXPIRY_DATE: oauth_tokens.get("expiry_date"),
                CONF_AUTO_EXPIRY_DATE: oauth_tokens.get("auto_expiry_date"),
            }

            if self.source == config_entries.SOURCE_REAUTH:
                reauth_entry = self._get_reauth_entry()
                return self.async_update_reload_and_abort(
                    reauth_entry,
                    data=config_data,
                    reason="reauth_successful"
                )

            # Get vehicle title for display
            vehicle_name = self.flow_state.get(f"vehicle_name_{vin}", f"VIN: {vin}")
            
            return self.async_create_entry(
                title=vehicle_name,
                data=config_data,
            )

        # Fetch available vehicles using Ford API tokens
        try:
            if self._session is None:
                self._session = async_create_clientsession(self.hass)

            bridge = ConnectedFordPassVehicle(
                self._session,
                username,
                "",
                region_key,
                coordinator=None,
                storage_path=Path(self.hass.config.config_dir).joinpath(STORAGE_DIR)
            )
            
            # Manually set tokens so bridge can use them for API calls
            bridge.token_data = oauth_tokens
            
            _LOGGER.debug("Fetching vehicles from Ford API")
            vehicles = await bridge.req_vehicles()
            
            if not vehicles or "userVehicles" not in vehicles:
                _LOGGER.warning("No vehicles found in Ford API response")
                return self.async_abort(reason="no_vehicles")
            
            vehicle_list = vehicles.get("userVehicles", {}).get("vehicleDetails", [])
            if not vehicle_list:
                return self.async_abort(reason="no_vehicles")
            
            # Build vehicle options and store display names
            vehicle_options = {}
            for vehicle in vehicle_list:
                vin = vehicle.get("VIN")
                if vin:
                    nickname = vehicle.get("nickName", f"VIN: {vin}")
                    vehicle_options[vin] = nickname
                    self.flow_state[f"vehicle_name_{vin}"] = nickname
            
            if not vehicle_options:
                return self.async_abort(reason="no_vehicles")
            
            # Filter out already configured vehicles
            already_configured = self.configured_vehicles(self.hass)
            available = {vin: name for vin, name in vehicle_options.items() if vin not in already_configured}
            
            if not available:
                return self.async_abort(reason="no_vehicles")
            
            return self.async_show_form(
                step_id="vehicle",
                data_schema=vol.Schema({
                    vol.Required(CONF_VIN): vol.In(available)
                }),
                errors=errors,
            )
            
        except Exception as e:
            _LOGGER.error(f"Error fetching vehicles: {e}")
            errors["base"] = "cannot_connect"
            return self.async_abort(reason="cannot_connect")

    @callback
    def configured_vehicles(self, hass: HomeAssistant) -> set[str]:
        """Return a set of configured vehicle VINs."""
        return {
            entry.data[CONF_VIN]
            for entry in hass.config_entries.async_entries(DOMAIN)
            if CONF_VIN in entry.data
        }


    @staticmethod
    @callback
    def async_get_options_flow(config_entry):
        """Get the options' flow for this handler."""
        return FordPassOptionsFlowHandler(config_entry)


class FordPassOptionsFlowHandler(OptionsFlow):
    def __init__(self, config_entry: config_entries.ConfigEntry):
        """Initialize options flow."""
        if len(dict(config_entry.options)) == 0:
            self._options = dict(config_entry.data)
        else:
            self._options = dict(config_entry.options)

    async def async_step_init(self, user_input=None):
        if user_input is not None:
            return self.async_create_entry(title="", data=user_input)

        options = {vol.Optional(CONF_PRESSURE_UNIT, default=self._options.get(CONF_PRESSURE_UNIT, DEFAULT_PRESSURE_UNIT),): vol.In(PRESSURE_UNITS),
                   vol.Optional(CONF_FORCE_REMOTE_CLIMATE_CONTROL, default=self._options.get(CONF_FORCE_REMOTE_CLIMATE_CONTROL, False),): bool,
                   vol.Optional(CONF_LOG_TO_FILESYSTEM, default=self._options.get(CONF_LOG_TO_FILESYSTEM, False),): bool,
                   vol.Optional(UPDATE_INTERVAL, default=self._options.get(UPDATE_INTERVAL, UPDATE_INTERVAL_DEFAULT),): int}
        return self.async_show_form(step_id="init", data_schema=vol.Schema(options), description_placeholders={"integration_name": "fordpass"})