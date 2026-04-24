"""OAuth2 handler for Ford integration with Home Assistant."""
import json
import logging
import time
from typing import Any, Dict

from aiohttp import ClientSession
from homeassistant.core import HomeAssistant
from homeassistant.helpers.aiohttp_client import async_get_clientsession

from .const import (
    REGIONS,
    CLIENT_ID,
    OAUTH_ID,
    FORD_FOUNDATIONAL_API,
)

_LOGGER = logging.getLogger(__name__)


class FordOAuth2Handler:
    """Handler for Ford OAuth2 flow with Home Assistant."""

    def __init__(
        self,
        hass: HomeAssistant,
        region_key: str,
    ):
        """Initialize Ford OAuth2 handler."""
        self.hass = hass
        self.region_key = region_key
        
        if region_key not in REGIONS:
            raise ValueError(f"Unknown region: {region_key}")
        
        self.region_config = REGIONS[region_key]
        self.app_id = self.region_config["app_id"]
        self.login_url = self.region_config["login_url"]
        self.locale = self.region_config["locale"]
        self.countrycode = self.region_config["countrycode"]

    def get_authorize_url(self) -> str:
        """Get the Azure B2C authorization URL for HA's OAuth2 callback handler."""
        sign_up = "B2C_1A_SignInSignUp_"
        if "sign_up_addon" in self.region_config:
            sign_up = f"{sign_up}{self.region_config['sign_up_addon']}"

        url = (
            f"{self.login_url}/{OAUTH_ID}/{sign_up}{self.locale}/"
            f"oauth2/v2.0/authorize?"
            f"client_id={CLIENT_ID}&"
            f"response_type=code&"
            f"redirect_uri={{redirect_uri}}&"  # HA will substitute this
            f"scope={CLIENT_ID}%20openid&"
            f"response_mode=query"
        )
        return url

    def get_token_url(self) -> str:
        """Get the B2C token endpoint URL."""
        sign_up = "B2C_1A_SignInSignUp_"
        if "sign_up_addon" in self.region_config:
            sign_up = f"{sign_up}{self.region_config['sign_up_addon']}"

        return (
            f"{self.login_url}/{OAUTH_ID}/{sign_up}{self.locale}/"
            f"oauth2/v2.0/token"
        )

    async def exchange_code_for_b2c_token(
        self, 
        session: ClientSession,
        code: str,
        redirect_uri: str,
    ) -> Dict[str, Any]:
        """Exchange authorization code for B2C token."""
        _LOGGER.debug(f"Exchanging code for B2C token (region: {self.region_key})")
        
        token_url = self.get_token_url()
        
        payload = {
            "client_id": CLIENT_ID,
            "scope": f"{CLIENT_ID} openid",
            "code": code,
            "redirect_uri": redirect_uri,
            "grant_type": "authorization_code",
            "resource": "",
        }
        
        headers = {
            "Content-Type": "application/x-www-form-urlencoded",
            "Accept-Encoding": "gzip",
            "Connection": "keep-alive",
            "User-Agent": "okhttp/4.12.0",
        }
        
        try:
            async with session.post(
                token_url,
                data=payload,
                headers=headers,
                ssl=True,
                timeout=None,
            ) as resp:
                data = await resp.json()
                
                if "access_token" not in data:
                    _LOGGER.error(f"B2C token exchange failed: {data}")
                    return None
                
                _LOGGER.debug("B2C token obtained successfully")
                return data
                
        except Exception as e:
            _LOGGER.error(f"Error exchanging code for B2C token: {e}")
            return None

    async def refresh_b2c_token(
        self,
        session: ClientSession,
        refresh_token: str,
    ) -> Dict[str, Any]:
        """Refresh the B2C (Azure AD) token using refresh token."""
        _LOGGER.debug(f"Refreshing B2C token (region: {self.region_key})")
        
        token_url = self.get_token_url()
        
        payload = {
            "client_id": CLIENT_ID,
            "scope": f"{CLIENT_ID} openid",
            "refresh_token": refresh_token,
            "grant_type": "refresh_token",
            "resource": "",
        }
        
        headers = {
            "Content-Type": "application/x-www-form-urlencoded",
            "Accept-Encoding": "gzip",
            "Connection": "keep-alive",
            "User-Agent": "okhttp/4.12.0",
        }
        
        try:
            async with session.post(
                token_url,
                data=payload,
                headers=headers,
                ssl=True,
                timeout=None,
            ) as resp:
                data = await resp.json()
                
                if "access_token" not in data:
                    _LOGGER.error(f"B2C token refresh failed: {data}")
                    return None
                
                _LOGGER.debug("B2C token refreshed successfully")
                return data
                
        except Exception as e:
            _LOGGER.error(f"Error refreshing B2C token: {e}")
            return None

    async def exchange_idp_for_ford_tokens(
        self,
        session: ClientSession,
        idp_token: str,
    ) -> Dict[str, Any]:
        """Exchange B2C IDP token for Ford API tokens."""
        _LOGGER.debug("Exchanging IDP token for Ford API tokens")
        
        exchange_url = f"{FORD_FOUNDATIONAL_API}/token/v2/cat-with-b2c-access-token"
        
        payload = {
            "idpToken": idp_token
        }
        
        headers = {
            "Content-Type": "application/json",
            "Accept-Encoding": "gzip",
            "Connection": "keep-alive",
            "User-Agent": "okhttp/4.12.0",
            "Application-Id": self.app_id,
        }
        
        try:
            async with session.post(
                exchange_url,
                json=payload,
                headers=headers,
                ssl=True,
                timeout=None,
            ) as resp:
                data = await resp.json()
                
                if "access_token" not in data:
                    _LOGGER.error(f"Ford token exchange failed: {data}")
                    return None
                
                # Convert expiry_in to expiry_date (Unix timestamp)
                if "expires_in" in data:
                    data["expiry_date"] = time.time() + data["expires_in"]
                    del data["expires_in"]
                
                if "refresh_expires_in" in data:
                    data["refresh_expiry_date"] = time.time() + data["refresh_expires_in"]
                    del data["refresh_expires_in"]
                
                _LOGGER.debug("Ford tokens obtained successfully")
                return data
                
        except Exception as e:
            _LOGGER.error(f"Error exchanging for Ford tokens: {e}")
            return None

    async def process_oauth2_tokens(
        self,
        b2c_tokens: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Process B2C tokens: get IDP token and exchange for Ford tokens.
        
        This completes the two-stage flow:
        1. B2C tokens (from authorization code exchange) contain 'access_token' (IDP)
        2. Exchange IDP for Ford API tokens
        """
        session = async_get_clientsession(self.hass)
        
        # Get IDP token from B2C
        idp_token = b2c_tokens.get("access_token")
        if not idp_token:
            _LOGGER.error("No IDP token in B2C response")
            return None
        
        # Exchange IDP for Ford tokens
        ford_tokens = await self.exchange_idp_for_ford_tokens(session, idp_token)
        if not ford_tokens:
            return None
        
        # Combine both token sets for storage
        return {
            # B2C tokens
            "b2c_access_token": b2c_tokens.get("access_token"),
            "b2c_refresh_token": b2c_tokens.get("refresh_token"),
            "b2c_expiry_date": time.time() + b2c_tokens.get("expires_in", 3600),
            
            # Ford API tokens
            "access_token": ford_tokens.get("access_token"),
            "auto_access_token": ford_tokens.get("auto_access_token"),
            "refresh_token": ford_tokens.get("refresh_token"),
            "auto_refresh_token": ford_tokens.get("auto_refresh_token"),
            "expiry_date": ford_tokens.get("expiry_date"),
            "auto_expiry_date": ford_tokens.get("auto_expiry_date"),
        }

