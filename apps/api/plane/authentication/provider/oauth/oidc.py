# Python imports
import json
import os
import uuid
from datetime import datetime
from urllib.parse import urlencode

import jwt
import pytz
import requests
from django.core.cache import cache
from jwt import PyJWKClient

from plane.authentication.adapter.error import (
    AUTHENTICATION_ERROR_CODES,
    AuthenticationException,
)

# Module imports
from plane.authentication.adapter.oauth import OauthAdapter
from plane.license.utils.instance_value import get_configuration_value


class OidcProvider(OauthAdapter):
    provider = "oidc"

    def __init__(self, request, code=None, state=None, callback=None):
        (OIDC_CLIENT_ID, OIDC_CLIENT_SECRET, OIDC_ISSUER_URL) = get_configuration_value(
            [
                {
                    "key": "OIDC_CLIENT_ID",
                    "default": os.environ.get("OIDC_CLIENT_ID"),
                },
                {
                    "key": "OIDC_CLIENT_SECRET",
                    "default": os.environ.get("OIDC_CLIENT_SECRET"),
                },
                {
                    "key": "OIDC_ISSUER_URL",
                    "default": os.environ.get("OIDC_ISSUER_URL"),
                },
            ]
        )

        if not (OIDC_CLIENT_ID and OIDC_CLIENT_SECRET and OIDC_ISSUER_URL):
            raise AuthenticationException(
                error_code=AUTHENTICATION_ERROR_CODES["OIDC_NOT_CONFIGURED"],
                error_message="OIDC_NOT_CONFIGURED",
            )

        # Discover OIDC endpoints
        try:
            oidc_config_url = f"{OIDC_ISSUER_URL.rstrip('/')}/.well-known/openid-configuration"
            response = requests.get(oidc_config_url, timeout=10)
            response.raise_for_status()
            oidc_config = response.json()

            auth_url_base = oidc_config.get("authorization_endpoint")
            token_url = oidc_config.get("token_endpoint")
            userinfo_url = oidc_config.get("userinfo_endpoint")
            self.jwks_uri = oidc_config.get("jwks_uri")
            self.issuer = oidc_config.get("issuer")

            if not all([auth_url_base, token_url, userinfo_url, self.jwks_uri]):
                raise ValueError("Missing required OIDC endpoints in discovery document")

        except (requests.RequestException, ValueError, KeyError) as e:
            raise AuthenticationException(
                error_code=AUTHENTICATION_ERROR_CODES["OIDC_DISCOVERY_FAILED"],
                error_message=f"OIDC_DISCOVERY_FAILED: {str(e)}",
            )

        client_id = OIDC_CLIENT_ID
        client_secret = OIDC_CLIENT_SECRET
        scope = "openid profile email"

        # Store state for later reference
        self.state = state

        redirect_uri = f"""{"https" if request.is_secure() else "http"}://{request.get_host()}/auth/oidc/callback/"""

        # Only generate and store nonce during initiate (when code is None)
        # During callback, we retrieve the existing nonce
        if code is None:
            # This is the initiate flow - generate new nonce
            nonce = uuid.uuid4().hex
            # Store nonce in Redis using state as key (more reliable than session cookies for OAuth redirects)
            if state:
                import logging

                logger = logging.getLogger("plane.api")

                # Store in Redis with longer timeout for reliability
                cache_key = f"oidc_nonce_{state}"
                cache.set(cache_key, nonce, timeout=900)  # 15 minute expiry

                # Verify it was stored
                stored_value = cache.get(cache_key)
                logger.info(
                    f"OIDC initiate - state: {state}, nonce: {nonce}, stored in Redis: {stored_value}, verified: {stored_value == nonce}"
                )

            # Also store in session as fallback
            request.session[f"oidc_nonce_{state}"] = nonce
            request.session.modified = True
        else:
            # This is the callback flow - retrieve existing nonce (will be set later)
            nonce = None

        url_params = {
            "client_id": client_id,
            "scope": scope,
            "redirect_uri": redirect_uri,
            "response_type": "code",
            "state": state,
            "nonce": nonce,
        }
        auth_url = f"{auth_url_base}?{urlencode(url_params)}"

        super().__init__(
            request,
            self.provider,
            client_id,
            scope,
            redirect_uri,
            auth_url,
            token_url,
            userinfo_url,
            client_secret,
            code,
            callback=callback,
        )

        self.oidc_issuer_url = OIDC_ISSUER_URL
        # Retrieve nonce from Redis first (more reliable), fallback to session
        import logging

        logger = logging.getLogger("plane.api")

        self.oidc_nonce = None
        if state:
            cache_key = f"oidc_nonce_{state}"
            self.oidc_nonce = cache.get(cache_key)
            logger.info(f"OIDC callback - state: {state}, nonce from Redis: {self.oidc_nonce}")

        if not self.oidc_nonce and state:
            # Try session with state-specific key
            self.oidc_nonce = request.session.get(f"oidc_nonce_{state}")
            if self.oidc_nonce:
                logger.info(f"OIDC callback - using session nonce (state-specific): {self.oidc_nonce}")

    def validate_id_token(self, id_token):
        """Validate ID token signature and claims"""
        try:
            # Get JWKS for signature verification
            jwks_client = PyJWKClient(self.jwks_uri)
            signing_key = jwks_client.get_signing_key_from_jwt(id_token)

            # Decode and validate ID token
            decoded_token = jwt.decode(
                id_token,
                signing_key.key,
                algorithms=["RS256"],
                audience=self.client_id,
                issuer=self.issuer,
                options={"verify_exp": True, "verify_iat": True},
            )

            # Validate nonce
            token_nonce = decoded_token.get("nonce")
            if not self.oidc_nonce:
                import logging

                logger = logging.getLogger("plane.api")
                logger.error(
                    f"No nonce found in storage. Token nonce: {token_nonce}, state: {getattr(self, 'state', 'unknown')}"
                )
                raise ValueError(f"No nonce found in session. Token nonce: {token_nonce}")
            if token_nonce != self.oidc_nonce:
                import logging

                logger = logging.getLogger("plane.api")
                logger.error(
                    f"Nonce mismatch. Expected: {self.oidc_nonce}, Got: {token_nonce}, state: {getattr(self, 'state', 'unknown')}"
                )
                raise ValueError(f"Invalid nonce in ID token. Expected: {self.oidc_nonce}, Got: {token_nonce}")

            return decoded_token

        except Exception as e:
            raise AuthenticationException(
                error_code=AUTHENTICATION_ERROR_CODES["OIDC_INVALID_ID_TOKEN"],
                error_message=f"OIDC_INVALID_ID_TOKEN: {str(e)}",
            )

    def set_token_data(self):
        data = {
            "code": self.code,
            "client_id": self.client_id,
            "client_secret": self.client_secret,
            "redirect_uri": self.redirect_uri,
            "grant_type": "authorization_code",
        }
        token_response = self.get_user_token(data=data)

        # Validate ID token if present
        id_token = token_response.get("id_token", "")
        if id_token:
            self.id_token_claims = self.validate_id_token(id_token)
        else:
            self.id_token_claims = {}

        super().set_token_data(
            {
                "access_token": token_response.get("access_token"),
                "refresh_token": token_response.get("refresh_token", None),
                "access_token_expired_at": (
                    datetime.fromtimestamp(token_response.get("expires_in"), tz=pytz.utc)
                    if token_response.get("expires_in")
                    else None
                ),
                "refresh_token_expired_at": None,
                "id_token": id_token,
            }
        )

    def set_user_data(self):
        # Try to get user info from ID token first, then fall back to userinfo endpoint
        if self.id_token_claims:
            email = self.id_token_claims.get("email")
            name = self.id_token_claims.get("name", "")
            given_name = self.id_token_claims.get("given_name", "")
            family_name = self.id_token_claims.get("family_name", "")
            picture = self.id_token_claims.get("picture", "")
            sub = self.id_token_claims.get("sub")
        else:
            # Fall back to userinfo endpoint
            user_info_response = self.get_user_response()
            email = user_info_response.get("email")
            name = user_info_response.get("name", "")
            given_name = user_info_response.get("given_name", "")
            family_name = user_info_response.get("family_name", "")
            picture = user_info_response.get("picture", "")
            sub = user_info_response.get("sub")

        # Parse name if first/last not provided
        if not given_name and not family_name and name:
            name_parts = name.split(" ", 1)
            given_name = name_parts[0]
            family_name = name_parts[1] if len(name_parts) > 1 else ""

        user_data = {
            "email": email,
            "user": {
                "avatar": picture,
                "first_name": given_name,
                "last_name": family_name,
                "provider_id": sub,
                "is_password_autoset": True,
            },
        }
        super().set_user_data(user_data)
