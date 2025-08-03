"""OAuth 2.0 Resource Protection using Authlib's ResourceProtector
Following security best practices - NO AD-HOC IMPLEMENTATIONS!
"""

from datetime import datetime, timezone
from typing import Any, Optional

import redis.asyncio as redis
from authlib.jose import JsonWebToken
from authlib.jose.errors import JoseError
from authlib.oauth2 import ResourceProtector
from authlib.oauth2.rfc6750 import BearerTokenValidator
from authlib.oauth2.rfc6750.errors import InvalidTokenError as BearerTokenError

from .config import Settings
from .keys import RSAKeyManager


class JWTBearerTokenValidator(BearerTokenValidator):
    """JWT Bearer token validator for Authlib's ResourceProtector.
    This replaces the custom verify_jwt_token implementation with
    Authlib's battle-tested security framework.
    """

    def __init__(self, settings: Settings, redis_client: redis.Redis, key_manager: RSAKeyManager):
        super().__init__()
        self.settings = settings
        self.redis_client = redis_client
        self.key_manager = key_manager
        self.jwt = JsonWebToken(algorithms=[settings.jwt_algorithm])

    async def authenticate_token(self, token_string: str) -> Optional[dict[str, Any]]:
        """Authenticate the bearer token with comprehensive logging.
        This method is called by ResourceProtector to validate tokens.

        Returns:
            Token claims if valid, None if invalid

        """
        from ...shared.logging import get_logger
        logger = get_logger(__name__)
        
        token_preview = token_string[:20] + "..." if len(token_string) > 20 else token_string
        
        logger.debug(
            "Starting JWT token authentication - DETAILED VALIDATION",
            token_preview=token_preview,
            jwt_algorithm=self.settings.jwt_algorithm,
            expected_issuer=f"https://auth.{self.settings.base_domain}",
            has_rsa_key=hasattr(self.key_manager, 'public_key') and self.key_manager.public_key is not None
        )
        
        try:
            # Decode and validate token using Authlib
            claims = None
            expected_issuer = f"https://auth.{self.settings.base_domain}"
            
            if self.settings.jwt_algorithm == "RS256":
                logger.debug(
                    "Using RS256 algorithm for token validation",
                    token_preview=token_preview,
                    public_key_available=self.key_manager.public_key is not None
                )
                # Use RSA public key for RS256 verification
                claims = self.jwt.decode(
                    token_string,
                    self.key_manager.public_key,
                    claims_options={
                        "iss": {
                            "essential": True,
                            "value": expected_issuer,
                        },
                        "exp": {"essential": True},
                        "jti": {"essential": True},
                    },
                )
            else:
                logger.debug(
                    "Using HS256 fallback algorithm for token validation",
                    token_preview=token_preview,
                    has_jwt_secret=bool(self.settings.jwt_secret)
                )
                # HS256 fallback during transition period
                claims = self.jwt.decode(
                    token_string,
                    self.settings.jwt_secret,
                    claims_options={
                        "iss": {
                            "essential": True,
                            "value": expected_issuer,
                        },
                        "exp": {"essential": True},
                        "jti": {"essential": True},
                    },
                )

            logger.debug(
                "JWT token decoded successfully - CLAIMS EXTRACTED",
                token_preview=token_preview,
                claims_keys=list(claims.keys()),
                token_jti=claims.get("jti"),
                token_sub=claims.get("sub"),
                token_iss=claims.get("iss"),
                token_aud=claims.get("aud"),
                token_exp=claims.get("exp"),
                token_iat=claims.get("iat"),
                token_azp=claims.get("azp"),
                token_scope=claims.get("scope"),
                claims_count=len(claims)
            )

            # Validate claims
            claims.validate()
            logger.debug("JWT claims validation passed", token_jti=claims.get("jti"))

            # Check if token exists in Redis (not revoked)
            jti = claims["jti"]
            token_key = f"oauth:token:{jti}"
            token_data = await self.redis_client.get(token_key)

            logger.debug(
                "Checking token revocation status in Redis",
                token_jti=jti,
                redis_key=token_key,
                token_exists_in_redis=bool(token_data),
                token_data_preview=str(token_data)[:100] if token_data else "None"
            )

            if not token_data:
                # Token has been revoked or doesn't exist
                logger.warning(
                    "JWT token validation failed - token revoked or not found in Redis",
                    token_jti=jti,
                    token_preview=token_preview,
                    redis_key=token_key,
                    failure_reason="token_revoked_or_not_found"
                )
                return None

            logger.info(
                "JWT token authentication successful - TOKEN VALIDATED",
                token_jti=jti,
                token_sub=claims.get("sub"),
                token_username=claims.get("username"),
                token_client_id=claims.get("azp"),
                token_scope=claims.get("scope"),
                token_aud=claims.get("aud"),
                validation_algorithm=self.settings.jwt_algorithm,
                redis_validation="passed"
            )

            # Return claims as dict for ResourceProtector
            return dict(claims)

        except JoseError as e:
            # Token validation failed
            logger.error(
                "JWT validation failed - JOSE error",
                token_preview=token_preview,
                error_type=type(e).__name__,
                error_message=str(e),
                jwt_algorithm=self.settings.jwt_algorithm,
                expected_issuer=expected_issuer,
                validation_stage="jwt_decode"
            )
            return None
        except Exception as e:
            logger.error(
                "JWT validation failed - unexpected error",
                token_preview=token_preview,
                error_type=type(e).__name__,
                error_message=str(e),
                jwt_algorithm=self.settings.jwt_algorithm,
                validation_stage="general_validation",
                exc_info=True
            )
            return None

    def request_invalid(self, request) -> Optional[str]:
        """Check if the request is invalid.
        Returns an error message if invalid, None if valid.
        """
        # Get authorization header
        auth_header = request.headers.get("Authorization", "")

        if not auth_header:
            return "Missing Authorization header"

        if not auth_header.startswith("Bearer "):
            return "Authorization header must use Bearer scheme"

        # Token will be validated in authenticate_token
        return None

    def token_revoked(self, token: dict[str, Any]) -> bool:
        """Check if the token has been revoked.
        Since we already check Redis in authenticate_token,
        we can return False here.
        """
        return False


class IntrospectionBearerTokenValidator(JWTBearerTokenValidator):
    """Extended validator for token introspection endpoint.
    Allows introspection of expired tokens.
    """

    async def authenticate_token(self, token_string: str) -> Optional[dict[str, Any]]:
        """Authenticate token for introspection - allows expired tokens."""
        try:
            # Decode without exp validation for introspection
            if self.settings.jwt_algorithm == "RS256":
                claims = self.jwt.decode(
                    token_string,
                    self.key_manager.public_key,
                    claims_options={
                        "iss": {
                            "essential": True,
                            "value": f"https://auth.{self.settings.base_domain}",
                        },
                        "jti": {"essential": True},
                        "exp": {"essential": False},  # Don't require valid exp for introspection
                    },
                )
            else:
                claims = self.jwt.decode(
                    token_string,
                    self.settings.jwt_secret,
                    claims_options={
                        "iss": {
                            "essential": True,
                            "value": f"https://auth.{self.settings.base_domain}",
                        },
                        "jti": {"essential": True},
                        "exp": {"essential": False},
                    },
                )

            # Check if token exists in Redis
            jti = claims.get("jti")
            if jti:
                token_data = await self.redis_client.get(f"oauth:token:{jti}")
                if token_data:
                    # Add active status based on expiration
                    claims["active"] = claims.get("exp", 0) > datetime.now(timezone.utc).timestamp()
                    return dict(claims)

            # Token not in Redis - it's been revoked
            return {"active": False}

        except JoseError:
            # Can't decode token - return inactive
            return {"active": False}


def create_resource_protector(
    settings: Settings,
    redis_client: redis.Redis,
    key_manager: RSAKeyManager,
) -> ResourceProtector:
    """Create and configure a ResourceProtector instance.
    This replaces the manual token validation with Authlib's secure implementation.
    """
    # Create the resource protector
    require_oauth = ResourceProtector()

    # Register our JWT bearer token validator
    validator = JWTBearerTokenValidator(settings, redis_client, key_manager)
    require_oauth.register_token_validator(validator)

    return require_oauth


def create_introspection_protector(
    settings: Settings,
    redis_client: redis.Redis,
    key_manager: RSAKeyManager,
) -> ResourceProtector:
    """Create a ResourceProtector specifically for token introspection.
    This allows inspection of expired tokens.
    """
    # Create the resource protector
    introspect_oauth = ResourceProtector()

    # Register our introspection validator
    validator = IntrospectionBearerTokenValidator(settings, redis_client, key_manager)
    introspect_oauth.register_token_validator(validator)

    return introspect_oauth


# Error handler for OAuth errors
def handle_oauth_error(error: BearerTokenError) -> dict:
    """Convert Authlib OAuth errors to our error format."""
    return {"error": error.error, "error_description": error.description, "error_uri": error.uri}
