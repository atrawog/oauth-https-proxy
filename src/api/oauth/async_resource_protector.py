"""Async-compatible ResourceProtector for FastAPI
Since Authlib's ResourceProtector doesn't support async natively,
we create a wrapper that works with FastAPI's async handlers.
"""

from typing import Any, Optional

import redis.asyncio as redis
from fastapi import HTTPException, Request

from .config import Settings
from .keys import RSAKeyManager
from .resource_protector import JWTBearerTokenValidator
from ...shared.logger import log_debug, log_info, log_warning, log_error, log_trace
from ...shared.client_ip import get_real_client_ip




class AsyncResourceProtector:
    """Async wrapper for Authlib's ResourceProtector that works with FastAPI.
    This maintains the security benefits of ResourceProtector while supporting async operations.
    """

    def __init__(self, settings: Settings, redis_client: redis.Redis, key_manager: RSAKeyManager):
        self.settings = settings
        self.redis_client = redis_client
        self.key_manager = key_manager
        self.validator = JWTBearerTokenValidator(settings, redis_client, key_manager)

    async def validate_request(self, request: Request, resource: Optional[str] = None) -> Optional[dict[str, Any]]:
        """Validate the request and extract token information.

        Args:
            request: FastAPI Request object
            resource: Optional resource URI for audience validation

        Returns:
            Token claims if valid, raises HTTPException if invalid

        """
        # Build WWW-Authenticate header with metadata URLs (RFC 9728)
        auth_server_url = f"https://auth.{self.settings.base_domain}"
        
        # If resource is provided, construct resource metadata URL
        if resource:
            # Parse resource URL to get host
            from urllib.parse import urlparse
            parsed = urlparse(resource)
            resource_host = parsed.netloc or parsed.path
            resource_metadata_url = f"{resource}/.well-known/oauth-protected-resource"
        else:
            # Use request host as resource
            host = request.headers.get("host", "localhost")
            proto = request.headers.get("x-forwarded-proto", "https")
            resource = f"{proto}://{host}"
            resource_metadata_url = f"{resource}/.well-known/oauth-protected-resource"
        
        www_auth_params = [
            'Bearer',
            f'realm="Protected Resource"',
            f'as_uri="{auth_server_url}/.well-known/oauth-authorization-server"',
            f'resource_uri="{resource_metadata_url}"'
        ]
        www_authenticate = ", ".join(www_auth_params)
        
        # Check if request is valid
        error = self.validator.request_invalid(request)
        if error:
            raise HTTPException(
                status_code=401,
                detail={"error": "invalid_request", "error_description": error},
                headers={"WWW-Authenticate": www_authenticate},
            )

        # Extract token from Authorization header
        auth_header = request.headers.get("Authorization", "")
        if not auth_header.startswith("Bearer "):
            raise HTTPException(
                status_code=401,
                detail={
                    "error": "invalid_request",
                    "error_description": "Authorization header must use Bearer scheme",
                },
                headers={"WWW-Authenticate": www_authenticate},
            )

        token_string = auth_header[7:]  # Remove "Bearer " prefix

        # Extract client IP using centralized function
        client_ip = get_real_client_ip(request)
        
        log_debug(
            "Starting token validation - DETAILED CONTEXT",
            client_ip=client_ip,
            resource=resource,
            token_preview=token_string[:20] + "..." if len(token_string) > 20 else token_string,
            jwt_algorithm=self.settings.jwt_algorithm,
            expected_issuer=f"https://auth.{self.settings.base_domain}",
            resource_metadata_url=resource_metadata_url if resource else None
        )
        
        # Validate token asynchronously
        token_data = await self.validator.authenticate_token(token_string)

        if not token_data:
            log_warning(
                "Token validation FAILED - invalid or expired token",
                client_ip=client_ip,
                resource=resource,
                token_preview=token_string[:20] + "..." if len(token_string) > 20 else token_string,
                jwt_algorithm=self.settings.jwt_algorithm,
                expected_issuer=f"https://auth.{self.settings.base_domain}",
                validation_failure="token_invalid_or_expired"
            )
            # Add error parameter to WWW-Authenticate
            www_auth_error = www_authenticate.replace('Bearer', 'Bearer error="invalid_token"')
            raise HTTPException(
                status_code=401,
                detail={
                    "error": "invalid_token",
                    "error_description": "The access token is invalid or expired",
                    "debug_info": {
                        "client_ip": client_ip,
                        "resource": resource
                    }
                },
                headers={"WWW-Authenticate": www_auth_error},
            )
        else:
            log_info(
                "Token validation SUCCESSFUL - token is valid",
                client_ip=client_ip,
                resource=resource,
                token_jti=token_data.get("jti"),
                token_sub=token_data.get("sub"),
                token_username=token_data.get("username"),
                token_client_id=token_data.get("azp"),
                token_scope=token_data.get("scope"),
                token_aud=token_data.get("aud")
            )

        # Validate audience if resource is specified
        if resource and token_data:
            aud = token_data.get("aud", [])
            # Normalize audience to list
            if isinstance(aud, str):
                aud = [aud]
            
            # Extract client IP using centralized function
            client_ip = get_real_client_ip(request)
            
            # Get allowed audiences from proxy configuration (passed via headers)
            allowed_audiences_header = request.headers.get("x-auth-allowed-audiences", "")
            allowed_audiences = []
            if allowed_audiences_header:
                allowed_audiences = [a.strip() for a in allowed_audiences_header.split(",") if a.strip()]
            
            log_info(
                "Starting token audience validation - DETAILED CONTEXT",
                client_ip=client_ip,
                requested_resource=resource,
                token_aud=aud,
                token_aud_type=type(aud).__name__,
                token_aud_count=len(aud),
                allowed_audiences=allowed_audiences,
                allowed_audiences_count=len(allowed_audiences),
                token_jti=token_data.get("jti"),
                token_sub=token_data.get("sub"),
                token_username=token_data.get("username"),
                token_client_id=token_data.get("azp"),
                token_scope=token_data.get("scope"),
                token_exp=token_data.get("exp"),
                token_iat=token_data.get("iat"),
                token_iss=token_data.get("iss"),
                request_headers={
                    "host": request.headers.get("host"),
                    "x-forwarded-host": request.headers.get("x-forwarded-host"),
                    "x-forwarded-proto": request.headers.get("x-forwarded-proto"),
                    "x-auth-allowed-audiences": allowed_audiences_header
                }
            )
            
            # Check if resource is in audience OR if any token audience is in allowed audiences
            resource_in_aud = resource in aud
            allowed_aud_match = False
            if allowed_audiences:
                # Check if any token audience is in the allowed list
                allowed_aud_match = any(token_aud in allowed_audiences for token_aud in aud)
            
            if not resource_in_aud and not allowed_aud_match:
                log_error(
                    "Token audience validation FAILED - CRITICAL: 403 invalid_audience error",
                    client_ip=client_ip,
                    requested_resource=resource,
                    token_aud=aud,
                    token_aud_type=type(aud).__name__,
                    token_aud_count=len(aud),
                    token_jti=token_data.get("jti"),
                    token_sub=token_data.get("sub"),
                    token_username=token_data.get("username"),
                    token_client_id=token_data.get("azp"),
                    token_scope=token_data.get("scope"),
                    token_iss=token_data.get("iss"),
                    audience_mismatch_details={
                        "expected_resource": resource,
                        "actual_audience": aud,
                        "allowed_audiences": allowed_audiences,
                        "audience_contains_resource": resource_in_aud,
                        "allowed_audience_match": allowed_aud_match,
                        "case_sensitive_match": any(res.lower() == resource.lower() for res in aud) if isinstance(aud, list) else False
                    },
                    request_context={
                        "client_ip": client_ip,
                        "host_header": request.headers.get("host"),
                        "forwarded_host": request.headers.get("x-forwarded-host"),
                        "forwarded_proto": request.headers.get("x-forwarded-proto"),
                        "user_agent": request.headers.get("user-agent"),
                        "method": request.method,
                        "path": str(request.url.path)
                    },
                    token_complete_claims={
                        k: v for k, v in token_data.items() 
                        if k not in ["access_token", "refresh_token"]
                    },
                    debugging_hints=[
                        f"Token was issued for audience: {aud}",
                        f"Request is for resource: {resource}",
                        "Check if the OAuth authorization included the correct resource parameter",
                        "Verify the client requested the correct resource during token exchange"
                    ]
                )
                www_auth_error = www_authenticate.replace('Bearer', 'Bearer error="invalid_audience"')
                raise HTTPException(
                    status_code=403,
                    detail={
                        "error": "invalid_audience",
                        "error_description": f"Token is not valid for resource: {resource}",
                        "debug_info": {
                            "requested_resource": resource,
                            "token_audience": aud,
                            "client_ip": client_ip
                        }
                    },
                    headers={"WWW-Authenticate": www_auth_error},
                )
            else:
                log_info(
                    "Token audience validation SUCCESSFUL",
                    client_ip=client_ip,
                    requested_resource=resource,
                    token_aud=aud,
                    allowed_audiences=allowed_audiences,
                    resource_in_aud=resource_in_aud,
                    allowed_aud_match=allowed_aud_match,
                    validation_result="passed",
                    validation_reason="resource_match" if resource_in_aud else "allowed_audience_match",
                    token_jti=token_data.get("jti"),
                    token_sub=token_data.get("sub"),
                    token_username=token_data.get("username")
                )

        return token_data


def create_async_resource_protector(
    settings: Settings,
    redis_client: redis.Redis,
    key_manager: RSAKeyManager,
) -> AsyncResourceProtector:
    """Create an async-compatible ResourceProtector instance.

    Args:
        settings: Application settings
        redis_client: Redis client for token storage
        key_manager: RSA key manager for JWT validation

    Returns:
        AsyncResourceProtector instance

    """
    return AsyncResourceProtector(settings, redis_client, key_manager)
