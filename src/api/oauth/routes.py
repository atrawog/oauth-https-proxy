"""OAuth 2.1 and RFC 7591 compliant routes with Authlib ResourceProtector
Using Authlib's security framework instead of custom implementations
"""

import json
import jwt
import logging
import secrets
import time
import traceback
from typing import Optional
from urllib.parse import urlencode

import redis.asyncio as redis
from fastapi import APIRouter, Depends, Form, HTTPException, Query, Request, Response
from fastapi.responses import HTMLResponse, RedirectResponse

from .async_resource_protector import create_async_resource_protector
from .auth_authlib import AuthManager
from .config import Settings
from .models import ClientRegistration, TokenResponse
from .rfc7592 import DynamicClientConfigurationEndpoint
from ...shared.logging import get_logger, log_request, log_response
from ...shared.config import Config
from ...shared.client_ip import get_real_client_ip

# Set up logging
logger = get_logger(__name__)


def get_external_url(request: Request, settings: Settings) -> str:
    """Get the external URL for this service from request headers.
    
    Handles proxied requests by checking X-Forwarded headers first.
    """
    # Get host from X-Forwarded-Host (set by proxy) or Host header
    host = request.headers.get("x-forwarded-host") or request.headers.get("host", f"auth.{settings.base_domain}")
    # Remove port if present
    if ":" in host:
        host = host.split(":")[0]
    
    # Get protocol from X-Forwarded-Proto (set by proxy) or request scheme
    proto = request.headers.get("x-forwarded-proto") or request.url.scheme
    
    return f"{proto}://{host}"


def create_oauth_router(settings: Settings, redis_manager, auth_manager: AuthManager) -> APIRouter:
    """Create OAuth router with all endpoints using Authlib ResourceProtector"""
    router = APIRouter()

    # Create AsyncResourceProtector instance - defer Redis client access until runtime
    require_oauth = None

    async def get_redis() -> redis.Redis:
        """Dependency to get Redis client"""
        return redis_manager.client

    # Custom dependency that uses AsyncResourceProtector
    async def verify_bearer_token(request: Request):
        """Verify bearer token using Authlib ResourceProtector"""
        # Create resource protector lazily to ensure Redis is initialized
        nonlocal require_oauth
        if require_oauth is None:
            require_oauth = create_async_resource_protector(
                settings,
                redis_manager.client,
                auth_manager.key_manager,
            )
        # AsyncResourceProtector handles all validation and error raising
        token = await require_oauth.validate_request(request)
        return token

    async def verify_github_user_auth(request: Request, token=Depends(verify_bearer_token)) -> str:
        """Dependency to verify GitHub user authentication for admin operations"""
        # Token is already validated by ResourceProtector
        username = token.get("username")

        if not username:
            raise HTTPException(
                status_code=403,
                detail={"error": "access_denied", "error_description": "No username in token"},
            )

        # Check if user is in allowed list
        allowed_users = (
            settings.allowed_github_users.split(",") if settings.allowed_github_users else []
        )
        # If ALLOWED_GITHUB_USERS is set to '*', allow any authenticated GitHub user
        if allowed_users and "*" not in allowed_users and username not in allowed_users:
            raise HTTPException(
                status_code=403,
                detail={
                    "error": "access_denied",
                    "error_description": f"User '{username}' not authorized for client registration",  # TODO: Break long line
                },
            )

        return username

    # .well-known/oauth-authorization-server endpoint (RFC 8414)
    @router.get("/.well-known/oauth-authorization-server")
    async def oauth_metadata(request: Request):
        """Server metadata shrine - reveals our OAuth capabilities"""
        # Get the external URL for this service
        api_url = get_external_url(request, settings)
        
        return {
            "issuer": api_url,
            "authorization_endpoint": f"{api_url}/authorize",
            "token_endpoint": f"{api_url}/token",
            "registration_endpoint": f"{api_url}/register",
            "jwks_uri": f"{api_url}/jwks",
            "response_types_supported": ["code"],
            "subject_types_supported": ["public"],
            "id_token_signing_alg_values_supported": ["HS256", "RS256"],
            "scopes_supported": ["openid", "profile", "email", "mcp:read", "mcp:write", "mcp:session"],
            "token_endpoint_auth_methods_supported": ["client_secret_post", "client_secret_basic"],
            "claims_supported": ["sub", "name", "email", "preferred_username", "aud", "azp"],
            "code_challenge_methods_supported": ["S256"],
            "grant_types_supported": ["authorization_code", "refresh_token"],
            "revocation_endpoint": f"{api_url}/revoke",
            "introspection_endpoint": f"{api_url}/introspect",
            "service_documentation": f"{api_url}/docs",
            "op_policy_uri": f"{api_url}/policy",
            "op_tos_uri": f"{api_url}/terms",
            # RFC 8707 Resource Indicators
            "resource_indicators_supported": True,
            "resource_parameter_supported": True,
            "authorization_response_iss_parameter_supported": True
        }

    # JWKS endpoint for RS256 public key distribution
    @router.get("/jwks")
    async def jwks():
        """JSON Web Key Set endpoint - distributes the divine RS256 public key!"""
        jwk = auth_manager.key_manager.get_jwk()
        return {"keys": [jwk]}

    # Dynamic Client Registration endpoint (RFC 7591) - PUBLIC ACCESS
    @router.post("/register", status_code=201)
    async def register_client(
        request: Request,
        registration: ClientRegistration,
        redis_client: redis.Redis = Depends(get_redis),
    ):
        """The Divine Registration Portal - RFC 7591 compliant - PUBLIC ACCESS"""
        # Get client IP
        client_ip = get_real_client_ip(request)
        
        logger.info(
            "OAuth client registration request",
            ip=client_ip,
            client_name=registration.client_name,
            software_id=registration.software_id,
            redirect_uris=registration.redirect_uris,
            scope=registration.scope
        )
        # Validate redirect URIs - RFC 7591 compliance
        if not registration.redirect_uris:
            raise HTTPException(
                status_code=400,
                detail={
                    "error": "invalid_client_metadata",
                    "error_description": "redirect_uris is required",
                },
            )

        # Validate each redirect URI
        for uri in registration.redirect_uris:
            if not uri or not isinstance(uri, str):
                raise HTTPException(
                    status_code=400,
                    detail={
                        "error": "invalid_redirect_uri",
                        "error_description": "Invalid redirect URI format",
                    },
                )

            # RFC 7591 - Must be HTTPS (except localhost)
            if uri.startswith("http://"):
                if not any(
                    uri.startswith(f"http://{host}")
                    for host in ["localhost", "127.0.0.1", "[::1]"]  # TODO: Break long line
                ):
                    raise HTTPException(
                        status_code=400,
                        detail={
                            "error": "invalid_redirect_uri",
                            "error_description": "HTTP redirect URIs are only allowed for localhost",
                        },
                    )
            elif not uri.startswith("https://") and ":" not in uri:
                raise HTTPException(
                    status_code=400,
                    detail={
                        "error": "invalid_redirect_uri",
                        "error_description": "Redirect URI must use HTTPS or be an app-specific URI",
                    },
                )

        # Generate client credentials
        credentials = auth_manager.generate_client_credentials()
        client_id = credentials["client_id"]
        client_secret = credentials["client_secret"]

        # Calculate client expiration time
        created_at = int(time.time())
        expires_at = 0 if settings.client_lifetime == 0 else created_at + settings.client_lifetime

        # Generate registration access token for RFC 7592 management
        registration_access_token = f"reg-{secrets.token_urlsafe(32)}"

        # Store client in Redis
        client_data = {
            "client_id": client_id,
            "client_secret": client_secret,
            "client_secret_expires_at": expires_at,
            "client_id_issued_at": created_at,
            "redirect_uris": json.dumps(registration.redirect_uris),
            "client_name": registration.client_name or "Unnamed Client",
            "scope": registration.scope or "openid profile email",
            "created_at": created_at,
            "response_types": json.dumps(["code"]),
            "grant_types": json.dumps(["authorization_code", "refresh_token"]),
            "registration_access_token": registration_access_token,
        }

        # Store with expiration matching client lifetime
        if settings.client_lifetime > 0:
            await redis_client.setex(
                f"oauth:client:{client_id}",
                settings.client_lifetime,
                json.dumps(client_data),  # TODO: Break long line
            )
        else:
            await redis_client.set(f"oauth:client:{client_id}", json.dumps(client_data))

        # Return registration response per RFC 7591
        response = {
            "client_id": client_id,
            "client_secret": client_secret,
            "client_secret_expires_at": expires_at,
            "client_id_issued_at": created_at,
            "redirect_uris": registration.redirect_uris,
            "client_name": registration.client_name,
            "scope": registration.scope,
            "registration_access_token": registration_access_token,
            "registration_client_uri": f"https://auth.{settings.base_domain}/register/{client_id}",  # TODO: Break long line
        }

        # Echo back all registered metadata
        for field in ["client_uri", "logo_uri", "contacts", "tos_uri", "policy_uri"]:
            value = getattr(registration, field, None)
            if value is not None:
                response[field] = value

        logger.info(
            "OAuth client registered successfully",
            ip=client_ip,
            client_id=client_id,
            client_name=registration.client_name,
            redirect_uris=registration.redirect_uris,
            scope=registration.scope
        )

        return response

    # Authorization endpoint
    @router.get("/authorize")
    async def authorize(
        request: Request,
        client_id: str = Query(...),
        redirect_uri: str = Query(...),
        response_type: str = Query(...),
        scope: str = Query("openid profile email"),
        state: str = Query(...),
        code_challenge: Optional[str] = Query(None),
        code_challenge_method: Optional[str] = Query("S256"),
        resource: Optional[list[str]] = Query(None),  # RFC 8707 Resource Indicators
        proxy_hostname: Optional[str] = Query(None),  # Proxy hostname for per-proxy GitHub user allowlists
        redis_client: redis.Redis = Depends(get_redis),
    ):
        """Portal to authentication realm - initiates GitHub OAuth flow"""
        # Get client IP
        client_ip = get_real_client_ip(request)
        
        logger.info(
            "OAuth authorization request - DETAILED WITH RESOURCES",
            ip=client_ip,
            client_id=client_id,
            redirect_uri=redirect_uri,
            scope=scope,
            state=state,
            resource=resource,
            resource_count=len(resource) if resource else 0,
            resource_details=[{"uri": r, "is_valid_url": r.startswith(("http://", "https://"))} for r in (resource or [])],
            code_challenge=bool(code_challenge),
            code_challenge_method=code_challenge_method if code_challenge else None,
            response_type=response_type,
            request_url=str(request.url),
            request_headers={k: v for k, v in request.headers.items() if k.lower() not in ['authorization', 'cookie']}
        )
        
        # Log request with OAuth context and store context
        request_context = await log_request(
            logger,
            request,
            client_ip,
            hostname=request.headers.get("host"),
            oauth_action="authorize",
            oauth_client_id=client_id,
            oauth_redirect_uri=redirect_uri,
            oauth_response_type=response_type,
            oauth_scope=scope,
            oauth_state=state,
            oauth_code_challenge=code_challenge[:8] + "..." if code_challenge else None,
            oauth_code_challenge_method=code_challenge_method,
            oauth_resources=resource if resource else [],
            oauth_resource_count=len(resource) if resource else 0
        )
        request_key = request_context.get("_request_key") if request_context else None
        # Validate client
        client = await auth_manager.get_client(client_id, redis_client)
        if not client:
            logger.warning(
                "OAuth authorization rejected - invalid client",
                ip=client_ip,
                client_id=client_id,
                oauth_rejection_reason="client_not_found",
                requested_redirect_uri=redirect_uri,
                requested_scope=scope
            )
            
            # Log the rejection in RequestLogger
            await log_response(
                logger,
                None,
                0,
                ip=client_ip,
                hostname=request.headers.get("host"),
                oauth_action="authorize_rejected",
                oauth_rejection_reason="invalid_client",
                oauth_client_id=client_id,
                oauth_authorization_granted="rejected",
                request_key=request_key
            )
            
            # RFC 6749 - MUST NOT redirect on invalid client_id
            return HTMLResponse(
                status_code=400,
                content=f"""
                <!DOCTYPE html>
                <html>
                <head>
                    <title>OAuth Client Registration Error</title>
                    <style>
                        body {{
                            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
                            padding: 40px;
                            max-width: 600px;
                            margin: 0 auto;
                            background-color: #f5f5f5;
                        }}
                        .error-container {{
                            background: white;
                            padding: 30px;
                            border-radius: 10px;
                            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
                        }}
                        h1 {{ color: #d73502; }}
                        .error-code {{
                            font-family: monospace;
                            background: #f0f0f0;
                            padding: 2px 6px;
                            border-radius: 3px;
                        }}
                        .client-id {{
                            word-break: break-all;
                            font-family: monospace;
                            font-size: 0.9em;
                        }}
                    </style>
                </head>
                <body>
                    <div class="error-container">
                        <h1>⚠️ OAuth Client Registration Invalid</h1>
                        <p>The application attempting to connect has an invalid or expired client registration.</p>

                        <p><strong>Technical Details:</strong></p>
                        <ul>
                            <li>Error: <span class="error-code">invalid_client</span></li>
                            <li>Client ID: <span class="client-id">{client_id}</span></li>
                        </ul>

                        <p style="margin-top: 30px; color: #666; font-size: 0.9em;">
                            For developers: The client should POST to
                            <code>{get_external_url(request, settings)}/register</code>
                            to obtain new credentials.
                        </p>
                    </div>
                </body>
                </html>
                """,
            )

        # Log successful client validation
        logger.info(
            "OAuth client validated",
            ip=client_ip,
            client_id=client_id,
            client_name=getattr(client, 'client_name', 'Unknown'),
            registered_redirect_uris=getattr(client, 'redirect_uris', [])
        )
        
        # Validate redirect_uri
        if not client.check_redirect_uri(redirect_uri):
            logger.warning(
                "OAuth authorization rejected - invalid redirect URI",
                ip=client_ip,
                client_id=client_id,
                oauth_rejection_reason="redirect_uri_not_registered",
                requested_redirect_uri=redirect_uri,
                registered_redirect_uris=getattr(client, 'redirect_uris', [])
            )
            
            await log_response(
                logger,
                None,
                0,
                ip=client_ip,
                hostname=request.headers.get("host"),
                oauth_action="authorize_rejected",
                oauth_rejection_reason="invalid_redirect_uri",
                oauth_client_id=client_id,
                oauth_authorization_granted="rejected"
            )
            
            raise HTTPException(
                status_code=400,
                detail={
                    "error": "invalid_redirect_uri",
                    "error_description": "Redirect URI not registered",
                },
            )

        # Validate response_type
        if not client.check_response_type(response_type):
            logger.warning(
                "OAuth authorization rejected - unsupported response type",
                ip=client_ip,
                client_id=client_id,
                oauth_rejection_reason="unsupported_response_type",
                requested_response_type=response_type,
                supported_response_types=getattr(client, 'response_types', ['code'])
            )
            
            await log_response(
                logger,
                None,
                0,
                ip=client_ip,
                hostname=request.headers.get("host"),
                oauth_action="authorize_rejected",
                oauth_rejection_reason="unsupported_response_type",
                oauth_client_id=client_id,
                oauth_authorization_granted="rejected"
            )
            
            return RedirectResponse(
                url=f"{redirect_uri}?error=unsupported_response_type&state={state}",
            )

        # Validate PKCE method
        if code_challenge and code_challenge_method != "S256":
            logger.warning(
                "OAuth authorization rejected - invalid PKCE method",
                ip=client_ip,
                client_id=client_id,
                oauth_rejection_reason="invalid_pkce_method",
                requested_pkce_method=code_challenge_method,
                supported_pkce_methods=["S256"]
            )
            
            await log_response(
                logger,
                None,
                0,
                ip=client_ip,
                hostname=request.headers.get("host"),
                oauth_action="authorize_rejected",
                oauth_rejection_reason="invalid_pkce_method",
                oauth_client_id=client_id,
                oauth_authorization_granted="rejected"
            )
            
            raise HTTPException(
                status_code=400,
                detail={
                    "error": "invalid_request",
                    "error_description": "Only S256 PKCE method is supported",
                },
            )

        # Validate resource parameters (RFC 8707)
        if resource:
            # Ensure all resources are valid URIs
            for res in resource:
                if not res.startswith(("http://", "https://")):
                    logger.warning(
                        "OAuth authorization rejected - invalid resource URI",
                        ip=client_ip,
                        client_id=client_id,
                        oauth_rejection_reason="invalid_resource_uri",
                        invalid_resource=res,
                        all_requested_resources=resource
                    )
                    
                    await log_response(
                        logger,
                        None,
                        0,
                        ip=client_ip,
                        hostname=request.headers.get("host"),
                        oauth_action="authorize_rejected",
                        oauth_rejection_reason="invalid_resource_uri",
                        oauth_client_id=client_id,
                        oauth_authorization_granted="rejected"
                    )
                    
                    return RedirectResponse(
                        url=f"{redirect_uri}?error=invalid_resource&error_description=Resource+must+be+a+valid+URI&state={state}",
                    )
            logger.info(
                "OAuth authorization accepted - all validations passed",
                ip=client_ip,
                client_id=client_id,
                resources=resource,
                scope=scope,
                has_pkce=bool(code_challenge)
            )

        # Store authorization request state
        auth_state = secrets.token_urlsafe(32)
        auth_data = {
            "client_id": client_id,
            "redirect_uri": redirect_uri,
            "scope": scope,
            "state": state,
            "code_challenge": code_challenge,
            "code_challenge_method": code_challenge_method,
            "resources": resource if resource else [],  # RFC 8707 Resource Indicators
            "proxy_hostname": proxy_hostname,  # Store proxy hostname for per-proxy GitHub user checks
        }

        await redis_client.setex(
            f"oauth:state:{auth_state}",
            300,
            json.dumps(auth_data),
        )  # TODO: Break long line
        logger.info(
            f"Created OAuth state: {auth_state} for client: {client_id}, original state: {state}",
        )

        # Redirect to GitHub OAuth
        # Get the external URL for the callback
        external_url = get_external_url(request, settings)
        github_params = {
            "client_id": settings.github_client_id,
            "redirect_uri": f"{external_url}/callback",
            "scope": "user:email",
            "state": auth_state,
        }

        github_url = f"https://github.com/login/oauth/authorize?{urlencode(github_params)}"  # TODO: Break long line
        
        # Log the redirect destination
        logger.info(
            "OAuth authorize redirecting to GitHub",
            ip=client_ip,
            client_id=client_id,
            redirect_to=github_url,
            auth_state=auth_state,
            oauth_validations_passed="all",
            oauth_authorization_decision="pending_user_consent"
        )
        
        response = RedirectResponse(
            url=github_url,
            status_code=307,
            headers={
                "Cache-Control": "no-cache, no-store, must-revalidate",
                "Pragma": "no-cache",
                "Expires": "0",
            },
        )
        
        # Log response with redirect info
        await log_response(
            logger,
            response,
            0,  # duration will be calculated by log_response
            ip=client_ip,
            hostname=request.headers.get("host"),
            oauth_action="authorize_redirect",
            oauth_redirect_to=github_url,
            oauth_authorization_granted="pending_github_auth"
        )
        
        return response

    # Callback endpoint
    @router.get("/callback")
    async def oauth_callback(
        request: Request,
        code: str = Query(...),
        state: str = Query(...),
        error: Optional[str] = Query(None),
        error_description: Optional[str] = Query(None),
        redis_client: redis.Redis = Depends(get_redis),
    ):
        """The blessed return path - handles GitHub OAuth callback"""
        # Get client IP
        client_ip = get_real_client_ip(request)
        
        logger.info(
            "OAuth callback received from GitHub",
            ip=client_ip,
            state=state,
            code_preview=f"{code[:8]}..." if code else "no code"
        )
        
        # Log request with OAuth context
        await log_request(
            logger,
            request,
            client_ip,
            hostname=request.headers.get("host"),
            oauth_action="callback",
            oauth_state=state,
            oauth_code=code[:8] + "..." if code else "no_code",
            oauth_error=error,
            oauth_error_description=error_description
        )
        
        # Retrieve authorization state
        auth_data_str = await redis_client.get(f"oauth:state:{state}")
        if not auth_data_str:
            logger.warning(
                "OAuth callback with invalid or expired state",
                    ip=client_ip,
                state=state
            )
            # Check if any similar states exist (for debugging)
            all_states = await redis_client.keys("oauth:state:*")
            logger.debug(f"Current states in Redis: {len(all_states)} total")

            # Redirect to user-friendly error page instead of returning JSON
            return RedirectResponse(
                url=f"/error?{urlencode({'error': 'invalid_request', 'error_description': 'Invalid or expired state. This usually happens when you take longer than 5 minutes to complete the authentication, or when you refresh an old authentication page.'})}",
                status_code=302,
                headers={
                    "Cache-Control": "no-cache, no-store, must-revalidate",
                    "Pragma": "no-cache",
                    "Expires": "0",
                },
            )

        auth_data = json.loads(auth_data_str)
        logger.debug(
            "OAuth state validated successfully",
            state=state,
            client_id=auth_data.get('client_id'),
            scope=auth_data.get('scope'),
            resources=auth_data.get('resources')
        )

        # Exchange GitHub code
        user_info = await auth_manager.exchange_github_code(code)

        if not user_info:
            logger.error(
                "Failed to exchange GitHub code",
                    ip=client_ip,
                client_id=auth_data.get('client_id')
            )
            return RedirectResponse(
                url=f"{auth_data['redirect_uri']}?error=server_error&state={auth_data['state']}",  # TODO: Break long line
            )

        logger.info(
            "GitHub code exchanged successfully",
            ip=client_ip,
            github_user_id=user_info.get("id"),
            github_username=user_info.get("login"),
            github_email=user_info.get("email")
        )
        
        # Update request log with GitHub user info
        await log_response(
            logger,
            Response(status_code=200),
            0,
            hostname=request.headers.get("host"),
            oauth_github_user_id=user_info.get("id"),
            oauth_github_username=user_info.get("login"),
            oauth_github_email=user_info.get("email")
        )

        # Check if user is allowed - first check proxy-specific, then fall back to global
        proxy_hostname = auth_data.get("proxy_hostname")
        allowed_users = []
        
        # Check if we have a proxy-specific user allowlist
        if proxy_hostname:
            from ....storage.redis_storage import RedisStorage
            storage = RedisStorage(redis_client)
            proxy_target = storage.get_proxy_target(proxy_hostname)
            
            if proxy_target and proxy_target.auth_required_users is not None:
                # Use proxy-specific list from auth_required_users
                allowed_users = proxy_target.auth_required_users
                logger.info(
                    "Using proxy-specific required users for GitHub authentication",
                    ip=client_ip,
                    proxy_hostname=proxy_hostname,
                    allowed_users=allowed_users
                )
            else:
                # Fall back to global list
                allowed_users = (
                    settings.allowed_github_users.split(",") if settings.allowed_github_users else []
                )
                logger.info(
                    "Using global GitHub allowed users (no proxy-specific required users)",
                    ip=client_ip,
                    proxy_hostname=proxy_hostname,
                    allowed_users=allowed_users
                )
        else:
            # No proxy specified, use global list
            allowed_users = (
                settings.allowed_github_users.split(",") if settings.allowed_github_users else []
            )
            logger.info(
                "Using global GitHub allowed users (no proxy specified)",
                ip=client_ip,
                allowed_users=allowed_users
            )
        
        # If allowed_users is set and doesn't contain '*', check if user is allowed
        if allowed_users and "*" not in allowed_users and user_info["login"] not in allowed_users:
            logger.warning(
                "GitHub user not in allowed list",
                    ip=client_ip,
                client_id=auth_data.get('client_id'),
                github_username=user_info.get("login"),
                allowed_users=allowed_users,
                proxy_hostname=proxy_hostname
            )
            return RedirectResponse(
                url=f"{auth_data['redirect_uri']}?error=access_denied&state={auth_data['state']}",  # TODO: Break long line
            )

        # Generate authorization code
        auth_code = secrets.token_urlsafe(32)

        # Store authorization code with user info
        code_data = {
            **auth_data,
            "user_id": str(user_info["id"]),
            "username": user_info["login"],
            "email": user_info.get("email", ""),
            "name": user_info.get("name", ""),
        }

        await redis_client.setex(
            f"oauth:code:{auth_code}",
            31536000,
            json.dumps(code_data),
        )  # TODO: Break long line

        # Clean up state
        await redis_client.delete(f"oauth:state:{state}")
        
        logger.info(
            "OAuth authorization code generated",
            ip=client_ip,
            client_id=auth_data.get('client_id'),
            user_id=str(user_info["id"]),
            username=user_info["login"],
            email=user_info.get("email", ""),
            scope=auth_data.get("scope"),
            resources=auth_data.get("resources"),
            redirect_uri=auth_data["redirect_uri"]
        )

        # Handle out-of-band redirect URI
        if auth_data["redirect_uri"] == "urn:ietf:wg:oauth:2.0:oob":
            logger.debug(
                "Using out-of-band redirect for auth code display",
                client_id=auth_data["client_id"],
                state=auth_data["state"]
            )
            return RedirectResponse(
                url=f"https://auth.{settings.base_domain}/success?code={auth_code}&state={auth_data['state']}",  # TODO: Break long line
                headers={
                    "Cache-Control": "no-cache, no-store, must-revalidate",
                    "Pragma": "no-cache",
                    "Expires": "0",
                },
            )

        # Normal redirect
        redirect_params = {"code": auth_code, "state": auth_data["state"]}

        final_redirect_url = f"{auth_data['redirect_uri']}?{urlencode(redirect_params)}"
        
        logger.info(
            "OAuth callback completed, redirecting to client",
            ip=client_ip,
            client_id=auth_data.get('client_id'),
            redirect_uri=auth_data["redirect_uri"],
            redirect_to=final_redirect_url,
            auth_code=auth_code[:8] + "...",
            github_username=user_info["login"],
            github_email=user_info.get("email", "")
        )
        
        response = RedirectResponse(
            url=final_redirect_url,
            status_code=307,
            headers={
                "Cache-Control": "no-cache, no-store, must-revalidate",
                "Pragma": "no-cache",
                "Expires": "0",
            },
        )
        
        # Log response with detailed OAuth context
        await log_response(
            logger,
            response,
            0,  # duration will be calculated by log_response
            ip=client_ip,
            hostname=request.headers.get("host"),
            oauth_action="callback_redirect",
            oauth_redirect_to=final_redirect_url,
            oauth_authorization_granted="success",
            oauth_github_username=user_info["login"],
            oauth_github_email=user_info.get("email", "")
        )
        
        return response

    # Token endpoint
    @router.post("/token")
    async def token_exchange(
        request: Request,
        grant_type: str = Form(...),
        code: Optional[str] = Form(None),
        redirect_uri: Optional[str] = Form(None),
        client_id: str = Form(...),
        client_secret: Optional[str] = Form(None),
        code_verifier: Optional[str] = Form(None),
        refresh_token: Optional[str] = Form(None),
        resource: Optional[list[str]] = Form(None),  # RFC 8707 Resource Indicators
        redis_client: redis.Redis = Depends(get_redis),
    ):
        """The transmutation chamber - exchanges codes for tokens"""
        # Get client IP
        client_ip = get_real_client_ip(request)
        
        # DEBUG: Add print to verify execution
        print(f"[DEBUG] Token exchange request from {client_ip}: grant_type={grant_type}, client_id={client_id}, resource={resource}")
        
        logger.info(
            "OAuth token exchange request",
            ip=client_ip,
            client_id=client_id,
            grant_type=grant_type,
            has_code=bool(code),
            has_refresh_token=bool(refresh_token),
            resource=resource,
            resource_count=len(resource) if resource else 0,
            redirect_uri=redirect_uri,
            has_code_verifier=bool(code_verifier),
            request_headers={k: v for k, v in request.headers.items() if k.lower() not in ['authorization', 'cookie']},
            request_form_data={
                "grant_type": grant_type,
                "client_id": client_id,
                "has_client_secret": bool(client_secret),
                "resource": resource,
                "redirect_uri": redirect_uri
            }
        )
        
        # Log request with OAuth context
        await log_request(
            logger,
            request,
            client_ip,
            hostname=request.headers.get("host"),
            oauth_action="token_exchange",
            oauth_client_id=client_id,
            oauth_grant_type=grant_type,
            oauth_resources=resource if resource else []
        )
        # Validate client
        client = await auth_manager.get_client(client_id, redis_client)
        if not client:
            logger.warning(
                "OAuth token request with invalid client",
                    ip=client_ip,
                client_id=client_id,
                grant_type=grant_type
            )
            raise HTTPException(
                status_code=401,
                detail={
                    "error": "invalid_client",
                    "error_description": "Client authentication failed",
                },
                headers={"WWW-Authenticate": "Basic"},
            )

        # Validate client secret
        if client_secret and not client.check_client_secret(client_secret):
            logger.warning(
                "OAuth token request with invalid client secret",
                    ip=client_ip,
                client_id=client_id,
                grant_type=grant_type
            )
            raise HTTPException(
                status_code=401,
                detail={
                    "error": "invalid_client",
                    "error_description": "Invalid client credentials",
                },
                headers={"WWW-Authenticate": "Basic"},
            )

        # Validate grant type
        if not client.check_grant_type(grant_type):
            raise HTTPException(
                status_code=400,
                detail={
                    "error": "unsupported_grant_type",
                    "error_description": f"Grant type '{grant_type}' is not supported",
                },
            )

        if grant_type == "authorization_code":
            if not code:
                raise HTTPException(
                    status_code=400,
                    detail={
                        "error": "invalid_request",
                        "error_description": "Missing authorization code",
                    },
                )

            # Retrieve authorization code
            code_data_str = await redis_client.get(f"oauth:code:{code}")
            if not code_data_str:
                raise HTTPException(
                    status_code=400,
                    detail={
                        "error": "invalid_grant",
                        "error_description": "Invalid or expired authorization code",
                    },
                )

            code_data = json.loads(code_data_str)

            # Validate redirect_uri
            if redirect_uri != code_data["redirect_uri"]:
                raise HTTPException(
                    status_code=400,
                    detail={"error": "invalid_grant", "error_description": "Redirect URI mismatch"},
                )

            # Validate PKCE
            if code_data.get("code_challenge"):
                if not code_verifier:
                    raise HTTPException(
                        status_code=400,
                        detail={
                            "error": "invalid_grant",
                            "error_description": "PKCE code_verifier required",
                        },
                    )

                if not auth_manager.verify_pkce_challenge(
                    code_verifier,
                    code_data["code_challenge"],
                    code_data["code_challenge_method"],
                ):
                    raise HTTPException(
                        status_code=400,
                        detail={
                            "error": "invalid_grant",
                            "error_description": "PKCE verification failed",
                        },
                    )

            # Validate resource parameters (RFC 8707)
            authorized_resources = code_data.get("resources", [])
            requested_resources = resource if resource else []
            
            # If resources were requested at token endpoint, ensure they were authorized
            if requested_resources:
                for res in requested_resources:
                    if res not in authorized_resources:
                        raise HTTPException(
                            status_code=400,
                            detail={
                                "error": "invalid_target",
                                "error_description": f"Resource '{res}' was not authorized",
                            },
                        )
                # Use only the requested subset of authorized resources
                token_resources = requested_resources
            else:
                # Use all authorized resources if none specifically requested
                token_resources = authorized_resources

            # Log detailed token creation context before generation
            logger.info(
                "Creating OAuth access token",
                ip=client_ip,
                client_id=client_id,
                user_id=code_data["user_id"],
                username=code_data["username"],
                scope=code_data["scope"],
                authorized_resources=authorized_resources,
                requested_resources=requested_resources,
                final_token_resources=token_resources,
                resource_count=len(token_resources),
                audience_will_be_set_to=token_resources  # This becomes the 'aud' claim
            )
            
            # Generate tokens with the correct issuer URL
            issuer_url = get_external_url(request, settings)
            access_token = await auth_manager.create_jwt_token(
                {
                    "sub": code_data["user_id"],
                    "username": code_data["username"],
                    "email": code_data["email"],
                    "name": code_data["name"],
                    "scope": code_data["scope"],
                    "client_id": client_id,
                    "resources": token_resources,  # RFC 8707 Resource Indicators
                },
                redis_client,
                issuer=issuer_url
            )

            refresh_token_value = await auth_manager.create_refresh_token(
                {
                    "user_id": code_data["user_id"],
                    "username": code_data["username"],
                    "client_id": client_id,
                    "scope": code_data["scope"],
                    "resources": token_resources,  # RFC 8707 Resource Indicators
                },
                redis_client,
            )

            # Delete used authorization code
            await redis_client.delete(f"oauth:code:{code}")

            # Extract token claims for detailed logging
            import jwt
            token_claims = jwt.decode(access_token, options={"verify_signature": False})
            
            logger.info(
                "OAuth token generated - DETAILED TOKEN INFO",
                ip=client_ip,
                client_id=client_id,
                user_id=code_data["user_id"],
                username=code_data["username"],
                token_resources=token_resources,
                token_audience=token_claims.get("aud"),
                token_audience_type=type(token_claims.get("aud")).__name__,
                token_issuer=token_claims.get("iss"),
                token_subject=token_claims.get("sub"),
                token_scope=token_claims.get("scope"),
                token_jti=token_claims.get("jti"),
                all_token_claims=token_claims,
                code_data_resources=code_data.get("resources", []),
                requested_resources_in_token_request=resource,
                authorized_resources_from_code=authorized_resources
            )
            
            # Log complete token payload (without signature verification)
            logger.info(
                "OAuth token issued via authorization code - COMPLETE TOKEN DETAILS",
                ip=client_ip,
                client_id=client_id,
                user_id=code_data["user_id"],
                username=code_data["username"],
                scope=code_data["scope"],
                resources=token_resources,
                token_jti=token_claims.get("jti"),
                token_aud=token_claims.get("aud"),
                token_aud_type=type(token_claims.get("aud")).__name__,
                token_aud_count=len(token_claims.get("aud", [])) if isinstance(token_claims.get("aud"), list) else 1,
                token_exp=token_claims.get("exp"),
                token_iat=token_claims.get("iat"),
                token_iss=token_claims.get("iss"),
                token_sub=token_claims.get("sub"),
                token_azp=token_claims.get("azp"),
                complete_claims={
                    k: v for k, v in token_claims.items() 
                    if k not in ["access_token", "refresh_token"]  # Don't log actual tokens
                },
                authorized_resources=authorized_resources,
                requested_resources=requested_resources,
                resource_validation_passed=True
            )
            
            # Log response with full token details
            await log_response(
                logger,
                Response(status_code=200),
                0,
                    hostname=request.headers.get("host"),
                oauth_token_issued="true",
                oauth_token_jti=token_claims.get("jti"),
                oauth_user_id=code_data["user_id"],
                oauth_username=code_data["username"],
                oauth_email=code_data["email"],
                oauth_scope=code_data["scope"],
                oauth_resources=token_resources,
                oauth_token_exp=token_claims.get("exp"),
                oauth_token_iat=token_claims.get("iat")
            )

            return TokenResponse(
                access_token=access_token,
                expires_in=settings.access_token_lifetime,
                refresh_token=refresh_token_value,
                scope=code_data["scope"],
            )

        elif grant_type == "refresh_token":
            if not refresh_token:
                raise HTTPException(
                    status_code=400,
                    detail={
                        "error": "invalid_request",
                        "error_description": "Missing refresh token",
                    },
                )

            # Retrieve refresh token data
            refresh_data_str = await redis_client.get(f"oauth:refresh:{refresh_token}")
            if not refresh_data_str:
                raise HTTPException(
                    status_code=400,
                    detail={
                        "error": "invalid_grant",
                        "error_description": "Invalid or expired refresh token",
                    },
                )

            refresh_data = json.loads(refresh_data_str)

            # Validate resource parameters if provided (RFC 8707)
            if resource:
                authorized_resources = refresh_data.get("resources", [])
                for res in resource:
                    if res not in authorized_resources:
                        raise HTTPException(
                            status_code=400,
                            detail={
                                "error": "invalid_target",
                                "error_description": f"Resource '{res}' was not authorized",
                            },
                        )
                token_resources = resource
            else:
                # Use all resources from refresh token
                token_resources = refresh_data.get("resources", [])

            # Log refresh token context
            logger.info(
                "Refreshing OAuth access token",
                ip=client_ip,
                client_id=client_id,
                user_id=refresh_data["user_id"],
                username=refresh_data["username"],
                scope=refresh_data["scope"],
                refresh_token_resources=refresh_data.get("resources", []),
                requested_resources=resource if resource else [],
                final_token_resources=token_resources,
                audience_will_be_set_to=token_resources
            )
            
            # Generate new access token with the correct issuer URL
            issuer_url = get_external_url(request, settings)
            access_token = await auth_manager.create_jwt_token(
                {
                    "sub": refresh_data["user_id"],
                    "username": refresh_data["username"],
                    "scope": refresh_data["scope"],
                    "client_id": client_id,
                    "resources": token_resources,  # RFC 8707 Resource Indicators
                },
                redis_client,
                issuer=issuer_url
            )

            # Extract token claims for detailed logging
            token_claims = jwt.decode(access_token, options={"verify_signature": False})
            
            logger.info(
                "OAuth token refreshed successfully - COMPLETE TOKEN DETAILS",
                ip=client_ip,
                client_id=client_id,
                user_id=refresh_data["user_id"],
                username=refresh_data["username"],
                scope=refresh_data["scope"],
                resources=token_resources,
                token_jti=token_claims.get("jti"),
                token_aud=token_claims.get("aud"),
                token_aud_type=type(token_claims.get("aud")).__name__,
                token_aud_count=len(token_claims.get("aud", [])) if isinstance(token_claims.get("aud"), list) else 1,
                complete_claims={
                    k: v for k, v in token_claims.items() 
                    if k not in ["access_token", "refresh_token"]
                },
                refresh_successful=True
            )

            return TokenResponse(
                access_token=access_token,
                expires_in=settings.access_token_lifetime,
                scope=refresh_data["scope"],
            )

        else:
            raise HTTPException(
                status_code=400,
                detail={
                    "error": "unsupported_grant_type",
                    "error_description": f"Grant type '{grant_type}' not supported",
                },
            )

    # ForwardAuth verification endpoint - Using ResourceProtector
    @router.get("/verify")
    @router.post("/verify")
    async def verify_token(request: Request):
        """Token examination oracle - validates Bearer tokens for Traefik"""
        # Get client IP for logging
        client_ip = get_real_client_ip(request)
        
        try:
            # Extract the target resource from forwarded headers
            forwarded_host = request.headers.get("x-forwarded-host", "")
            forwarded_proto = request.headers.get("x-forwarded-proto", "https")
            forwarded_path = request.headers.get("x-forwarded-path", "")
            forwarded_method = request.headers.get("x-original-method", "GET")
            
            # Construct the resource URI if we have the host
            # For MCP compliance, resource should include the full path to match protected resource metadata
            resource = None
            if forwarded_host:
                # Include the path in the resource URI to match what's in the protected resource metadata
                resource = f"{forwarded_proto}://{forwarded_host}{forwarded_path}" if forwarded_path else f"{forwarded_proto}://{forwarded_host}"
            
            # Get the real forwarded IP if present
            forwarded_ip = request.headers.get("x-forwarded-for", client_ip)
            if forwarded_ip and forwarded_ip != client_ip:
                logger.debug(
                    "Using forwarded IP for verification",
                    direct_ip=client_ip,
                    forwarded_ip=forwarded_ip
                )
            
            logger.debug(
                "OAuth token verification request",
                ip=forwarded_ip,
                resource=resource,
                path=forwarded_path,
                method=forwarded_method
            )
            
            # Validate token with resource context
            nonlocal require_oauth
            if require_oauth is None:
                require_oauth = create_async_resource_protector(
                    settings,
                    redis_manager.client,
                    auth_manager.key_manager,
                )
            
            # Validate with resource for audience checking
            token = await require_oauth.validate_request(request, resource=resource)
            
            # Additional validation for allowed scopes and audiences
            allowed_scopes_header = request.headers.get("x-auth-allowed-scopes", "")
            allowed_audiences_header = request.headers.get("x-auth-allowed-audiences", "")
            
            # Check allowed scopes if configured
            if allowed_scopes_header:
                allowed_scopes = [s.strip() for s in allowed_scopes_header.split(",") if s.strip()]
                token_scopes = token.get("scope", "").split()
                
                # Check if at least one token scope is in the allowed list
                if not any(scope in allowed_scopes for scope in token_scopes):
                    logger.warning(
                        "OAuth token validation failed - scope not allowed",
                        ip=forwarded_ip,
                        resource=resource,
                        token_scopes=token_scopes,
                        allowed_scopes=allowed_scopes
                    )
                    raise HTTPException(
                        status_code=403,
                        detail={
                            "error": "insufficient_scope",
                            "error_description": f"Token scopes {token_scopes} not in allowed scopes {allowed_scopes}"
                        }
                    )
            
            # Check allowed audiences if configured
            if allowed_audiences_header:
                allowed_audiences = [a.strip() for a in allowed_audiences_header.split(",") if a.strip()]
                token_audiences = token.get("aud", [])
                if isinstance(token_audiences, str):
                    token_audiences = [token_audiences]
                
                # Check if at least one token audience is in the allowed list
                if not any(aud in allowed_audiences for aud in token_audiences):
                    logger.warning(
                        "OAuth token validation failed - audience not allowed",
                        ip=forwarded_ip,
                        resource=resource,
                        token_audiences=token_audiences,
                        allowed_audiences=allowed_audiences
                    )
                    raise HTTPException(
                        status_code=403,
                        detail={
                            "error": "invalid_audience",
                            "error_description": f"Token audiences {token_audiences} not in allowed audiences {allowed_audiences}"
                        }
                    )
            
            logger.info(
                "OAuth token verified successfully",
                ip=forwarded_ip,
                resource=resource,
                user_id=token.get("sub"),
                username=token.get("username"),
                client_id=token.get("client_id"),
                scope=token.get("scope"),
                token_jti=token.get("jti")
            )
            
            # Return success with user info in JSON body
            return {
                "sub": token.get("sub", ""),
                "username": token.get("username", ""),
                "email": token.get("email", ""),
                "name": token.get("name", ""),
                "groups": token.get("groups", []),
                "scope": token.get("scope", ""),
                "client_id": token.get("client_id", ""),
            }
        except HTTPException as e:
            # Log specific HTTP exceptions (401, 403, etc.)
            logger.warning(
                "OAuth token verification failed",
                ip=forwarded_ip,
                resource=resource,
                status_code=e.status_code,
                error=e.detail
            )
            raise
        except Exception as e:
            logger.error(
                "OAuth token verification error",
                ip=forwarded_ip,
                resource=resource,
                error_type=type(e).__name__,
                error_message=str(e),
                exc_info=True
            )
            # Re-raise the exception to maintain proper error handling
            raise

    # Token revocation endpoint (RFC 7009)
    @router.post("/revoke")
    async def revoke_token(
        request: Request,
        token: str = Form(...),
        token_type_hint: Optional[str] = Form(None),
        client_id: str = Form(...),
        client_secret: Optional[str] = Form(None),
        redis_client: redis.Redis = Depends(get_redis),
    ):
        """Token banishment altar - revokes tokens"""
        # Get client IP
        client_ip = get_real_client_ip(request)
        
        logger.info(
            "OAuth token revocation request",
            ip=client_ip,
            client_id=client_id,
            token_type_hint=token_type_hint
        )
        
        # Validate client
        client = await auth_manager.get_client(client_id, redis_client)
        if not client:
            # RFC 7009 - invalid client should still return 200
            logger.debug(
                "Token revocation with invalid client (returning 200 per RFC 7009)",
                    ip=client_ip,
                client_id=client_id
            )
            return Response(status_code=200)

        if client_secret and not client.check_client_secret(client_secret):
            logger.debug(
                "Token revocation with invalid client secret (returning 200 per RFC 7009)",
                    ip=client_ip,
                client_id=client_id
            )
            return Response(status_code=200)

        # Revoke token
        await auth_manager.revoke_token(token, redis_client)

        logger.info(
            "OAuth token revoked successfully",
            ip=client_ip,
            client_id=client_id
        )

        # Always return 200 (RFC 7009)
        return Response(status_code=200)

    # Token introspection endpoint (RFC 7662)
    @router.post("/introspect")
    async def introspect_token(
        request: Request,
        token: str = Form(...),
        token_type_hint: Optional[str] = Form(None),
        client_id: str = Form(...),
        client_secret: Optional[str] = Form(None),
        redis_client: redis.Redis = Depends(get_redis),
    ):
        """Token examination oracle - RFC 7662 compliant"""
        # Get client IP
        client_ip = get_real_client_ip(request)
        
        logger.info(
            "OAuth token introspection request",
            ip=client_ip,
            client_id=client_id,
            token_type_hint=token_type_hint
        )
        
        # Log request with OAuth context
        await log_request(
            logger,
            request,
            client_ip,
            hostname=request.headers.get("host"),
            oauth_action="introspect",
            oauth_client_id=client_id,
            oauth_token_type_hint=token_type_hint
        )
        
        # Validate client
        client = await auth_manager.get_client(client_id, redis_client)
        if not client or (client_secret and not client.check_client_secret(client_secret)):
            logger.debug(
                "Token introspection with invalid client credentials",
                    ip=client_ip,
                client_id=client_id
            )
            return {"active": False}

        # Introspect token
        introspection_result = await auth_manager.introspect_token(token, redis_client)

        logger.info(
            "OAuth token introspection completed",
            ip=client_ip,
            client_id=client_id,
            token_active=introspection_result.get("active", False),
            token_sub=introspection_result.get("sub") if introspection_result.get("active") else None,
            token_client_id=introspection_result.get("client_id") if introspection_result.get("active") else None
        )
        
        # Log response with full introspection result
        await log_response(
            logger,
            Response(status_code=200),
            0,
            hostname=request.headers.get("host"),
            oauth_introspection_result=introspection_result,
            oauth_token_active=introspection_result.get("active", False),
            oauth_token_sub=introspection_result.get("sub") if introspection_result.get("active") else None,
            oauth_token_username=introspection_result.get("username") if introspection_result.get("active") else None,
            oauth_token_scope=introspection_result.get("scope") if introspection_result.get("active") else None,
            oauth_token_exp=introspection_result.get("exp") if introspection_result.get("active") else None,
            oauth_token_jti=introspection_result.get("jti") if introspection_result.get("active") else None
        )

        return introspection_result

    # OAuth error page
    @router.get("/error")
    async def oauth_error_page(
        error: str = Query(...),
        error_description: Optional[str] = Query(None),
    ):
        """User-friendly error page for OAuth flow failures"""
        return HTMLResponse(
            content=f"""
            <!DOCTYPE html>
            <html>
            <head>
                <title>OAuth Error</title>
                <meta http-equiv="Cache-Control" content="no-cache, no-store, must-revalidate">
                <meta http-equiv="Pragma" content="no-cache">
                <meta http-equiv="Expires" content="0">
            </head>
            <body style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; padding: 40px; max-width: 600px; margin: 0 auto;">
                <div style="background: #fef2f2; border: 1px solid #fecaca; border-radius: 8px; padding: 20px; margin-bottom: 20px;">
                    <h1 style="color: #dc2626; margin: 0 0 10px 0;">❌ OAuth Authentication Failed</h1>
                    <p style="font-size: 18px; margin: 0;"><strong>Error:</strong> {error}</p>
                    <p style="margin: 10px 0 0 0;"><strong>Details:</strong> {error_description or "No additional details available"}</p>
                </div>

                <div style="background: #f3f4f6; border-radius: 8px; padding: 20px; margin-bottom: 20px;">
                    <h2 style="margin: 0 0 10px 0;">What happened?</h2>
                    <p style="margin: 0;">{"Your authentication session expired. OAuth state tokens are valid for only 5 minutes for security reasons." if "expired state" in (error_description or "").lower() else "The OAuth authentication process encountered an error."}</p>
                </div>

                <div style="background: #dbeafe; border: 1px solid #93c5fd; border-radius: 8px; padding: 20px;">
                    <h2 style="color: #1d4ed8; margin: 0 0 10px 0;">How to fix this:</h2>
                    <ol style="margin: 10px 0; padding-left: 20px;">
                        <li><strong>Close this browser tab</strong></li>
                        <li><strong>Close any other OAuth tabs</strong> from previous attempts</li>
                        <li><strong>Run the command again:</strong> <code style="background: #f3f4f6; padding: 2px 4px; border-radius: 3px;">just generate-github-token</code></li>
                        <li><strong>Complete the flow quickly</strong> (within 5 minutes)</li>
                    </ol>
                    <p style="margin: 10px 0 0 0; font-size: 14px; color: #4b5563;">
                        <strong>Tip:</strong> If you see multiple browser tabs open, close all but the newest one to avoid confusion.
                    </p>
                </div>

                <p style="text-align: center; margin-top: 30px; color: #6b7280;">
                    This page prevents caching. You can safely close this tab.
                </p>
            </body>
            </html>
            """,
            headers={
                "Cache-Control": "no-cache, no-store, must-revalidate",
                "Pragma": "no-cache",
                "Expires": "0",
            },
        )

    # OAuth success page
    @router.get("/success")
    async def oauth_success(
        code: Optional[str] = Query(None),
        state: Optional[str] = Query(None),
        error: Optional[str] = Query(None),
        error_description: Optional[str] = Query(None),
    ):
        """OAuth success page for displaying authorization codes"""
        if error:
            return HTMLResponse(
                content=f"""
                <!DOCTYPE html>
                <html>
                <head><title>OAuth Error</title></head>
                <body style="font-family: Arial; padding: 20px; text-align: center;">
                    <h1>❌ OAuth Error</h1>
                    <p><strong>Error:</strong> {error}</p>
                    <p><strong>Description:</strong> {error_description or "No description provided"}</p>
                    <p>You can close this window.</p>
                </body>
                </html>
                """,
            )

        if code:
            return HTMLResponse(
                content=f"""
                <!DOCTYPE html>
                <html>
                <head><title>OAuth Success</title></head>
                <body style="font-family: Arial; padding: 20px; text-align: center;">
                    <h1>✅ OAuth Success!</h1>
                    <p>Authorization code received successfully.</p>
                    <div style="background: #f5f5f5; padding: 10px; margin: 20px; border-radius: 5px; font-family: monospace;">
                        <strong>Authorization Code:</strong><br>
                        {code}
                    </div>
                    <p><em>Copy the code above for token generation.</em></p>
                    <p>You can close this window.</p>
                </body>
                </html>
                """,
            )

        return HTMLResponse(
            content="""
            <!DOCTYPE html>
            <html>
            <head><title>OAuth Flow</title></head>
            <body style="font-family: Arial; padding: 20px; text-align: center;">
                <h1>⏳ OAuth Flow</h1>
                <p>No authorization code received yet.</p>
                <p>You can close this window.</p>
            </body>
            </html>
            """,
        )

    # RFC 7592 - Dynamic Client Registration Management Protocol
    @router.get("/register/{client_id}")
    async def get_client_registration(
        client_id: str,
        request: Request,
        redis_client: redis.Redis = Depends(get_redis),
    ):
        """Get client registration information - RFC 7592 compliant"""
        config_endpoint = DynamicClientConfigurationEndpoint(settings, redis_client)

        try:
            client = await config_endpoint.authenticate_client(request, client_id)
        except ValueError as e:
            raise HTTPException(status_code=404, detail="Client not found") from e

        if not client:
            auth_header = request.headers.get("Authorization", "")
            if not auth_header:
                raise HTTPException(
                    status_code=401,
                    detail="Missing authentication",
                    headers={"WWW-Authenticate": 'Bearer realm="auth"'},
                )
            elif not auth_header.startswith("Bearer "):
                raise HTTPException(
                    status_code=401,
                    detail="Invalid authentication method",
                    headers={"WWW-Authenticate": 'Bearer realm="auth"'},
                )
            else:
                raise HTTPException(
                    status_code=403,
                    detail="Invalid or expired registration access token",
                )

        if not await config_endpoint.check_permission(client, request):
            raise HTTPException(status_code=403, detail="Insufficient permissions")

        return config_endpoint.generate_client_configuration_response(client)

    @router.put("/register/{client_id}")
    async def update_client_registration(
        client_id: str,
        request: Request,
        client_metadata: dict,
        redis_client: redis.Redis = Depends(get_redis),
    ):
        """Update client registration - RFC 7592 compliant"""
        config_endpoint = DynamicClientConfigurationEndpoint(settings, redis_client)

        try:
            client = await config_endpoint.authenticate_client(request, client_id)
        except ValueError as e:
            raise HTTPException(status_code=404, detail="Client not found") from e

        if not client:
            auth_header = request.headers.get("Authorization", "")
            if not auth_header:
                raise HTTPException(
                    status_code=401,
                    detail="Missing authentication",
                    headers={"WWW-Authenticate": 'Bearer realm="auth"'},
                )
            elif not auth_header.startswith("Bearer "):
                raise HTTPException(
                    status_code=401,
                    detail="Invalid authentication method",
                    headers={"WWW-Authenticate": 'Bearer realm="auth"'},
                )
            else:
                raise HTTPException(
                    status_code=403,
                    detail="Invalid or expired registration access token",
                )

        if not await config_endpoint.check_permission(client, request):
            raise HTTPException(status_code=403, detail="Insufficient permissions")

        # Validate redirect_uris if provided
        if "redirect_uris" in client_metadata:
            if not client_metadata["redirect_uris"]:
                raise HTTPException(
                    status_code=400,
                    detail={
                        "error": "invalid_client_metadata",
                        "error_description": "redirect_uris cannot be empty",
                    },
                )

            for uri in client_metadata["redirect_uris"]:
                if not uri or not isinstance(uri, str):
                    raise HTTPException(
                        status_code=400,
                        detail={
                            "error": "invalid_redirect_uri",
                            "error_description": "Invalid redirect URI format",
                        },
                    )

                if uri.startswith("http://"):
                    if not any(
                        uri.startswith(f"http://{host}")
                        for host in ["localhost", "127.0.0.1", "[::1]"]
                    ):
                        raise HTTPException(
                            status_code=400,
                            detail={
                                "error": "invalid_redirect_uri",
                                "error_description": "HTTP redirect URIs are only allowed for localhost",
                            },
                        )
                elif not uri.startswith("https://") and ":" not in uri:
                    raise HTTPException(
                        status_code=400,
                        detail={
                            "error": "invalid_redirect_uri",
                            "error_description": "Redirect URI must use HTTPS or be an app-specific URI",
                        },
                    )

        try:
            updated_client = await config_endpoint.update_client(client, client_metadata)
            return config_endpoint.generate_client_configuration_response(updated_client)
        except ValueError as e:
            raise HTTPException(status_code=404, detail=str(e)) from e

    @router.delete("/register/{client_id}")
    async def delete_client_registration(
        client_id: str,
        request: Request,
        redis_client: redis.Redis = Depends(get_redis),
    ):
        """Delete client registration - RFC 7592 compliant"""
        config_endpoint = DynamicClientConfigurationEndpoint(settings, redis_client)

        try:
            client = await config_endpoint.authenticate_client(request, client_id)
        except ValueError as e:
            raise HTTPException(status_code=404, detail="Client not found") from e

        if not client:
            auth_header = request.headers.get("Authorization", "")
            if not auth_header:
                raise HTTPException(
                    status_code=401,
                    detail="Missing authentication",
                    headers={"WWW-Authenticate": 'Bearer realm="auth"'},
                )
            elif not auth_header.startswith("Bearer "):
                raise HTTPException(
                    status_code=401,
                    detail="Invalid authentication method",
                    headers={"WWW-Authenticate": 'Bearer realm="auth"'},
                )
            else:
                raise HTTPException(
                    status_code=403,
                    detail="Invalid or expired registration access token",
                )

        if not await config_endpoint.check_permission(client, request):
            raise HTTPException(status_code=403, detail="Insufficient permissions")

        await config_endpoint.delete_client(client)
        return Response(status_code=204)

    return router
