"""OAuth 2.1 and RFC 7591 compliant routes with Authlib ResourceProtector
Using Authlib's security framework instead of custom implementations
"""

import json
import jwt
import logging
import secrets
import time
import traceback
import httpx
from datetime import datetime, timedelta
from typing import Optional
from urllib.parse import urlencode

import redis.asyncio as redis
from fastapi import APIRouter, Depends, Form, HTTPException, Query, Request, Response
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse

from .async_resource_protector import create_async_resource_protector
from .auth_authlib import AuthManager
from .config import Settings
from .models import ClientRegistration, TokenResponse
from .rfc7592 import DynamicClientConfigurationEndpoint
from ...shared.logger import log_debug, log_info, log_warning, log_error, log_trace, log_request, log_response
from ...shared.config import Config
from ...shared.client_ip import get_real_client_ip

# Set up logging



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
    """Create OAuth router with all endpoints using Authlib ResourceProtector
    
    Args:
        settings: OAuth settings
        redis_manager: Redis manager for state management
        auth_manager: Authentication manager
    """
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
        # Try to get storage from app state for proxy-specific configuration
        storage = getattr(request.app.state, 'storage', None)
        if storage:
            # Use metadata handler for proxy-specific configuration
            from .metadata_handler import OAuthMetadataHandler
            metadata_handler = OAuthMetadataHandler(settings, storage)
            
            # Extract hostname from request headers to get proxy-specific config
            proxy_hostname = request.headers.get("x-forwarded-host", "").split(":")[0]
            if not proxy_hostname:
                proxy_hostname = request.headers.get("host", "").split(":")[0]
            
            return await metadata_handler.get_authorization_server_metadata(request, proxy_hostname)
        
        # Fall back to default metadata if no storage
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
        
        log_info(
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

        # RFC 7591 Section 3.2.1 - Handle client-suggested client_id
        if registration.client_id:
            # Check if the suggested client_id is already taken
            existing_client = await redis_client.get(f"oauth:client:{registration.client_id}")
            if existing_client:
                # RFC 7591 - Server MAY reject if client_id is already taken
                raise HTTPException(
                    status_code=400,
                    detail={
                        "error": "invalid_client_metadata",
                        "error_description": f"Client ID {registration.client_id} is already registered",
                    },
                )
            # Use the client-suggested ID
            client_id = registration.client_id
            # Generate only the secret
            client_secret = secrets.token_urlsafe(32)
        else:
            # Generate both client_id and secret
            credentials = auth_manager.generate_client_credentials()
            client_id = credentials["client_id"]
            client_secret = credentials["client_secret"]

        # Calculate client expiration time
        created_at = int(time.time())
        expires_at = 0 if settings.client_lifetime == 0 else created_at + settings.client_lifetime

        # Generate registration access token for RFC 7592 management
        registration_access_token = f"reg-{secrets.token_urlsafe(32)}"

        # RFC 7591 - Handle grant_types and response_types
        grant_types = registration.grant_types or ["authorization_code"]
        response_types = registration.response_types or ["code"]
        
        # Validate grant_types and response_types consistency
        if "authorization_code" in grant_types and "code" not in response_types:
            response_types.append("code")
        if "code" in response_types and "authorization_code" not in grant_types:
            grant_types.append("authorization_code")
        
        # Add refresh_token grant if not explicitly disabled
        if "authorization_code" in grant_types and "refresh_token" not in grant_types:
            grant_types.append("refresh_token")
        
        # Store client in Redis
        # Get the actual registration endpoint URL used by the client
        registration_client_uri = f"{get_external_url(request, settings)}/register/{client_id}"
        
        client_data = {
            "client_id": client_id,
            "client_secret": client_secret,
            "client_secret_expires_at": expires_at,
            "client_id_issued_at": created_at,
            "redirect_uris": json.dumps(registration.redirect_uris),
            "client_name": registration.client_name or "Unnamed Client",
            "scope": registration.scope or "openid profile email",
            "created_at": created_at,
            "response_types": json.dumps(response_types),
            "grant_types": json.dumps(grant_types),
            "token_endpoint_auth_method": registration.token_endpoint_auth_method or "client_secret_basic",
            "registration_access_token": registration_access_token,
            "registration_client_uri": registration_client_uri,
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
            "registration_client_uri": registration_client_uri,
        }

        # Echo back all registered metadata
        for field in ["client_uri", "logo_uri", "contacts", "tos_uri", "policy_uri"]:
            value = getattr(registration, field, None)
            if value is not None:
                response[field] = value

        log_info(
            "OAuth client registered successfully",
            ip=client_ip,
            client_id=client_id,
            client_name=registration.client_name,
            redirect_uris=registration.redirect_uris,
            scope=registration.scope
        )

        return response

    # Device Flow endpoints
    @router.post("/device/code")
    async def device_code(
        request: Request,
        client_id: str = Form(default="device_flow_client"),
        scope: str = Form(default="read:user user:email"),
        resource: Optional[str] = Form(default=None)
    ):
        """GitHub Device Flow - Step 1: Get device code (RFC 8628 + MCP compliant)
        
        Accepts client_id, scope, and resource as form parameters per RFC 8628 and RFC 8707
        The resource parameter identifies the proxy/MCP server the token will be used with
        Forwards request to GitHub's device endpoint to get a device code
        """
        client_ip = get_real_client_ip(request)
        
        # Default resource to localhost proxy if not specified (MCP compliance)
        if not resource:
            # Get the proxy hostname from request to use as default resource
            host = request.headers.get("host", "localhost")
            resource = f"http://{host}" if host == "localhost" else f"https://{host}"
            log_info(f"Device Flow: No resource specified, defaulting to {resource}", ip=client_ip)
        
        log_info(
            "Device Flow: Code request",
            ip=client_ip,
            client_id=client_id,
            scope=scope,
            resource=resource
        )
        
        # Forward to GitHub's device code endpoint
        # Note: We use GitHub's OAuth app credentials, not the client_id from request
        async with httpx.AsyncClient() as client:
            github_response = await client.post(
                "https://github.com/login/device/code",
                headers={"Accept": "application/json"},
                data={
                    "client_id": settings.github_client_id,
                    "scope": scope  # Use the requested scope
                }
            )
        
        result = github_response.json()
        
        # Store the requested resource with the device code for later use
        if result.get("device_code"):
            device_code_data = {
                "resource": resource,
                "scope": scope,
                "client_id": client_id
            }
            # Store in Redis with same expiry as GitHub's device code
            expires_in = result.get("expires_in", 900)  # Default 15 minutes
            redis_client = await get_redis()
            await redis_client.setex(
                f"device_code:{result['device_code']}",
                expires_in,
                json.dumps(device_code_data)
            )
        
        log_info(
            "Device Flow: Code generated",
            ip=client_ip,
            device_code=result.get("device_code", "")[:8] + "..." if result.get("device_code") else None,
            user_code=result.get("user_code"),
            resource=resource
        )
        
        # Include resource in response for client awareness
        result["resource"] = resource
        return result

    @router.post("/device/token") 
    async def device_token(
        request: Request,
        grant_type: str = Form(...),
        device_code: str = Form(...),
        client_id: str = Form(default="device_flow_client"),
        redis_client: redis.Redis = Depends(get_redis),
    ):
        """GitHub Device Flow - Step 2: Poll for token (RFC 8628 compliant)
        
        Accepts form parameters per RFC 8628 Section 3.4
        Validates grant_type and exchanges device code for access token
        """
        client_ip = get_real_client_ip(request)
        
        # Validate grant_type per RFC 8628
        if grant_type != "urn:ietf:params:oauth:grant-type:device_code":
            log_warning(
                f"Invalid grant_type: {grant_type}",
                ip=client_ip,
                client_id=client_id
            )
            return JSONResponse(
                {"error": "unsupported_grant_type"},
                status_code=400
            )
        
        log_debug(
            "Device Flow: Token exchange attempt",
            ip=client_ip,
            client_id=client_id,
            has_device_code=bool(device_code)
        )
        
        async with httpx.AsyncClient() as client:
            # Exchange device code for GitHub access token
            github_response = await client.post(
                "https://github.com/login/oauth/access_token",
                headers={"Accept": "application/json"},
                data={
                    "client_id": settings.github_client_id,
                    "client_secret": settings.github_client_secret,
                    "device_code": device_code,
                    "grant_type": "urn:ietf:params:oauth:grant-type:device_code"
                }
            )
        
        result = github_response.json()
        
        # If we got an access token, get user info and generate our JWT
        if "access_token" in result:
            github_token = result["access_token"]
            
            # Get GitHub user info
            async with httpx.AsyncClient() as client:
                user_response = await client.get(
                    "https://api.github.com/user",
                    headers={"Authorization": f"token {github_token}"}
                )
            user_info = user_response.json()
            
            github_user = user_info.get("login")
            log_info(
                "Device Flow: GitHub user authenticated",
                ip=client_ip,
                github_user=github_user,
                github_email=user_info.get("email")
            )
            
            # Get localhost proxy for scope assignment
            async_storage = request.app.state.async_storage
            proxy = await async_storage.get_proxy_target("localhost")
            
            assigned_scopes = []
            
            if proxy:
                # Check admin users
                if proxy.oauth_admin_users:
                    if "*" in proxy.oauth_admin_users or github_user in proxy.oauth_admin_users:
                        assigned_scopes.append("admin")
                
                # Check user users (standard access)
                if proxy.oauth_user_users:
                    if "*" in proxy.oauth_user_users or github_user in proxy.oauth_user_users:
                        assigned_scopes.append("user")
                
                # Check MCP users
                if proxy.oauth_mcp_users:
                    if "*" in proxy.oauth_mcp_users or github_user in proxy.oauth_mcp_users:
                        assigned_scopes.append("mcp")
            
            # Default to user scope if no scopes assigned
            if not assigned_scopes:
                log_info(
                    f"Device Flow: No scopes configured for {github_user}, defaulting to 'user'",
                    ip=client_ip,
                    github_user=github_user
                )
                assigned_scopes = ["user"]
            
            # Retrieve the resource from stored device code data
            device_code_data_str = await redis_client.get(f"device_code:{device_code}")
            if device_code_data_str:
                device_code_data = json.loads(device_code_data_str)
                resource = device_code_data.get("resource", "http://localhost")
                # Clean up the stored data
                await redis_client.delete(f"device_code:{device_code}")
            else:
                # Fallback if no stored data (shouldn't happen)
                resource = "http://localhost"
                log_warning(f"Device Flow: No stored resource for device code, using default", ip=client_ip)
            
            # Generate our JWT with assigned scopes
            jti = f"device_{secrets.token_urlsafe(16)}"
            now = datetime.utcnow()
            
            # Get the issuer URL (auth server)
            issuer_url = get_external_url(request, settings)
            
            # Audience is the resource (proxy/MCP server) where token will be used (MCP compliant)
            audience_url = resource
            
            log_info(
                f"Device Flow: Generating token",
                ip=client_ip,
                github_user=github_user,
                resource=resource,
                audience=audience_url,
                scopes=assigned_scopes
            )
            
            token_payload = {
                "iss": issuer_url,
                "sub": str(user_info.get("id")),
                "aud": audience_url,  # Resource URI where token will be used (MCP compliant)
                "exp": now + timedelta(seconds=settings.access_token_lifetime),
                "iat": now,
                "jti": jti,
                "scope": " ".join(assigned_scopes),
                "azp": "device_flow_client",
                "username": github_user,
                "email": user_info.get("email"),
                "name": user_info.get("name")
            }
            
            access_token = jwt.encode(
                token_payload,
                auth_manager.key_manager.private_key,
                algorithm=settings.jwt_algorithm
            )
            
            # Store token metadata in Redis
            token_data = {
                "jti": jti,
                "user_id": str(user_info.get("id")),
                "username": github_user,
                "client_id": "device_flow_client",
                "scope": " ".join(assigned_scopes),
                "expires_at": (now + timedelta(seconds=settings.access_token_lifetime)).isoformat()
            }
            
            await redis_client.setex(
                f"oauth:token:{jti}",
                settings.access_token_lifetime,
                json.dumps(token_data)
            )
            
            # Generate refresh token for device flow with the same resource
            refresh_token_value = await auth_manager.create_refresh_token(
                {
                    "user_id": str(user_info.get("id")),
                    "username": github_user,
                    "client_id": "device_flow_client",
                    "scope": " ".join(assigned_scopes),
                    "resource": resource  # Store the resource for refresh (MCP compliant)
                },
                redis_client
            )
            
            log_info(
                "Device Flow: Token generated with refresh token",
                ip=client_ip,
                github_user=github_user,
                scopes=assigned_scopes,
                jti=jti
            )
            
            return {
                "access_token": access_token,
                "token_type": "Bearer",
                "scope": " ".join(assigned_scopes),
                "expires_in": settings.access_token_lifetime,
                "refresh_token": refresh_token_value
            }
        
        # Return GitHub's response as-is (error or pending) with appropriate status
        if "error" in result:
            # Return 400 for OAuth errors per RFC 8628
            return JSONResponse(result, status_code=400)
        return result

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
        
        log_info(
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
        
        # Log request with OAuth context
        log_request(
            request.method,
            str(request.url.path),
            client_ip, 
            proxy_hostname=request.headers.get("host"),
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
        # Generate a request key for tracking
        request_key = f"oauth:request:{client_id}:{state}"
        # Validate client
        client = await auth_manager.get_client(client_id, redis_client)
        if not client:
            log_warning(
                "OAuth authorization rejected - invalid client",
                ip=client_ip,
                client_id=client_id,
                oauth_rejection_reason="client_not_found",
                requested_redirect_uri=redirect_uri,
                requested_scope=scope
            )
            
            # Log the rejection
            log_response(
                400,
                0,
                proxy_hostname=request.headers.get("host"),
                oauth_action="authorize_rejected",
                oauth_rejection_reason="invalid_client",
                oauth_client_id=client_id,
                oauth_authorization_granted="rejected",
                request_key=request_key
            )
            
            # RFC 6749 - MUST NOT redirect on invalid client_id
            # Check Accept header to determine response format
            accept_header = request.headers.get("accept", "text/html")
            
            # Return JSON for API clients (like Claude.ai)
            if "application/json" in accept_header:
                return JSONResponse(
                    status_code=400,
                    content={
                        "error": "invalid_client",
                        "error_description": f"Client {client_id} is not registered. Please register at {request.url.scheme}://{request.headers.get('host', 'localhost')}/register"
                    }
                )
            
            # Return HTML for browsers
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
        log_info(
            "OAuth client validated",
            ip=client_ip,
            client_id=client_id,
            client_name=getattr(client, 'client_name', 'Unknown'),
            registered_redirect_uris=getattr(client, 'redirect_uris', [])
        )
        
        # Track client usage
        await auth_manager.track_client_usage(client_id, redis_client)
        
        # Validate redirect_uri
        if not client.check_redirect_uri(redirect_uri):
            log_warning(
                "OAuth authorization rejected - invalid redirect URI",
                ip=client_ip,
                client_id=client_id,
                oauth_rejection_reason="redirect_uri_not_registered",
                requested_redirect_uri=redirect_uri,
                registered_redirect_uris=getattr(client, 'redirect_uris', [])
            )
            
            log_response(
            400,
            0,
            proxy_hostname=request.headers.get("host"),
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
            log_warning(
                "OAuth authorization rejected - unsupported response type",
                ip=client_ip,
                client_id=client_id,
                oauth_rejection_reason="unsupported_response_type",
                requested_response_type=response_type,
                supported_response_types=getattr(client, 'response_types', ['code'])
            )
            
            log_response(
            400,
            0,
            proxy_hostname=request.headers.get("host"),
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
            log_warning(
                "OAuth authorization rejected - invalid PKCE method",
                ip=client_ip,
                client_id=client_id,
                oauth_rejection_reason="invalid_pkce_method",
                requested_pkce_method=code_challenge_method,
                supported_pkce_methods=["S256"]
            )
            
            log_response(
            400,
            0,
            proxy_hostname=request.headers.get("host"),
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
                    log_warning(
                        "OAuth authorization rejected - invalid resource URI",
                        ip=client_ip,
                        client_id=client_id,
                        oauth_rejection_reason="invalid_resource_uri",
                        invalid_resource=res,
                        all_requested_resources=resource
                    )
                    
                    log_response(
            500,
            0,
            proxy_hostname=request.headers.get("host"),
                        oauth_action="authorize_rejected",
                        oauth_rejection_reason="invalid_resource_uri",
                        oauth_client_id=client_id,
                        oauth_authorization_granted="rejected"
                    )
                    
                    return RedirectResponse(
                        url=f"{redirect_uri}?error=invalid_resource&error_description=Resource+must+be+a+valid+URI&state={state}",
                    )
            log_info(
                "OAuth authorization accepted - all validations passed",
                ip=client_ip,
                client_id=client_id,
                resources=resource,
                scope=scope,
                has_pkce=bool(code_challenge)
            )

        # Extract proxy hostname from headers FIRST (before storing auth_data)
        # MUST use X-Forwarded-Host when request comes through proxy
        detected_proxy_hostname = request.headers.get("x-forwarded-host") or request.headers.get("host", "")
        detected_proxy_hostname = detected_proxy_hostname.split(":")[0]  # Remove port if present
        
        # Use the detected proxy hostname if not explicitly provided as parameter
        if not proxy_hostname:
            proxy_hostname = detected_proxy_hostname
        
        log_info(
            f"OAuth authorize - proxy hostname resolution",
            param_proxy_hostname=proxy_hostname if proxy_hostname != detected_proxy_hostname else None,
            detected_proxy_hostname=detected_proxy_hostname,
            final_proxy_hostname=proxy_hostname,
            component="oauth_authorize"
        )
        
        # Store authorization request state
        auth_state = secrets.token_urlsafe(32)
        auth_data = {
            "client_id": client_id,
            "redirect_uri": redirect_uri,  # This is the CLIENT's redirect_uri (e.g., Claude.ai's callback)
            "scope": scope,
            "state": state,
            "code_challenge": code_challenge,
            "code_challenge_method": code_challenge_method,
            "resources": resource if resource else [],  # RFC 8707 Resource Indicators
            "proxy_hostname": proxy_hostname,  # Store proxy hostname for per-proxy GitHub user checks (now correctly set!)
            # We'll add github_redirect_uri later after we build it
        }

        await redis_client.setex(
            f"oauth:state:{auth_state}",
            300,
            json.dumps(auth_data),
        )  # TODO: Break long line
        log_info(
            f"Created OAuth state: {auth_state} for client: {client_id}, original state: {state}, proxy: {proxy_hostname}",
        )

        # Redirect to GitHub OAuth
        # Get the external URL for the callback
        external_url = get_external_url(request, settings)
        
        # Get the appropriate GitHub client for this proxy
        async_storage = request.app.state.async_storage
        github_client = await auth_manager.get_github_client(proxy_hostname, async_storage)
        if not github_client:
            log_error(
                "No GitHub OAuth credentials available",
                ip=client_ip,
                proxy_hostname=proxy_hostname
            )
            return HTMLResponse(
                status_code=500,
                content="GitHub OAuth not configured for this proxy"
            )
        
        log_info(
            f"Using GitHub client for {proxy_hostname}",
            proxy_hostname=proxy_hostname,
            client_id=github_client.client_id,
            has_proxy_config=proxy_hostname in auth_manager._github_clients,
            x_forwarded_host=request.headers.get("x-forwarded-host"),
            host_header=request.headers.get("host")
        )
        
        # Build the GitHub redirect_uri - this MUST match what's registered in GitHub
        # For claude.atratest.org, this should be https://claude.atratest.org/callback
        github_redirect_uri = f"{external_url}/callback"
        
        log_info(
            f"Building GitHub redirect_uri",
            external_url=external_url,
            github_redirect_uri=github_redirect_uri,
            x_forwarded_host=request.headers.get("x-forwarded-host"),
            host_header=request.headers.get("host"),
            proxy_hostname=proxy_hostname,
            component="oauth_authorize"
        )
        
        # Update auth_data with the GitHub redirect_uri we're using
        auth_data["github_redirect_uri"] = github_redirect_uri
        
        # Re-store the updated auth_data with the GitHub redirect_uri
        await redis_client.setex(
            f"oauth:state:{auth_state}",
            300,
            json.dumps(auth_data),
        )
        
        log_info(
            f"Stored GitHub redirect_uri in auth state",
            github_redirect_uri=github_redirect_uri,
            auth_state=auth_state,
            client_redirect_uri=redirect_uri,  # This is Claude.ai's callback
            component="oauth_authorize"
        )
        
        github_params = {
            "client_id": github_client.client_id,
            "redirect_uri": github_redirect_uri,
            "scope": "user:email",
            "state": auth_state,
        }

        github_url = f"https://github.com/login/oauth/authorize?{urlencode(github_params)}"  # TODO: Break long line
        
        # Log the redirect destination
        log_info(
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
        log_response(
            302,
            0,
            # duration will be calculated by log_response
            proxy_hostname=request.headers.get("host"),
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
        
        # Wrap entire function in try-except to catch any unexpected errors
        try:
            return await _handle_oauth_callback(request, code, state, error, error_description, redis_client, client_ip)
        except HTTPException:
            raise  # Re-raise HTTP exceptions
        except Exception as e:
            log_error(f"Unexpected error in OAuth callback: {e}", component="oauth_callback", error_type=type(e).__name__)
            import traceback
            log_error(f"Traceback: {traceback.format_exc()}", component="oauth_callback")
            # Return generic error to avoid exposing internals
            raise HTTPException(500, "Internal server error during OAuth callback")
    
    async def _handle_oauth_callback(request, code, state, error, error_description, redis_client, client_ip):
        
        log_info(
            "OAuth callback received from GitHub",
            ip=client_ip,
            state=state,
            code_preview=f"{code[:8]}..." if code else "no code",
            host_header=request.headers.get("host"),
            x_forwarded_host=request.headers.get("x-forwarded-host"),
            full_url=str(request.url),
            component="oauth_callback"
        )
        
        # Log request with OAuth context
        log_request(
            method=request.method,
            path=str(request.url.path),
            ip=client_ip,
            proxy_hostname=request.headers.get("host", ""),
            oauth_action="callback",
            oauth_state=state,
            oauth_code=code[:8] + "..." if code else "no_code",
            oauth_error=error,
            oauth_error_description=error_description
        )
        
        # Retrieve authorization state
        auth_data_str = await redis_client.get(f"oauth:state:{state}")
        if not auth_data_str:
            log_warning(
                "OAuth callback with invalid or expired state",
                    ip=client_ip,
                state=state
            )
            # Check if any similar states exist (for debugging)
            all_states = await redis_client.keys("oauth:state:*")
            log_debug(f"Current states in Redis: {len(all_states)} total")

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
        log_debug(
            "OAuth state validated successfully",
            state=state,
            client_id=auth_data.get('client_id'),
            scope=auth_data.get('scope'),
            resources=auth_data.get('resources')
        )

        # Exchange GitHub code using proxy-specific credentials
        proxy_hostname = auth_data.get('proxy_hostname')
        
        # CRITICAL: Use the EXACT same redirect_uri we sent to GitHub in the authorize request
        # This was stored in auth_data to ensure consistency
        github_redirect_uri = auth_data.get('github_redirect_uri')
        
        if not github_redirect_uri:
            log_error(f"Missing github_redirect_uri in auth_data", component="oauth_callback")
            # Fallback to reconstructing it (shouldn't happen with updated code)
            external_url = get_external_url(request, settings)
            github_redirect_uri = f"{external_url}/callback"
            log_warning(f"Falling back to reconstructed redirect_uri: {github_redirect_uri}", component="oauth_callback")
        
        log_info(f"Exchanging GitHub code for proxy: {proxy_hostname}, github_redirect_uri: {github_redirect_uri}", component="oauth_callback")
        
        # Get async_storage from app.state for GitHub client lookup
        async_storage = request.app.state.async_storage
        
        try:
            user_info = await auth_manager.exchange_github_code(code, proxy_hostname, github_redirect_uri, async_storage)
        except Exception as e:
            log_error(
                f"Exception during GitHub code exchange: {e}",
                ip=client_ip,
                client_id=auth_data.get('client_id'),
                error_type=type(e).__name__,
                component="oauth_callback"
            )
            import traceback
            log_error(f"Traceback: {traceback.format_exc()}", component="oauth_callback")
            user_info = None

        if not user_info:
            log_error(
                "Failed to exchange GitHub code",
                    ip=client_ip,
                client_id=auth_data.get('client_id')
            )
            return RedirectResponse(
                url=f"{auth_data['redirect_uri']}?error=server_error&state={auth_data['state']}",  # TODO: Break long line
            )

        log_info(
            "GitHub code exchanged successfully",
            ip=client_ip,
            github_user_id=user_info.get("id"),
            github_username=user_info.get("login"),
            github_email=user_info.get("email")
        )
        
        # Update request log with GitHub user info
        log_response(
            200,
            0,
            proxy_hostname=request.headers.get("host"),
            oauth_github_user_id=user_info.get("id"),
            oauth_github_username=user_info.get("login"),
            oauth_github_email=user_info.get("email")
        )

        # Check if user is allowed - first check proxy-specific, then fall back to global
        proxy_hostname = auth_data.get("proxy_hostname")
        allowed_users = []
        
        # Check if we have a proxy-specific user allowlist
        if proxy_hostname:
            # Get async_storage from app.state (set by main.py)
            storage = request.app.state.async_storage
            proxy_target = await storage.get_proxy_target(proxy_hostname)
            
            if proxy_target and proxy_target.auth_required_users is not None:
                # Use proxy-specific list from auth_required_users
                allowed_users = proxy_target.auth_required_users
                log_info(
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
                log_info(
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
            log_info(
                "Using global GitHub allowed users (no proxy specified)",
                ip=client_ip,
                allowed_users=allowed_users
            )
        
        # If allowed_users is set and doesn't contain '*', check if user is allowed
        if allowed_users and "*" not in allowed_users and user_info["login"] not in allowed_users:
            log_warning(
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

        # Assign scopes based on proxy configuration and GitHub username
        github_user = user_info.get("login")
        assigned_scopes = []
        
        # Get proxy configuration for scope assignment
        proxy_hostname = auth_data.get("proxy_hostname", "localhost")
        if async_storage:
            proxy = await async_storage.get_proxy_target(proxy_hostname)
            if proxy:
                # Check admin users
                if proxy.oauth_admin_users:
                    if "*" in proxy.oauth_admin_users or github_user in proxy.oauth_admin_users:
                        assigned_scopes.append("admin")
                
                # Check user users (standard access)
                if proxy.oauth_user_users:
                    if "*" in proxy.oauth_user_users or github_user in proxy.oauth_user_users:
                        assigned_scopes.append("user")
                
                # Check MCP users
                if proxy.oauth_mcp_users:
                    if "*" in proxy.oauth_mcp_users or github_user in proxy.oauth_mcp_users:
                        assigned_scopes.append("mcp")
        
        # If no scopes assigned through proxy config, default to user scope
        if not assigned_scopes:
            log_info(
                f"No scopes configured for user {github_user} on {proxy_hostname}, defaulting to 'user' scope",
                ip=client_ip,
                github_user=github_user,
                proxy_hostname=proxy_hostname
            )
            assigned_scopes = ["user"]
        
        # Update auth_data with assigned scopes (overwrites requested scopes)
        auth_data["scope"] = " ".join(assigned_scopes)
        
        log_info(
            f"OAuth scopes assigned based on GitHub user",
            ip=client_ip,
            github_user=github_user,
            assigned_scopes=assigned_scopes,
            proxy_hostname=proxy_hostname
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
        
        log_info(
            "OAuth authorization code generated",
            ip=client_ip,
            client_id=auth_data.get('client_id'),
            user_id=str(user_info.get("id", "unknown")),
            username=user_info.get("login", "unknown"),
            email=user_info.get("email", ""),
            scope=auth_data.get("scope"),
            resources=auth_data.get("resources"),
            redirect_uri=auth_data.get("redirect_uri", "")
        )

        # Handle out-of-band redirect URI
        if auth_data.get("redirect_uri") == "urn:ietf:wg:oauth:2.0:oob":
            log_debug(
                "Using out-of-band redirect for auth code display",
                client_id=auth_data.get("client_id"),
                state=auth_data.get("state", state)
            )
            return RedirectResponse(
                url=f"https://auth.{settings.base_domain}/success?code={auth_code}&state={auth_data.get('state', state)}",  # TODO: Break long line
                headers={
                    "Cache-Control": "no-cache, no-store, must-revalidate",
                    "Pragma": "no-cache",
                    "Expires": "0",
                },
            )

        # Normal redirect
        redirect_params = {"code": auth_code, "state": auth_data.get("state", state)}

        client_redirect_uri = auth_data.get('redirect_uri')
        if not client_redirect_uri:
            log_error(f"Missing redirect_uri in auth_data", component="oauth_callback")
            raise HTTPException(500, "Missing redirect_uri in auth state")
        
        final_redirect_url = f"{client_redirect_uri}?{urlencode(redirect_params)}"
        
        log_info(
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
        log_response(
            302,
            0,
            # duration will be calculated by log_response
            proxy_hostname=request.headers.get("host"),
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
        log_debug(f"Token exchange request from {client_ip}: grant_type={grant_type}, client_id={client_id}, resource={resource}", component="oauth")
        
        log_info(
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
        log_request(
            method=request.method,
            path=str(request.url.path),
            ip=client_ip,
            proxy_hostname=request.headers.get("host", ""),
            oauth_action="token_exchange",
            oauth_client_id=client_id,
            oauth_grant_type=grant_type,
            oauth_resources=resource if resource else []
        )
        # Special handling for device_flow_client (public client)
        if client_id == "device_flow_client":
            # Device flow client is a public client that doesn't require registration
            # or client_secret authentication
            client = None
            log_debug(
                "Using public device_flow_client for token exchange",
                ip=client_ip,
                grant_type=grant_type
            )
        else:
            # Validate regular client
            client = await auth_manager.get_client(client_id, redis_client)
            if not client:
                log_warning(
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

            # Validate client secret for confidential clients
            if client_secret and not client.check_client_secret(client_secret):
                log_warning(
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

        # Validate grant type (skip for device_flow_client)
        if client and not client.check_grant_type(grant_type):
            raise HTTPException(
                status_code=400,
                detail={
                    "error": "unsupported_grant_type",
                    "error_description": f"Grant type '{grant_type}' is not supported",
                },
            )

        # Track client usage
        await auth_manager.track_client_usage(client_id, redis_client)

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
            log_info(
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
            token_claims = jwt.decode(access_token, options={"verify_signature": False})
            
            log_info(
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
            log_info(
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
            log_response(
            200,
            0,
            proxy_hostname=request.headers.get("host"),
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

            # Track refresh token usage
            try:
                usage_key = f"oauth:refresh_usage:{refresh_token}"
                usage_data = await redis_client.get(usage_key)
                
                if usage_data:
                    usage = json.loads(usage_data)
                    usage["last_used"] = int(time.time())
                    usage["usage_count"] = usage.get("usage_count", 0) + 1
                else:
                    usage = {
                        "last_used": int(time.time()),
                        "usage_count": 1
                    }
                
                # Store usage data with same TTL as refresh token
                ttl = await redis_client.ttl(f"oauth:refresh:{refresh_token}")
                if ttl > 0:
                    await redis_client.setex(usage_key, ttl, json.dumps(usage))
                else:
                    # Use default refresh token lifetime
                    await redis_client.setex(usage_key, settings.refresh_token_lifetime, json.dumps(usage))
                
                log_debug(f"Updated refresh token usage: count={usage['usage_count']}")
            except Exception as e:
                log_warning(f"Failed to track refresh token usage: {e}")

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
            log_info(
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
            
            # Generate new access token with the correct issuer URL and audience
            issuer_url = get_external_url(request, settings)
            
            # Use the resource from the refresh token as audience (MCP compliant)
            # This preserves the original resource the token was issued for
            resource = refresh_data.get("resource")
            if not resource:
                # For backward compatibility with old refresh tokens
                resources = refresh_data.get("resources", [])
                if resources:
                    resource = resources[0] if isinstance(resources, list) else resources
                else:
                    resource = "http://localhost"  # Last resort fallback
                    log_warning(
                        f"Refresh token missing resource, using default",
                        ip=client_ip,
                        refresh_token_preview=refresh_token[:10] if refresh_token else "N/A"
                    )
            
            log_info(
                f"Refreshing token with resource",
                ip=client_ip,
                resource=resource,
                username=refresh_data.get("username")
            )
            
            access_token = await auth_manager.create_jwt_token(
                {
                    "sub": refresh_data["user_id"],
                    "username": refresh_data["username"],
                    "scope": refresh_data["scope"],
                    "client_id": client_id,
                    "audience": resource,  # Use the original resource as audience (MCP compliant)
                },
                redis_client,
                issuer=issuer_url
            )

            # Extract token claims for detailed logging
            token_claims = jwt.decode(access_token, options={"verify_signature": False})
            
            log_info(
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
                log_debug(
                    "Using forwarded IP for verification",
                    direct_ip=client_ip,
                    forwarded_ip=forwarded_ip
                )
            
            log_debug(
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
                    log_warning(
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
                    log_warning(
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
            
            log_info(
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
            log_warning(
                "OAuth token verification failed",
                ip=forwarded_ip,
                resource=resource,
                status_code=e.status_code,
                error=e.detail
            )
            raise
        except Exception as e:
            log_error(
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
        
        log_info(
            "OAuth token revocation request",
            ip=client_ip,
            client_id=client_id,
            token_type_hint=token_type_hint
        )
        
        # Validate client
        client = await auth_manager.get_client(client_id, redis_client)
        if not client:
            # RFC 7009 - invalid client should still return 200
            log_debug(
                "Token revocation with invalid client (returning 200 per RFC 7009)",
                    ip=client_ip,
                client_id=client_id
            )
            return Response(status_code=200)

        if client_secret and not client.check_client_secret(client_secret):
            log_debug(
                "Token revocation with invalid client secret (returning 200 per RFC 7009)",
                    ip=client_ip,
                client_id=client_id
            )
            return Response(status_code=200)

        # Revoke token
        await auth_manager.revoke_token(token, redis_client)

        log_info(
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
        
        log_info(
            "OAuth token introspection request",
            ip=client_ip,
            client_id=client_id,
            token_type_hint=token_type_hint
        )
        
        # Log request with OAuth context
        log_request(
            method=request.method,
            path=str(request.url.path),
            ip=client_ip,
            proxy_hostname=request.headers.get("host", ""),
            oauth_action="introspect",
            oauth_client_id=client_id,
            oauth_token_type_hint=token_type_hint
        )
        
        # Validate client
        client = await auth_manager.get_client(client_id, redis_client)
        if not client or (client_secret and not client.check_client_secret(client_secret)):
            log_debug(
                "Token introspection with invalid client credentials",
                    ip=client_ip,
                client_id=client_id
            )
            return {"active": False}

        # Track client usage
        await auth_manager.track_client_usage(client_id, redis_client)

        # Introspect token
        introspection_result = await auth_manager.introspect_token(token, redis_client)

        log_info(
            "OAuth token introspection completed",
            ip=client_ip,
            client_id=client_id,
            token_active=introspection_result.get("active", False),
            token_sub=introspection_result.get("sub") if introspection_result.get("active") else None,
            token_client_id=introspection_result.get("client_id") if introspection_result.get("active") else None
        )
        
        # Log response with full introspection result
        log_response(
            200,
            0,
            proxy_hostname=request.headers.get("host"),
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
