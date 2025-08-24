"""Simplified async proxy handler with unified routing support and OAuth scopes."""
import json
import httpx
import jwt
import re
import socket
from typing import Optional, List, Dict, Any
from fastapi import Request, Response, HTTPException
from fastapi.responses import RedirectResponse
from urllib.parse import quote
from ..storage.async_redis_storage import AsyncRedisStorage
from ..storage.redis_clients import RedisClients
from ..shared.config import Config
from ..proxy.unified_routing import (
    RequestNormalizer, 
    UnifiedRoutingEngine, 
    RoutingDecisionType
)
from ..shared.logger import log_debug, log_info, log_warning, log_error
from ..proxy.auth_exclusions import merge_exclusions


class SimpleAsyncProxyHandler:
    """Simplified proxy handler with unified routing and OAuth scopes."""
    
    # OAuth scope requirements mapping
    # Format: (method_pattern, path_pattern): [required_scopes]
    SCOPE_REQUIREMENTS = [
        # Admin scope - all create/update/delete operations
        (r"POST|PUT|DELETE|PATCH", r"/tokens/.*", ["admin"]),
        (r"POST|PUT|DELETE|PATCH", r"/certificates/.*", ["admin"]),
        (r"POST|PUT|DELETE|PATCH", r"/services/.*", ["admin"]),
        (r"POST|PUT|DELETE|PATCH", r"/proxy/targets.*", ["admin"]),
        (r"POST|PUT|DELETE|PATCH", r"/routes/.*", ["admin"]),
        (r"POST|PUT|DELETE|PATCH", r"/resources/.*", ["admin"]),
        (r"POST|PUT|DELETE|PATCH", r"/auth/.*", ["admin"]),
        
        # MCP scope - protocol endpoints
        (r".*", r"/mcp.*", ["mcp"]),
        
        # User scope - all read operations (default for GET)
        (r"GET|HEAD|OPTIONS", r"/.*", ["user"]),
        
        # Public endpoints - no auth required
        (r".*", r"/health", None),
        (r".*", r"/.well-known/.*", None),
    ]
    
    def __init__(self, storage: AsyncRedisStorage, redis_clients: RedisClients, oauth_components=None, proxy_hostname=None):
        """Initialize simple proxy handler with OAuth scopes.
        
        Args:
            storage: Async storage instance
            redis_clients: Redis clients for operations
            oauth_components: OAuth components (optional)
            proxy_hostname: Hostname this handler is serving (for route filtering)
        """
        self.storage = storage
        self.redis_clients = redis_clients
        self.proxy_hostname = proxy_hostname
        self.oauth_components = oauth_components
        
        # Initialize unified routing components
        self.normalizer = RequestNormalizer()
        self.routing_engine = UnifiedRoutingEngine(storage)
        
        # Create httpx client with proper timeouts
        self.client = httpx.AsyncClient(
            follow_redirects=False,
            verify=False,
            timeout=httpx.Timeout(
                connect=float(Config.PROXY_CONNECT_TIMEOUT),
                read=float(Config.PROXY_REQUEST_TIMEOUT),
                write=10.0,
                pool=None
            ),
            limits=httpx.Limits(max_keepalive_connections=100)
        )
    
    def extract_bearer_token(self, request: Request) -> Optional[str]:
        """Extract bearer token from Authorization header."""
        auth_header = request.headers.get('authorization', '')
        if auth_header.startswith('Bearer '):
            return auth_header[7:]
        return None
    
    async def _get_proxy_resource_uri(self) -> str:
        """Get the proxy's resource URI for audience validation.
        
        The resource URI is the canonical identifier for this proxy as an MCP resource.
        For localhost, it's http://localhost. For production, it's https://{hostname}
        """
        # Get hostname from storage or default to localhost
        if hasattr(self, 'proxy_hostname'):
            hostname = self.proxy_hostname
        else:
            # Default to localhost if not set
            hostname = "localhost"
        
        # Build the resource URI
        if hostname == "localhost":
            return "http://localhost"
        else:
            return f"https://{hostname}"
    
    async def validate_oauth_jwt(self, token: str) -> Optional[Dict[str, Any]]:
        """Validate OAuth JWT token and return payload."""
        try:
            log_info(f"Starting OAuth JWT validation", component="proxy_handler", token_preview=token[:30] if token else "NO_TOKEN")
            
            # Get OAuth public key from storage or config
            if self.oauth_components and hasattr(self.oauth_components, 'public_key'):
                public_key = self.oauth_components.public_key
                log_info("Using public key from oauth_components", component="proxy_handler")
            else:
                # Try to get from storage
                log_info("Attempting to get public key from Redis storage", component="proxy_handler")
                public_key_data = await self.storage.get("oauth:public_key")
                if not public_key_data:
                    log_error("CRITICAL: No OAuth public key found in Redis at oauth:public_key", component="proxy_handler")
                    return None
                public_key = public_key_data
                log_info(f"Retrieved public key from Redis, length: {len(public_key) if public_key else 0} chars", component="proxy_handler")
            
            # Log key preview for debugging
            if public_key:
                key_preview = public_key[:100] if isinstance(public_key, str) else str(public_key)[:100]
                log_debug(f"Public key preview: {key_preview}...", component="proxy_handler")
            
            # Decode and validate JWT
            log_info("Attempting JWT decode with RS256/HS256 algorithms", component="proxy_handler")
            
            # First decode without audience validation to get the audience claim
            payload = jwt.decode(
                token,
                public_key,
                algorithms=["RS256", "HS256"],
                options={
                    "verify_signature": True, 
                    "verify_exp": True,
                    "verify_aud": False  # We'll validate audience manually
                }
            )
            
            # Get the proxy's resource URI
            proxy_resource_uri = await self._get_proxy_resource_uri()
            log_info(f"Proxy resource URI: {proxy_resource_uri}", component="proxy_handler")
            
            # Validate audience (MCP compliant)
            token_audience = payload.get('aud')
            if not token_audience:
                log_error("Token has no audience claim", component="proxy_handler")
                return None
            
            # Check if proxy's resource URI is in the audience
            # Audience can be a string or list of strings
            if isinstance(token_audience, str):
                audience_list = [token_audience]
            else:
                audience_list = token_audience
            
            log_info(
                f"Validating audience",
                component="proxy_handler",
                token_audience=audience_list,
                proxy_resource=proxy_resource_uri
            )
            
            if proxy_resource_uri not in audience_list:
                log_warning(
                    f"Token audience does not include proxy resource",
                    component="proxy_handler",
                    token_audience=audience_list,
                    required_resource=proxy_resource_uri
                )
                return None
            
            log_info(f"Audience validation successful", component="proxy_handler")
            
            log_info(
                f"JWT validation SUCCESSFUL",
                component="proxy_handler",
                user=payload.get('sub'),
                username=payload.get('username'),
                scope=payload.get('scope'),
                issuer=payload.get('iss'),
                audience=payload.get('aud'),
                client_id=payload.get('client_id')
            )
            return payload
            
        except jwt.ExpiredSignatureError as e:
            log_warning(f"JWT token expired: {e}", component="proxy_handler", token_preview=token[:30] if token else "NO_TOKEN")
            return None
        except jwt.InvalidTokenError as e:
            log_warning(f"Invalid JWT token: {e}", component="proxy_handler", token_preview=token[:30] if token else "NO_TOKEN", error_type=type(e).__name__)
            return None
        except Exception as e:
            log_error(f"Unexpected error validating JWT: {e}", component="proxy_handler", error_type=type(e).__name__, token_preview=token[:30] if token else "NO_TOKEN")
            import traceback
            log_error(f"Traceback: {traceback.format_exc()}", component="proxy_handler")
            return None
    
    def get_required_scopes(self, method: str, path: str) -> Optional[List[str]]:
        """Get required scopes for the given method and path."""
        for method_pattern, path_pattern, required_scopes in self.SCOPE_REQUIREMENTS:
            if re.match(method_pattern, method, re.IGNORECASE):
                if re.match(path_pattern, path):
                    return required_scopes
        # Default to user scope for unmatched patterns
        return ["user"]
    
    def validate_scopes(self, token_scopes: List[str], required_scopes: List[str]) -> bool:
        """Check if token has required scopes."""
        if not required_scopes:
            return True  # No scopes required (public endpoint)
        
        # Check if user has at least one required scope
        return any(scope in token_scopes for scope in required_scopes)
    
    def get_auth_config(self, route: Any, proxy_config: Dict[str, Any]) -> Dict[str, Any]:
        """Get auth config from route or proxy."""
        # Check route-level auth override first
        if route and hasattr(route, 'override_proxy_auth') and route.override_proxy_auth:
            if hasattr(route, 'auth_config') and route.auth_config:
                return route.auth_config
        
        # Fall back to proxy-level auth config
        return proxy_config.get('auth_config', {'auth_type': 'oauth'})
    
    def validate_user_access(self, token_info: Dict[str, Any], auth_config: Dict[str, Any]) -> bool:
        """Validate user access based on allowed users/orgs/emails."""
        username = token_info.get('sub', '')
        
        # Check allowed users
        allowed_users = auth_config.get('allowed_users', [])
        if allowed_users and allowed_users != ['*']:
            if username not in allowed_users:
                log_info(f"User {username} not in allowed users", component="proxy_handler")
                return False
        
        # Check allowed organizations
        user_orgs = token_info.get('orgs', [])
        allowed_orgs = auth_config.get('allowed_orgs', [])
        if allowed_orgs:
            if not any(org in allowed_orgs for org in user_orgs):
                log_info(f"User not in allowed organizations", component="proxy_handler")
                return False
        
        # Check allowed emails
        user_email = token_info.get('email', '')
        allowed_emails = auth_config.get('allowed_emails', [])
        if allowed_emails:
            email_allowed = False
            for pattern in allowed_emails:
                if '*' in pattern:
                    # Simple wildcard matching
                    regex_pattern = pattern.replace('*', '.*')
                    if re.match(regex_pattern, user_email):
                        email_allowed = True
                        break
                elif user_email == pattern:
                    email_allowed = True
                    break
            
            if not email_allowed:
                log_info(f"User email {user_email} not in allowed emails", component="proxy_handler")
                return False
        
        return True
    
    async def _check_auth(self, request: Request, proxy_hostname: str, decision=None, log_ctx=None) -> Response:
        """Check OAuth authentication with scope validation.
        
        Args:
            request: The incoming request
            proxy_hostname: The proxy hostname
            decision: Optional routing decision with route info
            log_ctx: Optional logging context with client info
        
        Returns:
            None if authenticated, Response object if auth failed/redirect needed
        """
        if log_ctx is None:
            log_ctx = {}
        log_info(f"OAuth auth check for {proxy_hostname}{request.url.path}", component="proxy_handler", **log_ctx)
        
        # Get proxy configuration
        try:
            proxy_target = await self.storage.get_proxy_target(proxy_hostname)
            if not proxy_target:
                log_warning(f"No proxy target found for {proxy_hostname}", component="proxy_handler", **log_ctx)
                return None
            
            proxy_config = {
                'auth_enabled': proxy_target.auth_enabled,
                'auth_type': 'oauth' if proxy_target.auth_proxy else 'none',
                'auth_proxy': proxy_target.auth_proxy,
                'auth_mode': proxy_target.auth_mode,
                'auth_excluded_paths': proxy_target.auth_excluded_paths,
                'admin_users': proxy_target.oauth_admin_users or [],
                'user_users': proxy_target.oauth_user_users or ['*'],
                'mcp_users': proxy_target.oauth_mcp_users or [],
            }
        except Exception as e:
            log_error(f"Error getting proxy config: {e}", component="proxy_handler", **log_ctx)
            proxy_config = {'auth_type': 'oauth'}
        
        # Get auth configuration (route overrides proxy)
        route = decision.route if decision else None
        auth_config = self.get_auth_config(route, proxy_config)
        
        # Check if auth is disabled
        if auth_config.get('auth_type') == 'none':
            log_info(f"Auth disabled for this request", component="proxy_handler", **log_ctx)
            return None
        
        # Check excluded paths
        request_path = request.url.path
        excluded_paths = auth_config.get('auth_excluded_paths', []) or proxy_config.get('auth_excluded_paths', [])
        for excluded_path in excluded_paths:
            if request_path.startswith(excluded_path):
                log_info(f"Path {request_path} excluded from auth", component="proxy_handler", **log_ctx)
                return None
        
        # Extract bearer token
        token = self.extract_bearer_token(request)
        if not token:
            log_info("No bearer token found in request", component="proxy_handler", **log_ctx)
            return await self._return_auth_error(request, proxy_config)
        
        # Validate OAuth JWT
        token_info = await self.validate_oauth_jwt(token)
        if not token_info:
            log_warning("Invalid or expired OAuth token", component="proxy_handler", **log_ctx)
            return await self._return_auth_error(request, proxy_config)
        
        # Get required scopes for this request
        method = request.method
        path = request.url.path
        
        # Check if route has specific scope requirements
        if route and hasattr(route, 'auth_config') and route.auth_config:
            required_scopes = route.auth_config.get('required_scopes', [])
            if not required_scopes:
                # Fall back to method/path based scope detection
                required_scopes = self.get_required_scopes(method, path)
        else:
            required_scopes = self.get_required_scopes(method, path)
        
        log_info(f"Required scopes for {method} {path}: {required_scopes}", component="proxy_handler")
        
        # Get user's scopes from token
        token_scopes = token_info.get('scope', '').split()
        log_info(f"User {token_info.get('sub')} has scopes: {token_scopes}", component="proxy_handler")
        
        # Validate scopes
        if required_scopes and not self.validate_scopes(token_scopes, required_scopes):
            log_warning(f"User lacks required scopes. Has: {token_scopes}, needs: {required_scopes}", component="proxy_handler")
            return Response(
                status_code=403,
                content=json.dumps({
                    "error": "insufficient_scope",
                    "error_description": f"Missing required scopes. Need one of: {required_scopes}"
                }),
                headers={"Content-Type": "application/json"}
            )
        
        # Validate user access (allowed users/orgs/emails)
        if not self.validate_user_access(token_info, auth_config):
            log_warning(f"User {token_info.get('sub')} not in allowed users/orgs/emails", component="proxy_handler")
            return Response(
                status_code=403,
                content=json.dumps({
                    "error": "access_denied",
                    "error_description": "User not authorized for this resource"
                }),
                headers={"Content-Type": "application/json"}
            )
        
        # Authentication successful - will forward with trust headers
        log_info(f"OAuth authentication successful for {token_info.get('sub')} with scopes: {token_scopes}", component="proxy_handler")
        
        # Store auth info in request state for forwarding
        request.state.auth_user = token_info.get('username', token_info.get('sub', 'anonymous'))
        request.state.auth_scopes = ' '.join(token_scopes)
        request.state.auth_email = token_info.get('email', '')
        
        log_info(f"Stored auth state - User: {request.state.auth_user}, Scopes: {request.state.auth_scopes}", component="proxy_handler", **log_ctx)
        
        return None  # Authentication successful
    
    async def _return_auth_error(self, request: Request, proxy_config: Dict[str, Any]) -> Response:
        """Return appropriate auth error response (401 with WWW-Authenticate or redirect)."""
        # Check if this is a browser request
        accept = request.headers.get("accept", "")
        user_agent = request.headers.get("user-agent", "").lower()
        is_browser = "text/html" in accept or any(x in user_agent for x in ["mozilla", "chrome", "safari", "firefox"])
        
        # Special handling for MCP endpoint
        is_mcp = request.url.path.startswith("/mcp")
        
        # Get auth proxy for OAuth redirect
        auth_proxy = proxy_config.get('auth_proxy', '')
        auth_mode = proxy_config.get('auth_mode', 'redirect')
        
        # API requests and MCP always get 401
        if not is_browser or is_mcp or auth_mode != 'redirect':
            # Build WWW-Authenticate header
            www_auth = 'Bearer'
            if auth_proxy:
                www_auth += f' realm="{auth_proxy}"'
            
            return Response(
                status_code=401,
                content=json.dumps({
                    "error": "unauthorized",
                    "error_description": "OAuth authentication required"
                }),
                headers={
                    "WWW-Authenticate": www_auth,
                    "Content-Type": "application/json"
                }
            )
        
        # Browser requests get redirect to OAuth
        if auth_proxy:
            from secrets import token_urlsafe
            state = token_urlsafe(32)
            
            # Get GitHub client ID
            github_client_id = proxy_config.get('github_client_id')
            if not github_client_id:
                from ..shared.config import Config
                github_client_id = Config.GITHUB_CLIENT_ID
            
            if not github_client_id:
                return Response(content="OAuth not configured", status_code=500)
            
            # Build OAuth authorize URL
            from urllib.parse import urlencode
            auth_params = {
                'response_type': 'code',
                'client_id': github_client_id,
                'redirect_uri': f'https://{request.headers.get("host")}/callback',
                'state': state,
                'scope': 'openid profile email'
            }
            
            auth_url = f"https://{auth_proxy}/authorize?{urlencode(auth_params)}"
            return RedirectResponse(url=auth_url, status_code=302)
        
        # No auth proxy configured
        return Response(
            status_code=401,
            content="Authentication required but not configured",
            headers={"WWW-Authenticate": "Bearer"}
        )
    
    async def handle_request(self, request: Request) -> Response:
        """Handle request with unified routing logic."""
        try:
            # Get proxy hostname from request
            proxy_hostname = request.headers.get("host", "unknown").split(":")[0]
            
            # Extract client info from headers (set by PROXY protocol handler)
            client_info = {
                'ip': request.headers.get('x-real-ip', '127.0.0.1'),
                'port': int(request.headers.get('x-client-port', '0'))
            }
            
            # Get client hostname via reverse DNS
            client_hostname = "unknown"
            try:
                client_hostname = socket.gethostbyaddr(client_info['ip'])[0]
            except:
                client_hostname = client_info['ip']  # Use IP if reverse DNS fails
            
            # Create log context for all logs in this request
            log_ctx = {
                'proxy_hostname': proxy_hostname,
                'client_ip': client_info['ip'],
                'client_hostname': client_hostname,
                'request_path': str(request.url.path),
                'request_method': request.method
            }
            
            # Normalize the HTTPS request
            try:
                normalized = self.normalizer.normalize_https(request, client_info)
                log_debug(f"Normalized request - hostname: {normalized.hostname}, path: {normalized.path}", component="proxy_handler", **log_ctx)
            except Exception as e:
                log_warning(f"Failed to normalize request: {e}", component="proxy_handler", **log_ctx)
                raise HTTPException(400, f"Failed to normalize request: {e}")
            
            # Process through unified routing engine FIRST to get route info
            log_info(f"Processing routing for {normalized.hostname}{normalized.path}", component="proxy_handler", **log_ctx)
            decision = await self.routing_engine.process_request(normalized)
            
            # Check authentication with routing decision context
            try:
                auth_response = await self._check_auth(request, normalized.hostname, decision, log_ctx)
                if auth_response:
                    return auth_response  # Return auth error or redirect
            except Exception as e:
                log_warning(f"Auth check failed: {e}", component="proxy_handler", **log_ctx)
                import traceback
                log_warning(f"Auth check traceback: {traceback.format_exc()}", component="proxy_handler", **log_ctx)
                # Continue without auth on error for now to debug
                pass
            
            log_info(
                f"Routing decision for {normalized.hostname}{normalized.path}: type={decision.type}, target={decision.target}, route_id={decision.route_id}",
                component="proxy_handler", **log_ctx
            )
            
            # Handle based on routing decision
            if decision.type == RoutingDecisionType.ROUTE:
                # Route matched - forward to service
                log_info(f"Forwarding to service via route {decision.route_id}: {decision.target}", component="proxy_handler", **log_ctx)
                return await self._forward_to_service(request, decision, normalized)
            
            elif decision.type == RoutingDecisionType.PROXY:
                # Proxy target found - forward to backend
                log_info(f"Forwarding to proxy backend: {decision.target}", component="proxy_handler", **log_ctx)
                return await self._forward_to_proxy(request, decision, normalized)
            
            else:
                # No route or proxy found
                log_error(f"NO ROUTE OR PROXY FOUND for {normalized.hostname}{normalized.path}", component="proxy_handler", **log_ctx)
                raise HTTPException(404, f"No route or proxy target for {normalized.hostname}")
        
        except HTTPException as he:
            log_warning(f"HTTPException in handle_request: status_code={he.status_code}, detail={he.detail}", component="proxy_handler", **log_ctx)
            raise
        except Exception as e:
            import traceback
            log_error(f"Unhandled exception in handle_request for {request.url}: {e}", component="proxy_handler", **log_ctx)
            log_error(f"Exception type: {type(e).__name__}", component="proxy_handler", **log_ctx)
            log_error(f"Full traceback: {traceback.format_exc()}", component="proxy_handler", **log_ctx)
            raise HTTPException(500, "Internal server error")
    
    async def _forward_to_service(self, request: Request, decision, normalized):
        """Forward request to a service based on route.
        
        Args:
            request: Original request
            decision: Routing decision with target
            normalized: Normalized request
            
        Returns:
            Response from service
        """
        if not decision.target:
            raise HTTPException(500, "Route target not resolved")
        
        target_url = f"{decision.target}{normalized.path}"
        if request.url.query:
            target_url += f"?{request.url.query}"
        
        log_info(
            f"Forwarding to service: {target_url}",
            component="proxy_handler"
        )
        
        # Add trust headers from auth
        custom_headers = {
            "X-Forwarded-Host": normalized.hostname,
            "X-Forwarded-Proto": "https"
        }
        
        # Add auth headers if available
        if hasattr(request.state, 'auth_user'):
            custom_headers["X-Auth-User"] = request.state.auth_user
            custom_headers["X-Auth-Scopes"] = request.state.auth_scopes
            custom_headers["X-Auth-Email"] = request.state.auth_email
        
        # Forward using common logic
        return await self._make_backend_request(request, target_url, preserve_host=False, custom_headers=custom_headers)
    
    async def _forward_to_proxy(self, request: Request, decision, normalized):
        """Forward request to proxy target.
        
        Args:
            request: Original request
            decision: Routing decision with target
            normalized: Normalized request
            
        Returns:
            Response from proxy target
        """
        if not decision.target:
            raise HTTPException(404, f"No proxy target for {normalized.hostname}")
        
        target_url = f"{decision.target}{normalized.path}"
        if request.url.query:
            target_url += f"?{request.url.query}"
        
        log_info(
            f"Forwarding to proxy: {target_url}",
            component="proxy_handler"
        )
        
        # Add auth headers if available
        custom_headers = decision.custom_headers or {}
        if hasattr(request.state, 'auth_user'):
            custom_headers["X-Auth-User"] = request.state.auth_user
            custom_headers["X-Auth-Scopes"] = request.state.auth_scopes
            custom_headers["X-Auth-Email"] = request.state.auth_email
            log_info(f"Adding auth headers to proxy request - User: {custom_headers.get('X-Auth-User')}, Scopes: {custom_headers.get('X-Auth-Scopes')}", component="proxy_handler")
        
        # Forward using common logic with preserve_host from decision
        return await self._make_backend_request(
            request, 
            target_url, 
            preserve_host=decision.preserve_host,
            custom_headers=custom_headers
        )
    
    async def _make_backend_request(self, request: Request, target_url: str, 
                                   preserve_host: bool = False, 
                                   custom_headers: dict = None) -> Response:
        """Make request to backend service.
        
        Args:
            request: Original request
            target_url: Target URL to forward to
            preserve_host: Whether to preserve original host header
            custom_headers: Additional headers to add
            
        Returns:
            Response from backend
        """
        try:
            # Prepare headers
            headers = dict(request.headers)
            
            # Remove hop-by-hop headers
            hop_by_hop = [
                "connection", "keep-alive", "proxy-authenticate",
                "proxy-authorization", "te", "trailers",
                "transfer-encoding", "upgrade", "host"
            ]
            for header in hop_by_hop:
                headers.pop(header, None)
            
            # Handle host header
            if not preserve_host:
                from urllib.parse import urlparse
                parsed = urlparse(target_url)
                headers["host"] = parsed.netloc
            
            # Add custom headers
            if custom_headers:
                headers.update(custom_headers)
                log_info(f"Added custom headers: {custom_headers}", component="proxy_handler")
            
            # Log auth headers being sent to backend
            auth_headers = {k: v for k, v in headers.items() if k.startswith('X-Auth-')}
            if auth_headers:
                log_info(f"Sending auth headers to backend: {auth_headers}", component="proxy_handler")
            
            # Read request body
            body = await request.body()
            
            # Make the backend request
            response = await self.client.request(
                method=request.method,
                url=target_url,
                headers=headers,
                content=body,
                follow_redirects=False
            )
            
            # Create response
            return Response(
                content=response.content,
                status_code=response.status_code,
                headers=dict(response.headers)
            )
            
        except httpx.TimeoutException:
            log_error(f"Timeout forwarding to {target_url}", component="proxy_handler")
            raise HTTPException(504, "Gateway timeout")
        except Exception as e:
            log_error(f"Error forwarding to {target_url}: {e}", component="proxy_handler")
            raise HTTPException(502, f"Bad gateway: {e}")
