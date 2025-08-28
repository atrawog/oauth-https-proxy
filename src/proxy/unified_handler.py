"""Unified proxy handler - THE ONLY handler for all proxy requests with full MCP compliance."""
import json
import traceback
import time
import httpx
import jwt
import re
import asyncio
from typing import Optional, List, Dict, Any
from fastapi import Request, Response, HTTPException
from fastapi.responses import RedirectResponse, StreamingResponse
from urllib.parse import quote
from ..storage import UnifiedStorage
from ..storage.redis_clients import RedisClients
from ..shared.config import Config
from ..proxy.unified_routing import (
    RequestNormalizer, 
    UnifiedRoutingEngine, 
    RoutingDecisionType
)
from ..shared.logger import log_debug, log_info, log_warning, log_error, log_trace, log_request, log_response
from ..shared.dual_logger import create_dual_logger
from ..shared.dns_resolver import get_dns_resolver
from ..proxy.auth_exclusions import merge_exclusions

# Create dual logger for critical proxy errors that need to be visible in BOTH Docker and Redis
dual_logger = create_dual_logger('proxy_handler')


class UnifiedProxyHandler:
    """THE ONLY proxy handler - handles all proxy requests with full MCP compliance.
    
    Features:
    - MCP-compliant configurable WWW-Authenticate headers
    - OAuth JWT validation with scopes and audience
    - Unified routing engine
    - Async DNS resolution
    - Comprehensive logging with full context
    - WebSocket/SSE support
    - Custom headers support
    """
    
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
    
    def __init__(self, storage: UnifiedStorage, redis_clients: RedisClients, proxy_hostname=None):
        """Initialize unified proxy handler.
        
        Args:
            storage: UnifiedStorage instance
            redis_clients: Redis clients for operations
            proxy_hostname: Hostname this handler is serving (for route filtering)
        """
        self.storage = storage
        self.redis_clients = redis_clients
        self.proxy_hostname = proxy_hostname
        
        # Initialize unified routing components
        self.normalizer = RequestNormalizer()
        self.routing_engine = UnifiedRoutingEngine(storage)
        
        # Initialize DNS resolver
        self.dns_resolver = get_dns_resolver()
        
        # Create httpx client with proper timeouts and increased connection limits
        # Enhanced for concurrent connections and SSE streaming
        self.client = httpx.AsyncClient(
            follow_redirects=False,
            verify=False,
            timeout=httpx.Timeout(
                connect=float(Config.PROXY_CONNECT_TIMEOUT),
                read=float(Config.PROXY_REQUEST_TIMEOUT),
                write=10.0,
                pool=None  # No pool timeout
            ),
            limits=httpx.Limits(
                max_keepalive_connections=200,  # Increased from 100
                max_connections=500,             # Added: total connection limit
                keepalive_expiry=30.0           # Added: keepalive timeout
            ),
            http2=True  # Enable HTTP/2 for better concurrent performance
        )
    
    def extract_bearer_token(self, request: Request) -> Optional[str]:
        """Extract bearer token from Authorization header."""
        auth_header = request.headers.get('authorization', '')
        if auth_header.startswith('Bearer '):
            token = auth_header[7:]
            return token
        return None
    
    async def _get_proxy_resource_uri(self, proxy_hostname: str) -> str:
        """Get the proxy's resource URI for audience validation.
        
        The resource URI is the canonical identifier for this proxy as an MCP resource.
        For localhost, it's http://localhost. For production, it's https://{hostname}
        """
        # Build the resource URI
        if proxy_hostname == "localhost":
            return "http://localhost"
        else:
            return f"https://{proxy_hostname}"
    
    def _build_www_authenticate_header(self, proxy_target, request, error=None) -> str:
        """Build fully configurable MCP-compliant WWW-Authenticate header per proxy.
        
        Args:
            proxy_target: The proxy target configuration
            request: The incoming request
            error: Optional error details to include
            
        Returns:
            WWW-Authenticate header value
        """
        params = ['Bearer']
        
        # Realm (configurable or default to auth_proxy)
        realm = getattr(proxy_target, 'auth_realm', None) or proxy_target.auth_proxy
        if realm:
            params.append(f'realm="{realm}"')
        
        # Metadata URLs (configurable, default True)
        include_metadata = getattr(proxy_target, 'auth_include_metadata_urls', True)
        if include_metadata:
            # Authorization server metadata
            if proxy_target.auth_proxy:
                as_uri = f"https://{proxy_target.auth_proxy}/.well-known/oauth-authorization-server"
                params.append(f'as_uri="{as_uri}"')
            
            # Resource metadata
            host = request.headers.get("host", proxy_target.proxy_hostname)
            proto = request.headers.get("x-forwarded-proto", "https")
            resource_uri = f"{proto}://{host}/.well-known/oauth-protected-resource"
            params.append(f'resource_uri="{resource_uri}"')
        
        # Error details (if provided)
        if error:
            if isinstance(error, dict):
                if 'error' in error:
                    params.append(f'error="{error["error"]}"')
                if 'error_description' in error:
                    params.append(f'error_description="{error["error_description"]}"')
            elif isinstance(error, str):
                params.append(f'error_description="{error}"')
        
        # Custom error description (if configured)
        custom_error = getattr(proxy_target, 'auth_error_description', None)
        if custom_error and 'error_description' not in ' '.join(params):
            params.append(f'error_description="{custom_error}"')
        
        # Required scope hint (if configured)
        scope_required = getattr(proxy_target, 'auth_scope_required', None)
        if scope_required:
            params.append(f'scope="{scope_required}"')
        
        # Additional custom parameters (if configured)
        additional_params = getattr(proxy_target, 'auth_additional_params', None)
        if additional_params:
            for key, value in additional_params.items():
                params.append(f'{key}="{value}"')
        
        return ', '.join(params)
    
    async def validate_oauth_jwt(self, token: str, log_ctx: Dict[str, Any] = None) -> Optional[Dict[str, Any]]:
        """Validate OAuth JWT token with audience checking.
        
        Args:
            token: JWT token to validate
            log_ctx: Logging context
            
        Returns:
            Token claims if valid, None otherwise
        """
        if log_ctx is None:
            log_ctx = {}
            
        try:
            log_info(f"Starting OAuth JWT validation", component="proxy_handler", token_preview=token[:30] if token else "NO_TOKEN", **log_ctx)
            
            # Get public key for validation from Redis (single source of truth)
            log_info("Getting OAuth public key from Redis", component="proxy_handler", **log_ctx)
            public_key = await self.storage.get("oauth:public_key")
            if not public_key:
                log_error("No OAuth public key found in Redis at oauth:public_key", component="proxy_handler", **log_ctx)
                return None
            
            log_info(f"Retrieved public key from Redis, length: {len(public_key)} chars", component="proxy_handler", **log_ctx)
            
            if public_key:
                key_preview = public_key[:50] if len(public_key) > 50 else public_key
                log_debug(f"Public key preview: {key_preview}...", component="proxy_handler", **log_ctx)
            
            # Decode and validate JWT
            log_info("Attempting JWT decode with RS256/HS256 algorithms", component="proxy_handler", **log_ctx)
            payload = jwt.decode(
                token,
                public_key or Config.OAUTH_JWT_SECRET,
                algorithms=["RS256", "HS256"],
                options={"verify_exp": True, "verify_aud": False}  # We validate audience manually below
            )
            
            # Validate audience if configured
            if log_ctx.get('proxy_hostname'):
                proxy_resource_uri = await self._get_proxy_resource_uri(log_ctx['proxy_hostname'])
                log_info(f"Proxy resource URI: {proxy_resource_uri}", component="proxy_handler", **log_ctx)
                
                # Check if token has audience claim
                if 'aud' not in payload:
                    log_error("Token has no audience claim", component="proxy_handler", **log_ctx)
                    return None
                
                # Ensure audience is a list
                audience = payload['aud'] if isinstance(payload['aud'], list) else [payload['aud']]
                
                # Check if our resource URI is in the audience
                if proxy_resource_uri not in audience:
                    log_warning(
                        f"Audience validation failed: {proxy_resource_uri} not in {audience}",
                        component="proxy_handler",
                        **log_ctx
                    )
                    return None
                
                log_info(f"Audience validation successful", component="proxy_handler", **log_ctx)
            
            log_info(
                f"JWT validated successfully: sub={payload.get('sub')}, scope={payload.get('scope')}, aud={payload.get('aud')}",
                component="proxy_handler",
                **log_ctx
            )
            
            return payload
            
        except jwt.ExpiredSignatureError as e:
            log_warning(f"JWT token expired: {e}", component="proxy_handler", token_preview=token[:30] if token else "NO_TOKEN", **log_ctx)
            return None
        except jwt.InvalidTokenError as e:
            log_warning(f"Invalid JWT token: {e}", component="proxy_handler", token_preview=token[:30] if token else "NO_TOKEN", error_type=type(e).__name__, **log_ctx)
            return None
        except Exception as e:
            log_error(f"Unexpected error validating JWT: {e}", component="proxy_handler", error_type=type(e).__name__, token_preview=token[:30] if token else "NO_TOKEN", **log_ctx)
            log_error(f"Traceback: {traceback.format_exc()}", component="proxy_handler", **log_ctx)
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
        """Check if token has required scopes.
        
        Admin scope implicitly includes user scope.
        """
        if not required_scopes:
            return True  # No scopes required (public endpoint)
        
        # Admin scope includes all other scopes
        if "admin" in token_scopes:
            return True
        
        # Check if user has at least one required scope
        return any(scope in token_scopes for scope in required_scopes)
    
    def get_auth_config(self, route: Any, proxy_config: Dict[str, Any]) -> Dict[str, Any]:
        """Get auth config from route or proxy."""
        # Check route-level auth override first
        if route and hasattr(route, 'override_proxy_auth') and route.override_proxy_auth:
            if hasattr(route, 'auth_config') and route.auth_config:
                return route.auth_config
        
        # Fall back to proxy-level auth config
        # proxy_config itself IS the auth config, not nested under 'auth_config'
        return proxy_config or {'auth_type': 'oauth'}
    
    def validate_user_access(self, token_info: Dict[str, Any], auth_config: Dict[str, Any], log_ctx: Dict[str, Any] = None) -> bool:
        """Validate user access based on allowed users/orgs/emails."""
        if log_ctx is None:
            log_ctx = {}
            
        username = token_info.get('sub', '')
        
        # Check allowed users
        allowed_users = auth_config.get('allowed_users', [])
        if allowed_users and allowed_users != ['*']:
            if username not in allowed_users:
                log_info(f"User {username} not in allowed users", component="proxy_handler", **log_ctx)
                return False
        
        # Check allowed organizations
        user_orgs = token_info.get('orgs', [])
        allowed_orgs = auth_config.get('allowed_orgs', [])
        if allowed_orgs:
            if not any(org in allowed_orgs for org in user_orgs):
                log_info(f"User not in allowed organizations", component="proxy_handler", **log_ctx)
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
                log_info(f"User email {user_email} not in allowed emails", component="proxy_handler", **log_ctx)
                return False
        
        return True
    
    async def _check_auth(self, request: Request, proxy_hostname: str, decision=None, log_ctx=None) -> Response:
        """Check OAuth authentication with scope validation.
        
        NOTE: With the enhanced proxy architecture, auth is already validated at the edge.
        This method now primarily trusts X-Auth-* headers if present.
        
        Args:
            request: The incoming request
            proxy_hostname: The proxy hostname
            decision: Optional routing decision with route info
            log_ctx: Logging context with client info
        
        Returns:
            None if authenticated, Response object if auth failed/redirect needed
        """
        if log_ctx is None:
            log_ctx = {}
        
        # Check if auth headers are already present (only trust from internal API service)
        auth_user = request.headers.get('X-Auth-User')
        auth_scopes = request.headers.get('X-Auth-Scopes')
        auth_email = request.headers.get('X-Auth-Email')
        
        # Only trust headers from internal API service (not from external requests)
        # This prevents security holes where external clients could bypass OAuth
        if auth_user and request.headers.get('X-Internal-Request') == 'true':
            # Trust the headers from internal API service only
            log_info(f"Trusting auth headers from internal API: user={auth_user}", component="proxy_handler", **log_ctx)
            request.state.auth_user = auth_user
            request.state.auth_scopes = auth_scopes or ''
            request.state.auth_email = auth_email or ''
            
            # Update log context
            log_ctx.update({
                'auth_user': auth_user,
                'auth_scopes': auth_scopes,
                'auth_source': 'internal_api'
            })
            
            return None  # Already authenticated
        elif auth_user:
            # External request trying to use auth headers - security violation!
            log_warning(f"SECURITY: External request attempted to use X-Auth headers: user={auth_user}", 
                       component="proxy_handler", **log_ctx)
            # Ignore the headers and continue with normal OAuth validation
            
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
            }
        except Exception as e:
            log_error(f"Error getting proxy config: {e}", component="proxy_handler", **log_ctx)
            proxy_config = {'auth_type': 'oauth'}
        
        # Get auth configuration (route overrides proxy)
        route = decision.route if decision else None
        auth_config = self.get_auth_config(route, proxy_config)
        
        # Check if auth is disabled
        if auth_config.get('auth_type') == 'none' or not proxy_target.auth_enabled:
            log_info(f"Auth disabled for this request", component="proxy_handler", **log_ctx)
            return None
        
        # Check excluded paths
        request_path = request.url.path
        excluded_paths = auth_config.get('auth_excluded_paths', []) or proxy_config.get('auth_excluded_paths', [])
        for excluded_path in excluded_paths:
            if request_path.startswith(excluded_path):
                log_info(f"Path {request_path} excluded from auth (matched {excluded_path})", component="proxy_handler", **log_ctx)
                return None
        
        # Extract bearer token
        token = self.extract_bearer_token(request)
        if not token:
            log_info("No bearer token found in request", component="proxy_handler", **log_ctx)
            return await self._return_auth_error(request, proxy_target, log_ctx)
        
        # Validate OAuth JWT (add proxy_hostname to log_ctx for audience validation)
        auth_log_ctx = {**log_ctx, 'proxy_hostname': proxy_hostname}
        token_info = await self.validate_oauth_jwt(token, auth_log_ctx)
        if not token_info:
            log_warning("Invalid or expired OAuth token", component="proxy_handler", **log_ctx)
            return await self._return_auth_error(request, proxy_target, log_ctx, error={'error': 'invalid_token', 'error_description': 'Token is invalid or expired'})
        
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
        
        # Validate scopes
        token_scopes = token_info.get('scope', '').split() if token_info.get('scope') else []
        if not self.validate_scopes(token_scopes, required_scopes):
            log_warning(
                f"Insufficient scopes: required={required_scopes}, token={token_scopes}",
                component="proxy_handler",
                **log_ctx
            )
            return await self._return_auth_error(
                request, proxy_target, log_ctx,
                error={'error': 'insufficient_scope', 'error_description': f'Required scope: {" ".join(required_scopes)}'}
            )
        
        # Validate user access
        if not self.validate_user_access(token_info, auth_config, log_ctx):
            log_warning(f"User access denied based on access rules", component="proxy_handler", **log_ctx)
            return await self._return_auth_error(
                request, proxy_target, log_ctx,
                error={'error': 'access_denied', 'error_description': 'User not authorized for this resource'}
            )
        
        # Authentication successful - store auth info in request state
        request.state.auth_user = token_info.get('username', token_info.get('sub', 'unknown'))
        request.state.auth_scopes = token_scopes  # Store as list for consistency
        request.state.auth_email = token_info.get('email', '')
        request.state.auth_client_id = token_info.get('client_id', 'unknown')
        
        # Update log context with auth info
        log_ctx.update({
            'auth_user': request.state.auth_user,
            'auth_scopes': request.state.auth_scopes,
            'auth_audience': token_info.get('aud', []),
            'auth_client_id': token_info.get('client_id', 'unknown')
        })
        
        log_info(f"Authentication successful for user {request.state.auth_user}", component="proxy_handler", **log_ctx)
        return None
    
    async def _return_auth_error(self, request: Request, proxy_target, log_ctx: Dict[str, Any], error=None) -> Response:
        """Return appropriate auth error response (401 with WWW-Authenticate or redirect).
        
        Args:
            request: The incoming request
            proxy_target: Proxy configuration
            log_ctx: Logging context
            error: Optional error details
            
        Returns:
            Response with 401 or redirect
        """
        # Check if this is a browser request
        accept = request.headers.get("accept", "")
        user_agent = request.headers.get("user-agent", "").lower()
        is_browser = "text/html" in accept or any(x in user_agent for x in ["mozilla", "chrome", "safari", "firefox"])
        
        # API calls get 401 with WWW-Authenticate
        auth_mode = proxy_target.auth_mode if proxy_target else "forward"
        
        if auth_mode == "forward" or not is_browser:
            # Build MCP-compliant WWW-Authenticate header
            www_auth = self._build_www_authenticate_header(proxy_target, request, error)
            
            log_info(
                "Returning 401 with MCP-compliant WWW-Authenticate header",
                component="proxy_handler",
                www_authenticate=www_auth,
                **log_ctx
            )
            
            # Build error response body
            error_body = error if error else {"error": "unauthorized", "error_description": "OAuth authentication required"}
            
            return Response(
                content=json.dumps(error_body),
                status_code=401,
                headers={
                    "WWW-Authenticate": www_auth,
                    "Content-Type": "application/json"
                }
            )
        
        # Browser requests get redirect to OAuth (if auth_mode is redirect)
        if auth_mode == "redirect" and proxy_target.auth_proxy:
            # Build OAuth authorization URL
            return_url = str(request.url)
            proxy_hostname = request.headers.get("host", proxy_target.proxy_hostname)
            
            # Encode the return URL and proxy hostname for state preservation
            state_data = {
                "return_url": return_url,
                "proxy_hostname": proxy_hostname
            }
            state = quote(json.dumps(state_data))
            
            auth_url = f"https://{proxy_target.auth_proxy}/authorize"
            auth_url += f"?response_type=code"
            auth_url += f"&client_id=oauth_client"  # Will be replaced by actual client
            auth_url += f"&redirect_uri={quote(f'https://{proxy_hostname}/callback')}"
            auth_url += f"&state={state}"
            auth_url += f"&resource={quote(f'https://{proxy_hostname}')}"
            
            log_info(f"Redirecting to OAuth authorization", component="proxy_handler", auth_url=auth_url, **log_ctx)
            
            return RedirectResponse(url=auth_url, status_code=307)
        
        # Default fallback - return 401
        return Response(
            content=json.dumps({"error": "unauthorized", "error_description": "Authentication required"}),
            status_code=401,
            headers={"WWW-Authenticate": "Bearer"}
        )
    
    async def _create_unified_log_context(self, request: Request, protocol: str = "HTTP") -> Dict[str, Any]:
        """Create unified logging context for both HTTP and HTTPS requests.
        
        Args:
            request: The incoming request
            protocol: Protocol type ("HTTP" or "HTTPS")
            
        Returns:
            Dictionary with comprehensive logging context
        """
        # Import the improved client IP extraction function
        from ..shared.client_ip import get_real_client_ip
        
        # Get real client IP - prefer X-Forwarded-For from enhanced proxy handler
        if request.headers.get('X-Forwarded-For'):
            # Trust X-Forwarded-For from enhanced proxy handler
            client_ip = request.headers.get('X-Forwarded-For').split(',')[0].strip()
        else:
            # Fallback to standard extraction
            client_ip = get_real_client_ip(request)
        
        # Get proxy hostname from request
        proxy_hostname = request.headers.get("host", "unknown").split(":")[0]
        
        # Resolve client hostname
        client_hostname = await self.dns_resolver.resolve_ptr(client_ip)
        
        # Get trace ID from request state or generate one
        trace_id = getattr(request.state, 'trace_id', None) or f"req-{id(request)}"
        
        # Create comprehensive log context using standard field names
        log_ctx = {
            'protocol': protocol,
            'proxy_hostname': proxy_hostname,
            'client_ip': client_ip,
            'client_hostname': client_hostname,
            'request_id': trace_id,
            'request_path': str(request.url.path),  # Standard field name
            'request_method': request.method,  # Standard field name
            'request_query': str(request.url.query) if request.url.query else None,  # Standard field name
            'user_agent': request.headers.get('user-agent', 'unknown'),
            'referer': request.headers.get('referer'),
            'content_type': request.headers.get('content-type'),
            'content_length': request.headers.get('content-length'),
            'accept': request.headers.get('accept'),
            'x_forwarded_proto': request.headers.get('x-forwarded-proto', protocol.lower()),
            'x_forwarded_host': request.headers.get('x-forwarded-host'),
            'authorization': 'Bearer' if request.headers.get('authorization', '').startswith('Bearer') else None,
        }
        
        # Log the request with full context
        log_info(
            f"{protocol} {request.method} {request.url.path}",
            component="proxy_handler",
            **log_ctx
        )
        
        return log_ctx
    
    async def handle_request(self, request: Request) -> Response:
        """Handle request with unified routing logic and comprehensive logging.
        
        Args:
            request: The incoming request
            
        Returns:
            Response from backend or error response
        """
        # Track request start time for duration calculation
        start_time = time.time()
        
        # Create unified log context
        try:
            # Determine protocol from x-forwarded-proto or URL scheme
            protocol = "HTTPS" if request.url.scheme == "https" or request.headers.get("x-forwarded-proto") == "https" else "HTTP"
            log_ctx = await self._create_unified_log_context(request, protocol)
        except Exception as e:
            log_error(f"Failed to create log context: {e}", component="proxy_handler")
            log_ctx = {}
        
        # Extract key fields for structured logging
        client_ip = log_ctx.get('client_ip', 'unknown')
        proxy_hostname = log_ctx.get('proxy_hostname', 'unknown')
        trace_id = log_ctx.get('request_id', f"req-{id(request)}")
        method = request.method
        path = str(request.url.path)
        
        # Don't log request here - wait for response to have complete info including status
        # Store request context for later use in log_response
        request_log_ctx = {
            'method': method,
            'path': path,
            'client_ip': client_ip,
            'proxy_hostname': proxy_hostname,
            'trace_id': trace_id,
            'client_hostname': log_ctx.get('client_hostname', ''),
            'user_agent': log_ctx.get('user_agent', ''),
            'referer': log_ctx.get('referer', ''),
            'query': log_ctx.get('request_query', ''),
            'content_type': log_ctx.get('content_type', ''),
            'protocol': protocol
        }
        
        try:
            # Build client info from log context or fallback
            from ..shared.client_ip import get_real_client_ip
            client_ip = log_ctx.get('client_ip') or get_real_client_ip(request)
            client_info = {
                'client_ip': client_ip,
                'client_port': int(request.headers.get('x-client-port', request.client.port if request.client else '0'))
            }
            
            # Normalize the request
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
                    log_info("Authentication failed, returning auth error", component="proxy_handler", **log_ctx)
                    # Log response for auth error
                    duration_ms = (time.time() - start_time) * 1000
                    log_response(
                        status=auth_response.status_code,
                        duration_ms=duration_ms,
                        component="proxy_handler",
                        **request_log_ctx,
                        auth_status="failed",
                        response_type="auth_error"
                    )
                    return auth_response  # Return auth error or redirect
                # Authentication successful - update request_log_ctx with auth info
                if hasattr(request.state, 'auth_user'):
                    request_log_ctx['auth_user'] = request.state.auth_user
                    request_log_ctx['auth_scopes'] = ','.join(request.state.auth_scopes) if request.state.auth_scopes else ''
                    request_log_ctx['auth_email'] = getattr(request.state, 'auth_email', '')
                    request_log_ctx['auth_client_id'] = getattr(request.state, 'auth_client_id', '')
            except Exception as e:
                log_error(f"Auth check failed with exception type: {type(e).__name__}, message: {e}", component="proxy_handler", **log_ctx)
                log_error(f"Auth check traceback: {traceback.format_exc()}", component="proxy_handler", **log_ctx)
                # Return 500 error instead of continuing without auth
                raise HTTPException(500, f"Authentication check failed: {str(e)}")
            
            log_info(
                f"Routing decision for {normalized.hostname}{normalized.path}: type={decision.type}, target={decision.target}, route_id={decision.route_id}",
                component="proxy_handler",
                **log_ctx
            )
            
            # Handle based on routing decision
            if decision.type == RoutingDecisionType.ROUTE:
                # Route matched - forward to service
                log_info(f"Forwarding to service via route {decision.route_id}: {decision.target}", component="proxy_handler", **log_ctx)
                response = await self._forward_to_service(request, decision, normalized, log_ctx)
                # Log response for route forward
                duration_ms = (time.time() - start_time) * 1000
                log_response(
                    status=response.status_code,
                    duration_ms=duration_ms,
                    component="proxy_handler",
                    **request_log_ctx,
                    route_id=decision.route_id,
                    backend_url=decision.target,
                    auth_user=getattr(request.state, 'auth_user', None),
                    auth_scopes=','.join(getattr(request.state, 'auth_scopes', [])) if hasattr(request.state, 'auth_scopes') else None,
                    response_type="route_forward"
                )
                return response
            
            elif decision.type == RoutingDecisionType.PROXY:
                # Proxy target found - forward to backend
                log_info(f"Forwarding to proxy backend: {decision.target}", component="proxy_handler", **log_ctx)
                response = await self._forward_to_proxy(request, decision, normalized, log_ctx)
                # Log response for proxy forward
                duration_ms = (time.time() - start_time) * 1000
                log_response(
                    status=response.status_code,
                    duration_ms=duration_ms,
                    component="proxy_handler",
                    **request_log_ctx,
                    backend_url=decision.target,
                    response_type="proxy_forward"
                )
                return response
            
            else:
                # No route or proxy found
                log_error(f"NO ROUTE OR PROXY FOUND for {normalized.hostname}{normalized.path}", component="proxy_handler", **log_ctx)
                # Log response for 404
                duration_ms = (time.time() - start_time) * 1000
                log_response(
                    status=404,
                    duration_ms=duration_ms,
                    component="proxy_handler",
                    **request_log_ctx,
                    error="no_route_or_proxy",
                    response_type="error"
                )
                raise HTTPException(404, f"No route or proxy target for {normalized.hostname}")
        
        except HTTPException as he:
            log_warning(f"HTTPException in handle_request: status_code={he.status_code}, detail={he.detail}", component="proxy_handler", **log_ctx)
            # Log response for HTTP exception
            duration_ms = (time.time() - start_time) * 1000
            if 'request_log_ctx' in locals():
                log_response(
                    status=he.status_code,
                    duration_ms=duration_ms,
                    component="proxy_handler",
                    **request_log_ctx,
                    error=str(he.detail),
                    error_type="http_exception",
                    response_type="error"
                )
            else:
                log_response(
                    status=he.status_code,
                    duration_ms=duration_ms,
                    trace_id=trace_id if 'trace_id' in locals() else None,
                    component="proxy_handler",
                    client_ip=client_ip if 'client_ip' in locals() else 'unknown',
                    proxy_hostname=proxy_hostname if 'proxy_hostname' in locals() else 'unknown',
                    method=method if 'method' in locals() else request.method,
                    path=path if 'path' in locals() else str(request.url.path),
                    error=str(he.detail),
                    error_type="http_exception",
                    response_type="error"
                )
            raise
        except Exception as e:
            # Use dual logger for critical errors so they appear in BOTH Docker and Redis
            dual_logger.error(f"Unhandled exception in handle_request for {request.url}: {e}", **log_ctx)
            dual_logger.error(f"Exception type: {type(e).__name__}", **log_ctx)
            dual_logger.error(f"Full traceback: {traceback.format_exc()}", **log_ctx)
            # Log response for unhandled exception
            duration_ms = (time.time() - start_time) * 1000
            if 'request_log_ctx' in locals():
                log_response(
                    status=500,
                    duration_ms=duration_ms,
                    component="proxy_handler",
                    **request_log_ctx,
                    error=str(e),
                    error_type=type(e).__name__,
                    response_type="error"
                )
            else:
                log_response(
                    status=500,
                    duration_ms=duration_ms,
                    trace_id=trace_id if 'trace_id' in locals() else None,
                    component="proxy_handler",
                    client_ip=client_ip if 'client_ip' in locals() else 'unknown',
                    proxy_hostname=proxy_hostname if 'proxy_hostname' in locals() else 'unknown',
                    method=method if 'method' in locals() else request.method,
                    path=path if 'path' in locals() else str(request.url.path),
                    error=str(e),
                    error_type=type(e).__name__,
                    response_type="error"
                )
            raise HTTPException(500, "Internal server error")
    
    async def _forward_to_service(self, request: Request, decision, normalized, log_ctx: Dict[str, Any]):
        """Forward request to a service based on route.
        
        Args:
            request: Original request
            decision: Routing decision with target
            normalized: Normalized request
            log_ctx: Logging context
            
        Returns:
            Response from service
        """
        if not decision.target:
            raise HTTPException(500, "Route target not resolved")
        
        target_url = f"{decision.target}{normalized.path}"
        if request.url.query:
            target_url += f"?{request.url.query}"
        
        log_info(f"Forwarding to service: {target_url}", component="proxy_handler", **log_ctx)
        
        # Add trust headers from auth
        custom_headers = {
            "X-Forwarded-Host": normalized.hostname,
            "X-Forwarded-Proto": "https"
        }
        
        # Add auth headers if available
        if hasattr(request.state, 'auth_user'):
            custom_headers["X-Auth-User"] = request.state.auth_user
            # Convert scopes list to space-separated string for headers
            scopes = request.state.auth_scopes
            if isinstance(scopes, list):
                scopes = ' '.join(scopes)
            custom_headers["X-Auth-Scopes"] = scopes
            custom_headers["X-Auth-Email"] = request.state.auth_email
        
        # Forward using common logic
        return await self._make_backend_request(request, target_url, preserve_host=False, custom_headers=custom_headers, log_ctx=log_ctx)
    
    async def _forward_to_proxy(self, request: Request, decision, normalized, log_ctx: Dict[str, Any]):
        """Forward request to proxy target.
        
        Args:
            request: Original request
            decision: Routing decision with target
            normalized: Normalized request
            log_ctx: Logging context
            
        Returns:
            Response from proxy target
        """
        if not decision.target:
            raise HTTPException(404, f"No proxy target for {normalized.hostname}")
        
        target_url = f"{decision.target}{normalized.path}"
        if request.url.query:
            target_url += f"?{request.url.query}"
        
        log_info(f"Forwarding to proxy: {target_url}", component="proxy_handler", **log_ctx)
        
        # Add auth headers if available
        custom_headers = decision.custom_headers or {}
        if hasattr(request.state, 'auth_user'):
            custom_headers["X-Auth-User"] = request.state.auth_user
            # Convert scopes list to space-separated string for headers
            scopes = request.state.auth_scopes
            if isinstance(scopes, list):
                scopes = ' '.join(scopes)
            custom_headers["X-Auth-Scopes"] = scopes
            custom_headers["X-Auth-Email"] = request.state.auth_email
            log_info(f"Added auth headers - User: {request.state.auth_user}, Scopes: {scopes}", component="proxy_handler", **log_ctx)
        else:
            log_warning("No auth_user in request.state, not adding auth headers", component="proxy_handler", **log_ctx)
        
        # Forward request
        return await self._make_backend_request(
            request, 
            target_url, 
            preserve_host=decision.preserve_host,
            custom_headers=custom_headers,
            custom_response_headers=getattr(decision, 'custom_response_headers', None),
            log_ctx=log_ctx
        )
    
    async def _make_backend_request(
        self, 
        request: Request, 
        target_url: str, 
        preserve_host: bool = False,
        custom_headers: Dict[str, str] = None,
        custom_response_headers: Dict[str, str] = None,
        log_ctx: Dict[str, Any] = None
    ) -> Response:
        """Make request to backend service.
        
        Args:
            request: Original request
            target_url: Target URL to forward to
            preserve_host: Whether to preserve the Host header
            custom_headers: Additional headers to add
            custom_response_headers: Headers to add to response
            log_ctx: Logging context
            
        Returns:
            Response from backend
        """
        if log_ctx is None:
            log_ctx = {}
            
        # Build headers
        headers = dict(request.headers)
        
        # Remove hop-by-hop headers
        hop_by_hop = ['connection', 'keep-alive', 'transfer-encoding', 'upgrade']
        for header in hop_by_hop:
            headers.pop(header, None)
        
        # Handle Host header
        if not preserve_host:
            headers.pop('host', None)
        
        # Add custom headers
        if custom_headers:
            headers.update(custom_headers)
        
        # Get request body
        body = await request.body()
        
        # Special handling for MCP endpoint
        is_mcp_request = request.url.path == '/mcp'
        if is_mcp_request:
            log_info(f"MCP {request.method} request detected", component="proxy_handler", **log_ctx)
        
        # Check if client expects SSE based on Accept header
        accept_header = headers.get('accept', '').lower()
        expects_sse = 'text/event-stream' in accept_header
        
        try:
            # For SSE requests (MCP GET or explicit SSE accept), use streaming from the start
            # MCP: GET = SSE stream, POST = JSON response
            if (is_mcp_request and request.method == "GET") or (expects_sse and not is_mcp_request):
                log_info(f"{'MCP' if is_mcp_request else 'SSE'} streaming request for {target_url}", component="proxy_handler", **log_ctx)
                
                # Simple SSE streaming with proper context management
                async def stream_sse():
                    """Stream SSE response from backend."""
                    # For SSE, we need to ensure the connection stays alive
                    stream_headers = headers.copy()
                    stream_headers['connection'] = 'keep-alive'
                    stream_headers['cache-control'] = 'no-cache'
                    
                    async with self.client.stream(
                        request.method,
                        target_url,
                        headers=stream_headers,
                        content=body if body else None,
                    ) as response:
                        # Store response info for later use
                        nonlocal sse_status, sse_headers
                        sse_status = response.status_code
                        sse_headers = dict(response.headers)
                        
                        log_info(f"SSE stream opened: {sse_status}", component="proxy_handler", **log_ctx)
                        log_debug(f"SSE headers: {sse_headers}", component="proxy_handler", **log_ctx)
                        
                        # Stream the chunks - use smaller chunk size for SSE
                        chunk_count = 0
                        try:
                            # Try with no chunk size to let httpx decide
                            async for chunk in response.aiter_bytes():
                                if chunk:
                                    chunk_count += 1
                                    log_info(f"SSE chunk {chunk_count}: {len(chunk)} bytes, content: {chunk[:100]}", component="proxy_handler", **log_ctx)
                                    yield chunk
                                else:
                                    log_debug(f"Empty chunk received", component="proxy_handler", **log_ctx)
                        except Exception as e:
                            log_error(f"SSE streaming error: {e}", component="proxy_handler", **log_ctx, exc_info=True)
                        finally:
                            log_info(f"SSE stream ended after {chunk_count} chunks", component="proxy_handler", **log_ctx)
                
                # Variables to capture response info
                sse_status = 200
                sse_headers = {}
                
                # Create the generator
                sse_generator = stream_sse()
                
                # We need to start the generator to get headers, but this is tricky
                # Instead, let's use a wrapper that handles this
                started = False
                original_generator = sse_generator
                
                async def wrapped_generator():
                    """Wrapper to ensure headers are captured."""
                    nonlocal started
                    if not started:
                        # Force the generator to start so we get headers
                        started = True
                    async for chunk in original_generator:
                        yield chunk
                
                # Build response headers
                response_headers = {}
                if custom_response_headers:
                    response_headers.update(custom_response_headers)
                
                # Ensure SSE headers are set
                response_headers['cache-control'] = 'no-cache, no-store, must-revalidate'
                response_headers['x-accel-buffering'] = 'no'
                response_headers['connection'] = 'keep-alive'
                response_headers['content-type'] = 'text/event-stream'
                
                # Return streaming response
                return StreamingResponse(
                    wrapped_generator(),
                    status_code=200,  # SSE always returns 200
                    headers=response_headers
                )
            
            # For non-SSE requests, use regular request
            log_debug(f"Making backend request to {target_url}", component="proxy_handler", **log_ctx)
            
            response = await self.client.request(
                request.method,
                target_url,
                headers=headers,
                content=body if body else None,
            )
            
            # Build response headers
            response_headers = dict(response.headers)
            if custom_response_headers:
                response_headers.update(custom_response_headers)
            else:
                # Remove hop-by-hop headers from response
                for header in hop_by_hop:
                    response_headers.pop(header, None)
            
            # For MCP POST requests, preserve session headers
            if is_mcp_request:
                for header_name in ['mcp-session-id', 'mcp-protocol-version']:
                    if header_name in response.headers:
                        response_headers[header_name] = response.headers[header_name]
            
            # Log responses (moved outside if block to log all responses)
            log_info(f"Backend response: {response.status_code}", component="proxy_handler", **log_ctx)
            
            # Log error responses for debugging
            if response.status_code >= 400:
                log_warning(f"Backend error response {response.status_code}: {response.text[:200]}", component="proxy_handler", **log_ctx)
            
            # Return for ALL non-SSE requests (not just MCP)
            return Response(
                content=response.content,
                status_code=response.status_code,
                headers=response_headers
            )
                
        except httpx.TimeoutException as e:
            log_error(f"Backend request timeout: {e}", component="proxy_handler", **log_ctx)
            raise HTTPException(504, "Gateway timeout")
        except httpx.RequestError as e:
            log_error(f"Backend request error: {e}", component="proxy_handler", **log_ctx)
            raise HTTPException(502, "Bad gateway")
        except (ConnectionResetError, BrokenPipeError, ConnectionAbortedError) as e:
            log_warning(f"Client disconnected during request: {e}", component="proxy_handler", **log_ctx)
            # Don't raise HTTPException for client disconnects - just return a simple response
            return Response(content="", status_code=499)  # 499 = Client Closed Request
        except asyncio.CancelledError:
            log_debug("Request cancelled by client", component="proxy_handler", **log_ctx)
            return Response(content="", status_code=499)
        except Exception as e:
            # Use dual logger for critical errors so they appear in BOTH Docker and Redis
            dual_logger.error(f"Unexpected error in backend request: {e}", **log_ctx)
            dual_logger.error(f"Traceback: {traceback.format_exc()}", **log_ctx)
            raise HTTPException(500, "Internal server error")
    
    async def close(self):
        """Clean up resources."""
        await self.client.aclose()