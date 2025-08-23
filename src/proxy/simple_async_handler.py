"""Simplified async proxy handler with unified routing support."""
import httpx
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
from ..shared.logger import log_debug, log_info, log_warning
from ..proxy.auth_exclusions import merge_exclusions
from ..auth import FlexibleAuthService


class SimpleAsyncProxyHandler:
    """Simplified proxy handler with unified routing."""
    
    def __init__(self, storage: AsyncRedisStorage, redis_clients: RedisClients, oauth_components=None, proxy_hostname=None, auth_service=None):
        """Initialize simple proxy handler with routing support.
        
        Args:
            storage: Async storage instance
            redis_clients: Redis clients for operations
            oauth_components: OAuth components (optional)
            proxy_hostname: Hostname this handler is serving (for route filtering)
            auth_service: FlexibleAuthService instance for authentication
        """
        self.storage = storage
        self.redis_clients = redis_clients
        self.proxy_hostname = proxy_hostname
        self.oauth_components = oauth_components
        
        # Initialize auth service if not provided
        if auth_service:
            self.auth_service = auth_service
        else:
            self.auth_service = FlexibleAuthService(
                storage=storage,
                oauth_components=oauth_components
            )
        
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
    
    async def _check_auth(self, request: Request, proxy_hostname: str) -> Response:
        """Check authentication for the request.
        
        Returns:
            None if authenticated, Response object if auth failed/redirect needed
        """
        # Get proxy target configuration
        proxy_target = await self.storage.get_proxy_target(proxy_hostname)
        if not proxy_target or not proxy_target.auth_enabled:
            return None  # No auth required
        
        # Check if path is excluded from auth
        request_path = request.url.path
        all_exclusions = merge_exclusions(proxy_target.auth_excluded_paths)
        
        for excluded_path in all_exclusions:
            if request_path.startswith(excluded_path):
                log_debug(f"Path {request_path} excluded from auth by rule: {excluded_path}", component="simple_proxy_handler")
                return None  # Path is excluded
        
        # Check authentication using auth service
        log_info(f"Checking authentication for {proxy_hostname}{request_path}", component="simple_proxy_handler")
        
        # Use FlexibleAuthService to check proxy auth
        auth_result = await self.auth_service.check_proxy_auth(
            request=request,
            proxy_hostname=proxy_hostname,
            path=request_path
        )
        
        # If auth_result is a dict with user info, authentication passed
        if isinstance(auth_result, dict):
            log_info(f"Authentication successful for user: {auth_result.get('principal')}", component="simple_proxy_handler")
            return None  # Authenticated
        
        # If auth_result is a Response, return it (401, 403, or redirect)
        if isinstance(auth_result, (Response, RedirectResponse)):
            log_warning(f"Authentication failed for {proxy_hostname}", component="simple_proxy_handler")
            return auth_result
        
        # Default to 401 if auth failed
        if proxy_target.auth_mode == "redirect":
            # Redirect to OAuth login
            return_url = str(request.url)
            auth_login_url = f"https://{proxy_target.auth_proxy}/login?return_url={quote(return_url)}&proxy_hostname={quote(proxy_hostname)}"
            log_info(f"Redirecting to auth login: {auth_login_url}", component="simple_proxy_handler")
            return RedirectResponse(url=auth_login_url, status_code=302)
        else:
            # Return 401 with MCP-compliant headers
            host = request.headers.get("host", proxy_hostname)
            proto = request.headers.get("x-forwarded-proto", "https")
            resource_metadata_url = f"{proto}://{host}/.well-known/oauth-protected-resource"
            auth_metadata_url = f"https://{proxy_target.auth_proxy}/.well-known/oauth-authorization-server"
            
            www_auth_params = [
                'Bearer',
                f'realm="{proxy_target.auth_proxy}"',
                f'as_uri="{auth_metadata_url}"',
                f'resource_uri="{resource_metadata_url}"'
            ]
            
            www_authenticate = ', '.join(www_auth_params)
            
            return Response(
                content="Authentication required",
                status_code=401,
                headers={"WWW-Authenticate": www_authenticate}
            )
    
    async def handle_request(self, request: Request) -> Response:
        """Handle request with unified routing logic."""
        try:
            # Extract client info from headers (set by PROXY protocol handler)
            client_info = {
                'ip': request.headers.get('x-real-ip', '127.0.0.1'),
                'port': int(request.headers.get('x-client-port', '0'))
            }
            
            # Normalize the HTTPS request
            normalized = self.normalizer.normalize_https(request, client_info)
            
            # Check authentication first
            auth_response = await self._check_auth(request, normalized.hostname)
            if auth_response:
                return auth_response  # Return auth error or redirect
            
            # Process through unified routing engine
            decision = await self.routing_engine.process_request(normalized)
            
            log_debug(
                f"Routing decision for {normalized.hostname}{normalized.path}: {decision.type}",
                component="proxy_handler"
            )
            
            # Handle based on routing decision
            if decision.type == RoutingDecisionType.ROUTE:
                # Route matched - forward to service
                return await self._forward_to_service(request, decision, normalized)
            
            elif decision.type == RoutingDecisionType.PROXY:
                # Proxy target found - forward to backend
                return await self._forward_to_proxy(request, decision, normalized)
            
            else:
                # No route or proxy found
                raise HTTPException(404, f"No route or proxy target for {normalized.hostname}")
        
        except HTTPException:
            raise
        except Exception as e:
            import traceback
            log_warning(f"Error in handle_request: {e}", component="proxy_handler")
            log_warning(f"Traceback: {traceback.format_exc()}", component="proxy_handler")
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
        
        # Add X-Forwarded-Host header for service routing
        custom_headers = {
            "X-Forwarded-Host": normalized.hostname,
            "X-Forwarded-Proto": "https"
        }
        
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
        
        # Forward using common logic with preserve_host from decision
        return await self._make_backend_request(
            request, 
            target_url, 
            preserve_host=decision.preserve_host,
            custom_headers=decision.custom_headers
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
            
            # Get request body
            try:
                body = await request.body()
            except Exception:
                body = b""
            
            # Make backend request
            method = request.method.upper()
            if method == "GET":
                backend_response = await self.client.get(
                    target_url,
                    headers=headers,
                    follow_redirects=False
                )
            elif method == "POST":
                backend_response = await self.client.post(
                    target_url,
                    headers=headers,
                    content=body,
                    follow_redirects=False
                )
            elif method == "PUT":
                backend_response = await self.client.put(
                    target_url,
                    headers=headers,
                    content=body,
                    follow_redirects=False
                )
            elif method == "DELETE":
                backend_response = await self.client.delete(
                    target_url,
                    headers=headers,
                    follow_redirects=False
                )
            elif method == "PATCH":
                backend_response = await self.client.patch(
                    target_url,
                    headers=headers,
                    content=body,
                    follow_redirects=False
                )
            elif method == "HEAD":
                backend_response = await self.client.head(
                    target_url,
                    headers=headers,
                    follow_redirects=False
                )
            elif method == "OPTIONS":
                backend_response = await self.client.options(
                    target_url,
                    headers=headers,
                    follow_redirects=False
                )
            else:
                # Fallback for other methods
                backend_response = await self.client.request(
                    method=method,
                    url=target_url,
                    headers=headers,
                    content=body,
                    follow_redirects=False
                )
            
            # Read response body
            try:
                response_body = await backend_response.aread()
            except AttributeError:
                # Fallback if aread() doesn't exist
                response_body = backend_response.content
                if hasattr(response_body, '__aiter__'):
                    # It's an async iterator
                    chunks = []
                    async for chunk in response_body:
                        chunks.append(chunk)
                    response_body = b''.join(chunks)
            
            # Prepare response headers
            response_headers = dict(backend_response.headers)
            
            # Remove hop-by-hop headers from response
            for header in hop_by_hop:
                response_headers.pop(header, None)
            
            # Return response
            return Response(
                content=response_body,
                status_code=backend_response.status_code,
                headers=response_headers
            )
            
        except httpx.ConnectError:
            raise HTTPException(502, "Cannot connect to backend")
        except httpx.TimeoutException:
            raise HTTPException(504, "Backend timeout")
        except HTTPException:
            raise
        except Exception as e:
            # Safe error handling
            error_msg = "Proxy error"
            try:
                error_msg = f"Proxy error: {str(e)}"
            except:
                pass
            raise HTTPException(500, error_msg)
    
    async def close(self):
        """Close the httpx client."""
        await self.client.aclose()