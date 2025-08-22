"""Enhanced HTTP/S Proxy handler with WebSocket and streaming support."""

import logging
import os
import json
import secrets
import time
import traceback
from typing import Dict, Optional, AsyncIterator, Union
from urllib.parse import quote
import httpx
import websockets
from fastapi import Request, Response, HTTPException, WebSocket
from fastapi.responses import StreamingResponse, RedirectResponse
from starlette.background import BackgroundTask
import asyncio
from .models import ProxyTarget
from .auth_exclusions import merge_exclusions
from ..shared.logging import get_logger, log_request, log_response
from ..shared.config import Config
from ..shared.client_ip import get_real_client_ip

logger = get_logger(__name__)


class EnhancedProxyHandler:
    """Handles HTTP/S proxy requests with WebSocket and streaming support."""
    
    def __init__(self, storage):
        """Initialize proxy handler with storage backend."""
        self.storage = storage
        # Get timeout from environment with proper hierarchy
        from ..shared.config import Config
        request_timeout = float(Config.PROXY_REQUEST_TIMEOUT)
        connect_timeout = float(Config.PROXY_CONNECT_TIMEOUT)
        
        # Create client with streaming support
        self.client = httpx.AsyncClient(
            follow_redirects=False,
            verify=False,  # Skip SSL verification for internal connections
            timeout=httpx.Timeout(
                connect=connect_timeout,     # Connection timeout
                read=request_timeout,        # Read timeout (use request timeout)
                write=10.0,                  # Write timeout
                pool=None                    # No pool timeout for streaming
            ),
            limits=httpx.Limits(
                max_keepalive_connections=200,  # Increased for better connection reuse
                max_connections=500,            # Support more concurrent connections
                keepalive_expiry=30.0          # Keep connections alive longer
            ),
            http2=False  # HTTP/1.1 is slightly faster for SSE
        )
        # Log at debug level to reduce overhead
        logger.debug(f"EnhancedProxyHandler initialized with timeouts: read={request_timeout}s, connect={connect_timeout}s")
    
    async def handle_request(self, request: Request) -> Response:
        """Handle incoming proxy request."""
        start_time = time.perf_counter()  # More accurate timing
        
        # Debug logging - removed from hot path for performance
        # logger.debug(f"Proxy handler received request: {request.method} {request.url} from {request.client}")
        
        # Extract client IP using centralized function
        client_ip = get_real_client_ip(request)
        
        # Log the client IP to verify PROXY protocol is working
        logger.info(
            f"Proxy handler received request from {client_ip} "
            f"(via {'X-Real-IP/X-Forwarded-For headers' if request.headers.get('x-real-ip') or request.headers.get('x-forwarded-for') else 'connection info'})"
        )
        
        # Extract hostname from request
        hostname = request.headers.get("host", "").split(":")[0]
        
        if not hostname:
            logger.warning(
                "No host header in request",
                ip=client_ip
            )
            raise HTTPException(404, "No host header")
        
        # Log the incoming request and store context
        request_context = await log_request(
            logger,
            request,
            client_ip,
            hostname=hostname
        )
        request_key = request_context.get("_request_key") if request_context else None
        
        # Store request_key in request state for use in response logging
        if request_key:
            request.state.request_key = request_key
        
        # Lookup proxy target
        target = self.storage.get_proxy_target(hostname)
        if not target:
            # Get list of available proxies for debugging
            available_proxies = []
            try:
                available_proxies = [p.hostname for p in self.storage.list_proxy_targets()] if self.storage else []
            except Exception:
                pass
            
            logger.warning(
                "No proxy target configured",
                ip=client_ip,
                hostname=hostname,
                available_proxies=available_proxies[:10]  # Show first 10
            )
            raise HTTPException(404, f"No proxy target configured for {hostname}")
        
        if not target.enabled:
            logger.warning(
                "Proxy target disabled - returning 503",
                ip=client_ip,
                hostname=hostname,
                target_url=target.target_url,
                created_at=str(target.created_at),
                auth_enabled=target.auth_enabled,
                cert_name=target.cert_name
            )
            raise HTTPException(503, f"Proxy target {hostname} is disabled")
        
        # Check routes FIRST - routes bypass proxy auth!
        from ..proxy.routes import get_applicable_routes, RouteTargetType
        applicable_routes = get_applicable_routes(self.storage, target)
        
        # Check if request matches any route
        request_path = request.url.path
        request_method = request.method
        
        logger.debug(
            "Checking routes for request",
            ip=client_ip,
            hostname=hostname,
            route_count=len(applicable_routes),
            method=request_method,
            path=request_path,
            route_mode=target.route_mode,
            enabled_routes=len(target.enabled_routes) if target.enabled_routes else 0,
            disabled_routes=len(target.disabled_routes) if target.disabled_routes else 0
        )
        
        for route in applicable_routes:
            logger.debug(
                "Checking route",
                route_id=route.route_id,
                route_pattern=route.path_pattern,
                priority=route.priority,
                methods=route.methods,
                target_type=route.target_type.value,
                target_value=route.target_value,
                is_regex=route.is_regex
            )
            match_result = route.matches(request_path, request_method)
            
            if not match_result:
                # Try to determine why it didn't match
                method_ok = not route.methods or request_method.upper() in route.methods
                logger.debug(
                    "Route did not match",
                    route_id=route.route_id,
                    reason="method" if not method_ok else "path",
                    request_path=request_path,
                    route_pattern=route.path_pattern
                )
            if match_result:
                logger.info(
                    "Route matched - bypassing proxy auth",
                    ip=client_ip,
                    hostname=hostname,
                    method=request_method,
                    path=request_path,
                    route_id=route.route_id,
                    route_pattern=route.path_pattern,
                    route_description=route.description,
                    target_type=route.target_type.value,
                    target_value=route.target_value
                )
                
                # Routes bypass proxy authentication entirely!
                # Handle different route types
                if route.target_type == RouteTargetType.URL:
                    return await self._handle_url_route(request, route, request_key)
                elif route.target_type == RouteTargetType.SERVICE:
                    # Handle SERVICE target type
                    return await self._handle_service_route(request, route, request_key)
                else:
                    # For other route types, we can't handle them here
                    logger.warning(
                        "Proxy cannot handle route type",
                        route_type=route.target_type.value,
                        route_id=route.route_id,
                        hostname=hostname
                    )
                    break
        
        # Check protocol-specific enable flags
        is_https = request.url.scheme == "https"
        if is_https and not target.enable_https:
            raise HTTPException(404, f"HTTPS not enabled for {hostname}")
        elif not is_https and not target.enable_http:
            raise HTTPException(404, f"HTTP not enabled for {hostname}")
        
        # Check if auth is required
        if target.auth_enabled and target.auth_proxy:
            # Check if this path is excluded from authentication
            path_excluded = False
            request_path = request.url.path
            
            # Get combined exclusions (defaults + custom)
            all_exclusions = merge_exclusions(target.auth_excluded_paths)
            
            for excluded_path in all_exclusions:
                if request_path.startswith(excluded_path):
                    path_excluded = True
                    logger.debug(f"Path {request_path} excluded from auth by rule: {excluded_path}")
                    break
            
            # Only perform auth check if path is not excluded
            if not path_excluded:
                # DEBUG: Print auth check details
                print(f"[DEBUG] Auth check for {hostname}: client_ip={client_ip}, path={request_path}, auth_enabled={target.auth_enabled}")
                
                # Extract and log Authorization header details
                auth_header = request.headers.get("authorization", "")
                auth_type = ""
                auth_token_preview = ""
                auth_token_jti = ""
                if auth_header:
                    parts = auth_header.split(" ", 1)
                    auth_type = parts[0] if parts else ""
                    if len(parts) > 1 and parts[1]:
                        # Show first and last 8 chars of token
                        token = parts[1]
                        if len(token) > 20:
                            auth_token_preview = f"{token[:8]}...{token[-8:]}"
                        else:
                            auth_token_preview = "***SHORT_TOKEN***"
                        
                        # Try to decode JWT to get JTI
                        try:
                            import jwt
                            decoded = jwt.decode(token, options={"verify_signature": False})
                            auth_token_jti = decoded.get("jti", "")
                        except:
                            pass
                
                logger.info(
                    "Starting authentication check - DETAILED CONTEXT WITH TOKEN INFO",
                    ip=client_ip,
                    hostname=hostname,
                    auth_proxy=target.auth_proxy,
                    auth_mode=target.auth_mode,
                    request_path=request_path,
                    request_method=request.method,
                    request_url=str(request.url),
                    has_auth_header=bool(auth_header),
                    auth_type=auth_type,
                    auth_token_preview=auth_token_preview,
                    auth_token_jti=auth_token_jti,
                    has_auth_cookie=target.auth_cookie_name in request.cookies if target.auth_cookie_name else False,
                    auth_cookie_name=target.auth_cookie_name,
                    auth_cookie_value_preview=f"{request.cookies.get(target.auth_cookie_name, '')[:8]}..." if target.auth_cookie_name and request.cookies.get(target.auth_cookie_name) else "",
                    auth_required_users=target.auth_required_users,
                    auth_required_emails=target.auth_required_emails,
                    auth_required_groups=target.auth_required_groups,
                    has_resource_metadata=bool(target.resource_endpoint) if hasattr(target, 'resource_endpoint') else False
                )
                auth_result = await self._check_unified_auth(request, target)
                if isinstance(auth_result, Response):
                    # Auth check returned a response (redirect or error)
                    duration_ms = (time.perf_counter() - start_time) * 1000
                    logger.warning(
                        "Authentication failed - DETAILED FAILURE ANALYSIS",
                        ip=client_ip,
                        hostname=hostname,
                        status=auth_result.status_code,
                        duration_ms=duration_ms,
                        auth_proxy=target.auth_proxy,
                        auth_mode=target.auth_mode,
                        request_path=request_path,
                        request_method=request.method,
                        failure_type="authentication_required" if auth_result.status_code in [401, 302] else "authentication_error",
                        response_headers=dict(auth_result.headers) if hasattr(auth_result, 'headers') else {},
                        response_body=getattr(auth_result, 'body', b'').decode('utf-8', errors='ignore')[:500] if hasattr(auth_result, 'body') else "No body"
                    )
                    await log_response(logger, auth_result, duration_ms, ip=client_ip, hostname=hostname, auth_failure=True, request_key=request_key)
                    return auth_result
                # auth_result contains user info to add as headers
                request.state.auth_user = auth_result
                logger.info(
                    "Authentication successful - USER DETAILS",
                    ip=client_ip,
                    hostname=hostname,
                    user_id=auth_result.get("sub"),
                    username=auth_result.get("username"),
                    email=auth_result.get("email"),
                    scope=auth_result.get("scope"),
                    client_id=auth_result.get("client_id"),
                    groups=auth_result.get("groups", []),
                    auth_method="verified_via_oauth_server",
                    auth_proxy_used=target.auth_proxy
                )
        
        # Handle OPTIONS (preflight) requests
        if request.method == "OPTIONS":
            headers = {
                "Access-Control-Allow-Origin": "*",
                "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS, PATCH",
                "Access-Control-Allow-Headers": "*",
                "Access-Control-Allow-Credentials": "true",
                "Access-Control-Max-Age": "86400"
            }
            headers = self._add_custom_response_headers(headers, target)
            return Response(
                status_code=200,
                headers=headers
            )
        
        # Check if this is a WebSocket upgrade request
        if (request.headers.get("connection", "").lower() == "upgrade" and 
            request.headers.get("upgrade", "").lower() == "websocket"):
            # WebSocket requests need special handling in FastAPI
            raise HTTPException(501, "WebSocket proxying requires WebSocket endpoint")
        
        # Build target URL
        path = request.url.path
        query = request.url.query
        target_url = f"{target.target_url}{path}"
        if query:
            target_url += f"?{query}"
        
        # Prepare headers
        headers = await self._prepare_headers(request, target, client_ip)
        
        # Forward the request with streaming
        try:
            # Create streaming request
            # Prepare request body
            content = None
            if request.method in ["POST", "PUT", "PATCH"]:
                # Stream the request body
                content = request.stream()
            
            # Log detailed request info before sending
            logger.debug(
                "Preparing proxy request",
                ip=client_ip,
                hostname=hostname,
                method=request.method,
                target_url=target_url,
                target_backend=target.target_url,
                headers_count=len(headers),
                has_auth=hasattr(request.state, 'auth_user'),
                has_content=content is not None
            )
            
            # Build and send request with streaming response
            req = self.client.build_request(
                method=request.method,
                url=target_url,
                headers=headers,
                cookies=request.cookies,
                content=content
            )
            
            # DEBUG: Print backend connection attempt
            print(f"[DEBUG] Attempting backend connection: {hostname} -> {target_url}")
            
            logger.info(
                "ATTEMPTING BACKEND CONNECTION - DETAILED DEBUG INFO",
                ip=client_ip,
                hostname=hostname,
                target_url=target_url,
                target_backend_base=target.target_url,
                request_method=request.method,
                request_path=request.url.path,
                request_query=str(request.url.query) if request.url.query else None,
                headers_being_sent=dict(headers),
                auth_headers_included=[h for h in headers if h.lower().startswith("x-auth-")],
                has_content=content is not None,
                content_length="async_generator" if hasattr(content, '__aiter__') else (len(content) if content else 0),
                httpx_timeout_config={
                    "connect": self.client.timeout.connect,
                    "read": self.client.timeout.read,
                    "write": self.client.timeout.write,
                    "pool": self.client.timeout.pool
                }
            )
            
            # Send request and get streaming response
            upstream_response = await self.client.send(req, stream=True)
            
            # Log successful proxy request
            duration_ms = (time.perf_counter() - start_time) * 1000
            logger.info(
                "Proxy request successful",
                ip=client_ip,
                hostname=hostname,
                method=request.method,
                path=request.url.path,
                target_url=target_url,
                status=upstream_response.status_code,
                duration_ms=duration_ms
            )
            
            # Filter response headers
            response_headers = self._filter_response_headers(dict(upstream_response.headers))
            
            # Add CORS headers for all proxy responses
            response_headers.update({
                "Access-Control-Allow-Origin": "*",
                "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS, PATCH",
                "Access-Control-Allow-Headers": "*",
                "Access-Control-Allow-Credentials": "true",
                "Access-Control-Max-Age": "86400"
            })
            
            # Add custom response headers from proxy configuration
            response_headers = self._add_custom_response_headers(response_headers, target)
            
            # Headers processed - no correlation ID needed
            
            # Return streaming response
            response = StreamingResponse(
                self._stream_response(upstream_response),
                status_code=upstream_response.status_code,
                headers=response_headers,
                media_type=upstream_response.headers.get("content-type"),
                background=BackgroundTask(upstream_response.aclose)
            )
            
            # Log response
            await log_response(logger, response, duration_ms, 
                             ip=client_ip, hostname=hostname, target_url=target_url, request_key=request_key)
            
            return response
            
        except httpx.ConnectError as e:
            duration_ms = (time.perf_counter() - start_time) * 1000
            logger.error(
                "Failed to connect to upstream - returning 502 - CONNECTION REFUSED",
                ip=client_ip,
                hostname=hostname,
                target_url=target_url,
                target_backend=target.target_url,
                duration_ms=duration_ms,
                error={"type": "connect_error", "message": str(e), "details": repr(e)},
                connection_details={
                    "method": request.method,
                    "path": request.url.path,
                    "full_target_url": target_url,
                    "backend_api_url": target.target_url,
                    "error_class": type(e).__name__,
                    "error_str": str(e),
                    "error_args": e.args if hasattr(e, 'args') else None,
                    "headers_sent": dict(headers) if headers else {},
                    "auth_headers_included": any(h.startswith("X-Auth-") for h in headers) if headers else False,
                    "httpx_request_details": {
                        "method": req.method if 'req' in locals() else None,
                        "url": str(req.url) if 'req' in locals() else None,
                    },
                    "network_details": {
                        "target_hostname": target.hostname,
                        "backend_url_parsed": {
                            "scheme": target.target_url.split("://")[0] if "://" in target.target_url else "",
                            "netloc": target.target_url.split("://")[1].split("/")[0] if "://" in target.target_url else target.target_url
                        }
                    }
                }
            )
            response = Response(content="Bad Gateway - Unable to connect to upstream server", status_code=502)
            await log_response(logger, response, duration_ms, ip=client_ip, hostname=hostname, request_key=request_key)
            raise HTTPException(502, "Bad Gateway - Unable to connect to upstream server")
        except httpx.TimeoutException as e:
            duration_ms = (time.perf_counter() - start_time) * 1000
            logger.error(
                "Timeout connecting to upstream - returning 504",
                ip=client_ip,
                hostname=hostname,
                target_url=target_url,
                target_backend=target.target_url,
                timeout_config=str(self.client.timeout),
                duration_ms=duration_ms,
                error={"type": "timeout", "message": str(e), "details": repr(e)}
            )
            response = Response(content="Gateway Timeout - Upstream server timeout", status_code=504)
            await log_response(logger, response, duration_ms, ip=client_ip, hostname=hostname, request_key=request_key)
            raise HTTPException(504, "Gateway Timeout - Upstream server timeout")
        except Exception as e:
            duration_ms = (time.perf_counter() - start_time) * 1000
            logger.error(
                "Proxy error - returning 500",
                ip=client_ip,
                hostname=hostname,
                target_url=target_url,
                target_backend=target.target_url if target else "unknown",
                exception_type=type(e).__name__,
                duration_ms=duration_ms,
                error={"type": "proxy_error", "message": str(e), "details": repr(e)},
                traceback=traceback.format_exc()
            )
            response = Response(content=f"Proxy error: {str(e)}", status_code=500)
            await log_response(logger, response, duration_ms, ip=client_ip, hostname=hostname, request_key=request_key)
            raise HTTPException(500, f"Proxy error: {str(e)}")
    
    async def handle_websocket(self, websocket: WebSocket, path: str):
        """Handle WebSocket proxy connections."""
        # Extract hostname
        hostname = websocket.headers.get("host", "").split(":")[0]
        
        if not hostname:
            await websocket.close(code=1008, reason="No host header")
            return
        
        # Lookup proxy target
        target = self.storage.get_proxy_target(hostname)
        if not target:
            await websocket.close(code=1008, reason=f"No proxy target for {hostname}")
            return
        
        if not target.enabled:
            await websocket.close(code=1008, reason=f"Proxy target {hostname} is disabled")
            return
        
        # Build WebSocket URL
        parsed = httpx.URL(target.target_url)
        ws_scheme = "wss" if parsed.scheme == "https" else "ws"
        target_ws_url = f"{ws_scheme}://{parsed.host}:{parsed.port or (443 if ws_scheme == 'wss' else 80)}{path}"
        if websocket.url.query:
            target_ws_url += f"?{websocket.url.query}"
        
        # Accept client connection
        await websocket.accept()
        
        try:
            # Connect to upstream WebSocket
            async with websockets.connect(
                target_ws_url,
                extra_headers=self._prepare_ws_headers(websocket, target)
            ) as upstream_ws:
                # Bidirectional message forwarding
                await asyncio.gather(
                    self._forward_ws_messages(websocket, upstream_ws),
                    self._forward_ws_messages(upstream_ws, websocket),
                    return_exceptions=True
                )
        except Exception as e:
            logger.error(f"WebSocket proxy error: {e}")
            await websocket.close(code=1011, reason="Proxy error")
    
    async def _stream_response(self, response: httpx.Response) -> AsyncIterator[bytes]:
        """Stream response body."""
        try:
            # CRITICAL FIX: Don't use 1-byte chunks for SSE!
            # That causes massive overhead and limits speed to ~10KB/s
            # Use reasonable chunk size even for SSE
            content_type = response.headers.get("content-type", "")
            if "text/event-stream" in content_type:
                # SSE still needs prompt delivery but not 1-byte chunks!
                # 4KB chunks are fine and much faster
                async for chunk in response.aiter_bytes(chunk_size=4096):
                    if chunk:
                        yield chunk
            else:
                # Regular streaming with larger chunks
                async for chunk in response.aiter_bytes(chunk_size=8192):
                    yield chunk
        finally:
            await response.aclose()
    
    async def _forward_ws_messages(self, from_ws, to_ws):
        """Forward WebSocket messages between connections."""
        try:
            async for message in from_ws:
                if isinstance(message, str):
                    await to_ws.send_text(message)
                else:
                    await to_ws.send_bytes(message)
        except websockets.exceptions.ConnectionClosed:
            pass
        except Exception as e:
            logger.error(f"WebSocket forwarding error: {e}")
    
    def _prepare_ws_headers(self, websocket: WebSocket, target: ProxyTarget) -> Dict[str, str]:
        """Prepare headers for WebSocket connection."""
        headers = dict(websocket.headers)
        
        # Remove WebSocket-specific headers that will be set by the client
        ws_headers = [
            "connection", "upgrade", "sec-websocket-key", 
            "sec-websocket-version", "sec-websocket-extensions",
            "host"
        ]
        for header in ws_headers:
            headers.pop(header, None)
        
        # Add custom headers if configured
        if target.custom_headers:
            headers.update(target.custom_headers)
        
        # Add X-Forwarded headers
        headers["x-forwarded-for"] = websocket.client.host if websocket.client else "unknown"
        headers["x-forwarded-proto"] = "wss" if websocket.url.scheme == "wss" else "ws"
        headers["x-forwarded-host"] = websocket.headers.get("host", "")
        
        return headers
    
    async def _prepare_headers(self, request: Request, target: ProxyTarget, client_ip: str) -> Dict[str, str]:
        """Prepare headers for upstream request."""
        # Start with request headers
        headers = dict(request.headers)
        
        # Remove hop-by-hop headers (but keep upgrade for WebSocket)
        hop_by_hop = [
            "connection", "keep-alive", "proxy-authenticate",
            "proxy-authorization", "te", "trailers", "transfer-encoding",
            "host"  # Host will be set separately
        ]
        
        # Keep upgrade header for WebSocket
        if not (request.headers.get("connection", "").lower() == "upgrade"):
            hop_by_hop.append("upgrade")
        
        for header in hop_by_hop:
            headers.pop(header, None)
        
        # Handle host header
        if target.preserve_host_header:
            headers["host"] = request.headers.get("host", "")
        else:
            # Extract host from target URL
            parsed = httpx.URL(target.target_url)
            headers["host"] = parsed.host
            if parsed.port and parsed.port not in (80, 443):
                headers["host"] += f":{parsed.port}"
        
        # Add custom headers if configured
        if target.custom_headers:
            headers.update(target.custom_headers)
        
        # Add X-Forwarded headers (preserve real client IP)
        headers["x-forwarded-for"] = client_ip
        headers["x-forwarded-proto"] = request.url.scheme
        headers["x-forwarded-host"] = request.headers.get("host", "")
        
        # Add auth user headers if available
        if hasattr(request.state, "auth_user") and target.auth_pass_headers:
            auth_user = request.state.auth_user
            header_prefix = target.auth_header_prefix
            
            # Add standard auth headers
            if "user_id" in auth_user:
                headers[f"{header_prefix}User-Id"] = str(auth_user["user_id"])
            if "username" in auth_user:
                headers[f"{header_prefix}User-Name"] = auth_user["username"]
            if "email" in auth_user:
                headers[f"{header_prefix}User-Email"] = auth_user["email"]
            if "groups" in auth_user:
                headers[f"{header_prefix}User-Groups"] = ",".join(auth_user["groups"])
            
            # Add custom claims
            for key, value in auth_user.items():
                if key not in ["user_id", "username", "email", "groups"]:
                    headers[f"{header_prefix}{key.title()}"] = str(value)
        
        return headers
    
    def _filter_response_headers(self, headers: Dict[str, str]) -> Dict[str, str]:
        """Filter hop-by-hop headers from response."""
        # Check if this is SSE response
        content_type = headers.get("content-type", "")
        is_sse = "text/event-stream" in content_type
        
        # Remove hop-by-hop headers from response
        hop_by_hop = [
            "connection", "keep-alive", "proxy-authenticate",
            "proxy-authorization", "te", "trailers",
            "upgrade", "content-length", "content-encoding"
        ]
        
        # For SSE, don't remove transfer-encoding as it might be needed
        if not is_sse:
            hop_by_hop.append("transfer-encoding")
        
        # Parse Connection header for additional hop-by-hop headers
        connection_header = headers.get("connection", "")
        if connection_header:
            for value in connection_header.split(","):
                hop_by_hop.append(value.strip().lower())
        
        # Remove hop-by-hop headers
        filtered = {}
        for name, value in headers.items():
            if name.lower() not in hop_by_hop:
                filtered[name] = value
        
        # For SSE, ensure proper headers are set
        if is_sse:
            filtered["cache-control"] = "no-cache, no-store, must-revalidate"
            filtered["x-accel-buffering"] = "no"  # Disable nginx buffering
        
        return filtered
    
    def _add_custom_response_headers(self, headers: Dict[str, str], target: ProxyTarget) -> Dict[str, str]:
        """Add custom response headers from proxy configuration."""
        if target.custom_response_headers:
            headers.update(target.custom_response_headers)
        return headers
    
    async def _handle_service_route(self, request: Request, route, request_key: Optional[str] = None) -> Response:
        """Handle service route by looking up the service target."""
        service_name = route.target_value
        
        # Look up service target from Redis
        service_target = None
        try:
            # Check service URL
            service_url = self.storage.redis_client.get(f"service:url:{service_name}")
            if service_url:
                service_target = service_url
                logger.debug(f"Found service {service_name} with URL: {service_url}")
        except Exception as e:
            logger.error(f"Failed to lookup service {service_name}: {e}")
        
        if not service_target:
            # Get available services for debugging
            available_services = []
            try:
                # Get all service keys from Redis
                service_keys = self.storage.redis_client.keys("service:url:*")
                available_services = [key.decode().split(":", 2)[2] for key in service_keys[:10]]
            except Exception:
                pass
                
            logger.error(
                "Service not found in registry - returning 503",
                service_name=service_name,
                available_services=available_services,
                route_id=route.route_id if hasattr(route, 'route_id') else None,
                route_pattern=route.path_pattern if hasattr(route, 'path_pattern') else None,
                route_target_type=route.target_type.value if hasattr(route, 'target_type') else None
            )
            raise HTTPException(503, f"Service {service_name} not available")
        
        # Forward to the service using the same logic as URL routes
        route.target_value = service_target
        return await self._handle_url_route(request, route, request_key)
    
    async def _handle_url_route(self, request: Request, route, request_key: Optional[str] = None) -> Response:
        """Handle URL route by forwarding to the specified URL."""
        start_time = time.perf_counter()  # More accurate timing
        hostname = request.headers.get("host", "").split(":")[0]
        
        # Extract client IP using centralized function
        client_ip = get_real_client_ip(request)
        
        target_url = route.target_value
        if not target_url.startswith(('http://', 'https://')):
            target_url = f'http://{target_url}'
        
        # Build full URL
        path = request.url.path
        query = request.url.query
        full_url = f"{target_url}{path}"
        if query:
            full_url += f"?{query}"
        
        logger.info(f"Forwarding URL route to {full_url}")
        
        try:
            # Prepare headers
            headers = dict(request.headers)
            # Remove hop-by-hop headers
            for header in ['host', 'connection', 'keep-alive', 'transfer-encoding']:
                headers.pop(header, None)
            
            # Add X-Forwarded headers (preserve real client IP)
            headers["x-forwarded-for"] = client_ip
            headers["x-forwarded-proto"] = request.url.scheme
            headers["x-forwarded-host"] = request.headers.get("host", "")
            
            # Get request body for streaming
            body = None
            if request.method in ["POST", "PUT", "PATCH"]:
                body = await request.body()
            
            # Build and send request with streaming response
            req = self.client.build_request(
                method=request.method,
                url=full_url,
                headers=headers,
                content=body if body else None,
                cookies=request.cookies
            )
            
            # Send request and get streaming response
            upstream_response = await self.client.send(req, stream=True)
            
            # Log successful proxy request
            duration_ms = (time.perf_counter() - start_time) * 1000
            logger.info(f"Route request to {full_url} returned {upstream_response.status_code}")
            
            # Prepare response headers
            response_headers = dict(upstream_response.headers)
            # Remove hop-by-hop headers
            for header in ['connection', 'keep-alive', 'transfer-encoding', 'upgrade']:
                response_headers.pop(header, None)
            
            # Check if it's an SSE or streaming response
            content_type = response_headers.get('content-type', '').lower()
            is_streaming = 'text/event-stream' in content_type or 'stream' in content_type
            
            if is_streaming:
                # Return streaming response for SSE
                response = StreamingResponse(
                    self._stream_response(upstream_response),
                    status_code=upstream_response.status_code,
                    headers=response_headers,
                    media_type=upstream_response.headers.get("content-type"),
                    background=BackgroundTask(upstream_response.aclose)
                )
            else:
                # For non-streaming responses, read the content
                content = await upstream_response.aread()
                await upstream_response.aclose()
                response = Response(
                    content=content,
                    status_code=upstream_response.status_code,
                    headers=response_headers
                )
            
            # Log the response
            await log_response(logger, response, duration_ms,
                             ip=client_ip, hostname=hostname, target_url=full_url, request_key=request_key)
            
            # Return the response
            return response
            
        except httpx.ConnectError:
            duration_ms = (time.perf_counter() - start_time) * 1000
            logger.error(f"Failed to connect to URL route {full_url}")
            error_response = Response(content="Bad Gateway - Unable to connect to route target", status_code=502)
            await log_response(logger, error_response, duration_ms,
                             ip=client_ip, hostname=hostname, target_url=full_url, request_key=request_key)
            raise HTTPException(502, "Bad Gateway - Unable to connect to route target")
        except httpx.TimeoutException:
            duration_ms = (time.perf_counter() - start_time) * 1000
            logger.error(f"Timeout connecting to URL route {full_url}")
            error_response = Response(content="Gateway Timeout - Route target timeout", status_code=504)
            await log_response(logger, error_response, duration_ms,
                             ip=client_ip, hostname=hostname, target_url=full_url, request_key=request_key)
            raise HTTPException(504, "Gateway Timeout - Route target timeout")
        except Exception as e:
            duration_ms = (time.perf_counter() - start_time) * 1000
            logger.error(f"URL route error: {e}")
            error_response = Response(content=f"Route error: {str(e)}", status_code=500)
            await log_response(logger, error_response, duration_ms,
                             ip=client_ip, hostname=hostname, target_url=full_url, request_key=request_key)
            raise HTTPException(500, f"Route error: {str(e)}")
    
    async def close(self):
        """Close the HTTP client."""
        await self.client.aclose()
    
    async def _check_unified_auth(self, request: Request, target: ProxyTarget) -> Union[Dict, Response]:
        """Check authentication via unified auth proxy with comprehensive logging."""
        
        # Extract client IP using centralized function
        client_ip = get_real_client_ip(request)
        
        # Build auth verification request
        # Use internal API service URL to avoid proxy loops
        api_url = "http://localhost:9000/verify"
        
        # Forward relevant headers and cookies
        headers = {
            "X-Original-URL": str(request.url),
            "X-Original-Method": request.method,
            "X-Forwarded-Host": target.hostname,  # Pass the actual target hostname for resource validation
            "X-Forwarded-Proto": request.url.scheme,
            "X-Forwarded-For": client_ip,
            "X-Forwarded-Path": request.url.path,  # Pass the path for full resource URL construction
        }
        
        # Add allowed scopes and audiences if configured
        if target.auth_allowed_scopes:
            headers["X-Auth-Allowed-Scopes"] = ",".join(target.auth_allowed_scopes)
        if target.auth_allowed_audiences:
            headers["X-Auth-Allowed-Audiences"] = ",".join(target.auth_allowed_audiences)
        
        # Log the headers being sent to auth service
        logger.debug(
            "Sending auth verification request - DETAILED HEADERS",
            ip=client_ip,
            hostname=target.hostname,
            api_url=api_url,
            forwarded_headers=headers,
            original_request_headers=dict(request.headers),
            resource_uri_will_be=f"{request.url.scheme}://{target.hostname}"
        )
        
        # Include auth cookie if present
        cookies = {}
        if target.auth_cookie_name in request.cookies:
            cookies[target.auth_cookie_name] = request.cookies[target.auth_cookie_name]
            logger.debug(f"Including auth cookie: {target.auth_cookie_name}", ip=client_ip)
        
        # Include Authorization header if present
        if "authorization" in request.headers:
            headers["Authorization"] = request.headers["authorization"]
            auth_header_preview = request.headers["authorization"][:20] + "..." if len(request.headers["authorization"]) > 20 else request.headers["authorization"]
            logger.debug(f"Including Authorization header: {auth_header_preview}", ip=client_ip, hostname=target.hostname)
        
        try:
            # Make auth verification request
            logger.debug(
                "Making auth verification request to OAuth server",
                ip=client_ip,
                hostname=target.hostname,
                api_url=api_url,
                has_auth_header=bool(headers.get("Authorization")),
                has_cookies=bool(cookies)
            )
            
            auth_response = await self.client.get(
                api_url,
                headers=headers,
                cookies=cookies,
                follow_redirects=False
            )
            
            # Log the raw auth response for debugging
            logger.debug(
                "Received auth verification response - RAW RESPONSE DETAILS",
                ip=client_ip,
                hostname=target.hostname,
                auth_proxy=target.auth_proxy,
                response_status=auth_response.status_code,
                response_headers=dict(auth_response.headers),
                response_body_preview=auth_response.text[:500] if auth_response.text else "No body",
                response_size=len(auth_response.content) if auth_response.content else 0
            )
            
            if auth_response.status_code == 200:
                # Authentication successful
                try:
                    user_info = auth_response.json()
                    logger.info(
                        "Auth verification successful - USER INFO RECEIVED",
                        ip=client_ip,
                        hostname=target.hostname,
                        auth_proxy=target.auth_proxy,
                        user_info=user_info,
                        user_id=user_info.get("sub"),
                        username=user_info.get("username"),
                        email=user_info.get("email"),
                        scope=user_info.get("scope"),
                        client_id=user_info.get("client_id")
                    )
                except json.JSONDecodeError as e:
                    logger.error(
                        "Auth service returned invalid JSON - returning 503",
                        ip=client_ip,
                        hostname=target.hostname,
                        auth_proxy=target.auth_proxy,
                        response_status=auth_response.status_code,
                        response_body=auth_response.text[:200],  # First 200 chars
                        json_decode_error=str(e)
                    )
                    headers = {}
                    headers = self._add_custom_response_headers(headers, target)
                    return Response(content="Authentication service error", status_code=503, headers=headers)
                
                # Check user/email/group restrictions with detailed logging
                if target.auth_required_users:
                    username = user_info.get("username")
                    if username not in target.auth_required_users:
                        logger.warning(
                            "User authorization failed - user not in allowed list",
                            ip=client_ip,
                            hostname=target.hostname,
                            username=username,
                            required_users=target.auth_required_users
                        )
                        headers = {}
                        headers = self._add_custom_response_headers(headers, target)
                        return Response(content="User not authorized", status_code=403, headers=headers)
                
                if target.auth_required_emails:
                    email = user_info.get("email", "")
                    email_matches = [pattern for pattern in target.auth_required_emails if pattern in email]
                    if not email_matches:
                        logger.warning(
                            "Email authorization failed - email not in allowed patterns",
                            ip=client_ip,
                            hostname=target.hostname,
                            user_email=email,
                            required_email_patterns=target.auth_required_emails
                        )
                        headers = {}
                        headers = self._add_custom_response_headers(headers, target)
                        return Response(content="Email not authorized", status_code=403, headers=headers)
                
                if target.auth_required_groups:
                    user_groups = user_info.get("groups", [])
                    group_matches = [group for group in target.auth_required_groups if group in user_groups]
                    if not group_matches:
                        logger.warning(
                            "Group authorization failed - user not in required groups",
                            ip=client_ip,
                            hostname=target.hostname,
                            user_groups=user_groups,
                            required_groups=target.auth_required_groups
                        )
                        headers = {}
                        headers = self._add_custom_response_headers(headers, target)
                        return Response(content="Group not authorized", status_code=403, headers=headers)
                
                return user_info
            
            elif auth_response.status_code == 401:
                # Not authenticated - handle based on mode
                logger.warning(
                    "Auth verification failed - 401 Unauthorized from OAuth server",
                    ip=client_ip,
                    hostname=target.hostname,
                    auth_proxy=target.auth_proxy,
                    auth_mode=target.auth_mode,
                    response_body=auth_response.text[:200] if auth_response.text else "No body",
                    www_authenticate_header=auth_response.headers.get("WWW-Authenticate")
                )
                
                if target.auth_mode == "redirect":
                    # Redirect to auth proxy login with proxy hostname for per-proxy GitHub user checking
                    return_url = str(request.url)
                    auth_login_url = f"https://{target.auth_proxy}/login?return_url={quote(return_url)}&proxy_hostname={quote(target.hostname)}"
                    logger.info(f"Redirecting to auth login: {auth_login_url}", ip=client_ip, hostname=target.hostname)
                    headers = {}
                    headers = self._add_custom_response_headers(headers, target)
                    return RedirectResponse(url=auth_login_url, status_code=302, headers=headers)
                else:
                    # Return 401 Unauthorized with MCP-compliant headers (RFC 9728)
                    # Build resource metadata URL based on current host
                    host = request.headers.get("host", target.hostname)
                    proto = request.headers.get("x-forwarded-proto", "https")
                    resource_metadata_url = f"{proto}://{host}/.well-known/oauth-protected-resource"
                    auth_metadata_url = f"https://{target.auth_proxy}/.well-known/oauth-authorization-server"
                    
                    # Build WWW-Authenticate header per RFC 9728 Section 5.1
                    www_auth_params = [
                        'Bearer',
                        f'realm="{target.auth_proxy}"',
                        f'as_uri="{auth_metadata_url}"',
                        f'resource_uri="{resource_metadata_url}"'
                    ]
                    
                    www_authenticate_header = ', '.join(www_auth_params)
                    logger.info(
                        "Returning 401 with MCP-compliant WWW-Authenticate header",
                        ip=client_ip,
                        hostname=target.hostname,
                        www_authenticate=www_authenticate_header,
                        resource_metadata_url=resource_metadata_url,
                        auth_metadata_url=auth_metadata_url
                    )
                    
                    headers = {"WWW-Authenticate": www_authenticate_header}
                    headers = self._add_custom_response_headers(headers, target)
                    return Response(
                        content="Authentication required",
                        status_code=401,
                        headers=headers
                    )
            
            else:
                # Auth service error - detailed logging for debugging
                error_detail = "Authentication service error"
                error_response_body = ""
                
                # Try to get response body for debugging
                try:
                    error_response_body = auth_response.text[:500] if auth_response.text else "No response body"
                except:
                    error_response_body = "Could not read response body"
                
                # Check if it's an audience validation error
                is_audience_error = False
                error_data = {}
                if auth_response.status_code == 403:
                    try:
                        error_data = auth_response.json()
                        if error_data.get("detail", {}).get("error") == "invalid_audience":
                            is_audience_error = True
                            error_detail = f"Token not valid for {target.hostname}. Please re-authenticate with this resource."
                    except:
                        pass
                
                # Log comprehensive error details
                logger.error(
                    "Auth service returned unexpected status - COMPREHENSIVE ERROR DETAILS",
                    ip=client_ip,
                    hostname=target.hostname,
                    auth_proxy=target.auth_proxy,
                    api_url=api_url,
                    response_status=auth_response.status_code,
                    response_headers=dict(auth_response.headers),
                    response_body=error_response_body,
                    error_detail=error_detail,
                    is_audience_error=is_audience_error,
                    parsed_error_data=error_data,
                    request_headers_sent=headers,
                    cookies_sent=bool(cookies),
                    expected_resource_uri=f"{request.url.scheme}://{target.hostname}",
                    debug_context={
                        "client_ip": client_ip,
                        "hostname": target.hostname,
                        "request_path": request.url.path,
                        "request_method": request.method,
                        "auth_mode": target.auth_mode
                    }
                )
                headers = {}
                headers = self._add_custom_response_headers(headers, target)
                return Response(content=error_detail, status_code=503, headers=headers)
                
        except httpx.ConnectError as e:
            logger.error(
                "Failed to connect to auth service - CONNECTION ERROR",
                ip=client_ip,
                hostname=target.hostname,
                auth_proxy=target.auth_proxy,
                api_url=api_url,
                auth_mode=target.auth_mode,
                error=str(e),
                error_type=type(e).__name__,
                connection_details={
                    "target_url": api_url,
                    "client_ip": client_ip,
                    "hostname": target.hostname,
                    "timeout_config": str(self.client.timeout)
                }
            )
            if target.auth_mode == "passthrough":
                # Continue without auth in passthrough mode
                logger.info(f"Passthrough mode enabled - continuing without auth", ip=client_ip, hostname=target.hostname)
                return {}
            headers = {}
            headers = self._add_custom_response_headers(headers, target)
            return Response(content="Authentication service unavailable", status_code=503, headers=headers)
        except httpx.TimeoutException as e:
            logger.error(
                "Timeout connecting to auth service - TIMEOUT ERROR",
                ip=client_ip,
                hostname=target.hostname,
                auth_proxy=target.auth_proxy,
                api_url=api_url,
                auth_mode=target.auth_mode,
                timeout_config=str(self.client.timeout),
                error=str(e),
                timeout_details={
                    "connect_timeout": self.client.timeout.connect,
                    "read_timeout": self.client.timeout.read,
                    "write_timeout": self.client.timeout.write
                }
            )
            if target.auth_mode == "passthrough":
                # Continue without auth in passthrough mode
                logger.info(f"Passthrough mode enabled - continuing without auth", ip=client_ip, hostname=target.hostname)
                return {}
            headers = {}
            headers = self._add_custom_response_headers(headers, target)
            return Response(content="Authentication service timeout", status_code=503, headers=headers)
        except Exception as e:
            logger.error(
                "Failed to verify auth - UNEXPECTED ERROR",
                ip=client_ip,
                hostname=target.hostname,
                auth_proxy=target.auth_proxy,
                api_url=api_url,
                auth_mode=target.auth_mode,
                exception_type=type(e).__name__,
                error=str(e),
                traceback=traceback.format_exc(),
                request_context={
                    "client_ip": client_ip,
                    "hostname": target.hostname,
                    "method": request.method,
                    "path": request.url.path,
                    "query": str(request.url.query)
                }
            )
            if target.auth_mode == "passthrough":
                # Continue without auth in passthrough mode
                logger.info(f"Passthrough mode enabled - continuing without auth", ip=client_ip, hostname=target.hostname)
                return {}
            headers = {}
            headers = self._add_custom_response_headers(headers, target)
            return Response(content="Authentication service error", status_code=503, headers=headers)
    
