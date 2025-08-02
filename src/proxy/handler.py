"""Enhanced HTTP/S Proxy handler with WebSocket and streaming support."""

import logging
import os
import json
import secrets
import time
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
from ..shared.logging import get_logger, correlation_id_var, log_request, log_response
from ..shared.config import Config

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
            limits=httpx.Limits(max_keepalive_connections=100)
        )
        logger.info(f"EnhancedProxyHandler initialized with timeouts: read={request_timeout}s, connect={connect_timeout}s")
    
    async def handle_request(self, request: Request) -> Response:
        """Handle incoming proxy request."""
        start_time = time.time()
        
        # Debug logging to trace requests
        logger.info(f"Proxy handler received request: {request.method} {request.url} from {request.client}")
        
        # Extract correlation ID from headers or generate new one
        correlation_id = request.headers.get(Config.LOG_CORRELATION_ID_HEADER)
        if correlation_id:
            correlation_id_var.set(correlation_id)
        else:
            # If no correlation ID from dispatcher, use the one from context (if set)
            correlation_id = correlation_id_var.get()
        
        # Extract client IP from headers first (injected by PROXY protocol handler)
        client_ip = request.headers.get("x-real-ip") or request.headers.get("x-forwarded-for")
        if client_ip:
            # X-Forwarded-For may contain multiple IPs, take the first one
            client_ip = client_ip.split(",")[0].strip()
        else:
            # Fallback to connection info
            client_ip = request.client.host if request.client else "unknown"
        
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
                correlation_id=correlation_id,
                ip=client_ip
            )
            raise HTTPException(404, "No host header")
        
        # Log the incoming request
        await log_request(
            logger,
            request,
            correlation_id,
            client_ip,
            hostname=hostname
        )
        
        # Lookup proxy target
        target = self.storage.get_proxy_target(hostname)
        if not target:
            logger.warning(
                "No proxy target configured",
                correlation_id=correlation_id,
                ip=client_ip,
                hostname=hostname
            )
            raise HTTPException(404, f"No proxy target configured for {hostname}")
        
        if not target.enabled:
            logger.warning(
                "Proxy target disabled",
                correlation_id=correlation_id,
                ip=client_ip,
                hostname=hostname
            )
            raise HTTPException(503, f"Proxy target {hostname} is disabled")
        
        # Check routes FIRST - routes bypass proxy auth!
        from ..proxy.routes import get_applicable_routes, RouteTargetType
        applicable_routes = get_applicable_routes(self.storage, target)
        
        # Check if request matches any route
        request_path = request.url.path
        request_method = request.method
        
        logger.debug(
            "Checking routes",
            correlation_id=correlation_id,
            route_count=len(applicable_routes),
            method=request_method,
            path=request_path
        )
        
        for route in applicable_routes:
            logger.debug(
                "Checking route",
                correlation_id=correlation_id,
                route_pattern=route.path_pattern,
                priority=route.priority,
                methods=route.methods
            )
            match_result = route.matches(request_path, request_method)
            if match_result:
                logger.info(
                    "Route matched",
                    correlation_id=correlation_id,
                    ip=client_ip,
                    hostname=hostname,
                    method=request_method,
                    path=request_path,
                    route_pattern=route.path_pattern,
                    route_description=route.description
                )
                
                # Routes bypass proxy authentication entirely!
                # Handle different route types
                if route.target_type == RouteTargetType.URL:
                    return await self._handle_url_route(request, route)
                elif route.target_type == RouteTargetType.INSTANCE:
                    return await self._handle_instance_route(request, route)
                else:
                    # For other route types, we can't handle them here
                    logger.warning(f"Proxy cannot handle route type {route.target_type}")
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
                logger.debug(
                    "Checking authentication",
                    correlation_id=correlation_id,
                    ip=client_ip,
                    hostname=hostname,
                    auth_proxy=target.auth_proxy
                )
                auth_result = await self._check_unified_auth(request, target)
                if isinstance(auth_result, Response):
                    # Auth check returned a response (redirect or error)
                    duration_ms = (time.time() - start_time) * 1000
                    logger.info(
                        "Authentication required",
                        correlation_id=correlation_id,
                        ip=client_ip,
                        hostname=hostname,
                        status=auth_result.status_code,
                        duration_ms=duration_ms
                    )
                    await log_response(logger, auth_result, duration_ms, correlation_id, hostname=hostname)
                    return auth_result
                # auth_result contains user info to add as headers
                request.state.auth_user = auth_result
                logger.info(
                    "Authentication successful",
                    correlation_id=correlation_id,
                    ip=client_ip,
                    hostname=hostname,
                    user_id=auth_result.get("sub"),
                    username=auth_result.get("username")
                )
        
        # Handle OPTIONS (preflight) requests
        if request.method == "OPTIONS":
            return Response(
                status_code=200,
                headers={
                    "Access-Control-Allow-Origin": "*",
                    "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS, PATCH",
                    "Access-Control-Allow-Headers": "*",
                    "Access-Control-Allow-Credentials": "true",
                    "Access-Control-Max-Age": "86400"
                }
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
        headers = await self._prepare_headers(request, target)
        
        # Forward the request with streaming
        try:
            # Create streaming request
            # Prepare request body
            content = None
            if request.method in ["POST", "PUT", "PATCH"]:
                # Stream the request body
                content = request.stream()
            
            # Build and send request with streaming response
            req = self.client.build_request(
                method=request.method,
                url=target_url,
                headers=headers,
                cookies=request.cookies,
                content=content
            )
            
            # Send request and get streaming response
            upstream_response = await self.client.send(req, stream=True)
            
            # Log successful proxy request
            duration_ms = (time.time() - start_time) * 1000
            logger.info(
                "Proxy request successful",
                correlation_id=correlation_id,
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
            
            # Add correlation ID to response headers if configured
            if Config.LOG_INCLUDE_CORRELATION_ID_RESPONSE == 'true' and correlation_id:
                response_headers[Config.LOG_CORRELATION_ID_HEADER] = correlation_id
            
            # Return streaming response
            response = StreamingResponse(
                self._stream_response(upstream_response),
                status_code=upstream_response.status_code,
                headers=response_headers,
                media_type=upstream_response.headers.get("content-type"),
                background=BackgroundTask(upstream_response.aclose)
            )
            
            # Log response
            await log_response(logger, response, duration_ms, correlation_id, 
                             hostname=hostname, target_url=target_url)
            
            return response
            
        except httpx.ConnectError as e:
            duration_ms = (time.time() - start_time) * 1000
            logger.error(
                "Failed to connect to upstream",
                correlation_id=correlation_id,
                ip=client_ip,
                hostname=hostname,
                target_url=target_url,
                duration_ms=duration_ms,
                error={"type": "connect_error", "message": str(e)}
            )
            response = Response(content="Bad Gateway - Unable to connect to upstream server", status_code=502)
            await log_response(logger, response, duration_ms, correlation_id, hostname=hostname)
            raise HTTPException(502, "Bad Gateway - Unable to connect to upstream server")
        except httpx.TimeoutException as e:
            duration_ms = (time.time() - start_time) * 1000
            logger.error(
                "Timeout connecting to upstream",
                correlation_id=correlation_id,
                ip=client_ip,
                hostname=hostname,
                target_url=target_url,
                duration_ms=duration_ms,
                error={"type": "timeout", "message": str(e)}
            )
            response = Response(content="Gateway Timeout - Upstream server timeout", status_code=504)
            await log_response(logger, response, duration_ms, correlation_id, hostname=hostname)
            raise HTTPException(504, "Gateway Timeout - Upstream server timeout")
        except Exception as e:
            duration_ms = (time.time() - start_time) * 1000
            logger.error(
                "Proxy error",
                correlation_id=correlation_id,
                ip=client_ip,
                hostname=hostname,
                target_url=target_url,
                duration_ms=duration_ms,
                error={"type": "proxy_error", "message": str(e)}
            )
            response = Response(content=f"Proxy error: {str(e)}", status_code=500)
            await log_response(logger, response, duration_ms, correlation_id, hostname=hostname)
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
    
    async def _prepare_headers(self, request: Request, target: ProxyTarget) -> Dict[str, str]:
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
        
        # Add X-Forwarded headers
        headers["x-forwarded-for"] = request.client.host if request.client else "unknown"
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
        # Remove hop-by-hop headers from response
        hop_by_hop = [
            "connection", "keep-alive", "proxy-authenticate",
            "proxy-authorization", "te", "trailers", "transfer-encoding",
            "upgrade", "content-length", "content-encoding"
        ]
        
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
        
        return filtered
    
    async def _handle_instance_route(self, request: Request, route) -> Response:
        """Handle instance route by looking up the instance target."""
        instance_name = route.target_value
        
        # For domain-specific proxy instances, we need to forward all instance routes
        # including the "api" instance to the appropriate target port
        
        # Look up instance target from Redis
        instance_target = None
        try:
            # First try to get it as a port (for localhost instances)
            port = self.storage.redis_client.get(f"instance:{instance_name}")
            if port:
                # Instance ports in Redis have PROXY protocol enabled
                # But the proxy handler doesn't need to know - it just forwards
                instance_target = f"http://localhost:{port}"
            else:
                # Try to get it as a service URL
                service_url = self.storage.redis_client.get(f"instance_url:{instance_name}")
                if service_url:
                    instance_target = service_url
        except Exception as e:
            logger.error(f"Failed to lookup instance {instance_name}: {e}")
        
        if not instance_target:
            logger.error(f"Instance {instance_name} not found in registry")
            raise HTTPException(503, f"Instance {instance_name} not available")
        
        # Forward to the instance using the same logic as URL routes
        route.target_value = instance_target
        return await self._handle_url_route(request, route)
    
    async def _handle_url_route(self, request: Request, route) -> Response:
        """Handle URL route by forwarding to the specified URL."""
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
            
            # Add X-Forwarded headers
            headers["x-forwarded-for"] = request.client.host if request.client else "unknown"
            headers["x-forwarded-proto"] = request.url.scheme
            headers["x-forwarded-host"] = request.headers.get("host", "")
            
            # Get request body
            body = await request.body()
            
            # Forward the request
            response = await self.client.request(
                method=request.method,
                url=full_url,
                headers=headers,
                content=body if body else None,
                cookies=request.cookies
            )
            
            # Return the response
            return Response(
                content=response.content,
                status_code=response.status_code,
                headers=dict(response.headers)
            )
            
        except httpx.ConnectError:
            logger.error(f"Failed to connect to URL route {full_url}")
            raise HTTPException(502, "Bad Gateway - Unable to connect to route target")
        except httpx.TimeoutException:
            logger.error(f"Timeout connecting to URL route {full_url}")
            raise HTTPException(504, "Gateway Timeout - Route target timeout")
        except Exception as e:
            logger.error(f"URL route error: {e}")
            raise HTTPException(500, f"Route error: {str(e)}")
    
    async def close(self):
        """Close the HTTP client."""
        await self.client.aclose()
    
    async def _check_unified_auth(self, request: Request, target: ProxyTarget) -> Union[Dict, Response]:
        """Check authentication via unified auth proxy."""
        
        # Build auth verification request
        # Use internal API service URL to avoid proxy loops
        auth_url = "http://localhost:9000/verify"
        
        # Forward relevant headers and cookies
        headers = {
            "X-Original-URL": str(request.url),
            "X-Original-Method": request.method,
            "X-Forwarded-Host": target.hostname,  # Pass the actual target hostname for resource validation
            "X-Forwarded-Proto": request.url.scheme,
            "X-Forwarded-For": request.client.host if request.client else "",
            "X-Forwarded-Path": request.url.path,  # Pass the path for full resource URL construction
        }
        
        # Include auth cookie if present
        cookies = {}
        if target.auth_cookie_name in request.cookies:
            cookies[target.auth_cookie_name] = request.cookies[target.auth_cookie_name]
        
        # Include Authorization header if present
        if "authorization" in request.headers:
            headers["Authorization"] = request.headers["authorization"]
        
        try:
            # Make auth verification request
            auth_response = await self.client.get(
                auth_url,
                headers=headers,
                cookies=cookies,
                follow_redirects=False
            )
            
            if auth_response.status_code == 200:
                # Authentication successful
                try:
                    user_info = auth_response.json()
                except json.JSONDecodeError:
                    logger.error("Auth service returned invalid JSON")
                    return Response(content="Authentication service error", status_code=503)
                
                # Check user/email/group restrictions
                if target.auth_required_users:
                    if user_info.get("username") not in target.auth_required_users:
                        return Response(content="User not authorized", status_code=403)
                
                if target.auth_required_emails:
                    email = user_info.get("email", "")
                    if not any(pattern in email for pattern in target.auth_required_emails):
                        return Response(content="Email not authorized", status_code=403)
                
                if target.auth_required_groups:
                    user_groups = user_info.get("groups", [])
                    if not any(group in user_groups for group in target.auth_required_groups):
                        return Response(content="Group not authorized", status_code=403)
                
                return user_info
            
            elif auth_response.status_code == 401:
                # Not authenticated - handle based on mode
                if target.auth_mode == "redirect":
                    # Redirect to auth proxy login
                    return_url = str(request.url)
                    auth_login_url = f"https://{target.auth_proxy}/login?return_url={quote(return_url)}"
                    return RedirectResponse(url=auth_login_url, status_code=302)
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
                    
                    return Response(
                        content="Authentication required",
                        status_code=401,
                        headers={"WWW-Authenticate": ', '.join(www_auth_params)}
                    )
            
            else:
                # Auth service error
                logger.error(f"Auth service returned {auth_response.status_code}")
                return Response(content="Authentication service error", status_code=503)
                
        except httpx.ConnectError:
            logger.error(f"Failed to connect to auth service at {target.auth_proxy}")
            if target.auth_mode == "passthrough":
                # Continue without auth in passthrough mode
                return {}
            return Response(content="Authentication service unavailable", status_code=503)
        except httpx.TimeoutException:
            logger.error(f"Timeout connecting to auth service at {target.auth_proxy}")
            if target.auth_mode == "passthrough":
                # Continue without auth in passthrough mode
                return {}
            return Response(content="Authentication service timeout", status_code=503)
        except Exception as e:
            logger.error(f"Failed to verify auth: {e}")
            if target.auth_mode == "passthrough":
                # Continue without auth in passthrough mode
                return {}
            return Response(content="Authentication service error", status_code=503)
    
