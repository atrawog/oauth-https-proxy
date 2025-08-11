"""Enhanced async proxy handler with comprehensive request tracing.

This module provides HTTP/S proxy handling with full request tracing,
event publishing, and correlation through the unified logging system.
"""

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
from ..shared.unified_logger import UnifiedAsyncLogger
from ..shared.config import Config
from ..shared.client_ip import get_real_client_ip
from ..storage.async_redis_storage import AsyncRedisStorage
from ..storage.redis_clients import RedisClients

logger = logging.getLogger(__name__)


class EnhancedAsyncProxyHandler:
    """Async proxy handler with comprehensive request tracing."""
    
    def __init__(self, storage: AsyncRedisStorage, redis_clients: RedisClients):
        """Initialize enhanced proxy handler.
        
        Args:
            storage: Async Redis storage instance
            redis_clients: Redis clients for logging
        """
        self.storage = storage
        self.redis_clients = redis_clients
        
        # Initialize unified logger
        self.logger = UnifiedAsyncLogger(redis_clients)
        self.logger.set_component("proxy_handler")
        
        # Get timeouts from configuration
        request_timeout = float(Config.PROXY_REQUEST_TIMEOUT)
        connect_timeout = float(Config.PROXY_CONNECT_TIMEOUT)
        
        # Create client with streaming support
        self.client = httpx.AsyncClient(
            follow_redirects=False,
            verify=False,  # Skip SSL verification for internal connections
            timeout=httpx.Timeout(
                connect=connect_timeout,
                read=request_timeout,
                write=10.0,
                pool=None  # No pool timeout for streaming
            ),
            limits=httpx.Limits(max_keepalive_connections=100)
        )
        
        logger.info(f"EnhancedAsyncProxyHandler initialized with timeouts: read={request_timeout}s, connect={connect_timeout}s")
    
    async def handle_request(self, request: Request) -> Response:
        """Handle incoming proxy request with full tracing.
        
        Args:
            request: FastAPI request object
            
        Returns:
            Proxy response
        """
        start_time = time.time()
        
        # Extract client IP
        client_ip = get_real_client_ip(request)
        
        # Extract hostname from request
        hostname = request.headers.get("host", "").split(":")[0]
        
        # Generate trace ID for this request
        trace_id = self.logger.start_trace(
            "proxy_request",
            hostname=hostname,
            method=request.method,
            path=str(request.url.path),
            client_ip=client_ip
        )
        
        # Store trace ID in request state for downstream use
        request.state.trace_id = trace_id
        
        try:
            # Log incoming request
            await self.logger.log_request(
                method=request.method,
                path=str(request.url.path),
                ip=client_ip,
                hostname=hostname,
                trace_id=trace_id,
                query=str(request.url.query) if request.url.query else None,
                user_agent=request.headers.get("user-agent"),
                referer=request.headers.get("referer")
            )
            
            # Validate host header
            if not hostname:
                await self.logger.warning(
                    "No host header in request",
                    trace_id=trace_id,
                    ip=client_ip
                )
                await self._log_response_error(trace_id, 400, start_time, "No host header")
                raise HTTPException(400, "No host header")
            
            # Lookup proxy target
            target = await self.storage.get_proxy_target(hostname)
            
            if not target:
                await self.logger.warning(
                    f"No proxy target configured for {hostname}",
                    trace_id=trace_id,
                    ip=client_ip
                )
                await self._log_response_error(trace_id, 404, start_time, f"No proxy target for {hostname}")
                raise HTTPException(404, f"No proxy target configured for {hostname}")
            
            if not target.enabled:
                await self.logger.warning(
                    f"Proxy target {hostname} is disabled",
                    trace_id=trace_id,
                    ip=client_ip,
                    target_url=target.target_url
                )
                await self._log_response_error(trace_id, 503, start_time, f"Proxy target disabled")
                raise HTTPException(503, f"Proxy target {hostname} is disabled")
            
            # Check routes
            route_target = await self._check_routes(request, target, trace_id)
            if route_target:
                # Route matched - use route target instead
                await self.logger.debug(
                    f"Route matched, redirecting to {route_target}",
                    trace_id=trace_id
                )
                backend_url = route_target
            else:
                backend_url = target.target_url
            
            # Check authentication if enabled
            if target.auth_enabled and not route_target:
                auth_result = await self._check_authentication(request, target, trace_id)
                if not auth_result["authenticated"]:
                    await self._log_response_error(trace_id, 401, start_time, "Authentication required")
                    
                    if target.auth_mode == "redirect":
                        return RedirectResponse(
                            url=f"https://{target.auth_proxy}/authorize?redirect_uri={quote(str(request.url))}"
                        )
                    else:
                        raise HTTPException(401, "Authentication required")
            
            # Proxy the request
            response = await self._proxy_request(
                request=request,
                backend_url=backend_url,
                target=target,
                trace_id=trace_id
            )
            
            # Calculate duration
            duration_ms = (time.time() - start_time) * 1000
            
            # Log successful response
            await self.logger.log_response(
                status=response.status_code,
                duration_ms=duration_ms,
                trace_id=trace_id,
                backend_url=backend_url,
                response_size=len(response.content) if hasattr(response, 'content') else 0
            )
            
            # Publish proxy success event
            await self.logger.event(
                "proxy_request_completed",
                {
                    "hostname": hostname,
                    "status": response.status_code,
                    "duration_ms": duration_ms,
                    "client_ip": client_ip
                },
                trace_id=trace_id
            )
            
            # End trace successfully
            await self.logger.end_trace(trace_id, "success", duration_ms=duration_ms)
            
            return response
            
        except HTTPException:
            # Already logged
            raise
            
        except Exception as e:
            duration_ms = (time.time() - start_time) * 1000
            
            # Log error
            await self.logger.log_error_exception(
                error=e,
                context={
                    "hostname": hostname,
                    "path": str(request.url.path),
                    "client_ip": client_ip
                },
                trace_id=trace_id
            )
            
            # Publish proxy failure event
            await self.logger.event(
                "proxy_request_failed",
                {
                    "hostname": hostname,
                    "error": str(e),
                    "error_type": type(e).__name__,
                    "duration_ms": duration_ms,
                    "client_ip": client_ip
                },
                trace_id=trace_id
            )
            
            await self.logger.end_trace(trace_id, "error", error=str(e), duration_ms=duration_ms)
            
            # Return error response
            await self._log_response_error(trace_id, 502, start_time, str(e))
            raise HTTPException(502, f"Backend error: {str(e)}")
    
    async def _check_routes(self, request: Request, target: ProxyTarget, 
                          trace_id: str) -> Optional[str]:
        """Check if request matches any routes.
        
        Args:
            request: FastAPI request
            target: Proxy target configuration
            trace_id: Request trace ID
            
        Returns:
            Route target URL if matched, None otherwise
        """
        from ..proxy.routes import get_applicable_routes, RouteTargetType
        
        self.logger.add_span(trace_id, "check_routes",
                            hostname=target.hostname,
                            path=str(request.url.path))
        
        applicable_routes = await get_applicable_routes(self.storage, target)
        
        request_path = str(request.url.path)
        request_method = request.method
        
        await self.logger.debug(
            f"Checking {len(applicable_routes)} routes",
            trace_id=trace_id,
            method=request_method,
            path=request_path
        )
        
        for route in applicable_routes:
            if route.matches(request_path, request_method):
                await self.logger.info(
                    f"Route matched: {route.route_id}",
                    trace_id=trace_id,
                    pattern=route.path_pattern,
                    target_type=route.target_type.value,
                    target_value=route.target_value
                )
                
                # Convert route target to URL
                if route.target_type == RouteTargetType.PORT:
                    return f"http://localhost:{route.target_value}"
                elif route.target_type == RouteTargetType.SERVICE:
                    # Look up service URL
                    service_url = await self._get_service_url(route.target_value, trace_id)
                    return service_url
                elif route.target_type == RouteTargetType.HOSTNAME:
                    # Look up proxy target
                    route_target = await self.storage.get_proxy_target(route.target_value)
                    if route_target:
                        return route_target.target_url
                elif route.target_type == RouteTargetType.URL:
                    return route.target_value
        
        return None
    
    async def _get_service_url(self, service_name: str, trace_id: str) -> Optional[str]:
        """Get URL for a service.
        
        Args:
            service_name: Service name
            trace_id: Request trace ID
            
        Returns:
            Service URL or None
        """
        # Check external services
        service_data = await self.storage.redis_client.get(f"service:url:{service_name}")
        if service_data:
            service_info = json.loads(service_data)
            return service_info.get("target_url")
        
        # Check Docker services
        docker_data = await self.storage.redis_client.get(f"docker_service:{service_name}")
        if docker_data:
            docker_info = json.loads(docker_data)
            internal_port = docker_info.get("internal_port", 8080)
            return f"http://{service_name}:{internal_port}"
        
        # Check internal services
        if service_name == "api":
            return "http://api:9000"
        
        await self.logger.warning(
            f"Service {service_name} not found",
            trace_id=trace_id
        )
        return None
    
    async def _check_authentication(self, request: Request, target: ProxyTarget,
                                   trace_id: str) -> Dict[str, any]:
        """Check authentication for protected proxy.
        
        Args:
            request: FastAPI request
            target: Proxy target configuration
            trace_id: Request trace ID
            
        Returns:
            Authentication result dictionary
        """
        self.logger.add_span(trace_id, "check_authentication",
                            auth_mode=target.auth_mode)
        
        # Check for excluded paths
        if target.auth_excluded_paths:
            request_path = str(request.url.path)
            for excluded_path in target.auth_excluded_paths:
                if request_path.startswith(excluded_path):
                    await self.logger.debug(
                        f"Path {request_path} excluded from auth",
                        trace_id=trace_id
                    )
                    return {"authenticated": True, "reason": "excluded_path"}
        
        # Check for bearer token
        auth_header = request.headers.get("authorization")
        if auth_header and auth_header.startswith("Bearer "):
            token = auth_header[7:]
            
            # Validate token (would call OAuth validation endpoint)
            # For now, simplified validation
            if token:
                await self.logger.debug(
                    "Bearer token authenticated",
                    trace_id=trace_id
                )
                return {"authenticated": True, "method": "bearer"}
        
        # Check for cookie
        cookie_name = target.auth_cookie_name or "unified_auth_token"
        auth_cookie = request.cookies.get(cookie_name)
        if auth_cookie:
            # Validate cookie (would call OAuth validation endpoint)
            await self.logger.debug(
                "Cookie authenticated",
                trace_id=trace_id
            )
            return {"authenticated": True, "method": "cookie"}
        
        await self.logger.info(
            "Authentication required but not provided",
            trace_id=trace_id,
            auth_mode=target.auth_mode
        )
        
        return {"authenticated": False}
    
    async def _proxy_request(self, request: Request, backend_url: str,
                           target: ProxyTarget, trace_id: str) -> Response:
        """Proxy request to backend.
        
        Args:
            request: FastAPI request
            backend_url: Backend URL to proxy to
            target: Proxy target configuration
            trace_id: Request trace ID
            
        Returns:
            Proxied response
        """
        self.logger.add_span(trace_id, "proxy_to_backend",
                            backend_url=backend_url)
        
        # Build target URL
        target_url = f"{backend_url}{request.url.path}"
        if request.url.query:
            target_url += f"?{request.url.query}"
        
        # Prepare headers
        headers = dict(request.headers)
        
        # Remove hop-by-hop headers
        hop_by_hop = [
            "connection", "keep-alive", "proxy-authenticate",
            "proxy-authorization", "te", "trailers",
            "transfer-encoding", "upgrade"
        ]
        for header in hop_by_hop:
            headers.pop(header, None)
        
        # Handle host header
        if target.preserve_host_header:
            # Keep original host
            pass
        else:
            # Update to backend host
            from urllib.parse import urlparse
            parsed = urlparse(backend_url)
            headers["host"] = parsed.netloc
        
        # Add custom headers
        if target.custom_headers:
            headers.update(target.custom_headers)
        
        # Add trace ID header for correlation
        headers["x-trace-id"] = trace_id
        
        # Get request body
        body = await request.body()
        
        await self.logger.debug(
            f"Proxying {request.method} request to {target_url}",
            trace_id=trace_id,
            body_size=len(body) if body else 0
        )
        
        # Make backend request
        backend_response = await self.client.request(
            method=request.method,
            url=target_url,
            headers=headers,
            content=body,
            follow_redirects=False
        )
        
        # Prepare response headers
        response_headers = dict(backend_response.headers)
        
        # Remove hop-by-hop headers from response
        for header in hop_by_hop:
            response_headers.pop(header, None)
        
        # Add custom response headers
        if target.custom_response_headers:
            response_headers.update(target.custom_response_headers)
        
        await self.logger.debug(
            f"Backend responded with status {backend_response.status_code}",
            trace_id=trace_id
        )
        
        # Return response
        return Response(
            content=backend_response.content,
            status_code=backend_response.status_code,
            headers=response_headers
        )
    
    async def handle_websocket(self, websocket: WebSocket, hostname: str) -> None:
        """Handle WebSocket proxy connection.
        
        Args:
            websocket: FastAPI WebSocket connection
            hostname: Target hostname
        """
        trace_id = self.logger.start_trace(
            "websocket_proxy",
            hostname=hostname,
            client_ip=websocket.client.host if websocket.client else "unknown"
        )
        
        try:
            # Accept WebSocket connection
            await websocket.accept()
            
            # Get proxy target
            target = await self.storage.get_proxy_target(hostname)
            if not target or not target.enabled:
                await websocket.close(code=1008, reason="No proxy target")
                await self.logger.warning(
                    f"No proxy target for WebSocket: {hostname}",
                    trace_id=trace_id
                )
                await self.logger.end_trace(trace_id, "no_target")
                return
            
            # Connect to backend WebSocket
            backend_url = target.target_url.replace("http://", "ws://").replace("https://", "wss://")
            backend_url += websocket.url.path
            
            await self.logger.info(
                f"Proxying WebSocket to {backend_url}",
                trace_id=trace_id
            )
            
            async with websockets.connect(backend_url) as backend_ws:
                # Proxy messages bidirectionally
                async def forward_to_backend():
                    try:
                        while True:
                            data = await websocket.receive_text()
                            await backend_ws.send(data)
                            
                            await self.logger.debug(
                                "Forwarded message to backend",
                                trace_id=trace_id,
                                size=len(data)
                            )
                    except Exception as e:
                        await self.logger.debug(
                            f"WebSocket forward to backend ended: {e}",
                            trace_id=trace_id
                        )
                
                async def forward_to_client():
                    try:
                        async for message in backend_ws:
                            await websocket.send_text(message)
                            
                            await self.logger.debug(
                                "Forwarded message to client",
                                trace_id=trace_id,
                                size=len(message)
                            )
                    except Exception as e:
                        await self.logger.debug(
                            f"WebSocket forward to client ended: {e}",
                            trace_id=trace_id
                        )
                
                # Run both directions concurrently
                await asyncio.gather(
                    forward_to_backend(),
                    forward_to_client(),
                    return_exceptions=True
                )
            
            await self.logger.info(
                "WebSocket proxy session ended",
                trace_id=trace_id
            )
            await self.logger.end_trace(trace_id, "success")
            
        except Exception as e:
            await self.logger.error(
                f"WebSocket proxy error: {str(e)}",
                trace_id=trace_id
            )
            await self.logger.end_trace(trace_id, "error", error=str(e))
            
            try:
                await websocket.close(code=1011, reason="Proxy error")
            except:
                pass
    
    async def _log_response_error(self, trace_id: str, status_code: int,
                                 start_time: float, error_message: str):
        """Log error response.
        
        Args:
            trace_id: Request trace ID
            status_code: HTTP status code
            start_time: Request start time
            error_message: Error message
        """
        duration_ms = (time.time() - start_time) * 1000
        
        await self.logger.log_response(
            status=status_code,
            duration_ms=duration_ms,
            trace_id=trace_id,
            error=error_message
        )
    
    async def close(self):
        """Clean up resources."""
        await self.client.aclose()
        await self.logger.flush()