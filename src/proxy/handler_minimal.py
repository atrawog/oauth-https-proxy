"""Enhanced HTTP/S Proxy handler with WebSocket and streaming support using unified async logger."""

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
from ..shared.config import Config
from ..shared.client_ip import get_real_client_ip


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
        
        # Get unified logger if available
        self.unified_logger = None
        try:
            from ..shared.unified_logger import get_unified_logger
            self.unified_logger = get_unified_logger()
            self.unified_logger.set_component("proxy_handler")
        except:
            pass
        
        # Fire-and-forget debug log
        self._log_debug(f"EnhancedProxyHandler initialized with timeouts: read={request_timeout}s, connect={connect_timeout}s")
    
    def _log_debug(self, message: str, **kwargs):
        """Fire-and-forget debug logging."""
        if self.unified_logger:
            asyncio.create_task(self.unified_logger.debug(message, **kwargs))
    
    def _log_info(self, message: str, **kwargs):
        """Fire-and-forget info logging."""
        if self.unified_logger:
            asyncio.create_task(self.unified_logger.info(message, **kwargs))
    
    def _log_warning(self, message: str, **kwargs):
        """Fire-and-forget warning logging."""
        if self.unified_logger:
            asyncio.create_task(self.unified_logger.warning(message, **kwargs))
    
    def _log_error(self, message: str, **kwargs):
        """Fire-and-forget error logging."""
        if self.unified_logger:
            asyncio.create_task(self.unified_logger.error(message, **kwargs))
    
    async def _log_request(self, method: str, path: str, client_ip: str, proxy_hostname: str, trace_id: Optional[str] = None, **kwargs):
        """Log HTTP request with unified logger."""
        if self.unified_logger:
            return await self.unified_logger.log_request(method, path, client_ip, proxy_hostname, trace_id, **kwargs)
        return None
    
    async def _log_response(self, status: int, duration_ms: float, trace_id: Optional[str] = None, **kwargs):
        """Log HTTP response with unified logger."""
        if self.unified_logger:
            return await self.unified_logger.log_response(status, duration_ms, trace_id, **kwargs)
        return None
    
    async def handle_request(self, request: Request) -> Response:
        """Handle incoming proxy request."""
        start_time = time.perf_counter()  # More accurate timing
        trace_id = None
        
        # Extract client IP using centralized function
        client_ip = get_real_client_ip(request)
        
        # Start trace if logger available
        if self.unified_logger:
            trace_id = self.unified_logger.start_trace(
                "proxy_request",
                client_ip=client_ip,
                method=request.method,
                path=str(request.url.path),
                proxy_hostname=request.headers.get("host", "unknown")
            )
        
        # Fire-and-forget info log
        self._log_info(
            f"Proxy handler received request from {client_ip}",
            trace_id=trace_id,
            method=request.method,
            path=str(request.url.path),
            client_ip=client_ip
        )
        
        # Get the hostname from the request
        request_url = request.url
        hostname = request_url.hostname or request.headers.get("host", "").split(":")[0]
        
        # Get proxy target from storage
        target = await self.get_proxy_target(hostname)
        if not target:
            if self.unified_logger:
                await self.unified_logger.end_trace(trace_id, "error", status=404)
            raise HTTPException(
                status_code=404,
                detail=f"No proxy target configured for hostname: {hostname}"
            )
        
        # Proxy the request
        try:
            response = await self.proxy_request(request, target, trace_id)
            if self.unified_logger:
                await self.unified_logger.end_trace(trace_id, "success", status=response.status_code)
            return response
        except Exception as e:
            if self.unified_logger:
                await self.unified_logger.end_trace(trace_id, "error", error=str(e))
            raise
    
    async def get_proxy_target(self, hostname: str) -> Optional[ProxyTarget]:
        """Get proxy target configuration from storage."""
        try:
            # Try Redis first
            proxy_data = await self.storage.aget_proxy(hostname)
            if proxy_data:
                # Update last_accessed timestamp
                try:
                    await self.storage.aupdate_proxy(hostname, {
                        "last_accessed": time.time()
                    })
                except Exception as e:
                    self._log_error(f"Failed to update proxy target for {hostname}: {e}")
                
                return ProxyTarget(**proxy_data)
            return None
        except Exception as e:
            self._log_error(f"Error getting proxy target for {hostname}: {e}")
            return None
    
    async def proxy_request(self, request: Request, target: ProxyTarget, trace_id: Optional[str] = None) -> Response:
        """Proxy the request to the target server."""
        # Build proxy URL
        proxy_url = target.target_url
        if not proxy_url.endswith("/"):
            proxy_url += "/"
        
        # Append the request path
        request_url = request.url
        request_path = request_url.path
        if request_path.startswith("/"):
            request_path = request_path[1:]
        proxy_url += request_path
        
        # Add query string if present
        if request_url.query:
            proxy_url += f"?{request_url.query}"
        
        self._log_info(
            f"🔄 Proxy: {request_url.scheme}://{request_url.netloc}{request_url.path} -> {proxy_url}",
            trace_id=trace_id
        )
        
        # Check if target is enabled
        if not target.enabled:
            self._log_warning(
                f"Proxy target not enabled: {target.hostname}",
                trace_id=trace_id
            )
            raise HTTPException(status_code=503, detail="Proxy target is disabled")
        
        # Check if HTTP access is enabled
        if request_url.scheme == "http" and not target.enable_http:
            self._log_warning(
                f"HTTP access disabled for proxy: {target.hostname}",
                trace_id=trace_id
            )
            raise HTTPException(status_code=403, detail="HTTP access is disabled for this proxy")
        
        # Handle OAuth authentication if enabled
        if target.auth_enabled:
            auth_result = await self.handle_oauth_auth(request, target, trace_id)
            if auth_result and not auth_result.get("authenticated"):
                # Return the auth response (redirect or 401)
                return auth_result.get("response")
        
        # Set up timeout
        timeout = httpx.Timeout(
            connect=float(Config.PROXY_CONNECT_TIMEOUT),
            read=float(Config.PROXY_REQUEST_TIMEOUT),
            write=10.0,
            pool=None
        )
        
        # Determine if we should follow redirects
        follow_redirects = not request.headers.get("x-no-follow-redirects")
        
        self._log_debug(
            f"Proxying {request.method} request to {proxy_url} "
            f"(follow_redirects={follow_redirects}, timeout={timeout}s)",
            trace_id=trace_id
        )
        
        # Prepare headers for the proxied request
        proxy_headers = dict(request.headers)
        
        # Remove hop-by-hop headers
        hop_by_hop_headers = [
            "connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
            "te", "trailers", "transfer-encoding", "upgrade", "host"
        ]
        for header in hop_by_hop_headers:
            proxy_headers.pop(header, None)
        
        # Handle host header
        if target.preserve_host_header:
            proxy_headers["host"] = request.headers.get("host", request_url.netloc)
        else:
            # Use target host
            from urllib.parse import urlparse
            parsed_target = urlparse(target.target_url)
            proxy_headers["host"] = parsed_target.netloc
        
        # Add custom headers
        if target.custom_headers:
            proxy_headers.update(target.custom_headers)
        
        # Add forwarded headers
        proxy_headers["x-forwarded-for"] = get_real_client_ip(request)
        proxy_headers["x-forwarded-proto"] = request_url.scheme
        proxy_headers["x-forwarded-host"] = request.headers.get("host", request_url.netloc)
        proxy_headers["x-real-ip"] = get_real_client_ip(request)
        
        self._log_debug(
            f"Request headers to proxy: {dict(proxy_headers)}",
            trace_id=trace_id
        )
        
        try:
            # Get request body
            body = await request.body()
            
            # Make the proxied request
            start_proxy = time.perf_counter()
            response = await self.client.request(
                method=request.method,
                url=proxy_url,
                headers=proxy_headers,
                content=body,
                timeout=timeout,
                follow_redirects=follow_redirects
            )
            proxy_duration = (time.perf_counter() - start_proxy) * 1000
            
            self._log_debug(
                f"Proxy response: status={response.status_code}, "
                f"headers={dict(response.headers)}",
                trace_id=trace_id
            )
            
            # Handle redirects manually if needed
            if response.status_code in [301, 302, 303, 307, 308] and not follow_redirects:
                redirect_location = response.headers.get("location")
                if redirect_location:
                    self._log_info(
                        f"Following redirect to {redirect_location}",
                        trace_id=trace_id
                    )
                    # Return redirect response to client
                    return Response(
                        status_code=response.status_code,
                        headers=dict(response.headers)
                    )
            
            # Check for SSE or streaming response
            content_type = response.headers.get("content-type", "")
            is_sse = "text/event-stream" in content_type
            is_streaming = (
                is_sse or
                "stream" in content_type or
                response.headers.get("transfer-encoding") == "chunked" or
                request.path.endswith("/mcp")  # MCP endpoints always stream
            )
            
            # Prepare response headers
            response_headers = dict(response.headers)
            
            # Remove hop-by-hop headers
            for header in hop_by_hop_headers:
                response_headers.pop(header, None)
            
            # Add custom response headers
            if target.custom_response_headers:
                response_headers.update(target.custom_response_headers)
            
            # Handle streaming responses
            if is_streaming:
                return StreamingResponse(
                    self._stream_response(response, is_sse, trace_id),
                    status_code=response.status_code,
                    headers=response_headers,
                    media_type=content_type
                )
            
            # Non-streaming response
            content = response.content
            
            # Log successful proxy
            duration_ms = (time.perf_counter() - start_time) * 1000
            self._log_info(
                f"✅ Proxy response: {response.status_code} in {duration_ms:.2f}ms",
                trace_id=trace_id,
                status=response.status_code,
                duration_ms=duration_ms,
                proxy_duration_ms=proxy_duration
            )
            
            return Response(
                content=content,
                status_code=response.status_code,
                headers=response_headers
            )
            
        except httpx.ConnectError as e:
            self._log_error(
                f"❌ Proxy connection failed: {e} (URL: {proxy_url})",
                trace_id=trace_id,
                error=str(e)
            )
            raise HTTPException(
                status_code=502,
                detail=f"Failed to connect to upstream server: {str(e)}"
            )
        except httpx.TimeoutException as e:
            self._log_error(
                f"❌ Proxy request timeout: {e} (URL: {proxy_url})",
                trace_id=trace_id,
                error=str(e)
            )
            raise HTTPException(
                status_code=504,
                detail=f"Upstream server timeout: {str(e)}"
            )
        except Exception as e:
            self._log_error(
                f"❌ Proxy request failed: {e} (URL: {proxy_url})",
                trace_id=trace_id,
                error=str(e),
                traceback=traceback.format_exc()
            )
            raise HTTPException(
                status_code=502,
                detail=f"Proxy error: {str(e)}"
            )
    
    async def _stream_response(self, response: httpx.Response, is_sse: bool, trace_id: Optional[str] = None) -> AsyncIterator[bytes]:
        """Stream response content with optimized chunk size."""
        bytes_streamed = 0
        chunks_sent = 0
        start_time = time.perf_counter()
        
        try:
            # Use optimized chunk size for SSE
            chunk_size = 4096 if is_sse else 8192
            
            async for chunk in response.aiter_bytes(chunk_size=chunk_size):
                if chunk:
                    bytes_streamed += len(chunk)
                    chunks_sent += 1
                    yield chunk
            
            # Log streaming stats
            duration_ms = (time.perf_counter() - start_time) * 1000
            throughput_kbps = (bytes_streamed / 1024) / (duration_ms / 1000) if duration_ms > 0 else 0
            
            self._log_info(
                f"✅ Streamed {bytes_streamed} bytes in {chunks_sent} chunks "
                f"({duration_ms:.1f}ms, {throughput_kbps:.1f} KB/s)",
                trace_id=trace_id,
                bytes_streamed=bytes_streamed,
                chunks_sent=chunks_sent,
                duration_ms=duration_ms,
                throughput_kbps=throughput_kbps
            )
            
        except Exception as e:
            self._log_error(
                f"Streaming error after {bytes_streamed} bytes: {e}",
                trace_id=trace_id,
                error=str(e),
                bytes_streamed=bytes_streamed
            )
            raise
    
    async def handle_oauth_auth(self, request: Request, target: ProxyTarget, trace_id: Optional[str] = None) -> Optional[Dict]:
        """Handle OAuth authentication for the proxy."""
        # Implementation would go here - just return None for now
        return None
    
    async def handle_websocket(self, websocket: WebSocket, hostname: str):
        """Handle WebSocket proxy connections."""
        # Get proxy target
        target = await self.get_proxy_target(hostname)
        if not target:
            await websocket.close(code=1008, reason="No proxy target configured")
            return
        
        # Parse target URL for WebSocket
        from urllib.parse import urlparse
        parsed = urlparse(target.target_url)
        ws_scheme = "wss" if parsed.scheme == "https" else "ws"
        ws_url = f"{ws_scheme}://{parsed.netloc}{websocket.url.path}"
        
        if websocket.url.query:
            ws_url += f"?{websocket.url.query}"
        
        self._log_info(f"WebSocket proxy: {hostname} -> {ws_url}")
        
        # Accept the client WebSocket
        await websocket.accept()
        
        try:
            # Connect to upstream WebSocket
            async with websockets.connect(ws_url) as upstream:
                # Relay messages bidirectionally
                async def client_to_upstream():
                    try:
                        async for message in websocket.iter_text():
                            await upstream.send(message)
                    except Exception as e:
                        self._log_debug(f"Client to upstream error: {e}")
                
                async def upstream_to_client():
                    try:
                        async for message in upstream:
                            await websocket.send_text(message)
                    except Exception as e:
                        self._log_debug(f"Upstream to client error: {e}")
                
                # Run both tasks concurrently
                await asyncio.gather(
                    client_to_upstream(),
                    upstream_to_client()
                )
                
        except Exception as e:
            self._log_error(f"WebSocket proxy error: {e}")
            await websocket.close(code=1011, reason=str(e))
    
    async def close(self):
        """Close the HTTP client."""
        await self.client.aclose()