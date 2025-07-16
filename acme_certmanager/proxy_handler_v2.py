"""Enhanced HTTP/S Proxy handler with WebSocket and streaming support."""

import logging
from typing import Dict, Optional, AsyncIterator
import httpx
import websockets
from fastapi import Request, Response, HTTPException, WebSocket
from fastapi.responses import StreamingResponse
from starlette.background import BackgroundTask
import asyncio
from .storage import RedisStorage
from .models import ProxyTarget

logger = logging.getLogger(__name__)


class EnhancedProxyHandler:
    """Handles HTTP/S proxy requests with WebSocket and streaming support."""
    
    def __init__(self, storage: RedisStorage):
        """Initialize proxy handler with storage backend."""
        self.storage = storage
        # Create client with streaming support
        self.client = httpx.AsyncClient(
            follow_redirects=False,
            timeout=httpx.Timeout(
                connect=5.0,     # Connection timeout
                read=30.0,       # Read timeout
                write=10.0,      # Write timeout
                pool=None        # No pool timeout for streaming
            ),
            limits=httpx.Limits(max_keepalive_connections=100)
        )
    
    async def handle_request(self, request: Request) -> Response:
        """Handle incoming proxy request."""
        # Extract hostname from request
        hostname = request.headers.get("host", "").split(":")[0]
        
        if not hostname:
            raise HTTPException(404, "No host header")
        
        # Lookup proxy target
        target = self.storage.get_proxy_target(hostname)
        if not target:
            raise HTTPException(404, f"No proxy target configured for {hostname}")
        
        if not target.enabled:
            raise HTTPException(503, f"Proxy target {hostname} is disabled")
        
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
            req = self.client.build_request(
                method=request.method,
                url=target_url,
                headers=headers,
                cookies=request.cookies
            )
            
            # Stream request body if present
            if request.method in ["POST", "PUT", "PATCH"]:
                # Stream the request body
                req.content = request.stream()
            
            # Send request and get streaming response
            upstream_response = await self.client.send(req, stream=True)
            
            # Filter response headers
            response_headers = self._filter_response_headers(dict(upstream_response.headers))
            
            # Return streaming response
            return StreamingResponse(
                self._stream_response(upstream_response),
                status_code=upstream_response.status_code,
                headers=response_headers,
                media_type=upstream_response.headers.get("content-type"),
                background=BackgroundTask(upstream_response.aclose)
            )
            
        except httpx.ConnectError:
            logger.error(f"Failed to connect to upstream {target_url}")
            raise HTTPException(502, "Bad Gateway - Unable to connect to upstream server")
        except httpx.TimeoutException:
            logger.error(f"Timeout connecting to upstream {target_url}")
            raise HTTPException(504, "Gateway Timeout - Upstream server timeout")
        except Exception as e:
            logger.error(f"Proxy error for {hostname}: {e}")
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
    
    async def close(self):
        """Close the HTTP client."""
        await self.client.aclose()