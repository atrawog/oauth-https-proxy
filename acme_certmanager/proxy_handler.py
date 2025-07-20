"""HTTP/S Proxy handler with automatic certificate management."""

import logging
import os
from typing import Dict, Optional
import httpx
from fastapi import Request, Response, HTTPException
from fastapi.responses import StreamingResponse
from .storage import RedisStorage
from .models import ProxyTarget

logger = logging.getLogger(__name__)


class ProxyHandler:
    """Handles HTTP/S proxy requests with streaming support."""
    
    def __init__(self, storage: RedisStorage):
        """Initialize proxy handler with storage backend."""
        self.storage = storage
        # Get timeout from environment with proper hierarchy
        request_timeout_str = os.getenv('PROXY_REQUEST_TIMEOUT')
        if not request_timeout_str:
            raise ValueError("PROXY_REQUEST_TIMEOUT not set in environment - required for proxy configuration")
        request_timeout = float(request_timeout_str)
        
        connect_timeout_str = os.getenv('PROXY_CONNECT_TIMEOUT')
        if not connect_timeout_str:
            raise ValueError("PROXY_CONNECT_TIMEOUT not set in environment - required for proxy configuration")
        connect_timeout = float(connect_timeout_str)
        
        # Create client with configured timeout
        self.client = httpx.AsyncClient(
            follow_redirects=False,
            timeout=httpx.Timeout(request_timeout, connect=connect_timeout)
        )
        logger.info(f"ProxyHandler initialized with timeouts: request={request_timeout}s, connect={connect_timeout}s")
    
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
        
        # Build target URL
        path = request.url.path
        query = request.url.query
        target_url = f"{target.target_url}{path}"
        if query:
            target_url += f"?{query}"
        
        # Prepare headers
        headers = await self._prepare_headers(request, target)
        
        # Forward the request
        try:
            # Stream request body if present
            content = await request.body() if request.method in ["POST", "PUT", "PATCH"] else None
            
            # Make the upstream request
            upstream_response = await self.client.request(
                method=request.method,
                url=target_url,
                headers=headers,
                content=content,
                cookies=request.cookies
            )
            
            # Return streamed response
            return StreamingResponse(
                upstream_response.aiter_bytes(),
                status_code=upstream_response.status_code,
                headers=dict(upstream_response.headers),
                media_type=upstream_response.headers.get("content-type")
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
    
    async def _prepare_headers(self, request: Request, target: ProxyTarget) -> Dict[str, str]:
        """Prepare headers for upstream request."""
        # Start with request headers
        headers = dict(request.headers)
        
        # Remove hop-by-hop headers
        hop_by_hop = [
            "connection", "keep-alive", "proxy-authenticate",
            "proxy-authorization", "te", "trailers", "transfer-encoding",
            "upgrade", "host"  # Host will be set separately
        ]
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
    
    async def close(self):
        """Close the HTTP client."""
        await self.client.aclose()