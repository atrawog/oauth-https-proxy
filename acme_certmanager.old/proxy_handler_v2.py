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
from .storage import RedisStorage
from .models import ProxyTarget

logger = logging.getLogger(__name__)


class EnhancedProxyHandler:
    """Handles HTTP/S proxy requests with WebSocket and streaming support."""
    
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
        
        # Check protocol-specific enable flags
        is_https = request.url.scheme == "https"
        if is_https and not target.enable_https:
            raise HTTPException(404, f"HTTPS not enabled for {hostname}")
        elif not is_https and not target.enable_http:
            raise HTTPException(404, f"HTTP not enabled for {hostname}")
        
        # Check if auth is required
        if target.auth_enabled and target.auth_proxy:
            auth_result = await self._check_unified_auth(request, target)
            if isinstance(auth_result, Response):
                # Auth check returned a response (redirect or error)
                return auth_result
            # auth_result contains user info to add as headers
            request.state.auth_user = auth_result
        
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
    
    async def close(self):
        """Close the HTTP client."""
        await self.client.aclose()
    
    async def _check_unified_auth(self, request: Request, target: ProxyTarget) -> Union[Dict, Response]:
        """Check authentication via unified auth proxy."""
        
        # Build auth verification request
        auth_url = f"https://{target.auth_proxy}/verify"
        
        # Forward relevant headers and cookies
        headers = {
            "X-Original-URL": str(request.url),
            "X-Original-Method": request.method,
            "X-Forwarded-Host": request.headers.get("host", ""),
            "X-Forwarded-Proto": request.url.scheme,
            "X-Forwarded-For": request.client.host if request.client else "",
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