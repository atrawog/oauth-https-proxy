"""Simplified async proxy handler that works without async_generator errors."""
import httpx
from fastapi import Request, Response, HTTPException
from ..storage.async_redis_storage import AsyncRedisStorage
from ..storage.redis_clients import RedisClients
from ..shared.config import Config


class SimpleAsyncProxyHandler:
    """Simplified proxy handler that avoids async_generator issues."""
    
    def __init__(self, storage: AsyncRedisStorage, redis_clients: RedisClients, oauth_components=None):
        """Initialize simple proxy handler."""
        self.storage = storage
        self.redis_clients = redis_clients
        
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
    
    async def handle_request(self, request: Request) -> Response:
        """Handle proxy request with simplified logic."""
        try:
            # Extract hostname
            hostname = request.headers.get("host", "").split(":")[0]
            if not hostname:
                raise HTTPException(400, "No host header")
            
            # Get proxy target
            target = await self.storage.get_proxy_target(hostname)
            if not target:
                raise HTTPException(404, f"No proxy target for {hostname}")
            
            if not target.enabled:
                raise HTTPException(503, f"Proxy target {hostname} is disabled")
            
            # Build target URL
            target_url = f"{target.target_url}{request.url.path}"
            if request.url.query:
                target_url += f"?{request.url.query}"
            
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
            if not target.preserve_host_header:
                from urllib.parse import urlparse
                parsed = urlparse(target.target_url)
                headers["host"] = parsed.netloc
            
            # Add custom headers
            if target.custom_headers:
                headers.update(target.custom_headers)
            
            # Get request body
            try:
                body = await request.body()
            except Exception:
                body = b""
            
            # Make backend request
            try:
                # Use specific method functions to avoid issues
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
                
                # Add custom response headers
                if target.custom_response_headers:
                    response_headers.update(target.custom_response_headers)
                
                # Return response
                return Response(
                    content=response_body,
                    status_code=backend_response.status_code,
                    headers=response_headers
                )
                
            except httpx.ConnectError as e:
                raise HTTPException(502, "Cannot connect to backend")
            except httpx.TimeoutException as e:
                raise HTTPException(504, "Backend timeout")
            except Exception as e:
                # Safe error handling
                error_msg = "Backend request failed"
                try:
                    error_msg = f"Backend error: {str(e)}"
                except:
                    pass
                raise HTTPException(502, error_msg)
                
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