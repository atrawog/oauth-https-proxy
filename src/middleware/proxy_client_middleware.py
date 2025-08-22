"""
ASGI middleware to inject client IP from PROXY protocol into request headers.

This middleware looks up the real client IP from Redis (stored by PROXY protocol handler)
and injects it into request headers for unified HTTP/HTTPS handling.
"""
import logging
import json
from starlette.types import ASGIApp, Scope, Receive, Send
from starlette.datastructures import MutableHeaders
import redis

logger = logging.getLogger(__name__)


class ProxyClientMiddleware:
    """Middleware to inject real client IP into request headers."""
    
    def __init__(self, app: ASGIApp, redis_client: redis.Redis = None):
        self.app = app
        self.redis_client = redis_client
        
    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] == "http":
            # Get connection info from ASGI scope
            client = scope.get("client")
            server = scope.get("server")
            
            if client and server and self.redis_client:
                # The connection is from PROXY handler, so client[1] is the source port
                # server[1] is the destination port (9001, 12002, etc)
                client_port = client[1]
                server_port = server[1]
                
                # Look up real client info from Redis
                try:
                    key = f"proxy:client:{server_port}:{client_port}"
                    data = self.redis_client.get(key)
                    
                    if data:
                        client_info = json.loads(data)
                        real_client_ip = client_info["client_ip"]
                        
                        # Create mutable headers
                        headers = MutableHeaders(scope=scope)
                        
                        # Add headers if not already present
                        if not headers.get("x-real-ip"):
                            headers["x-real-ip"] = real_client_ip
                        if not headers.get("x-forwarded-for"):
                            headers["x-forwarded-for"] = real_client_ip
                        
                        # Add trace_id if present in metadata
                        trace_id = client_info.get("trace_id")
                        if trace_id and not headers.get("x-trace-id"):
                            headers["x-trace-id"] = trace_id
                            logger.debug(f"Injected trace_id {trace_id} from Redis")
                        
                        # Add client_hostname if present
                        client_hostname = client_info.get("client_hostname")
                        if client_hostname and not headers.get("x-client-hostname"):
                            headers["x-client-hostname"] = client_hostname
                        
                        # Add proxy_hostname if present
                        proxy_hostname = client_info.get("proxy_hostname")
                        if proxy_hostname and not headers.get("x-proxy-hostname"):
                            headers["x-proxy-hostname"] = proxy_hostname
                        
                        logger.debug(f"Injected metadata from Redis (key: {key}): IP={real_client_ip}, trace={trace_id}")
                    else:
                        logger.debug(f"No client info found in Redis for key: {key}")
                except Exception as e:
                    logger.error(f"Failed to get client info from Redis: {e}")
        
        await self.app(scope, receive, send)