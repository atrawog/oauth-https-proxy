"""Minimal ASGI application for proxy-only instances.

This app is used for domain instances that only need to forward requests,
without the overhead of FastAPI's lifespan management and API endpoints.
"""

import logging
import httpx
from typing import Dict, Optional
from starlette.requests import Request
from starlette.responses import Response, PlainTextResponse
from starlette.applications import Starlette
from starlette.routing import Route
from starlette.middleware.base import BaseHTTPMiddleware
from .handler import EnhancedProxyHandler
from ..shared.logging import get_logger
from ..middleware.proxy_client_middleware import ProxyClientMiddleware

logger = get_logger(__name__)


class ProxyOnlyApp:
    """Minimal proxy application without FastAPI overhead."""
    
    def __init__(self, storage, domains=None):
        """Initialize proxy-only app with its own resources."""
        self.storage = storage
        self.domains = domains or []
        
        # Always configure Redis logging for proxy instances
        # Each Hypercorn instance needs its own Redis handler
        import logging as std_logging
        from ..shared.logging import configure_logging, AsyncRedisLogHandler
        
        if storage and storage.redis_client:
            # Always create new Redis logging configuration
            self.logging_components = configure_logging(storage.redis_client)
            logger.info("Proxy instance configured with dedicated Redis logging")
        else:
            self.logging_components = None
            logger.warning("Proxy instance running without Redis logging - no storage/redis_client")
            
        # Each instance gets its own proxy handler with isolated httpx client
        self.proxy_handler = EnhancedProxyHandler(storage)
        
        # Create minimal Starlette app
        self.app = Starlette(
            routes=[
                Route("/{path:path}", self.handle_proxy, methods=["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"]),
            ],
            on_startup=[self.startup],
            on_shutdown=[self.shutdown]
        )
        
        # Add middleware to inject client IP from PROXY protocol
        redis_client = storage.redis_client if storage else None
        self.app.add_middleware(ProxyClientMiddleware, redis_client=redis_client)
        
        # Add middleware to identify instance
        async def add_instance_header(request: Request, call_next):
            response = await call_next(request)
            instance_name = ','.join(self.domains) if self.domains else 'proxy'
            response.headers["X-Instance-Name"] = instance_name
            return response
        
        self.app.add_middleware(BaseHTTPMiddleware, dispatch=add_instance_header)
    
    async def startup(self):
        """Minimal startup - no lifespan complexity."""
        logger.info("Proxy-only instance starting")
        
        # Start async Redis log handler only if we created it
        if self.logging_components and self.logging_components.get("redis_handler"):
            await self.logging_components["redis_handler"].start()
            logger.info("Async Redis log handler started for proxy instance")
    
    async def shutdown(self):
        """Clean shutdown of instance resources only."""
        logger.info("Proxy-only instance shutting down")
        
        # Stop async Redis log handler only if we created it
        if self.logging_components and self.logging_components.get("redis_handler"):
            await self.logging_components["redis_handler"].stop()
            logger.info("Async Redis log handler stopped for proxy instance")
            
        # Close only this instance's httpx client
        await self.proxy_handler.close()
    
    async def handle_proxy(self, request: Request) -> Response:
        """Handle all proxy requests."""
        try:
            # Use the enhanced proxy handler
            return await self.proxy_handler.handle_request(request)
        except httpx.HTTPStatusError as e:
            return PlainTextResponse(
                f"Proxy error: {e.response.status_code}",
                status_code=e.response.status_code
            )
        except Exception as e:
            logger.error(f"Proxy error: {e}")
            return PlainTextResponse(
                f"Proxy error: {str(e)}",
                status_code=502
            )
    
    def get_asgi_app(self):
        """Return the ASGI application."""
        return self.app


def create_proxy_app(storage, domains=None):
    """Factory function to create a proxy-only ASGI app."""
    proxy_app = ProxyOnlyApp(storage, domains)
    return proxy_app.get_asgi_app()