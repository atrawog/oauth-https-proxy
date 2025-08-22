"""Minimal ASGI application for proxy-only instances.

This app is used for domain instances that only need to forward requests,
without the overhead of FastAPI's lifespan management and API endpoints.
"""

import httpx
from typing import Dict, Optional
from starlette.requests import Request
from starlette.responses import Response, PlainTextResponse, JSONResponse
from starlette.applications import Starlette
from starlette.routing import Route
from starlette.middleware.base import BaseHTTPMiddleware
from .handler import EnhancedProxyHandler
from ..shared.logger import get_logger_compat
from ..middleware.proxy_client_middleware import ProxyClientMiddleware
from ..api.oauth.metadata_handler import OAuthMetadataHandler
from ..api.oauth.config import Settings

logger = get_logger_compat(__name__)


class ProxyOnlyApp:
    """Minimal proxy application without FastAPI overhead."""
    
    def __init__(self, storage, domains=None, async_storage=None):
        """Initialize proxy-only app with its own resources."""
        self.storage = storage
        self.async_storage = async_storage
        self.domains = domains or []
        
        # Always configure Redis logging for proxy instances
        # Each Hypercorn instance needs its own Redis handler
        # Configure Redis logging for this instance
        from ..shared.logging import configure_logging
        
        if storage and storage.redis_client:
            # Always create new Redis logging configuration
            self.logging_components = configure_logging(storage.redis_client)
            logger.info("Proxy instance configured with dedicated Redis logging")
        else:
            self.logging_components = None
            logger.warning("Proxy instance running without Redis logging - no storage/redis_client")
            
        # Each instance gets its own proxy handler with isolated httpx client
        # Pass async_storage if available for better performance
        self.proxy_handler = EnhancedProxyHandler(storage, async_storage=async_storage)
        
        # Create OAuth metadata handler
        self.settings = Settings()
        self.metadata_handler = OAuthMetadataHandler(self.settings, storage)
        
        # Create minimal Starlette app
        self.app = Starlette(
            routes=[
                Route("/.well-known/oauth-authorization-server", self.handle_oauth_metadata, methods=["GET"]),
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
    
    async def handle_oauth_metadata(self, request: Request) -> Response:
        """Handle OAuth authorization server metadata requests."""
        try:
            # Get hostname from request
            hostname = request.headers.get("host", "").split(":")[0]
            if not hostname:
                return JSONResponse({"error": "No host header"}, status_code=404)
            
            # Get metadata using the handler
            metadata = await self.metadata_handler.get_authorization_server_metadata(request, hostname)
            return JSONResponse(metadata)
        except Exception as e:
            logger.error(f"OAuth metadata error: {e}")
            return JSONResponse({"error": str(e)}, status_code=500)
    
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


def create_proxy_app(storage, domains=None, async_storage=None):
    """Factory function to create a proxy-only ASGI app."""
    proxy_app = ProxyOnlyApp(storage, domains, async_storage=async_storage)
    return proxy_app.get_asgi_app()