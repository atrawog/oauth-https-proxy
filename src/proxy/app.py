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
from .handler import EnhancedProxyHandler

logger = logging.getLogger(__name__)


class ProxyOnlyApp:
    """Minimal proxy application without FastAPI overhead."""
    
    def __init__(self, storage):
        """Initialize proxy-only app with its own resources."""
        self.storage = storage
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
    
    async def startup(self):
        """Minimal startup - no lifespan complexity."""
        logger.info("Proxy-only instance starting")
    
    async def shutdown(self):
        """Clean shutdown of instance resources only."""
        logger.info("Proxy-only instance shutting down")
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


def create_proxy_app(storage):
    """Factory function to create a proxy-only ASGI app."""
    proxy_app = ProxyOnlyApp(storage)
    return proxy_app.get_asgi_app()