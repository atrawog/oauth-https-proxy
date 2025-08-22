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
from .async_handler import EnhancedAsyncProxyHandler
from ..shared.logger import log_debug, log_info, log_warning, log_error, log_trace
from ..middleware.proxy_client_middleware import ProxyClientMiddleware
from ..api.oauth.metadata_handler import OAuthMetadataHandler
from ..api.oauth.config import Settings


class ProxyOnlyApp:
    """Minimal proxy application without FastAPI overhead."""
    
    def __init__(self, storage, domains=None, async_storage=None):
        """Initialize proxy-only app with its own resources."""
        self.storage = storage
        self.async_storage = async_storage
        self.domains = domains or []
        
        # Create Redis clients for unified logging
        from ..storage.redis_clients import RedisClients
        import asyncio
        self.redis_clients = RedisClients()
        self.redis_clients_initialized = False
        self.init_lock = asyncio.Lock()
        
        # No longer need to configure Redis logging - unified logger handles it
        if storage and storage.redis_client:
            log_info("Proxy instance initialized with Redis storage", component="proxy_app")
        else:
            log_warning("Proxy instance running without Redis storage", component="proxy_app")
            
        # Store async_storage for proxy handler
        if async_storage:
            self.handler_storage = async_storage
        else:
            # Create async storage from regular storage for the handler
            from ..storage.async_redis_storage import AsyncRedisStorage
            from ..shared.config import Config
            self.handler_storage = AsyncRedisStorage(Config.REDIS_URL)
        
        # Proxy handler will be created on first request after redis_clients initialization
        self.proxy_handler = None
        
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
        log_info("Proxy-only instance starting", component="proxy_app")
        
        # Initialize components eagerly if called
        await self._ensure_initialized()
        
        # No longer need to manage Redis log handler - unified logger handles it
        log_info("Proxy instance startup complete", component="proxy_app")
    
    async def shutdown(self):
        """Clean shutdown of instance resources only."""
        log_info("Proxy-only instance shutting down", component="proxy_app")
            
        # Close proxy handler (includes httpx client) if it was created
        if self.proxy_handler:
            await self.proxy_handler.close()
        
        # Close Redis clients
        if self.redis_clients:
            await self.redis_clients.close()
            log_info("Redis clients closed for proxy instance", component="proxy_app")
        
        # Close async storage if we created it
        if hasattr(self, 'handler_storage') and hasattr(self.handler_storage, 'close'):
            await self.handler_storage.close()
            log_info("Async storage closed for proxy instance", component="proxy_app")
    
    async def _ensure_initialized(self):
        """Ensure the proxy handler is initialized."""
        if self.proxy_handler:
            return
            
        async with self.init_lock:
            # Double-check after acquiring lock
            if self.proxy_handler:
                return
                
            try:
                # Initialize Redis clients if not done
                if not self.redis_clients_initialized:
                    await self.redis_clients.initialize()
                    self.redis_clients_initialized = True
                    log_info("Redis clients initialized on first request", component="proxy_app")
                
                # Initialize async storage if needed
                if hasattr(self.handler_storage, 'initialize'):
                    await self.handler_storage.initialize()
                    log_info("Async storage initialized on first request", component="proxy_app")
                
                # Create the proxy handler
                self.proxy_handler = EnhancedAsyncProxyHandler(self.handler_storage, self.redis_clients)
                log_info("Proxy handler created on first request", component="proxy_app")
            except Exception as e:
                log_error(f"Failed to initialize proxy handler: {e}", component="proxy_app")
                import traceback
                traceback.print_exc()
                self.proxy_handler = None
    
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
            log_error(f"OAuth metadata error: {e}", component="proxy_app")
            return JSONResponse({"error": str(e)}, status_code=500)
    
    async def handle_proxy(self, request: Request) -> Response:
        """Handle all proxy requests."""
        try:
            # Initialize proxy handler on first request if needed
            if not self.proxy_handler:
                await self._ensure_initialized()
                if not self.proxy_handler:
                    return PlainTextResponse(
                        "Service initialization failed",
                        status_code=503
                    )
            # Use the enhanced proxy handler
            return await self.proxy_handler.handle_request(request)
        except httpx.HTTPStatusError as e:
            return PlainTextResponse(
                f"Proxy error: {e.response.status_code}",
                status_code=e.response.status_code
            )
        except Exception as e:
            log_error(f"Proxy error: {e}", component="proxy_app")
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