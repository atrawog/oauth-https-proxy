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
from starlette.exceptions import HTTPException
import asyncio
# Lazy import UnifiedProxyHandler to avoid circular dependency
from ..shared.logger import log_debug, log_info, log_warning, log_error, log_trace, set_global_logger
from ..shared.unified_logger import UnifiedAsyncLogger
from ..middleware.proxy_client_middleware import ProxyClientMiddleware
from ..api.oauth.metadata_handler import OAuthMetadataHandler
from ..api.oauth.config import Settings


class DisconnectHandlerMiddleware(BaseHTTPMiddleware):
    """Safety net middleware for proxy app - should not be needed if handlers are fixed properly."""
    
    async def dispatch(self, request: Request, call_next):
        """Catch disconnect exceptions that handlers missed - these indicate bugs to fix."""
        try:
            response = await call_next(request)
            return response
        except asyncio.CancelledError:
            # Should be handled in handle_proxy()
            log_warning(f"SAFETY NET: Unhandled CancelledError in proxy for {request.url.path}", component="disconnect_middleware")
            return PlainTextResponse("", status_code=499)
        except (ConnectionResetError, BrokenPipeError, ConnectionAbortedError) as e:
            # Should be handled in handle_proxy()
            log_warning(f"SAFETY NET: Unhandled {type(e).__name__} in proxy for {request.url.path}", component="disconnect_middleware")
            return PlainTextResponse("", status_code=499)
        except GeneratorExit:
            # Should be handled in streaming responses
            log_warning(f"SAFETY NET: Unhandled GeneratorExit in proxy for {request.url.path}", component="disconnect_middleware")
            return PlainTextResponse("", status_code=499)
        except Exception as e:
            # Check if this is a wrapped disconnect exception
            error_str = str(e).lower()
            if any(x in error_str for x in ['disconnect', 'cancelled', 'broken pipe', 'connection reset']):
                log_warning(f"SAFETY NET: Wrapped {type(e).__name__} in proxy for {request.url.path}", component="disconnect_middleware")
                return PlainTextResponse("", status_code=499)
            # Re-raise real errors
            raise


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
        # CRITICAL: Track whether we created it or it was shared!
        self.owns_handler_storage = False
        if async_storage:
            self.handler_storage = async_storage
            # This is a SHARED instance - we must NOT close it!
            self.owns_handler_storage = False
        else:
            # Create unified storage for the handler
            from ..storage import UnifiedStorage
            from ..shared.config import Config
            self.handler_storage = UnifiedStorage(Config.REDIS_URL)
            # We created this instance - we should close it
            self.owns_handler_storage = True
        
        # Proxy handler will be created on first request after redis_clients initialization
        self.proxy_handler = None
        
        # Create OAuth metadata handler
        self.settings = Settings()
        self.metadata_handler = OAuthMetadataHandler(self.settings, storage)
        
        # Create minimal Starlette app
        self.app = Starlette(
            routes=[
                Route("/proxy-health", self.handle_health, methods=["GET"]),  # Health check endpoint
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
        
        # Add disconnect handler middleware as the outermost layer
        # This catches all disconnect exceptions before they bubble up
        self.app.add_middleware(DisconnectHandlerMiddleware)
    
    async def startup(self):
        """Minimal startup - no lifespan complexity."""
        # Initialize Redis clients first for logging
        if not self.redis_clients_initialized:
            await self.redis_clients.initialize()
            self.redis_clients_initialized = True
            
        # Set up unified logger for proxy instance
        self.unified_logger = UnifiedAsyncLogger(self.redis_clients, component="proxy_app")
        set_global_logger(self.unified_logger)
        
        log_info(f"Proxy-only instance starting for domains: {self.domains}", component="proxy_app")
        log_info(f"ProxyOnlyApp routes configured: {[str(r) for r in self.app.routes]}", component="proxy_app")
        
        # Initialize components eagerly if called
        await self._ensure_initialized()
        
        # No longer need to manage Redis log handler - unified logger handles it
        log_info(f"Proxy instance startup complete for {self.domains}", component="proxy_app")
    
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
        
        # CRITICAL: Only close async storage if we created it (not if it's shared!)
        if self.owns_handler_storage and hasattr(self, 'handler_storage') and hasattr(self.handler_storage, 'close'):
            await self.handler_storage.close()
            log_info("Async storage closed for proxy instance (owned)", component="proxy_app")
        elif not self.owns_handler_storage and hasattr(self, 'handler_storage'):
            log_info("Skipping async storage close (shared instance)", component="proxy_app")
    
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
                
                # Initialize storage if needed (UnifiedStorage uses initialize_async)
                if hasattr(self.handler_storage, 'initialize_async'):
                    await self.handler_storage.initialize_async()
                    log_info("UnifiedStorage initialized on first request", component="proxy_app")
                elif hasattr(self.handler_storage, 'initialize'):
                    # Fallback for old AsyncRedisStorage
                    await self.handler_storage.initialize()
                    log_info("Storage initialized on first request", component="proxy_app")
                
                # Create the proxy handler with hostname for route filtering
                proxy_hostname = self.domains[0] if self.domains else None
                # Lazy import to avoid circular dependency
                from .unified_handler import UnifiedProxyHandler
                self.proxy_handler = UnifiedProxyHandler(
                    self.handler_storage, 
                    self.redis_clients,
                    proxy_hostname=proxy_hostname
                )
                log_info(f"Proxy handler created on first request for {proxy_hostname}", component="proxy_app")
            except Exception as e:
                log_error(f"Failed to initialize proxy handler: {e}", component="proxy_app")
                import traceback
                traceback.print_exc()
                self.proxy_handler = None
    
    async def handle_health(self, request: Request) -> Response:
        """Health check endpoint for proxy instance."""
        log_info(f"Health check requested for proxy instance: {self.domains}", component="proxy_app")
        return JSONResponse({
            "status": "healthy",
            "instance": "proxy",
            "domains": self.domains,
            "handler_initialized": self.proxy_handler is not None
        })
    
    async def handle_oauth_metadata(self, request: Request) -> Response:
        """Handle OAuth authorization server metadata requests."""
        try:
            # Get hostname from request
            proxy_hostname = request.headers.get("host", "").split(":")[0]
            if not proxy_hostname:  # Fixed: use correct variable name
                return JSONResponse({"error": "No host header"}, status_code=404)
            
            # Get metadata using the handler
            metadata = await self.metadata_handler.get_authorization_server_metadata(request, proxy_hostname)  # Fixed: use correct variable name
            return JSONResponse(metadata)
        except Exception as e:
            log_error(f"OAuth metadata error: {e}", component="proxy_app")
            return JSONResponse({"error": str(e)}, status_code=500)
    
    async def handle_proxy(self, request: Request) -> Response:
        """Handle all proxy requests."""
        import asyncio
        log_info(f"PROXY APP: Received request to {request.url.path}", component="proxy_app")
        log_info(f"PROXY APP: Request headers: {list(request.headers.keys())}", component="proxy_app")
        # Check for Authorization header specifically
        auth_header = request.headers.get('authorization') or request.headers.get('Authorization')
        if auth_header:
            log_info(f"PROXY APP: Found Authorization header: {auth_header[:50]}...", component="proxy_app")
        else:
            log_info(f"PROXY APP: No Authorization header found", component="proxy_app")
        try:
            # Initialize proxy handler on first request if needed
            if not self.proxy_handler:
                log_debug(f"PROXY APP: Initializing proxy handler", component="proxy_app")
                await self._ensure_initialized()
                if not self.proxy_handler:
                    log_error(f"PROXY APP: Failed to initialize proxy handler", component="proxy_app")
                    return PlainTextResponse(
                        "Service initialization failed",
                        status_code=503
                    )
            # Use the enhanced proxy handler
            log_debug(f"PROXY APP: Calling proxy_handler.handle_request", component="proxy_app")
            return await self.proxy_handler.handle_request(request)
        except asyncio.CancelledError:
            # Client disconnected - this is NORMAL, not an error
            log_debug(f"PROXY APP: Client disconnected during request", component="proxy_app")
            # Return 499 Client Closed Request (nginx standard)
            return PlainTextResponse("", status_code=499)
        except (ConnectionResetError, BrokenPipeError, ConnectionAbortedError) as e:
            # Client connection issues - also normal
            log_debug(f"PROXY APP: Client connection lost: {type(e).__name__}", component="proxy_app")
            return PlainTextResponse("", status_code=499)
        except GeneratorExit:
            # Generator cleanup when client disconnects during streaming
            log_debug(f"PROXY APP: Generator cleanup on client disconnect", component="proxy_app")
            return PlainTextResponse("", status_code=499)
        except HTTPException as he:
            # Handle HTTPException from the proxy handler
            log_warning(f"PROXY APP: Caught HTTPException status={he.status_code} detail={he.detail}", component="proxy_app")
            return PlainTextResponse(
                str(he.detail),
                status_code=he.status_code
            )
        except httpx.HTTPStatusError as e:
            return PlainTextResponse(
                f"Proxy error: {e.response.status_code}",
                status_code=e.response.status_code
            )
        except Exception as e:
            # Check if this is a disconnect-related exception wrapped in another exception
            if "disconnect" in str(e).lower() or "cancelled" in str(e).lower():
                log_debug(f"PROXY APP: Wrapped disconnect exception: {type(e).__name__}", component="proxy_app")
                return PlainTextResponse("", status_code=499)
            
            log_error(f"PROXY APP: Caught exception type={type(e).__name__}, msg={str(e)}", component="proxy_app", error=e)
            import traceback
            log_debug(f"PROXY APP: Traceback: {traceback.format_exc()}", component="proxy_app")
            # Handle exceptions that might contain async generators
            try:
                error_msg = str(e)
            except TypeError as te:
                if "'async_generator' object is not iterable" in str(te):
                    error_msg = f"Backend connection failed: {type(e).__name__}"
                else:
                    error_msg = f"Error: {type(e).__name__}"
            
            log_error(f"Proxy error: {error_msg}", component="proxy_app")
            return PlainTextResponse(
                f"Proxy error: {error_msg}",
                status_code=502
            )
    
    def get_asgi_app(self):
        """Return the ASGI application."""
        return self.app


def create_proxy_app(storage, domains=None, async_storage=None):
    """Factory function to create a proxy-only ASGI app."""
    proxy_app = ProxyOnlyApp(storage, domains, async_storage=async_storage)
    return proxy_app.get_asgi_app()