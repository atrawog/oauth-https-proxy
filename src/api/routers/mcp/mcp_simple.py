"""Simplified MCP FastAPI integration using direct ASGI mounting."""

import asyncio
import logging
from typing import Optional

from fastapi import APIRouter, Request
from starlette.responses import Response

from ....storage.async_redis_storage import AsyncRedisStorage
from ....shared.unified_logger import UnifiedAsyncLogger
from .mcp_server import IntegratedMCPServer

logger = logging.getLogger(__name__)

# Global MCP app instance
_mcp_app = None
_mcp_task = None
_mcp_server_instance = None
_initialization_lock = asyncio.Lock()


async def initialize_mcp_server(
    async_storage: AsyncRedisStorage,
    cert_manager,
    docker_manager,
    unified_logger: UnifiedAsyncLogger
):
    """Initialize the MCP server with proper task group."""
    global _mcp_app, _mcp_task, _mcp_server_instance
    
    async with _initialization_lock:
        if _mcp_app is not None:
            logger.info("MCP server already initialized")
            return
        
        logger.info("Initializing MCP server")
        
        try:
            # Create integrated MCP server
            _mcp_server_instance = IntegratedMCPServer(
                async_storage,
                unified_logger,
                cert_manager,
                docker_manager
            )
            
            # Get the FastMCP instance
            mcp = _mcp_server_instance.get_server()
            
            # Get the streamable HTTP app
            _mcp_app = mcp.streamable_http_app()
            logger.info("Got MCP streamable HTTP app")
            
            # Start the task group in background (required for streamable HTTP)
            _mcp_task = asyncio.create_task(mcp.run_streamable_http_async())
            logger.info("Started MCP server task group")
            
        except Exception as e:
            logger.error(f"Failed to initialize MCP server: {e}", exc_info=True)
            _mcp_app = None
            _mcp_task = None
            _mcp_server_instance = None
            raise


def create_mcp_router(
    async_storage: AsyncRedisStorage,
    cert_manager=None,
    docker_manager=None,
    unified_logger: Optional[UnifiedAsyncLogger] = None
) -> APIRouter:
    """Create a simplified MCP router that directly proxies to the MCP app."""
    
    if not unified_logger:
        raise RuntimeError("Unified logger is required for MCP server")
    
    router = APIRouter(tags=["mcp"])
    
    # Store initialization parameters
    init_params = {
        'async_storage': async_storage,
        'cert_manager': cert_manager,
        'docker_manager': docker_manager,
        'unified_logger': unified_logger
    }
    
    @router.on_event("startup")
    async def startup_event():
        """Initialize MCP server on startup."""
        await initialize_mcp_server(**init_params)
    
    @router.on_event("shutdown")
    async def shutdown_event():
        """Shutdown MCP server."""
        global _mcp_task
        if _mcp_task:
            _mcp_task.cancel()
            try:
                await _mcp_task
            except asyncio.CancelledError:
                pass
    
    # Use a catch-all route that proxies directly to the MCP app
    @router.api_route("", methods=["GET", "POST"])
    @router.api_route("/", methods=["GET", "POST"])
    @router.api_route("/{path:path}", methods=["GET", "POST", "PUT", "DELETE"])
    async def mcp_proxy(request: Request, path: str = "") -> Response:
        """Proxy requests directly to the MCP ASGI app."""
        global _mcp_app
        
        if _mcp_app is None:
            # Try to initialize if not ready
            try:
                await initialize_mcp_server(**init_params)
            except Exception:
                pass
        
        if _mcp_app is None:
            return Response(
                content='{"error": "MCP service not available"}',
                status_code=503,
                media_type="application/json"
            )
        
        # The MCP app is an ASGI app, we need to call it properly
        # FastAPI/Starlette will handle the ASGI interface for us
        # We just need to pass the request through
        
        # Create a simple pass-through response
        class ProxyResponse:
            def __init__(self):
                self.status_code = 200
                self.headers = {}
                self.body = []
                
            async def __call__(self, scope, receive, send):
                """Pass through to the MCP app."""
                await _mcp_app(scope, receive, send)
        
        # Return a response that will call the MCP app
        return ProxyResponse()
    
    @router.get("/health")
    async def mcp_health():
        """Health check for MCP service."""
        return {
            "status": "healthy" if _mcp_app else "not_initialized",
            "service": "mcp"
        }
    
    return router