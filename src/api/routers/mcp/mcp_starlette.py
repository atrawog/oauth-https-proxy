"""Simple MCP integration using SDK's Starlette app directly.

This module creates and returns the SDK's Starlette app for direct mounting.
"""

import asyncio
import contextlib
import logging
from typing import AsyncIterator, Optional, Tuple

import anyio
from starlette.applications import Starlette
from starlette.middleware.cors import CORSMiddleware

from ....storage.async_redis_storage import AsyncRedisStorage
from ....shared.unified_logger import UnifiedAsyncLogger
from .mcp_server import IntegratedMCPServer

logger = logging.getLogger(__name__)


def create_mcp_starlette_app(
    async_storage: AsyncRedisStorage,
    cert_manager=None,
    docker_manager=None,
    unified_logger: Optional[UnifiedAsyncLogger] = None
) -> Tuple[Starlette, asyncio.Task]:
    """Create the MCP Starlette application for direct mounting.
    
    This returns the SDK's Starlette app that should be mounted at /mcp.
    """
    
    if not unified_logger:
        raise RuntimeError("Unified logger is required for MCP server")
    
    logger.info("[MCP STARLETTE] Creating MCP Starlette application")
    
    # Create integrated MCP server
    mcp_server = IntegratedMCPServer(
        async_storage,
        unified_logger,
        cert_manager,
        docker_manager
    )
    
    # Get FastMCP instance
    mcp = mcp_server.get_server()
    tool_count = len(mcp._tool_manager._tools) if hasattr(mcp, '_tool_manager') else 0
    logger.info(f"[MCP STARLETTE] Registered {tool_count} tools")
    
    # Get the streamable HTTP app from the SDK
    # This creates a Starlette app with the route at "/" (since we set streamable_http_path="/")
    sdk_app = mcp.streamable_http_app()
    
    # Store the session manager for lifespan management
    session_manager = mcp._session_manager
    
    # Create lifespan context manager that initializes the task group
    @contextlib.asynccontextmanager
    async def lifespan(app: Starlette) -> AsyncIterator[None]:
        """Lifespan context manager that initializes MCP task group."""
        logger.info("[MCP STARLETTE] Starting MCP lifespan with task group initialization")
        
        # Initialize the session manager's task group
        async with session_manager.run():
            # Log startup
            await unified_logger.event(
                "mcp_server_started",
                {"tools_count": tool_count, "status": "mounted"}
            )
            logger.info("[MCP STARLETTE] MCP server started with task group")
            
            yield
            
            # Log shutdown
            await unified_logger.event("mcp_server_stopped", {})
            logger.info("[MCP STARLETTE] MCP server stopped")
    
    # Create a new Starlette app with the lifespan
    # We need to copy the routes from the SDK app
    from starlette.routing import Mount
    
    # The SDK app has a single route at "/"
    # We'll mount it as a sub-application
    app_with_lifespan = Starlette(
        lifespan=lifespan,
        routes=[
            Mount("/", app=sdk_app)
        ]
    )
    
    # Add CORS middleware for browser support
    app_with_lifespan.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS", "PATCH"],
        allow_headers=["*"],
        allow_credentials=False,
        expose_headers=["Mcp-Session-Id", "Mcp-Protocol-Version"]
    )
    
    logger.info("[MCP STARLETTE] MCP Starlette app created successfully with lifespan")
    return app_with_lifespan