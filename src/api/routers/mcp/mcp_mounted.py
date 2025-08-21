"""Properly mounted MCP implementation using Starlette sub-application.

This module mounts the MCP SDK's Starlette app directly at /mcp,
allowing the SDK to handle the full request lifecycle properly.
"""

import asyncio
import logging
from typing import Optional

from fastapi import APIRouter
from starlette.applications import Starlette
from starlette.middleware.cors import CORSMiddleware
from starlette.routing import Mount

from ....storage.async_redis_storage import AsyncRedisStorage
from ....shared.unified_logger import UnifiedAsyncLogger
from .mcp_server import IntegratedMCPServer

logger = logging.getLogger(__name__)

# Global MCP app instance
_mcp_starlette_app = None
_mcp_server = None
_init_lock = asyncio.Lock()


async def get_or_create_mcp_app(
    async_storage: AsyncRedisStorage,
    cert_manager,
    docker_manager,
    unified_logger: UnifiedAsyncLogger
) -> Starlette:
    """Get or create the MCP Starlette application."""
    global _mcp_starlette_app, _mcp_server
    
    async with _init_lock:
        if _mcp_starlette_app is not None:
            return _mcp_starlette_app
        
        logger.info("[MCP MOUNT] Creating MCP Starlette application")
        
        # Create integrated MCP server
        _mcp_server = IntegratedMCPServer(
            async_storage,
            unified_logger,
            cert_manager,
            docker_manager
        )
        
        # Get FastMCP instance
        mcp = _mcp_server.get_server()
        tool_count = len(mcp._tool_manager._tools) if hasattr(mcp, '_tool_manager') else 0
        logger.info(f"[MCP MOUNT] Registered {tool_count} tools")
        
        # Get the streamable HTTP app from the SDK
        sdk_app = mcp.streamable_http_app()
        
        # Wrap it with CORS middleware for browser support
        sdk_app.add_middleware(
            CORSMiddleware,
            allow_origins=["*"],
            allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS", "PATCH"],
            allow_headers=["*"],
            allow_credentials=False,
            expose_headers=["Mcp-Session-Id", "Mcp-Protocol-Version"]
        )
        
        # Log all MCP events to Redis Streams
        @sdk_app.on_event("startup")
        async def log_startup():
            await unified_logger.event(
                "mcp_server_started",
                {"tools_count": tool_count, "status": "mounted"}
            )
            logger.info("[MCP MOUNT] MCP server started and mounted")
        
        @sdk_app.on_event("shutdown")
        async def log_shutdown():
            await unified_logger.event("mcp_server_stopped", {})
            logger.info("[MCP MOUNT] MCP server stopped")
        
        _mcp_starlette_app = sdk_app
        return _mcp_starlette_app


def create_mcp_router(
    async_storage: AsyncRedisStorage,
    cert_manager=None,
    docker_manager=None,
    unified_logger: Optional[UnifiedAsyncLogger] = None
) -> APIRouter:
    """Create MCP router that returns a mountable Starlette app.
    
    This router doesn't handle requests directly - it just provides
    the Starlette app that should be mounted at /mcp in the main app.
    """
    
    if not unified_logger:
        raise RuntimeError("Unified logger is required for MCP server")
    
    logger.info("[MCP ROUTER] Creating MCP router for mounting")
    
    router = APIRouter(tags=["mcp"])
    
    # Store dependencies for lazy initialization
    router.mcp_async_storage = async_storage
    router.mcp_cert_manager = cert_manager
    router.mcp_docker_manager = docker_manager
    router.mcp_unified_logger = unified_logger
    
    # The router itself doesn't handle any routes
    # The Starlette app will be mounted directly
    
    return router