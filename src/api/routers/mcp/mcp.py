"""MCP Starlette app mounting with proper task group initialization.

This module handles mounting the MCP SDK's Starlette app directly on FastAPI,
ensuring the task group is properly initialized for stateful operation.
"""

import asyncio
import json
import logging
import time
import uuid
from typing import Optional, Dict, Any

import anyio
from fastapi import FastAPI, Request, Response
from starlette.middleware.cors import CORSMiddleware
from starlette.routing import BaseRoute, Match, NoMatchFound

from ....storage import UnifiedStorage
from ....shared.unified_logger import UnifiedAsyncLogger
from ....shared.dns_resolver import get_dns_resolver
from .mcp_server import IntegratedMCPServer

logger = logging.getLogger(__name__)

# Global references for MCP components
_mcp_app = None
_mcp_session_manager = None
_mcp_task_group = None
_mcp_task = None
_unified_logger = None


class MCPASGIWrapper:
    """ASGI wrapper that intercepts /mcp requests BEFORE FastAPI.
    
    This bypasses ALL FastAPI middleware to avoid the BaseHTTPMiddleware SSE bug.
    It provides direct passthrough to the Starlette MCP app without any buffering.
    """
    
    def __init__(self, fastapi_app, mcp_starlette_app):
        self.fastapi_app = fastapi_app
        self.mcp_app = mcp_starlette_app
        
    async def __call__(self, scope, receive, send):
        """Route /mcp directly to MCP app, everything else to FastAPI."""
        # Check if this is an /mcp request
        if scope["type"] == "http" and scope["path"] == "/mcp":
            # Log the request for debugging
            method = scope.get("method", "UNKNOWN")
            headers = dict(scope.get("headers", []))
            
            # Extract key headers for logging
            accept = headers.get(b"accept", b"").decode("utf-8", errors="ignore")
            user_agent = headers.get(b"user-agent", b"").decode("utf-8", errors="ignore")
            session_id = headers.get(b"mcp-session-id", b"").decode("utf-8", errors="ignore")
            
            logger.info(f"[MCP WRAPPER] {method} /mcp request")
            logger.debug(f"[MCP WRAPPER] Accept: {accept}")
            logger.debug(f"[MCP WRAPPER] User-Agent: {user_agent}")
            if session_id:
                logger.debug(f"[MCP WRAPPER] Session-ID: {session_id}")
            
            # Modify scope to set path to / for the Starlette app
            mcp_scope = dict(scope)
            mcp_scope["path"] = "/"
            
            # Direct passthrough to MCP app - no buffering!
            await self.mcp_app(mcp_scope, receive, send)
        else:
            # Everything else goes to FastAPI
            await self.fastapi_app(scope, receive, send)


def mount_mcp_app(
    app: FastAPI,
    async_storage: UnifiedStorage,
    cert_manager=None,
    docker_manager=None,
    unified_logger: Optional[UnifiedAsyncLogger] = None
):
    """Mount MCP Starlette app directly on FastAPI.
    
    This mounts the pure MCP server's Starlette app at /mcp using
    FastAPI's standard mount() method for sub-applications.
    
    Args:
        app: FastAPI application instance
        async_storage: UnifiedStorage for Redis operations
        cert_manager: Optional certificate manager
        docker_manager: Optional Docker manager
        unified_logger: UnifiedAsyncLogger for logging
        
    Returns:
        The FastAPI app (no wrapper needed)
    """
    if not unified_logger:
        raise RuntimeError("Unified logger is required for MCP server")
    
    logger.info("[MCP MOUNT] Mounting pure MCP server")
    
    # Create integrated MCP server
    mcp_server = IntegratedMCPServer(
        async_storage,
        unified_logger,
        cert_manager,
        docker_manager
    )
    
    # Get the Starlette app
    starlette_app = mcp_server.get_starlette_app()
    
    # Get server info for logging
    mcp = mcp_server.get_server()
    tool_count = len(mcp.tools)
    tool_names = list(mcp.tools.keys())
    
    logger.info(f"[MCP MOUNT] Registered {tool_count} tools")
    if tool_names:
        logger.info(f"[MCP MOUNT] Tool names: {tool_names[:10]}")
    
    # Create the ASGI wrapper that bypasses FastAPI middleware
    wrapper = MCPASGIWrapper(app, starlette_app)
    
    logger.info("[MCP MOUNT] Created ASGI wrapper to bypass ALL middleware for /mcp")
    
    # Log server started event
    if unified_logger:
        asyncio.create_task(unified_logger.event(
            "mcp_server_started",
            {"tools_count": tool_count, "status": "mounted"}
        ))
    
    # Add shutdown handler
    @app.on_event("shutdown")
    async def shutdown_mcp():
        """Cleanup MCP server on shutdown."""
        logger.info("[MCP MOUNT] Shutting down MCP server")
        if unified_logger:
            await unified_logger.event("mcp_server_stopped", {})
    
    logger.info("[MCP MOUNT] MCP mounting complete")
    
    # Return the wrapper to be served instead of the app
    return wrapper