"""MCP server integration wrapper for proper Starlette mounting.

This module creates a wrapper Starlette app that properly handles
the MCP server initialization and routing.
"""

import asyncio
import json
import logging
from typing import Optional

from starlette.applications import Starlette
from starlette.responses import JSONResponse, Response
from starlette.requests import Request
from starlette.routing import Route

from ....storage.async_redis_storage import AsyncRedisStorage
from ....shared.unified_logger import UnifiedAsyncLogger
from .mcp_server import IntegratedMCPServer

logger = logging.getLogger(__name__)


def create_mcp_app(
    async_storage: AsyncRedisStorage,
    cert_manager=None,
    docker_manager=None,
    unified_logger: Optional[UnifiedAsyncLogger] = None
) -> Starlette:
    """Create the MCP Starlette app with full system integration.

    Args:
        async_storage: Async Redis storage instance
        cert_manager: Optional certificate manager
        docker_manager: Optional Docker manager
        unified_logger: Unified logger instance

    Returns:
        Configured Starlette app for MCP protocol
    """
    # Ensure we have a unified logger
    if not unified_logger:
        logger.error("Unified logger is required for MCP server but was not provided")
        raise RuntimeError("Unified logger is required for MCP server")
    
    logger.info("Creating MCP server with proper unified logger")

    # Create integrated MCP server
    try:
        mcp_server = IntegratedMCPServer(
            async_storage,
            unified_logger,
            cert_manager,
            docker_manager
        )
        logger.info("Successfully created IntegratedMCPServer instance")
    except Exception as e:
        logger.error(f"Failed to create IntegratedMCPServer: {e}", exc_info=True)
        raise

    # Get the FastMCP instance
    try:
        mcp = mcp_server.get_server()
        logger.info("Successfully obtained FastMCP server instance")
    except Exception as e:
        logger.error(f"Failed to get FastMCP server: {e}", exc_info=True)
        raise
    
    # The FastMCP streamable_http_app needs proper initialization
    # We'll get the app immediately and handle initialization in startup
    
    # Get the MCP app
    try:
        mcp_app = mcp.streamable_http_app()
        logger.info("Successfully created MCP streamable HTTP app")
    except Exception as e:
        logger.error(f"Failed to create streamable HTTP app: {e}", exc_info=True)
        raise
    
    async def startup():
        """Initialize the MCP server on startup."""
        logger.info("MCP wrapper app startup initiated")
        # The streamable HTTP app initialization happens automatically
        # when the first request is received
    
    async def shutdown():
        """Clean up the MCP server on shutdown."""
        logger.info("MCP wrapper app shutdown initiated")
    
    async def mcp_handler(request: Request) -> Response:
        """Handle MCP requests by forwarding to the MCP app."""
        logger.debug(f"MCP handler received request: {request.method} {request.url.path}")
        
        try:
            # Read the request body
            body = await request.body()
            
            if body:
                try:
                    # Parse to verify it's valid JSON
                    json_body = json.loads(body)
                    logger.debug(f"MCP request body: method={json_body.get('method')}, id={json_body.get('id')}")
                except json.JSONDecodeError as e:
                    logger.error(f"Invalid JSON in MCP request: {e}")
                    return JSONResponse(
                        {"jsonrpc": "2.0", "error": {"code": -32700, "message": "Parse error"}},
                        status_code=400
                    )
            
            # The MCP app expects the path to be /mcp
            scope = request.scope.copy()
            
            # Ensure the path is /mcp for the MCP app
            original_path = scope.get('path', '/')
            if original_path in ['/', '', '/mcp/', '/mcp']:
                scope['path'] = '/mcp'
            
            logger.debug(f"Forwarding to MCP app with path: {scope['path']}")
            
            # Store the response data
            response_data = []
            response_status = 200
            response_headers = []
            
            async def receive():
                """Return the request body."""
                return {
                    'type': 'http.request',
                    'body': body,
                    'more_body': False
                }
            
            async def send(message):
                """Capture the response."""
                nonlocal response_status, response_headers, response_data
                if message['type'] == 'http.response.start':
                    response_status = message.get('status', 200)
                    response_headers = message.get('headers', [])
                    logger.debug(f"MCP response started with status: {response_status}")
                elif message['type'] == 'http.response.body':
                    body_chunk = message.get('body', b'')
                    if body_chunk:
                        response_data.append(body_chunk)
                        logger.debug(f"MCP response body chunk: {len(body_chunk)} bytes")
            
            # Call the MCP app
            try:
                await mcp_app(scope, receive, send)
                logger.debug("MCP app processing completed")
            except Exception as e:
                logger.error(f"Error in MCP app processing: {e}", exc_info=True)
                return JSONResponse(
                    {"jsonrpc": "2.0", "error": {"code": -32603, "message": "Internal error", "data": str(e)}},
                    status_code=500
                )
            
            # Build the response
            response_body = b''.join(response_data)
            
            # Convert headers list to dict
            headers_dict = {}
            for header_name, header_value in response_headers:
                headers_dict[header_name.decode('utf-8')] = header_value.decode('utf-8')
            
            logger.debug(f"MCP response: status={response_status}, body_size={len(response_body)}")
            
            return Response(
                content=response_body,
                status_code=response_status,
                headers=headers_dict,
                media_type=headers_dict.get('content-type', 'application/json')
            )
            
        except Exception as e:
            logger.error(f"Unhandled error in MCP handler: {e}", exc_info=True)
            return JSONResponse(
                {"jsonrpc": "2.0", "error": {"code": -32603, "message": "Internal error", "data": str(e)}},
                status_code=500
            )
    
    # Create wrapper Starlette app with proper routing
    # Handle both with and without trailing slash to prevent redirects
    routes = [
        Route("/", mcp_handler, methods=["POST"]),       # Root handler for mounted app
        Route("/mcp", mcp_handler, methods=["POST"]),    # Direct /mcp path
        Route("/mcp/", mcp_handler, methods=["POST"]),   # With trailing slash
    ]
    
    wrapper_app = Starlette(
        routes=routes,
        on_startup=[startup],
        on_shutdown=[shutdown],
        debug=False  # Don't enable debug mode which might cause redirects
    )
    
    logger.info("Successfully created MCP wrapper app with lifecycle management and comprehensive logging")
    
    return wrapper_app