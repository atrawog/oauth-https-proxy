"""MCP Starlette app mounting with proper task group initialization.

This module handles mounting the MCP SDK's Starlette app directly on FastAPI,
ensuring the task group is properly initialized for stateful operation.
"""

import asyncio
import logging
from typing import Optional

import anyio
from fastapi import FastAPI, Request, Response
from starlette.middleware.cors import CORSMiddleware

from ....storage.async_redis_storage import AsyncRedisStorage
from ....shared.unified_logger import UnifiedAsyncLogger
from .mcp_server import IntegratedMCPServer

logger = logging.getLogger(__name__)

# Global references for MCP components
_mcp_app = None
_mcp_session_manager = None
_mcp_task_group = None
_mcp_task = None


def mount_mcp_app(
    app: FastAPI,
    async_storage: AsyncRedisStorage,
    cert_manager=None,
    docker_manager=None,
    unified_logger: Optional[UnifiedAsyncLogger] = None
) -> None:
    """Mount MCP Starlette app directly with proper initialization.
    
    This mounts the SDK's Starlette app at /mcp and ensures the task group
    is properly initialized for stateful operation.
    """
    global _mcp_app, _mcp_session_manager, _mcp_task_group, _mcp_task
    
    if not unified_logger:
        raise RuntimeError("Unified logger is required for MCP server")
    
    logger.info("[MCP MOUNT] Creating MCP server and Starlette app")
    
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
    logger.info(f"[MCP MOUNT] Registered {tool_count} tools")
    
    # Get the streamable HTTP app from the SDK
    _mcp_app = mcp.streamable_http_app()
    
    # Store the session manager for task group initialization
    _mcp_session_manager = mcp._session_manager
    
    # Add CORS middleware
    _mcp_app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS", "PATCH"],
        allow_headers=["*"],
        allow_credentials=False,
        expose_headers=["Mcp-Session-Id", "Mcp-Protocol-Version"]
    )
    
    # Mount the MCP app at /mcp/ (with trailing slash)
    app.mount("/mcp/", _mcp_app)
    logger.info("[MCP MOUNT] Mounted MCP Starlette app at /mcp/")
    
    # Add specific handler for /mcp (without trailing slash) to avoid redirects
    @app.api_route("/mcp", methods=["GET", "POST", "PUT", "DELETE", "OPTIONS", "PATCH"])
    async def mcp_no_slash(request: Request) -> Response:
        """Handle /mcp requests without redirecting to /mcp/."""
        logger.info(f"[MCP HANDLER] Received {request.method} request to /mcp")
        
        # Simply forward to the mounted app with adjusted path
        # The mounted app at /mcp/ expects the request at the root path /
        from starlette.responses import StreamingResponse
        import asyncio
        
        # Build complete ASGI scope for the MCP app
        # The MCP app expects to receive requests at the root "/"
        scope = {
            'type': 'http',
            'asgi': {'version': '3.0'},
            'http_version': '1.1',
            'method': request.method,
            'path': '/',  # MCP app expects root path
            'root_path': '',
            'scheme': request.url.scheme,
            'query_string': request.url.query.encode() if request.url.query else b'',
            'headers': [(k.encode(), v.encode()) for k, v in request.headers.items()],
            'server': (request.client.host if request.client else '127.0.0.1',
                      request.client.port if request.client else 80),
            'client': (request.client.host if request.client else '127.0.0.1',
                      request.client.port if request.client else 0),
            'state': {}
        }
        
        # Get the request body
        body = await request.body()
        body_sent = False
        
        # Create receive callable
        async def receive():
            nonlocal body_sent
            if not body_sent:
                body_sent = True
                return {
                    'type': 'http.request',
                    'body': body,
                    'more_body': False
                }
            else:
                # This simulates waiting for more body that will never come
                await asyncio.Event().wait()
        
        # Queue for streaming response chunks
        response_queue = asyncio.Queue()
        response_started = False
        response_status = 200
        response_headers = {}
        
        async def send(message):
            nonlocal response_started, response_status, response_headers
            if message['type'] == 'http.response.start':
                response_started = True
                response_status = message.get('status', 200)
                # Convert headers to dict
                for name, value in message.get('headers', []):
                    name_str = name.decode('utf-8') if isinstance(name, bytes) else name
                    value_str = value.decode('utf-8') if isinstance(value, bytes) else value
                    response_headers[name_str] = value_str
            elif message['type'] == 'http.response.body':
                body_chunk = message.get('body', b'')
                more_body = message.get('more_body', False)
                await response_queue.put((body_chunk, more_body))
                if not more_body:
                    # Signal end of stream
                    await response_queue.put((None, False))
        
        # Run the MCP app in background
        task = asyncio.create_task(_mcp_app(scope, receive, send))
        
        # Create streaming response generator
        async def generate():
            try:
                while True:
                    chunk, more = await response_queue.get()
                    if chunk is None:
                        break
                    if chunk:
                        yield chunk
                    if not more:
                        break
            finally:
                # Cancel the task if not done
                if not task.done():
                    task.cancel()
                    try:
                        await task
                    except asyncio.CancelledError:
                        pass
        
        # Wait for response to start to get headers
        while not response_started:
            await asyncio.sleep(0.01)
        
        # Check if it's an SSE stream
        content_type = response_headers.get('content-type', '').lower()
        if 'text/event-stream' in content_type:
            # Use StreamingResponse for SSE
            return StreamingResponse(
                generate(),
                status_code=response_status,
                headers=response_headers,
                media_type='text/event-stream'
            )
        else:
            # For non-SSE responses, collect all chunks
            chunks = []
            async for chunk in generate():
                chunks.append(chunk)
            return Response(
                content=b''.join(chunks),
                status_code=response_status,
                headers=response_headers
            )
    
    logger.info("[MCP MOUNT] Added /mcp route handler (no trailing slash)")
    
    # Initialize task group immediately
    logger.info("[MCP MOUNT] Starting MCP task group initialization")
    
    async def run_mcp_session_manager():
        """Run the MCP session manager with its task group."""
        try:
            async with _mcp_session_manager.run():
                logger.info("[MCP MOUNT] MCP session manager started with task group")
                await unified_logger.event(
                    "mcp_server_started",
                    {"tools_count": tool_count, "status": "mounted"}
                )
                # Keep running until cancelled
                await asyncio.Event().wait()
        except asyncio.CancelledError:
            logger.info("[MCP MOUNT] MCP session manager cancelled")
            await unified_logger.event("mcp_server_stopped", {})
        except Exception as e:
            logger.error(f"[MCP MOUNT ERROR] Session manager failed: {e}")
    
    # Start the session manager in a background task immediately
    _mcp_task = asyncio.create_task(run_mcp_session_manager())
    logger.info("[MCP MOUNT] MCP session manager task created")
    
    # Add shutdown event to cleanup
    @app.on_event("shutdown")
    async def shutdown_mcp_task_group():
        """Cleanup MCP task group on application shutdown."""
        global _mcp_task
        
        logger.info("[MCP MOUNT] Shutting down MCP task group")
        if _mcp_task and not _mcp_task.done():
            _mcp_task.cancel()
            try:
                await _mcp_task
            except asyncio.CancelledError:
                pass
        logger.info("[MCP MOUNT] MCP task group shutdown complete")
    
    logger.info("[MCP MOUNT] MCP app mounting complete")