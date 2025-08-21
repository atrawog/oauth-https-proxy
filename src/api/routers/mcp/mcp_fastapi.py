"""MCP FastAPI integration - direct route handler without mounting issues.

This module provides a direct FastAPI route handler for MCP that avoids
the path stripping and redirect issues of mounted Starlette apps.
"""

import asyncio
import json
import logging
from typing import Optional

from fastapi import APIRouter, Request, Response, HTTPException
from fastapi.responses import StreamingResponse, JSONResponse
from starlette.background import BackgroundTask

from ....storage.async_redis_storage import AsyncRedisStorage
from ....shared.unified_logger import UnifiedAsyncLogger
from .mcp_server import IntegratedMCPServer

logger = logging.getLogger(__name__)

# Global MCP app instance and initialization task
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
    """Initialize the MCP server with proper task group.
    
    This function initializes the MCP server and starts its task group
    for proper streamable HTTP operation.
    """
    global _mcp_app, _mcp_task, _mcp_server_instance
    
    async with _initialization_lock:
        if _mcp_app is not None:
            logger.info("MCP server already initialized")
            return
        
        logger.info("Initializing MCP server with task group")
        
        try:
            # Create integrated MCP server
            _mcp_server_instance = IntegratedMCPServer(
                async_storage,
                unified_logger,
                cert_manager,
                docker_manager
            )
            logger.info("Created IntegratedMCPServer instance")
            
            # Get the FastMCP instance
            mcp = _mcp_server_instance.get_server()
            logger.info("Got FastMCP server instance")
            
            # Get the streamable HTTP app first
            _mcp_app = mcp.streamable_http_app()
            logger.info("Got MCP streamable HTTP app")
            
            # Start the MCP server task group in background
            # This is required for streamable HTTP to work properly
            # Note: run_streamable_http_async() runs forever, so we don't await it
            _mcp_task = asyncio.create_task(mcp.run_streamable_http_async())
            logger.info("Started MCP server task group in background")
            
            logger.info("MCP server initialization complete")
            
        except Exception as e:
            logger.error(f"Failed to initialize MCP server: {e}", exc_info=True)
            _mcp_app = None
            _mcp_task = None
            _mcp_server_instance = None
            raise


async def shutdown_mcp_server():
    """Shutdown the MCP server and clean up resources."""
    global _mcp_app, _mcp_task, _mcp_server_instance
    
    logger.info("Shutting down MCP server")
    
    if _mcp_task:
        _mcp_task.cancel()
        try:
            await _mcp_task
        except asyncio.CancelledError:
            pass
        _mcp_task = None
    
    _mcp_app = None
    _mcp_server_instance = None
    logger.info("MCP server shutdown complete")


def create_mcp_router(
    async_storage: AsyncRedisStorage,
    cert_manager=None,
    docker_manager=None,
    unified_logger: Optional[UnifiedAsyncLogger] = None
) -> APIRouter:
    """Create a FastAPI router for MCP protocol handling.
    
    This creates a proper FastAPI router that handles MCP protocol
    without the mounting issues of Starlette sub-apps.
    
    Args:
        async_storage: Async Redis storage instance
        cert_manager: Optional certificate manager
        docker_manager: Optional Docker manager
        unified_logger: Unified logger instance
    
    Returns:
        FastAPI APIRouter configured for MCP protocol
    """
    if not unified_logger:
        logger.error("CRITICAL: Unified logger is required for MCP server")
        raise RuntimeError("Unified logger is required for MCP server")
    
    logger.info("Creating MCP FastAPI router")
    
    # Create the router
    router = APIRouter(tags=["mcp"])
    
    # Store initialization parameters for lazy initialization
    init_params = {
        'async_storage': async_storage,
        'cert_manager': cert_manager,
        'docker_manager': docker_manager,
        'unified_logger': unified_logger
    }
    
    @router.on_event("startup")
    async def startup_event():
        """Initialize MCP server on router startup."""
        logger.info("MCP router startup event triggered")
        try:
            await initialize_mcp_server(**init_params)
            logger.info("MCP server initialized successfully in startup event")
        except Exception as e:
            logger.error(f"Failed to initialize MCP server in startup: {e}", exc_info=True)
    
    @router.on_event("shutdown")
    async def shutdown_event():
        """Shutdown MCP server on router shutdown."""
        logger.info("MCP router shutdown event triggered")
        await shutdown_mcp_server()
    
    @router.get("")  # GET for SSE streaming
    @router.get("/")  # Also handle /mcp/ just in case
    @router.post("")  # POST for JSON-RPC messages
    @router.post("/")  # Also handle /mcp/ just in case
    async def handle_mcp_request(request: Request) -> Response:
        """Handle MCP protocol requests.
        
        This endpoint handles MCP (Model Context Protocol) requests using
        the streamable HTTP transport as specified in:
        https://modelcontextprotocol.io/specification/2025-06-18/basic/transports#streamable-http
        
        Supports:
        - GET: Opens an SSE stream for server-to-client communication
        - POST: Accepts JSON-RPC messages for client-to-server communication
        
        The endpoint can return either:
        - Regular JSON responses for simple requests
        - Server-Sent Events (SSE) for streaming responses
        """
        global _mcp_app
        
        logger.info(f"MCP endpoint received {request.method} request")
        
        # Ensure MCP is initialized
        if _mcp_app is None:
            logger.warning("MCP app not initialized, attempting initialization")
            try:
                await initialize_mcp_server(**init_params)
            except Exception as e:
                logger.error(f"Failed to initialize MCP on demand: {e}")
                return JSONResponse(
                    content={
                        "jsonrpc": "2.0",
                        "error": {
                            "code": -32603,
                            "message": "MCP service not available",
                            "data": str(e)
                        }
                    },
                    status_code=503
                )
        
        if _mcp_app is None:
            logger.error("MCP app still not available after initialization attempt")
            return JSONResponse(
                content={
                    "jsonrpc": "2.0",
                    "error": {
                        "code": -32603,
                        "message": "MCP service initialization failed"
                    }
                },
                status_code=503
            )
        
        try:
            # Read the request body
            body = await request.body()
            logger.debug(f"MCP request body size: {len(body)} bytes")
            
            # Validate JSON if body exists
            if body:
                try:
                    json_body = json.loads(body)
                    method = json_body.get('method', 'unknown')
                    request_id = json_body.get('id')
                    logger.info(f"MCP request: method={method}, id={request_id}")
                except json.JSONDecodeError as e:
                    logger.error(f"Invalid JSON in MCP request: {e}")
                    return JSONResponse(
                        content={
                            "jsonrpc": "2.0",
                            "error": {
                                "code": -32700,
                                "message": "Parse error",
                                "data": str(e)
                            }
                        },
                        status_code=400
                    )
            
            # Create ASGI scope for the MCP app
            # The MCP app expects the path to be /mcp
            scope = {
                'type': 'http',
                'asgi': {'version': '3.0'},
                'http_version': '1.1',
                'method': request.method,
                'path': '/mcp',  # MCP app expects this exact path
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
            
            # Prepare receive callable
            async def receive():
                return {
                    'type': 'http.request',
                    'body': body,
                    'more_body': False
                }
            
            # Capture response
            response_started = False
            response_status = 200
            response_headers = []
            response_body = []
            
            async def send(message):
                nonlocal response_started, response_status, response_headers, response_body
                
                logger.debug(f"MCP send called with message type: {message.get('type')}")
                
                if message['type'] == 'http.response.start':
                    response_started = True
                    response_status = message.get('status', 200)
                    response_headers = message.get('headers', [])
                    logger.debug(f"MCP response starting: status={response_status}, headers={response_headers}")
                    
                elif message['type'] == 'http.response.body':
                    body_chunk = message.get('body', b'')
                    logger.debug(f"MCP response body: {len(body_chunk) if body_chunk else 0} bytes")
                    if body_chunk:
                        response_body.append(body_chunk)
                        logger.debug(f"Body content preview: {body_chunk[:100] if len(body_chunk) > 0 else 'empty'}")
            
            # Special handling for SSE streams
            is_sse = False
            
            # Call the MCP app
            logger.debug("Calling MCP app with prepared ASGI scope")
            logger.debug(f"MCP app object: {_mcp_app}")
            logger.debug(f"Scope type: {scope['type']}, method: {scope['method']}, path: {scope['path']}")
            
            try:
                logger.debug("About to call MCP app...")
                
                # For SSE streams, we need to handle them differently
                # Check if this might be an SSE request based on the Accept header
                accept_header = request.headers.get("accept", "")
                if "text/event-stream" in accept_header:
                    logger.debug("Request accepts SSE, preparing for streaming response")
                    
                    # Create an async generator for SSE streaming
                    async def sse_generator():
                        """Generate SSE events from the MCP app."""
                        sse_body = []
                        sse_complete = False
                        
                        async def sse_send(message):
                            nonlocal is_sse, sse_complete
                            
                            if message['type'] == 'http.response.start':
                                headers = dict(message.get('headers', []))
                                content_type = headers.get(b'content-type', b'').decode('utf-8')
                                if 'text/event-stream' in content_type:
                                    is_sse = True
                                    logger.debug("SSE stream detected, starting streaming")
                                    
                            elif message['type'] == 'http.response.body':
                                body_chunk = message.get('body', b'')
                                if body_chunk and is_sse:
                                    logger.debug(f"SSE chunk: {len(body_chunk)} bytes")
                                    sse_body.append(body_chunk)
                                if not message.get('more_body', True):
                                    sse_complete = True
                        
                        # Start the MCP app in background
                        import asyncio
                        task = asyncio.create_task(_mcp_app(scope, receive, sse_send))
                        
                        # Wait a moment for headers to be sent
                        await asyncio.sleep(0.1)
                        
                        # If it's an SSE stream, yield chunks as they come
                        if is_sse:
                            while not sse_complete:
                                if sse_body:
                                    chunk = sse_body.pop(0)
                                    yield chunk
                                else:
                                    await asyncio.sleep(0.01)
                            
                            # Yield any remaining chunks
                            for chunk in sse_body:
                                yield chunk
                        
                        # Wait for task to complete
                        try:
                            await task
                        except Exception as e:
                            logger.error(f"SSE task error: {e}")
                    
                    # Try SSE streaming first
                    return StreamingResponse(
                        sse_generator(),
                        media_type="text/event-stream",
                        headers={
                            "Cache-Control": "no-cache",
                            "Connection": "keep-alive",
                            "X-Accel-Buffering": "no"
                        }
                    )
                
                # Regular non-SSE handling
                result = await _mcp_app(scope, receive, send)
                logger.debug(f"MCP app returned: {result}")
                logger.info("MCP app processing completed successfully")
                
            except Exception as e:
                logger.error(f"ERROR in MCP app processing: {e}", exc_info=True)
                return JSONResponse(
                    content={
                        "jsonrpc": "2.0",
                        "error": {
                            "code": -32603,
                            "message": "Internal error",
                            "data": str(e)
                        }
                    },
                    status_code=500
                )
            
            # Build the response
            logger.debug(f"Building response - started: {response_started}, status: {response_status}, body chunks: {len(response_body)}")
            
            if not response_started:
                logger.error("MCP app did not send any response!")
                return JSONResponse(
                    content={
                        "jsonrpc": "2.0",
                        "error": {
                            "code": -32603,
                            "message": "MCP server did not respond"
                        }
                    },
                    status_code=500
                )
            
            final_body = b''.join(response_body)
            logger.debug(f"Final body size: {len(final_body)}")
            
            # Convert headers to dict
            headers_dict = {}
            for header_name, header_value in response_headers:
                name = header_name.decode('utf-8') if isinstance(header_name, bytes) else header_name
                value = header_value.decode('utf-8') if isinstance(header_value, bytes) else header_value
                headers_dict[name] = value
            
            # Determine content type
            content_type = headers_dict.get('content-type', 'application/json')
            
            logger.info(f"MCP response: status={response_status}, size={len(final_body)}, type={content_type}")
            
            # Check if this is an SSE response for streaming
            if 'text/event-stream' in content_type:
                logger.info("Returning SSE streaming response for MCP")
                
                async def generate():
                    """Generate SSE events."""
                    yield final_body
                
                return StreamingResponse(
                    generate(),
                    media_type="text/event-stream",
                    headers={
                        "Cache-Control": "no-cache",
                        "Connection": "keep-alive",
                        "X-Accel-Buffering": "no"  # Disable nginx buffering
                    }
                )
            
            # Regular JSON response
            return Response(
                content=final_body,
                status_code=response_status,
                headers=headers_dict,
                media_type=content_type
            )
            
        except Exception as e:
            logger.error(f"UNHANDLED ERROR in MCP handler: {e}", exc_info=True)
            return JSONResponse(
                content={
                    "jsonrpc": "2.0",
                    "error": {
                        "code": -32603,
                        "message": "Internal server error",
                        "data": str(e)
                    }
                },
                status_code=500
            )
    
    @router.get("/health")
    async def mcp_health():
        """Health check endpoint for MCP service."""
        return {
            "status": "healthy" if _mcp_app else "not_initialized",
            "service": "mcp",
            "protocol": "streamable-http",
            "tools_available": _mcp_app is not None
        }
    
    logger.info("MCP FastAPI router created successfully with lifecycle management")
    return router