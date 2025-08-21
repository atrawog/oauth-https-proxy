"""Direct MCP integration without path redirects.

This module provides MCP at exactly /mcp (no trailing slash) by directly
integrating the MCP server into FastAPI without mounting issues.
"""

import asyncio
import json
import logging
import uuid
from datetime import datetime
from typing import Optional

from fastapi import APIRouter, Request, Response, HTTPException
from fastapi.responses import StreamingResponse, JSONResponse
from starlette.background import BackgroundTask

from ....storage.async_redis_storage import AsyncRedisStorage
from ....shared.unified_logger import UnifiedAsyncLogger
from .mcp_server import IntegratedMCPServer

logger = logging.getLogger(__name__)

# Global MCP state
_mcp_server = None
_mcp_app = None
_mcp_task = None
_initialization_lock = asyncio.Lock()


async def initialize_mcp(
    async_storage: AsyncRedisStorage,
    cert_manager,
    docker_manager,
    unified_logger: UnifiedAsyncLogger
):
    """Initialize MCP server components."""
    global _mcp_server, _mcp_app, _mcp_task
    
    async with _initialization_lock:
        if _mcp_app is not None:
            logger.info("[MCP INIT] Already initialized")
            return
        
        logger.info("[MCP INIT] Starting MCP server initialization")
        
        try:
            # Create integrated MCP server
            logger.info("[MCP INIT] Creating IntegratedMCPServer")
            _mcp_server = IntegratedMCPServer(
                async_storage,
                unified_logger,
                cert_manager,
                docker_manager
            )
            
            # Get FastMCP instance
            mcp = _mcp_server.get_server()
            tool_count = len(mcp._tool_manager._tools) if hasattr(mcp, '_tool_manager') else 0
            logger.info(f"[MCP INIT] Got FastMCP server with {tool_count} tools")
            
            # Get streamable HTTP app FIRST (this creates the session manager)
            _mcp_app = mcp.streamable_http_app()
            logger.info("[MCP INIT] Got streamable HTTP app")
            
            # Now initialize the task group for the session manager
            # The session manager is created by streamable_http_app()
            
            async def init_mcp_task_group():
                """Initialize MCP task group without starting a server."""
                try:
                    import anyio
                    from contextlib import AsyncExitStack
                    
                    # Create an async exit stack to manage the task group lifecycle
                    exit_stack = AsyncExitStack()
                    
                    # Create and enter the task group context
                    tg = await exit_stack.enter_async_context(anyio.create_task_group())
                    
                    # Now the session manager should exist after calling streamable_http_app()
                    if hasattr(mcp, 'session_manager'):
                        # Set the task group on the session manager
                        mcp.session_manager._task_group = tg
                        mcp.session_manager._exit_stack = exit_stack
                        logger.info("[MCP INIT] Task group initialized and attached to session manager")
                    else:
                        logger.warning("[MCP INIT] Session manager not found on MCP instance")
                    
                    # Keep the task group alive
                    await asyncio.Event().wait()
                    
                except asyncio.CancelledError:
                    logger.info("[MCP INIT] Task group cancelled")
                    if hasattr(mcp, 'session_manager') and hasattr(mcp.session_manager, '_exit_stack'):
                        await mcp.session_manager._exit_stack.aclose()
                except Exception as e:
                    logger.error(f"[MCP INIT ERROR] Failed to initialize task group: {e}", exc_info=True)
            
            # Start the task group manager in background
            _mcp_task = asyncio.create_task(init_mcp_task_group())
            logger.info("[MCP INIT] Started task group manager")
            
            # Wait for initialization
            await asyncio.sleep(0.2)
            
            # Log to Redis
            tools_count = len(mcp._tool_manager._tools) if hasattr(mcp, '_tool_manager') else 0
            await unified_logger.event(
                "mcp_server_initialized",
                {"tools_count": tools_count}
            )
            
            logger.info("[MCP INIT] MCP server initialization complete")
            
        except Exception as e:
            logger.error(f"[MCP INIT ERROR] Failed to initialize: {e}", exc_info=True)
            _mcp_server = None
            _mcp_app = None
            _mcp_task = None
            raise


def create_mcp_router(
    async_storage: AsyncRedisStorage,
    cert_manager=None,
    docker_manager=None,
    unified_logger: Optional[UnifiedAsyncLogger] = None
) -> APIRouter:
    """Create MCP router with direct integration (no mounting redirects).
    
    This provides MCP at exactly /mcp without any trailing slash redirects.
    """
    
    if not unified_logger:
        raise RuntimeError("Unified logger is required for MCP server")
    
    logger.info("[MCP ROUTER] Creating MCP router with direct integration")
    
    router = APIRouter(tags=["mcp"])
    
    # Store init params for lazy initialization
    init_params = {
        'async_storage': async_storage,
        'cert_manager': cert_manager,
        'docker_manager': docker_manager,
        'unified_logger': unified_logger
    }
    
    @router.on_event("startup")
    async def startup_event():
        """Initialize MCP on startup."""
        logger.info("[MCP STARTUP] Router startup event triggered")
        try:
            await initialize_mcp(**init_params)
        except Exception as e:
            logger.error(f"[MCP STARTUP ERROR] {e}")
    
    @router.on_event("shutdown")
    async def shutdown_event():
        """Cleanup MCP on shutdown."""
        global _mcp_task
        logger.info("[MCP SHUTDOWN] Router shutdown event triggered")
        if _mcp_task:
            _mcp_task.cancel()
            try:
                await _mcp_task
            except asyncio.CancelledError:
                pass
    
    # Main MCP handler - handles both GET and POST at exactly /mcp
    @router.api_route("", methods=["GET", "POST"])
    async def mcp_handler(request: Request) -> Response:
        """Handle MCP requests at /mcp (no trailing slash).
        
        GET: Opens SSE stream for server-to-client communication
        POST: Handles JSON-RPC messages
        """
        global _mcp_app
        
        # Log request details
        start_time = datetime.utcnow()
        request_id = f"mcp-req-{start_time.timestamp()}"
        
        logger.info(f"[MCP REQUEST] {request_id} - {request.method} /mcp")
        logger.info(f"  Headers: {dict(request.headers)}")
        logger.info(f"  Client: {request.client}")
        
        # Ensure MCP is initialized
        if _mcp_app is None:
            logger.warning("[MCP REQUEST] MCP not initialized, attempting initialization")
            try:
                await initialize_mcp(**init_params)
            except Exception as e:
                logger.error(f"[MCP REQUEST] Failed to initialize: {e}")
                return JSONResponse(
                    content={"error": "MCP service not available"},
                    status_code=503,
                    headers={
                        "Access-Control-Allow-Origin": "*",
                        "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS, PATCH"
                    }
                )
        
        if _mcp_app is None:
            logger.error("[MCP REQUEST] MCP still not available after init attempt")
            return JSONResponse(
                content={"error": "MCP service initialization failed"},
                status_code=503,
                headers={
                    "Access-Control-Allow-Origin": "*",
                    "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS, PATCH"
                }
            )
        
        # Log request body for POST
        body_bytes = b''
        if request.method == "POST":
            body_bytes = await request.body()
            logger.info(f"[MCP REQUEST BODY] {request_id} - {len(body_bytes)} bytes")
            if body_bytes:
                try:
                    json_body = json.loads(body_bytes)
                    method = json_body.get("method", "unknown")
                    req_id = json_body.get("id")
                    logger.info(f"[MCP JSON-RPC] {request_id} - Method: {method}, ID: {req_id}")
                except Exception as e:
                    logger.warning(f"[MCP JSON PARSE] {request_id} - Failed: {e}")
        
        # Log Origin header for monitoring (SDK may handle validation)
        origin = request.headers.get("origin", "")
        if origin:
            logger.info(f"[MCP ORIGIN] {request_id} - Origin: {origin}")
        
        # The SDK handles protocol version validation internally
        protocol_version = request.headers.get("mcp-protocol-version", "")
        if protocol_version:
            logger.info(f"[MCP VERSION] {request_id} - Protocol version: {protocol_version}")
        
        # Check for SSE request
        accept = request.headers.get("accept", "")
        is_sse = "text/event-stream" in accept
        
        # Check Last-Event-ID for SSE resumption (SDK may use this)
        last_event_id = request.headers.get("last-event-id")
        if last_event_id:
            logger.info(f"[MCP RESUME] {request_id} - Last-Event-ID: {last_event_id}")
        
        if is_sse:
            logger.info(f"[MCP SSE] {request_id} - Client requesting SSE stream")
        
        # Create ASGI scope for the MCP app
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
        
        # Create receive callable
        async def receive():
            return {
                'type': 'http.request',
                'body': body_bytes,
                'more_body': False
            }
        
        # For SSE streams, use streaming response
        if is_sse:
            logger.info(f"[MCP SSE STREAM] {request_id} - Setting up SSE stream")
            
            async def sse_generator():
                """Generate SSE events from MCP."""
                import asyncio
                
                # Create a queue to pass data from send callback to generator
                data_queue = asyncio.Queue()
                response_started = False
                stream_complete = False
                
                async def send(message):
                    nonlocal response_started, stream_complete
                    
                    if message['type'] == 'http.response.start':
                        response_started = True
                        # Headers are handled by StreamingResponse
                        
                    elif message['type'] == 'http.response.body':
                        body = message.get('body', b'')
                        if body:
                            logger.debug(f"[MCP SSE DATA] {request_id} - {len(body)} bytes")
                            await data_queue.put(body)
                        
                        # Check if more body is coming
                        if not message.get('more_body', True):
                            logger.info(f"[MCP SSE END] {request_id} - Stream complete")
                            stream_complete = True
                            await data_queue.put(None)  # Signal end of stream
                
                # Start MCP app in background
                app_task = asyncio.create_task(_mcp_app(scope, receive, send))
                
                # Yield data from queue
                try:
                    while True:
                        data = await data_queue.get()
                        if data is None:  # End of stream
                            break
                        yield data
                except Exception as e:
                    logger.error(f"[MCP SSE ERROR] {request_id} - {e}")
                finally:
                    # Ensure app task is completed
                    if not app_task.done():
                        app_task.cancel()
                        try:
                            await app_task
                        except asyncio.CancelledError:
                            pass
            
            # Generate session ID
            session_id = str(uuid.uuid4())
            
            # Build response headers - let SDK handle protocol headers
            response_headers = {
                "Cache-Control": "no-cache",
                "Connection": "keep-alive",
                "X-Accel-Buffering": "no",
                "Mcp-Session-Id": session_id,
                # CORS headers for browser-based clients like claude.ai
                "Access-Control-Allow-Origin": "*",
                "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS, PATCH",
                "Access-Control-Allow-Headers": "Content-Type, Accept, MCP-Protocol-Version, MCP-Session-ID, Last-Event-ID"
            }
            
            return StreamingResponse(
                sse_generator(),
                media_type="text/event-stream",
                headers=response_headers
            )
        
        # Regular JSON response
        else:
            logger.info(f"[MCP JSON] {request_id} - Handling JSON-RPC request")
            
            response_status = 200
            response_headers = []
            response_body = []
            
            async def send(message):
                nonlocal response_status, response_headers, response_body
                
                if message['type'] == 'http.response.start':
                    response_status = message.get('status', 200)
                    response_headers = message.get('headers', [])
                    logger.debug(f"[MCP RESPONSE START] {request_id} - Status: {response_status}")
                    
                elif message['type'] == 'http.response.body':
                    body = message.get('body', b'')
                    if body:
                        response_body.append(body)
                        logger.debug(f"[MCP RESPONSE BODY] {request_id} - {len(body)} bytes")
            
            # Call MCP app
            await _mcp_app(scope, receive, send)
            
            # Build response
            final_body = b''.join(response_body)
            
            # Convert headers
            headers_dict = {}
            for name, value in response_headers:
                name_str = name.decode('utf-8') if isinstance(name, bytes) else name
                value_str = value.decode('utf-8') if isinstance(value, bytes) else value
                headers_dict[name_str] = value_str
            
            # Add CORS headers for browser-based clients
            headers_dict["Access-Control-Allow-Origin"] = "*"
            headers_dict["Access-Control-Allow-Methods"] = "GET, POST, PUT, DELETE, OPTIONS, PATCH"
            headers_dict["Access-Control-Allow-Headers"] = "Content-Type, Accept, MCP-Protocol-Version, MCP-Session-ID, Last-Event-ID"
            
            duration = (datetime.utcnow() - start_time).total_seconds()
            logger.info(f"[MCP RESPONSE] {request_id} - Status: {response_status}, Size: {len(final_body)}, Duration: {duration:.3f}s")
            
            # Log to Redis
            await unified_logger.event(
                "mcp_request",
                {
                    "request_id": request_id,
                    "method": request.method,
                    "status": response_status,
                    "duration_ms": int(duration * 1000),
                    "is_sse": False
                }
            )
            
            return Response(
                content=final_body,
                status_code=response_status,
                headers=headers_dict,
                media_type=headers_dict.get('content-type', 'application/json')
            )
    
    # Handle OPTIONS requests for CORS preflight
    @router.options("")
    async def mcp_options():
        """Handle CORS preflight requests."""
        return Response(
            status_code=204,
            headers={
                "Access-Control-Allow-Origin": "*",
                "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS, PATCH",
                "Access-Control-Allow-Headers": "Content-Type, Accept, MCP-Protocol-Version, MCP-Session-ID, Last-Event-ID",
                "Access-Control-Max-Age": "86400"
            }
        )
    
    # Also handle trailing slash for compatibility (redirect to non-slash)
    @router.api_route("/", methods=["GET", "POST"])
    async def mcp_redirect():
        """Redirect /mcp/ to /mcp."""
        return Response(status_code=308, headers={"Location": "/mcp"})
    
    @router.get("/health")
    async def mcp_health():
        """MCP health check."""
        return {
            "status": "healthy" if _mcp_app else "not_initialized",
            "service": "mcp",
            "has_server": _mcp_server is not None,
            "has_app": _mcp_app is not None,
            "has_task": _mcp_task is not None and not _mcp_task.done()
        }
    
    logger.info("[MCP ROUTER] MCP router created successfully")
    return router