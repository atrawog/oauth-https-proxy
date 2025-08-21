"""MCP Starlette app with comprehensive connection logging."""

import asyncio
import logging
from datetime import datetime
from typing import Optional

from starlette.applications import Starlette
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

from ....storage.async_redis_storage import AsyncRedisStorage
from ....shared.unified_logger import UnifiedAsyncLogger
from .mcp_server import IntegratedMCPServer

logger = logging.getLogger(__name__)


class MCPLoggingMiddleware(BaseHTTPMiddleware):
    """Middleware to log all MCP connection details."""
    
    def __init__(self, app, unified_logger: UnifiedAsyncLogger):
        super().__init__(app)
        self.unified_logger = unified_logger
    
    async def dispatch(self, request: Request, call_next):
        """Log complete MCP connection lifecycle."""
        start_time = datetime.utcnow()
        request_id = f"mcp-{start_time.timestamp()}"
        
        # Log incoming request
        logger.info(f"[MCP CONNECTION START] {request_id}")
        logger.info(f"  Method: {request.method}")
        logger.info(f"  Path: {request.url.path}")
        logger.info(f"  Headers: {dict(request.headers)}")
        logger.info(f"  Client: {request.client}")
        
        # Check if this is an SSE request
        accept = request.headers.get("accept", "")
        is_sse = "text/event-stream" in accept
        
        if is_sse:
            logger.info(f"[MCP SSE REQUEST] {request_id} - Client requesting Server-Sent Events stream")
        
        # Read body for POST requests
        if request.method == "POST":
            body = await request.body()
            logger.info(f"[MCP REQUEST BODY] {request_id} - Size: {len(body)} bytes")
            if body:
                try:
                    import json
                    json_body = json.loads(body)
                    method = json_body.get("method", "unknown")
                    req_id = json_body.get("id")
                    logger.info(f"[MCP JSON-RPC] {request_id} - Method: {method}, ID: {req_id}")
                    
                    # Log specific method details
                    if method == "initialize":
                        params = json_body.get("params", {})
                        protocol = params.get("protocolVersion")
                        client_info = params.get("clientInfo", {})
                        logger.info(f"[MCP INITIALIZE] {request_id} - Protocol: {protocol}, Client: {client_info}")
                    elif method == "tools/list":
                        logger.info(f"[MCP TOOLS LIST] {request_id} - Client requesting available tools")
                    elif method == "tools/call":
                        params = json_body.get("params", {})
                        tool_name = params.get("name", "unknown")
                        logger.info(f"[MCP TOOL CALL] {request_id} - Tool: {tool_name}")
                        
                except Exception as e:
                    logger.warning(f"[MCP PARSE ERROR] {request_id} - Could not parse JSON body: {e}")
        
        # Track response
        response = None
        error = None
        
        try:
            # Call the actual MCP app
            logger.info(f"[MCP PROCESSING] {request_id} - Forwarding to MCP server")
            response = await call_next(request)
            
            # Log response details
            duration = (datetime.utcnow() - start_time).total_seconds()
            logger.info(f"[MCP RESPONSE] {request_id} - Status: {response.status_code}, Duration: {duration:.3f}s")
            logger.info(f"[MCP RESPONSE HEADERS] {request_id} - {dict(response.headers)}")
            
            # Check if it's an SSE response
            content_type = response.headers.get("content-type", "")
            if "text/event-stream" in content_type:
                session_id = response.headers.get("mcp-session-id", "unknown")
                logger.info(f"[MCP SSE ESTABLISHED] {request_id} - Session: {session_id}")
                logger.info(f"[MCP SSE STREAM] {request_id} - SSE connection established, streaming events...")
                
                # Log to Redis for monitoring
                await self.unified_logger.event(
                    "mcp_sse_connection",
                    request_id=request_id,
                    session_id=session_id,
                    client=str(request.client),
                    duration_ms=int(duration * 1000)
                )
            else:
                # For non-SSE responses, try to log the body
                if hasattr(response, 'body'):
                    body_size = len(response.body) if response.body else 0
                    logger.info(f"[MCP RESPONSE BODY] {request_id} - Size: {body_size} bytes")
                    
                    if response.body and response.status_code != 200:
                        try:
                            import json
                            error_body = json.loads(response.body)
                            logger.warning(f"[MCP ERROR RESPONSE] {request_id} - {error_body}")
                        except:
                            pass
            
            return response
            
        except Exception as e:
            error = str(e)
            logger.error(f"[MCP ERROR] {request_id} - Error processing request: {e}", exc_info=True)
            
            # Log error to Redis
            await self.unified_logger.event(
                "mcp_error",
                request_id=request_id,
                error=error,
                method=request.method,
                path=request.url.path
            )
            
            raise
        
        finally:
            # Log connection end
            total_duration = (datetime.utcnow() - start_time).total_seconds()
            status = "success" if not error else "error"
            logger.info(f"[MCP CONNECTION END] {request_id} - Status: {status}, Total Duration: {total_duration:.3f}s")
            
            # Log summary to Redis
            await self.unified_logger.event(
                "mcp_request_complete",
                request_id=request_id,
                method=request.method,
                path=request.url.path,
                status=status,
                duration_ms=int(total_duration * 1000),
                is_sse=is_sse
            )


def create_mcp_app(
    async_storage: AsyncRedisStorage,
    cert_manager=None,
    docker_manager=None,
    unified_logger: Optional[UnifiedAsyncLogger] = None
) -> Starlette:
    """Create a Starlette app with the MCP server and comprehensive logging.
    
    This returns a Starlette app that can be mounted in FastAPI.
    """
    
    if not unified_logger:
        raise RuntimeError("Unified logger is required for MCP server")
    
    logger.info("[MCP INIT] Creating MCP Starlette application")
    
    # Create a wrapper Starlette app
    app = Starlette()
    
    # Store the MCP server instance
    mcp_server = None
    mcp_task = None
    mcp_app = None
    
    @app.on_event("startup")
    async def startup():
        """Initialize MCP server on startup."""
        nonlocal mcp_server, mcp_task, mcp_app
        
        logger.info("[MCP STARTUP] Initializing MCP server components")
        
        try:
            # Create integrated MCP server
            logger.info("[MCP STARTUP] Creating IntegratedMCPServer")
            mcp_server = IntegratedMCPServer(
                async_storage,
                unified_logger,
                cert_manager,
                docker_manager
            )
            
            # Get the FastMCP instance
            logger.info("[MCP STARTUP] Getting FastMCP server instance")
            mcp = mcp_server.get_server()
            
            # Get the streamable HTTP app
            logger.info("[MCP STARTUP] Getting streamable HTTP app")
            mcp_app = mcp.streamable_http_app()
            
            # Start the task group in background (required for streamable HTTP)
            logger.info("[MCP STARTUP] Starting MCP task group for streamable HTTP")
            mcp_task = asyncio.create_task(mcp.run_streamable_http_async())
            
            # Store the MCP app in the Starlette app state
            app.state.mcp_app = mcp_app
            app.state.mcp_task = mcp_task
            app.state.mcp_server = mcp_server
            
            logger.info("[MCP STARTUP] MCP server initialization complete")
            
            # Log to Redis
            await unified_logger.event(
                "mcp_server_started",
                status="ready",
                tools_count=len(mcp._tools) if hasattr(mcp, '_tools') else 0
            )
            
        except Exception as e:
            logger.error(f"[MCP STARTUP ERROR] Failed to initialize MCP server: {e}", exc_info=True)
            await unified_logger.event(
                "mcp_server_startup_failed",
                error=str(e)
            )
            raise
    
    @app.on_event("shutdown")
    async def shutdown():
        """Shutdown MCP server."""
        logger.info("[MCP SHUTDOWN] Shutting down MCP server")
        
        if app.state.mcp_task:
            app.state.mcp_task.cancel()
            try:
                await app.state.mcp_task
            except asyncio.CancelledError:
                pass
        
        await unified_logger.event("mcp_server_stopped")
        logger.info("[MCP SHUTDOWN] MCP server shutdown complete")
    
    # Add logging middleware
    app.add_middleware(MCPLoggingMiddleware, unified_logger=unified_logger)
    
    # Add catch-all route that proxies to the MCP app
    @app.route("/{path:path}", methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"])
    async def mcp_handler(request: Request):
        """Handle all MCP requests."""
        
        if not hasattr(app.state, 'mcp_app') or app.state.mcp_app is None:
            logger.error("[MCP HANDLER] MCP app not initialized")
            return Response(
                content='{"error": "MCP service not available"}',
                status_code=503,
                media_type="application/json"
            )
        
        # The MCP app handles the ASGI interface directly
        # We just need to pass the request through
        return app.state.mcp_app
    
    logger.info("[MCP INIT] MCP Starlette application created successfully")
    return app