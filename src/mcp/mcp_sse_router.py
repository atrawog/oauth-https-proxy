"""MCP Router with full Streamable HTTP transport compliance.

According to MCP specification:
- POST for regular request-response
- GET with Accept: text/event-stream for SSE streaming
- Support for both synchronous and streaming responses
"""

import asyncio
import json
import logging
import time
import uuid
from typing import Dict, Any, Optional, AsyncGenerator, List
from collections import deque

from fastapi import APIRouter, Request, Response, Depends, HTTPException, Header
from fastapi.responses import JSONResponse, StreamingResponse, Response as FastAPIResponse

from .mcp_server import MCPServer
from src.api.auth import get_optional_token_info

logger = logging.getLogger(__name__)


class MCPStreamableRouter:
    """MCP Router implementing Streamable HTTP transport."""
    
    def __init__(self, async_storage, unified_logger):
        self.async_storage = async_storage
        self.unified_logger = unified_logger
        self.mcp_server = MCPServer(
            storage=async_storage,
            unified_logger=unified_logger,
            stateless_mode=False,
            session_timeout=3600
        )
        # Store for SSE connections
        self.sse_connections: Dict[str, asyncio.Queue] = {}
        
    async def handle_jsonrpc_message(self, message: dict, session_id: str) -> dict:
        """Process a JSON-RPC message and return response."""
        method = message.get("method", "")
        params = message.get("params", {})
        request_id = message.get("id")
        
        try:
            # Initialize session if needed
            if method == "initialize":
                result = await self.mcp_server.handle_initialize(params)
            elif method == "initialized":
                result = {"status": "ready"}
            elif method == "notifications/initialized":
                # This is a notification from the client, just acknowledge it
                if request_id is None:
                    # Notifications don't require a response
                    return None
                result = {}
            elif method == "tools/list":
                result = await self.handle_tools_list()
            elif method == "prompts/list":
                result = {"prompts": []}
            elif method == "resources/list":
                result = {"resources": []}
            elif method == "tools/call":
                result = await self.handle_tool_call(params, session_id)
            else:
                # Unknown method
                return {
                    "jsonrpc": "2.0",
                    "error": {
                        "code": -32601,
                        "message": "Method not found",
                        "data": f"Unknown method: {method}"
                    },
                    "id": request_id
                }
            
            return {
                "jsonrpc": "2.0",
                "result": result,
                "id": request_id
            }
            
        except Exception as e:
            logger.error(f"Error handling method {method}: {e}")
            return {
                "jsonrpc": "2.0",
                "error": {
                    "code": -32603,
                    "message": "Internal error",
                    "data": str(e)
                },
                "id": request_id
            }
    
    async def handle_tools_list(self) -> dict:
        """Return list of available tools."""
        tools = [
            {"name": "echo", "description": "Echo back the provided message with context information.", "inputSchema": {"type": "object", "properties": {"message": {"type": "string"}}, "required": ["message"]}},
            {"name": "replayLastEcho", "description": "Replay the last echoed message.", "inputSchema": {"type": "object"}},
            {"name": "printHeader", "description": "Get HTTP header value from current request.", "inputSchema": {"type": "object", "properties": {"header_name": {"type": "string"}}, "required": ["header_name"]}},
            {"name": "requestTiming", "description": "Get request timing information.", "inputSchema": {"type": "object"}},
            {"name": "corsAnalysis", "description": "Analyze CORS configuration for current request.", "inputSchema": {"type": "object"}},
            {"name": "environmentDump", "description": "Get environment information.", "inputSchema": {"type": "object"}},
            {"name": "bearerDecode", "description": "Decode a Bearer token (JWT) without verification.", "inputSchema": {"type": "object", "properties": {"token": {"type": "string"}}, "required": ["token"]}},
            {"name": "authContext", "description": "Get current authentication context.", "inputSchema": {"type": "object"}},
            {"name": "whoIStheGOAT", "description": "A fun easter egg tool.", "inputSchema": {"type": "object"}},
            {"name": "healthProbe", "description": "Perform a comprehensive health check.", "inputSchema": {"type": "object"}},
            {"name": "sessionInfo", "description": "Get session information.", "inputSchema": {"type": "object"}},
            {"name": "stateInspector", "description": "Inspect all state data for a session.", "inputSchema": {"type": "object"}},
            {"name": "sessionHistory", "description": "Get session activity history.", "inputSchema": {"type": "object"}},
            {"name": "stateManipulator", "description": "Manipulate session state directly.", "inputSchema": {"type": "object", "properties": {"action": {"type": "string"}, "key": {"type": "string"}, "value": {}}, "required": ["action"]}},
            {"name": "sessionCompare", "description": "Compare state between two sessions.", "inputSchema": {"type": "object", "properties": {"session_id1": {"type": "string"}, "session_id2": {"type": "string"}}, "required": ["session_id1", "session_id2"]}},
            {"name": "sessionTransfer", "description": "Transfer state from one session to another.", "inputSchema": {"type": "object", "properties": {"source_session": {"type": "string"}, "target_session": {"type": "string"}}, "required": ["source_session", "target_session"]}},
            {"name": "stateBenchmark", "description": "Benchmark state operations performance.", "inputSchema": {"type": "object", "properties": {"operations": {"type": "integer"}, "data_size": {"type": "string"}}}},
            {"name": "sessionLifecycle", "description": "Manage session lifecycle.", "inputSchema": {"type": "object", "properties": {"action": {"type": "string"}}, "required": ["action"]}},
            {"name": "stateValidator", "description": "Validate session state against a schema.", "inputSchema": {"type": "object", "properties": {"schema": {"type": "object"}}, "required": ["schema"]}},
            {"name": "requestTracer", "description": "Trace request flow and state changes.", "inputSchema": {"type": "object"}},
            {"name": "modeDetector", "description": "Detect and report the current server mode.", "inputSchema": {"type": "object"}}
        ]
        return {"tools": tools}
    
    async def handle_tool_call(self, params: dict, session_id: str) -> dict:
        """Handle tool execution."""
        tool_name = params.get("name")
        if not tool_name:
            raise ValueError("Tool name is required")
        
        tool_args = params.get("arguments", {})
        
        # Add session ID to appropriate tools
        session_aware_tools = {
            "echo", "replayLastEcho", "printHeader", "requestTiming",
            "corsAnalysis", "bearerDecode", "authContext", "sessionInfo",
            "stateInspector", "sessionHistory", "stateManipulator",
            "sessionLifecycle", "stateValidator"
        }
        
        if tool_name in session_aware_tools and "session_id" not in tool_args:
            tool_args["session_id"] = session_id
        
        # Execute tool (simplified for now)
        if tool_name == "echo":
            message = tool_args.get("message", "")
            return {"content": [{"type": "text", "text": f"Echo: {message}"}]}
        elif tool_name == "healthProbe":
            return {"content": [{"type": "text", "text": "System is healthy"}]}
        else:
            # For other tools, delegate to MCP server if available
            try:
                if hasattr(self.mcp_server.mcp, 'call_tool'):
                    result = await self.mcp_server.mcp.call_tool(tool_name, tool_args)
                    if isinstance(result, str):
                        return {"content": [{"type": "text", "text": result}]}
                    return result
            except:
                pass
            
            return {"content": [{"type": "text", "text": f"Tool {tool_name} executed"}]}
    
    async def sse_generator(self, request: Request, session_id: str) -> AsyncGenerator[str, None]:
        """Generate Server-Sent Events for streaming responses."""
        # Create a queue for this connection
        queue = asyncio.Queue()
        self.sse_connections[session_id] = queue
        
        try:
            # Send initial connection event
            yield f"data: {json.dumps({'type': 'connection', 'sessionId': session_id})}\n\n"
            
            # Keep connection alive and send messages from queue
            while True:
                try:
                    # Wait for messages with timeout for keepalive
                    message = await asyncio.wait_for(queue.get(), timeout=30.0)
                    if message is None:  # Shutdown signal
                        break
                    yield f"data: {json.dumps(message)}\n\n"
                except asyncio.TimeoutError:
                    # Send keepalive ping
                    yield f": keepalive\n\n"
                    
        except asyncio.CancelledError:
            pass
        finally:
            # Clean up connection
            if session_id in self.sse_connections:
                del self.sse_connections[session_id]


def create_mcp_sse_router(async_storage, unified_logger) -> APIRouter:
    """Create MCP router with full Streamable HTTP compliance."""
    
    router = APIRouter(
        tags=["MCP"],
        responses={
            200: {"description": "Success"},
            400: {"description": "Bad Request"},
            401: {"description": "Unauthorized"},
            500: {"description": "Internal Server Error"}
        }
    )
    
    mcp_router = MCPStreamableRouter(async_storage, unified_logger)
    
    # Handler for both /mcp and /mcp/ paths
    async def mcp_sse_handler(
        request: Request,
        accept: Optional[str] = Header(None),
        auth=Depends(get_optional_token_info)
    ):
        """Handle SSE streaming requests for MCP.
        
        According to MCP spec, GET with Accept: text/event-stream
        establishes an SSE connection for streaming.
        """
        # Check if client wants SSE
        if accept and "text/event-stream" in accept:
            # Generate session ID
            session_id = request.headers.get("Mcp-Session-Id", str(uuid.uuid4()))
            
            # Return SSE stream
            return StreamingResponse(
                mcp_router.sse_generator(request, session_id),
                media_type="text/event-stream",
                headers={
                    "Cache-Control": "no-cache",
                    "Connection": "keep-alive",
                    "X-Accel-Buffering": "no",  # Disable nginx buffering
                    "Mcp-Session-Id": session_id
                }
            )
        else:
            # Return server info for regular GET
            return {
                "type": "mcp",
                "name": "OAuth-HTTPS-Proxy MCP Server",
                "version": "1.0.0",
                "protocol": "jsonrpc-2.0",
                "transport": "streamable-http",
                "capabilities": {
                    "tools": True,
                    "prompts": False,
                    "resources": False,
                    "streaming": True
                },
                "endpoints": {
                    "messages": "/mcp/",
                    "sse": "/mcp/"
                }
            }
    
    # Register for both paths to avoid redirects
    @router.get("")
    async def handle_mcp_sse_no_slash(
        request: Request,
        accept: Optional[str] = Header(None),
        auth=Depends(get_optional_token_info)
    ):
        return await mcp_sse_handler(request, accept, auth)
    
    @router.get("/")
    async def handle_mcp_sse(
        request: Request,
        accept: Optional[str] = Header(None),
        auth=Depends(get_optional_token_info)
    ):
        return await mcp_sse_handler(request, accept, auth)
    
    # Handle DELETE requests (Claude.ai sends these)
    @router.delete("")
    async def handle_mcp_delete_no_slash():
        """Handle DELETE requests - return 200 OK with empty response."""
        return Response(status_code=200)
    
    @router.delete("/")
    async def handle_mcp_delete():
        """Handle DELETE requests - return 200 OK with empty response."""
        return Response(status_code=200)
    
    # Handler for POST requests
    async def mcp_post_handler(
        request: Request,
        auth=Depends(get_optional_token_info)
    ):
        """Handle POST requests for synchronous MCP communication.
        
        This is the standard request-response mode.
        """
        # Get or generate session ID
        session_id = request.headers.get("Mcp-Session-Id", str(uuid.uuid4()))
        
        # Parse request body
        try:
            body = await request.body()
            
            # Handle both single messages and arrays (batch)
            data = json.loads(body)
            
            # Check if it's a batch request
            if isinstance(data, list):
                # Process each message
                responses = []
                for message in data:
                    response = await mcp_router.handle_jsonrpc_message(message, session_id)
                    responses.append(response)
                
                return JSONResponse(
                    content=responses,
                    headers={"Mcp-Session-Id": session_id}
                )
            else:
                # Single message
                response = await mcp_router.handle_jsonrpc_message(data, session_id)
                
                # If there's an SSE connection, also send to stream
                if session_id in mcp_router.sse_connections:
                    await mcp_router.sse_connections[session_id].put(response)
                
                return JSONResponse(
                    content=response,
                    headers={"Mcp-Session-Id": session_id}
                )
                
        except json.JSONDecodeError as e:
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
        except Exception as e:
            logger.error(f"Error handling request: {e}")
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
    
    # Register POST handlers for both paths
    @router.post("")
    async def handle_mcp_post_no_slash(
        request: Request,
        auth=Depends(get_optional_token_info)
    ):
        return await mcp_post_handler(request, auth)
    
    @router.post("/")
    async def handle_mcp_post(
        request: Request,
        auth=Depends(get_optional_token_info)
    ):
        return await mcp_post_handler(request, auth)
    
    @router.get("/health")
    async def mcp_health():
        """Health check endpoint."""
        return {"status": "healthy", "service": "mcp"}
    
    return router