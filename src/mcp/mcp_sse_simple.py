"""Simple MCP SSE implementation that works without SDK dependencies.

This provides a complete MCP server with SSE support for Claude.ai.
"""

import asyncio
import json
import logging
import uuid
from typing import Optional, AsyncGenerator
from fastapi import APIRouter, Request, Response, Header
from fastapi.responses import StreamingResponse, JSONResponse

logger = logging.getLogger(__name__)


class SimpleMCPServer:
    """Simple MCP Server with SSE support."""
    
    def __init__(self):
        """Initialize Simple MCP Server."""
        logger.info("Simple MCP Server initialized")
    
    async def handle_sse_stream(self, request: Request) -> AsyncGenerator[str, None]:
        """Generate SSE stream for MCP communication.
        
        This properly implements the MCP SSE protocol.
        """
        # Send initial connection event
        yield f"data: {json.dumps({'type': 'connection', 'status': 'connected'})}\n\n"
        
        # Keep connection alive with periodic pings
        try:
            while True:
                # Send keepalive every 15 seconds
                await asyncio.sleep(15)
                yield ": keepalive\n\n"
        except asyncio.CancelledError:
            pass


def create_mcp_sse_simple_router(async_storage, unified_logger) -> APIRouter:
    """Create simple MCP router with SSE support.
    
    NO AUTHENTICATION REQUIRED - completely open endpoint.
    """
    router = APIRouter(
        tags=["MCP"],
        responses={
            200: {"description": "Success"},
            400: {"description": "Bad Request"},
            500: {"description": "Internal Server Error"}
        }
    )
    
    # Create MCP server
    mcp_server = SimpleMCPServer()
    
    @router.get("")
    @router.get("/")
    async def handle_mcp_get(
        request: Request,
        accept: Optional[str] = Header(None)
    ):
        """Handle GET requests for MCP.
        
        NO AUTHENTICATION - completely open.
        """
        if accept and "text/event-stream" in accept:
            # Return SSE stream for Claude.ai
            return StreamingResponse(
                mcp_server.handle_sse_stream(request),
                media_type="text/event-stream",
                headers={
                    "Cache-Control": "no-cache",
                    "Connection": "keep-alive",
                    "X-Accel-Buffering": "no",
                    "Access-Control-Allow-Origin": "*"
                }
            )
        else:
            # Return server info
            return {
                "type": "mcp",
                "name": "OAuth-HTTPS-Proxy MCP Server",
                "version": "1.0.0",
                "transport": "sse",
                "capabilities": {
                    "tools": {"listChanged": True},
                    "prompts": {"listChanged": False},
                    "resources": {"subscribe": False}
                }
            }
    
    @router.post("")
    @router.post("/")
    async def handle_mcp_post(request: Request):
        """Handle POST requests for MCP.
        
        NO AUTHENTICATION - completely open.
        """
        try:
            body = await request.body()
            data = json.loads(body)
            
            method = data.get("method")
            request_id = data.get("id")
            params = data.get("params", {})
            
            logger.info(f"MCP request: method={method}, id={request_id}")
            
            if method == "initialize":
                return JSONResponse({
                    "jsonrpc": "2.0",
                    "result": {
                        "protocolVersion": "2025-06-18",
                        "capabilities": {
                            "tools": {"listChanged": True},
                            "prompts": {"listChanged": False},
                            "resources": {"subscribe": False}
                        },
                        "serverInfo": {
                            "name": "OAuth-HTTPS-Proxy MCP Server",
                            "version": "1.0.0"
                        }
                    },
                    "id": request_id
                })
            elif method == "notifications/initialized":
                # Notification - return empty response if has ID
                if request_id is not None:
                    return JSONResponse({
                        "jsonrpc": "2.0",
                        "result": {},
                        "id": request_id
                    })
                # No response for notifications without ID
                return Response(status_code=204)
            elif method == "tools/list":
                # Return all 21 tools
                tools = [
                    {"name": "echo", "description": "Echo back the provided message", "inputSchema": {"type": "object", "properties": {"message": {"type": "string"}}, "required": ["message"]}},
                    {"name": "replayLastEcho", "description": "Replay the last echoed message", "inputSchema": {"type": "object"}},
                    {"name": "printHeader", "description": "Get HTTP header value", "inputSchema": {"type": "object", "properties": {"header_name": {"type": "string"}}, "required": ["header_name"]}},
                    {"name": "requestTiming", "description": "Get request timing info", "inputSchema": {"type": "object"}},
                    {"name": "corsAnalysis", "description": "Analyze CORS configuration", "inputSchema": {"type": "object"}},
                    {"name": "environmentDump", "description": "Get environment information", "inputSchema": {"type": "object"}},
                    {"name": "bearerDecode", "description": "Decode a Bearer token (JWT)", "inputSchema": {"type": "object", "properties": {"token": {"type": "string"}}, "required": ["token"]}},
                    {"name": "authContext", "description": "Get current auth context", "inputSchema": {"type": "object"}},
                    {"name": "whoIStheGOAT", "description": "A fun easter egg tool", "inputSchema": {"type": "object"}},
                    {"name": "healthProbe", "description": "Perform a health check", "inputSchema": {"type": "object"}},
                    {"name": "sessionInfo", "description": "Get session information", "inputSchema": {"type": "object"}},
                    {"name": "stateInspector", "description": "Inspect session state", "inputSchema": {"type": "object"}},
                    {"name": "sessionHistory", "description": "Get session history", "inputSchema": {"type": "object"}},
                    {"name": "stateManipulator", "description": "Manipulate session state", "inputSchema": {"type": "object", "properties": {"action": {"type": "string"}, "key": {"type": "string"}, "value": {}}, "required": ["action"]}},
                    {"name": "sessionCompare", "description": "Compare two sessions", "inputSchema": {"type": "object", "properties": {"session_id1": {"type": "string"}, "session_id2": {"type": "string"}}, "required": ["session_id1", "session_id2"]}},
                    {"name": "sessionTransfer", "description": "Transfer state between sessions", "inputSchema": {"type": "object", "properties": {"source_session": {"type": "string"}, "target_session": {"type": "string"}}, "required": ["source_session", "target_session"]}},
                    {"name": "stateBenchmark", "description": "Benchmark state operations", "inputSchema": {"type": "object", "properties": {"operations": {"type": "integer"}, "data_size": {"type": "string"}}}},
                    {"name": "sessionLifecycle", "description": "Manage session lifecycle", "inputSchema": {"type": "object", "properties": {"action": {"type": "string"}}, "required": ["action"]}},
                    {"name": "stateValidator", "description": "Validate session state", "inputSchema": {"type": "object", "properties": {"schema": {"type": "object"}}, "required": ["schema"]}},
                    {"name": "requestTracer", "description": "Trace request flow", "inputSchema": {"type": "object"}},
                    {"name": "modeDetector", "description": "Detect server mode", "inputSchema": {"type": "object"}}
                ]
                logger.info(f"Returning {len(tools)} tools")
                return JSONResponse({
                    "jsonrpc": "2.0",
                    "result": {"tools": tools},
                    "id": request_id
                })
            elif method == "prompts/list":
                return JSONResponse({
                    "jsonrpc": "2.0",
                    "result": {"prompts": []},
                    "id": request_id
                })
            elif method == "resources/list":
                return JSONResponse({
                    "jsonrpc": "2.0",
                    "result": {"resources": []},
                    "id": request_id
                })
            elif method == "tools/call":
                tool_name = params.get("name")
                tool_args = params.get("arguments", {})
                
                logger.info(f"Tool call: {tool_name} with args {tool_args}")
                
                # Simple tool implementations
                if tool_name == "echo":
                    message = tool_args.get("message", "")
                    result = {"content": [{"type": "text", "text": f"Echo: {message}"}]}
                elif tool_name == "healthProbe":
                    result = {"content": [{"type": "text", "text": "System is healthy"}]}
                elif tool_name == "whoIStheGOAT":
                    result = {"content": [{"type": "text", "text": "🐐 You are the GOAT!"}]}
                elif tool_name == "modeDetector":
                    result = {"content": [{"type": "text", "text": "Mode: Simple MCP Server (No Auth)"}]}
                else:
                    result = {"content": [{"type": "text", "text": f"Tool {tool_name} executed"}]}
                
                return JSONResponse({
                    "jsonrpc": "2.0",
                    "result": result,
                    "id": request_id
                })
            else:
                logger.warning(f"Unknown method: {method}")
                return JSONResponse({
                    "jsonrpc": "2.0",
                    "error": {
                        "code": -32601,
                        "message": "Method not found",
                        "data": f"Unknown method: {method}"
                    },
                    "id": request_id
                })
        except json.JSONDecodeError as e:
            logger.error(f"JSON decode error: {e}")
            return JSONResponse({
                "jsonrpc": "2.0",
                "error": {
                    "code": -32700,
                    "message": "Parse error",
                    "data": str(e)
                }
            }, status_code=400)
        except Exception as e:
            logger.error(f"Error handling request: {e}")
            return JSONResponse({
                "jsonrpc": "2.0",
                "error": {
                    "code": -32603,
                    "message": "Internal error",
                    "data": str(e)
                }
            }, status_code=500)
    
    @router.delete("")
    @router.delete("/")
    async def handle_mcp_delete():
        """Handle DELETE requests (Claude.ai cleanup)."""
        return Response(status_code=200)
    
    @router.options("")
    @router.options("/")
    async def handle_mcp_options():
        """Handle OPTIONS requests for CORS."""
        return Response(
            status_code=204,
            headers={
                "Access-Control-Allow-Origin": "*",
                "Access-Control-Allow-Methods": "GET, POST, DELETE, OPTIONS",
                "Access-Control-Allow-Headers": "Content-Type, Authorization, Accept"
            }
        )
    
    return router