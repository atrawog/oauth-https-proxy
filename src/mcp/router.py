"""FastAPI router for MCP endpoint with full MCP Streamable HTTP compliance."""

import asyncio
import json
import logging
import time
import uuid
from typing import Dict, Any, Optional, AsyncGenerator

from fastapi import APIRouter, Request, Response, Depends, HTTPException
from fastapi.responses import JSONResponse, StreamingResponse
from sse_starlette.sse import EventSourceResponse

from .mcp_server import MCPServer
from src.api.auth import get_optional_token_info

logger = logging.getLogger(__name__)


def create_mcp_router(async_storage, unified_logger):
    """Create MCP router for FastAPI integration.
    
    Args:
        async_storage: AsyncRedisStorage instance
        unified_logger: UnifiedAsyncLogger instance
        
    Returns:
        FastAPI APIRouter configured for MCP
    """
    
    router = APIRouter(
        tags=["MCP"],
        responses={
            200: {"description": "Success"},
            400: {"description": "Bad Request"},
            401: {"description": "Unauthorized"},
            500: {"description": "Internal Server Error"}
        }
    )
    
    # Initialize MCP server
    mcp_server = MCPServer(
        storage=async_storage,
        unified_logger=unified_logger,
        stateless_mode=False,  # Default to stateful, can be configured
        session_timeout=3600   # 1 hour default
    )
    
    @router.get("/")
    async def mcp_info():
        """Return basic MCP server information for GET requests.
        
        This helps clients discover that this is an MCP endpoint.
        """
        return {
            "type": "mcp_server",
            "name": "OAuth-HTTPS-Proxy MCP Server",
            "version": "1.0.0",
            "protocol": "jsonrpc",
            "protocol_version": "2.0",
            "mcp_version": "2025-06-18",
            "methods": [
                "initialize",
                "initialized",
                "tools/list",
                "tools/call",
                "prompts/list",
                "resources/list",
                "notifications/initialized"
            ],
            "description": "MCP server with debugging and auth tools",
            "endpoint": "/mcp/",
            "method": "POST"
        }
    
    @router.post("/")
    async def handle_mcp_request(
        request: Request,
        auth=Depends(get_optional_token_info)
    ):
        """Handle MCP JSON-RPC requests.
        
        This endpoint processes Model Context Protocol requests using
        the JSON-RPC 2.0 format.
        """
        # Generate or extract session ID
        session_id = request.headers.get("Mcp-Session-Id")
        if not session_id:
            session_id = str(uuid.uuid4())
            logger.debug(f"Generated new session ID: {session_id}")
        
        # Store request context for tools
        request_context_key = f"mcp:current_request:{session_id}"
        
        # Store headers
        headers_dict = dict(request.headers)
        headers_key = f"{request_context_key}:headers"
        # Store each header as a field in the hash
        for key, value in headers_dict.items():
            await async_storage.redis_client.hset(headers_key, key, value)
        
        # Store timing information
        start_time = time.time()
        timing_key = f"{request_context_key}:timing"
        await async_storage.redis_client.hset(timing_key, "start_time", str(start_time))
        await async_storage.redis_client.hset(timing_key, "method", request.method)
        await async_storage.redis_client.hset(timing_key, "path", str(request.url.path))
        
        # Store auth context if available
        if auth:
            auth_key = f"{request_context_key}:auth"
            await async_storage.redis_client.hset(auth_key, "user", auth.get("user", ""))
            await async_storage.redis_client.hset(auth_key, "client_id", auth.get("client_id", ""))
            await async_storage.redis_client.hset(auth_key, "scopes", ",".join(auth.get("scopes", [])))
            await async_storage.redis_client.hset(auth_key, "method", "oauth")
        
        # Parse JSON-RPC request
        try:
            body = await request.body()
            rpc_request = json.loads(body)
        except json.JSONDecodeError as e:
            logger.error(f"JSON decode error: {e}")
            return JSONResponse(
                content={
                    "jsonrpc": "2.0",
                    "error": {
                        "code": -32700,
                        "message": "Parse error",
                        "data": str(e)
                    }
                },
                headers={"Mcp-Session-Id": session_id}
            )
        
        # Validate JSON-RPC format
        if not isinstance(rpc_request, dict):
            return JSONResponse(
                content={
                    "jsonrpc": "2.0",
                    "error": {
                        "code": -32600,
                        "message": "Invalid Request",
                        "data": "Request must be an object"
                    }
                },
                headers={"Mcp-Session-Id": session_id}
            )
        
        # Extract method and params
        method = rpc_request.get("method", "")
        params = rpc_request.get("params", {})
        request_id = rpc_request.get("id")
        
        # Log request
        await unified_logger.event("mcp_request", {
            "session_id": session_id,
            "method": method,
            "has_params": bool(params),
            "authenticated": bool(auth)
        })
        
        # Route to appropriate handler
        try:
            result = await handle_mcp_method(
                mcp_server,
                method,
                params,
                session_id,
                async_storage
            )
            
            # Build response
            response_data = {
                "jsonrpc": "2.0",
                "result": result
            }
            
            # Include ID if present in request
            if request_id is not None:
                response_data["id"] = request_id
            
            # Log successful response
            await unified_logger.event("mcp_response", {
                "session_id": session_id,
                "method": method,
                "success": True,
                "duration_ms": (time.time() - start_time) * 1000
            })
            
            return JSONResponse(
                content=response_data,
                headers={"Mcp-Session-Id": session_id}
            )
            
        except MethodNotFoundError as e:
            logger.error(f"Method not found: {e}")
            return JSONResponse(
                content={
                    "jsonrpc": "2.0",
                    "error": {
                        "code": -32601,
                        "message": "Method not found",
                        "data": str(e)
                    },
                    "id": request_id
                },
                headers={"Mcp-Session-Id": session_id}
            )
        except InvalidParamsError as e:
            logger.error(f"Invalid params: {e}")
            return JSONResponse(
                content={
                    "jsonrpc": "2.0",
                    "error": {
                        "code": -32602,
                        "message": "Invalid params",
                        "data": str(e)
                    },
                    "id": request_id
                },
                headers={"Mcp-Session-Id": session_id}
            )
        except Exception as e:
            logger.exception(f"Internal error handling method {method}")
            await unified_logger.event("mcp_error", {
                "session_id": session_id,
                "method": method,
                "error": str(e)
            })
            
            return JSONResponse(
                content={
                    "jsonrpc": "2.0",
                    "error": {
                        "code": -32603,
                        "message": "Internal error",
                        "data": str(e)
                    },
                    "id": request_id
                },
                headers={"Mcp-Session-Id": session_id},
                status_code=500
            )
    
    @router.get("/health")
    async def mcp_health():
        """MCP endpoint health check."""
        return {
            "status": "healthy",
            "server": "OAuth-HTTPS-Proxy MCP Server",
            "protocol": "MCP 2025-06-18",
            "tools": 21  # Total number of tools
        }
    
    @router.get("/info")
    async def mcp_info():
        """Get MCP server information."""
        return mcp_server.get_server_info()
    
    return router


class MethodNotFoundError(Exception):
    """Raised when MCP method is not found."""
    pass


class InvalidParamsError(Exception):
    """Raised when MCP method params are invalid."""
    pass


async def handle_mcp_method(
    mcp_server: MCPServer,
    method: str,
    params: Dict[str, Any],
    session_id: str,
    storage
) -> Dict[str, Any]:
    """Handle specific MCP methods.
    
    Args:
        mcp_server: MCPServer instance
        method: MCP method name
        params: Method parameters
        session_id: Session ID
        storage: AsyncRedisStorage instance
        
    Returns:
        Method result
        
    Raises:
        MethodNotFoundError: If method is not recognized
        InvalidParamsError: If parameters are invalid
    """
    
    # Handle standard MCP methods
    if method == "initialize":
        return await mcp_server.handle_initialize(params)
    
    elif method == "initialized":
        # Client confirms initialization
        return {"status": "ready"}
    
    elif method == "tools/list":
        # List all available tools from the MCP server
        # Since we're using SimpleMCP as fallback, use its list_tools method
        if hasattr(mcp_server.mcp, 'list_tools'):
            tools = mcp_server.mcp.list_tools()
        else:
            # Fallback to hardcoded list if list_tools not available
            tools = [
                # Echo tools
                {"name": "echo", "description": "Echo back the provided message"},
                {"name": "replayLastEcho", "description": "Replay the last echoed message"},
                
                # Debug tools
                {"name": "printHeader", "description": "Get HTTP header value from current request"},
                {"name": "requestTiming", "description": "Get request timing information"},
                {"name": "corsAnalysis", "description": "Analyze CORS configuration"},
                {"name": "environmentDump", "description": "Get environment information"},
                
                # Auth tools
                {"name": "bearerDecode", "description": "Decode a Bearer token (JWT) without verification"},
                {"name": "authContext", "description": "Get current authentication context"},
                {"name": "whoIStheGOAT", "description": "A fun easter egg tool"},
                
                # System tools
                {"name": "healthProbe", "description": "Perform a comprehensive health check"},
                {"name": "sessionInfo", "description": "Get session information"},
                
                # State tools
                {"name": "stateInspector", "description": "Inspect all state data for a session"},
                {"name": "sessionHistory", "description": "Get session activity history"},
                {"name": "stateManipulator", "description": "Manipulate session state directly"},
                {"name": "sessionCompare", "description": "Compare state between two sessions"},
                {"name": "sessionTransfer", "description": "Transfer state from one session to another"},
                {"name": "stateBenchmark", "description": "Benchmark state operations performance"},
                {"name": "sessionLifecycle", "description": "Manage session lifecycle"},
                {"name": "stateValidator", "description": "Validate session state against a schema"},
                {"name": "requestTracer", "description": "Trace request flow and state changes"},
                {"name": "modeDetector", "description": "Detect and report the current server mode"}
            ]
        
        return {"tools": tools}
    
    elif method == "prompts/list":
        # List available prompts (we don't have any yet)
        return {"prompts": []}
    
    elif method == "resources/list":
        # List available resources (we don't have any yet)
        return {"resources": []}
    
    elif method == "notifications/initialized":
        # Client notification that initialization is complete
        # This is a notification, not a request, so just acknowledge it
        return {}
    
    elif method == "tools/call":
        # Call a specific tool
        tool_name = params.get("name")
        if not tool_name:
            raise InvalidParamsError("Tool name is required")
        
        tool_args = params.get("arguments", {})
        
        # Tools that accept session_id parameter
        # Note: sessionCompare uses session_id1/session_id2
        # sessionTransfer uses source_session/target_session
        session_aware_tools = {
            "echo", "replayLastEcho", "printHeader", "requestTiming", 
            "corsAnalysis", "bearerDecode", "authContext", "sessionInfo",
            "stateInspector", "sessionHistory", "stateManipulator", 
            "sessionLifecycle", "stateValidator"
            # NOT sessionCompare or sessionTransfer - they have different params
        }
        
        # Only add session_id if the tool accepts it and it's not already present
        if tool_name in session_aware_tools and "session_id" not in tool_args:
            tool_args["session_id"] = session_id
        
        # Execute the actual tool
        try:
            # First check if tool exists
            if hasattr(mcp_server.mcp, 'tools'):
                if tool_name not in mcp_server.mcp.tools:
                    raise MethodNotFoundError(f"Tool not found: {tool_name}")
            
            # Check if we're using SimpleMCP (has call_tool method)
            if hasattr(mcp_server.mcp, 'call_tool'):
                result = await mcp_server.mcp.call_tool(tool_name, tool_args)
            # Otherwise try to call the tool directly from the tools dict
            elif hasattr(mcp_server.mcp, 'tools') and tool_name in mcp_server.mcp.tools:
                tool_func = mcp_server.mcp.tools[tool_name]
                result = await tool_func(**tool_args)
            else:
                raise MethodNotFoundError(f"Tool not found: {tool_name}")
            
            # Format result for MCP response
            if isinstance(result, str):
                return {
                    "content": [{
                        "type": "text",
                        "text": result
                    }]
                }
            elif isinstance(result, dict):
                # Return dict as JSON text
                import json
                return {
                    "content": [{
                        "type": "text",
                        "text": json.dumps(result, indent=2)
                    }]
                }
            else:
                # Convert other types to string
                return {
                    "content": [{
                        "type": "text",
                        "text": str(result)
                    }]
                }
        except MethodNotFoundError:
            # Re-raise method not found errors
            raise
        except Exception as e:
            logger.error(f"Error calling tool {tool_name}: {e}")
            raise InvalidParamsError(f"Error calling tool: {str(e)}")
    
    elif method == "completion/complete":
        # Handle completion requests
        return {"completions": []}
    
    elif method == "logging/setLevel":
        # Set logging level
        level = params.get("level", "info")
        return {"level": level}
    
    elif method == "ping":
        # Ping/pong for keepalive
        return {"pong": True}
    
    else:
        raise MethodNotFoundError(f"Unknown method: {method}")