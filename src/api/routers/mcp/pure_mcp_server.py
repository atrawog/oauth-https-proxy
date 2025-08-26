"""Pure MCP Server implementation with full system integration.

This module provides a clean MCP server implementation that properly handles
SSE streaming and integrates with UnifiedAsyncLogger and Redis Streams.
"""

import asyncio
import json
import logging
import secrets
import time
import traceback
from typing import Any, Dict, List, Optional, Callable
from datetime import datetime, timezone

from ....storage import UnifiedStorage
from ....shared.unified_logger import UnifiedAsyncLogger
from ....storage.unified_stream_publisher import UnifiedStreamPublisher

logger = logging.getLogger(__name__)


class PureMCPServer:
    """Pure Python MCP server with full Redis and logging integration."""
    
    def __init__(
        self,
        name: str = "OAuth-HTTPS-Proxy-MCP",
        version: str = "2.0.0",
        storage: Optional[UnifiedStorage] = None,
        unified_logger: Optional[UnifiedAsyncLogger] = None
    ):
        """Initialize the pure MCP server.
        
        Args:
            name: Server name for identification
            version: Server version
            storage: UnifiedStorage instance for Redis operations
            unified_logger: UnifiedAsyncLogger for logging
        """
        self.server_info = {"name": name, "version": version}
        self.storage = storage
        
        # Create component-specific logger
        if unified_logger:
            redis_clients = getattr(unified_logger, 'redis_clients', None)
            if redis_clients:
                self.logger = UnifiedAsyncLogger(redis_clients, component="mcp_server")
            else:
                self.logger = unified_logger
        else:
            self.logger = None
            
        # Create event publisher for MCP events
        if storage:
            redis_client = getattr(storage, 'redis_client', None) or getattr(storage, 'redis', None)
            if redis_client:
                self.event_publisher = UnifiedStreamPublisher(
                    redis_client=redis_client,
                    redis_url=getattr(storage, 'redis_url', None)
                )
            else:
                self.event_publisher = None
        else:
            self.event_publisher = None
        
        # Session configuration
        self.session_prefix = "mcp:session:"
        self.session_ttl = 3600  # 1 hour
        
        # Tool registry
        self.tools = {}
        
        # Capabilities
        self.capabilities = {
            "experimental": {},
            "prompts": {"listChanged": False},
            "resources": {"subscribe": False, "listChanged": False},
            "tools": {"listChanged": False}
        }
        
        # Protocol handlers
        self.handlers = {
            "initialize": self.handle_initialize,
            "notifications/initialized": self.handle_initialized,
            "tools/list": self.handle_tools_list,
            "tools/call": self.handle_tools_call,
            "ping": self.handle_ping
        }
        
        logger.info(f"[PURE MCP] Server initialized: {name} v{version}")
    
    async def get_or_create_session(self, session_id: Optional[str] = None) -> str:
        """Get existing session or create new one in Redis.
        
        Args:
            session_id: Optional existing session ID
            
        Returns:
            Session ID (existing or newly created)
        """
        if not session_id:
            session_id = secrets.token_hex(16)
            trace_id = f"mcp_session_{session_id}"
            
            if self.logger:
                # Start trace for this session
                self.logger.start_trace(trace_id)
        
        if not self.storage:
            # No storage, just return the session ID
            return session_id
            
        session_key = f"{self.session_prefix}{session_id}"
        
        try:
            # Check if session exists in Redis
            session_data = await self.storage.redis_client.get(session_key)
            
            if not session_data:
                # Create new session
                session = {
                    "id": session_id,
                    "created_at": time.time(),
                    "initialized": False,
                    "protocol_version": None,
                    "client_info": {},
                    "context": {},
                    "tools_called": 0,
                    "last_activity": time.time()
                }
                
                # Store in Redis with TTL
                # Use the proper method for AsyncRedisStorage
                await self.storage.redis_client.setex(
                    session_key,
                    self.session_ttl,
                    json.dumps(session)
                )
                
                # Publish session creation event
                if self.event_publisher:
                    await self.event_publisher.publish_event(
                        event_type="mcp_session_created",
                        data={"session_id": session_id},
                        trace_id=f"mcp_session_{session_id}",
                        component="mcp_server"
                    )
                
                # Log with unified logger
                if self.logger:
                    self.logger.info(
                        "MCP session created",
                        trace_id=f"mcp_session_{session_id}",
                        session_id=session_id
                    )
            else:
                # Update last activity
                session = json.loads(session_data)
                session["last_activity"] = time.time()
                await self.storage.redis_client.setex(
                    session_key,
                    self.session_ttl,
                    json.dumps(session)
                )
                
        except Exception as e:
            logger.error(f"[PURE MCP] Session management error: {e}")
            # Continue without session persistence
        
        return session_id
    
    async def process_request(self, message: dict, session_id: str) -> dict:
        """Process a JSON-RPC request and return response.
        
        Args:
            message: JSON-RPC request message
            session_id: Session ID for this request
            
        Returns:
            JSON-RPC response dict
        """
        method = message.get("method")
        params = message.get("params", {})
        msg_id = message.get("id")
        
        trace_id = f"mcp_req_{secrets.token_hex(8)}"
        
        if self.logger:
            self.logger.debug(
                f"Processing MCP request: {method}",
                trace_id=trace_id,
                session_id=session_id,
                method=method,
                request_id=msg_id
            )
        
        # Check if we have a handler for this method
        if method in self.handlers:
            try:
                # Call the handler
                result = await self.handlers[method](params, session_id)
                
                # Return success response
                response = {
                    "jsonrpc": "2.0",
                    "id": msg_id,
                    "result": result
                }
                
                if self.logger:
                    self.logger.debug(
                        f"MCP request successful: {method}",
                        trace_id=trace_id,
                        session_id=session_id,
                        method=method
                    )
                
                return response
                
            except Exception as e:
                # Log error
                if self.event_publisher:
                    await self.event_publisher.publish_error(
                        error=e,
                        component="mcp_server",
                        context={
                            "session_id": session_id,
                            "method": method,
                            "params": params
                        },
                        trace_id=trace_id
                    )
                
                # Return error response
                return {
                    "jsonrpc": "2.0",
                    "id": msg_id,
                    "error": {
                        "code": -32603,
                        "message": f"Internal error: {str(e)}",
                        "data": traceback.format_exc() if logger.level == logging.DEBUG else None
                    }
                }
        else:
            # Method not found
            return {
                "jsonrpc": "2.0",
                "id": msg_id,
                "error": {
                    "code": -32601,
                    "message": f"Method not found: {method}"
                }
            }
    
    # Protocol Handlers
    
    async def handle_initialize(self, params: dict, session_id: str) -> dict:
        """Handle initialize request with full logging."""
        trace_id = f"mcp_session_{session_id}"
        
        # Log initialization
        if self.logger:
            self.logger.info(
                "MCP session initialization",
                trace_id=trace_id,
                session_id=session_id,
                protocol_version=params.get("protocolVersion"),
                client_info=json.dumps(params.get("clientInfo", {}))
            )
        
        # Update session in Redis if available
        if self.storage:
            try:
                session_key = f"{self.session_prefix}{session_id}"
                session_data = await self.storage.get(session_key)
                
                if session_data:
                    session = json.loads(session_data)
                    session.update({
                        "initialized": True,
                        "protocol_version": params.get("protocolVersion"),
                        "client_info": params.get("clientInfo", {}),
                        "initialized_at": time.time()
                    })
                    await self.storage.redis_client.setex(session_key, self.session_ttl, json.dumps(session))
            except Exception as e:
                logger.error(f"[PURE MCP] Failed to update session: {e}")
        
        # Publish initialization event
        if self.event_publisher:
            await self.event_publisher.publish_event(
                event_type="mcp_session_initialized",
                data={
                    "session_id": session_id,
                    "protocol_version": params.get("protocolVersion"),
                    "client_name": params.get("clientInfo", {}).get("name")
                },
                trace_id=trace_id,
                component="mcp_server"
            )
        
        # Return capabilities
        return {
            "protocolVersion": params.get("protocolVersion", "2025-06-18"),
            "capabilities": self.capabilities,
            "serverInfo": self.server_info
        }
    
    async def handle_initialized(self, params: dict, session_id: str) -> dict:
        """Handle initialized notification (no response needed)."""
        if self.logger:
            self.logger.debug(
                "MCP client initialized",
                session_id=session_id
            )
        return {}
    
    async def handle_tools_list(self, params: dict, session_id: str) -> dict:
        """List available tools with comprehensive logging."""
        trace_id = f"mcp_tools_{secrets.token_hex(4)}"
        
        logger.info(f"[PURE MCP] tools/list called for session {session_id}")
        
        # Format tools for response per MCP spec
        tools_list = []
        for name, tool in self.tools.items():
            tool_def = {
                "name": name,
                "description": tool["description"],
                "inputSchema": tool.get("inputSchema", {
                    "type": "object",
                    "properties": tool.get("parameters", {}),
                    "additionalProperties": False
                })
            }
            tools_list.append(tool_def)
            logger.debug(f"[PURE MCP] Tool: {name} - {tool['description'][:50]}...")
        
        result = {"tools": tools_list}
        
        # Log the response
        logger.info(f"[PURE MCP] Returning {len(tools_list)} tools for session {session_id}")
        
        # Log with unified logger
        if self.logger:
            response_json = json.dumps(result)
            self.logger.info(
                f"Tools list response ready",
                trace_id=trace_id,
                session_id=session_id,
                tools_count=len(tools_list),
                response_size=len(response_json),
                tool_names=list(self.tools.keys()),
                first_tool=tools_list[0]["name"] if tools_list else None
            )
            
            # Log preview of response
            preview = response_json[:500] if len(response_json) > 500 else response_json
            self.logger.debug(
                "Tools list response preview",
                trace_id=trace_id,
                session_id=session_id,
                preview=preview
            )
        
        return result
    
    async def handle_tools_call(self, params: dict, session_id: str) -> dict:
        """Execute tool with comprehensive tracking."""
        trace_id = f"mcp_tool_{secrets.token_hex(8)}"
        tool_name = params["name"]
        tool_args = params.get("arguments", {})
        
        # Log tool call
        if self.logger:
            self.logger.info(
                f"MCP tool called: {tool_name}",
                trace_id=trace_id,
                session_id=session_id,
                tool_name=tool_name,
                arguments=json.dumps(tool_args)
            )
        
        # Publish tool call event
        if self.event_publisher:
            await self.event_publisher.publish_event(
                event_type="mcp_tool_called",
                data={
                    "session_id": session_id,
                    "tool_name": tool_name,
                    "arguments": tool_args
                },
                trace_id=trace_id,
                component="mcp_server"
            )
        
        try:
            # Execute tool
            start_time = time.time()
            
            if tool_name not in self.tools:
                raise ValueError(f"Unknown tool: {tool_name}")
            
            tool = self.tools[tool_name]
            func = tool["function"]
            
            # Call the tool function
            if asyncio.iscoroutinefunction(func):
                result = await func(**tool_args)
            else:
                result = func(**tool_args)
            
            execution_time = (time.time() - start_time) * 1000
            
            # Log success
            if self.logger:
                self.logger.info(
                    f"MCP tool completed: {tool_name}",
                    trace_id=trace_id,
                    session_id=session_id,
                    tool_name=tool_name,
                    execution_time_ms=execution_time,
                    result_preview=str(result)[:200] if result else ""
                )
            
            # Update session stats if storage available
            if self.storage:
                try:
                    session_key = f"{self.session_prefix}{session_id}"
                    session_data = await self.storage.get(session_key)
                    if session_data:
                        session = json.loads(session_data)
                        session["tools_called"] = session.get("tools_called", 0) + 1
                        session["last_tool"] = tool_name
                        session["last_activity"] = time.time()
                        await self.storage.redis_client.setex(session_key, self.session_ttl, json.dumps(session))
                except Exception as e:
                    logger.error(f"[PURE MCP] Failed to update session stats: {e}")
            
            # Format response
            return {
                "content": [{"type": "text", "text": str(result)}],
                "isError": False
            }
            
        except Exception as e:
            # Log error
            if self.event_publisher:
                await self.event_publisher.publish_error(
                    error=e,
                    component="mcp_server",
                    context={
                        "session_id": session_id,
                        "tool_name": tool_name,
                        "arguments": tool_args
                    },
                    trace_id=trace_id
                )
            
            return {
                "content": [{"type": "text", "text": f"Error: {str(e)}"}],
                "isError": True
            }
    
    async def handle_ping(self, params: dict, session_id: str) -> dict:
        """Handle ping request."""
        return {"pong": True}
    
    # Tool Management
    
    def add_tool(
        self,
        func: Callable,
        name: str,
        description: str,
        parameters: Optional[dict] = None,
        inputSchema: Optional[dict] = None
    ):
        """Register a tool with the server.
        
        Args:
            func: The function to call for this tool
            name: Tool name
            description: Tool description
            parameters: Parameter schema (old style)
            inputSchema: Full JSON schema (new style)
        """
        if inputSchema:
            # Use provided schema
            schema = inputSchema
        else:
            # Build schema from parameters
            schema = {
                "type": "object",
                "properties": parameters or {},
                "additionalProperties": False
            }
            
            # Add required fields if we can determine them
            if parameters:
                required = [k for k, v in parameters.items() if v.get("required", False)]
                if required:
                    schema["required"] = required
        
        self.tools[name] = {
            "name": name,
            "description": description,
            "function": func,
            "parameters": parameters,
            "inputSchema": schema
        }
        
        logger.info(f"[PURE MCP] Registered tool: {name}")
    
    def list_tools(self) -> List[str]:
        """Get list of registered tool names."""
        return list(self.tools.keys())