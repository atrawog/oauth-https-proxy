"""MCP Server - Clean, integrated with unified logging and Redis Streams."""

import asyncio
import base64
import json
import secrets
import time
import inspect
from typing import Dict, Any, Callable, Optional
from datetime import datetime, timezone
from starlette.applications import Starlette
from starlette.responses import StreamingResponse, Response
from starlette.routing import Route

from ....storage import UnifiedStorage
from ....shared.logger import log_info, log_debug, log_warning, log_error, log_trace


class MCPServer:
    """The ONE MCP server. Properly integrated with codebase patterns."""
    
    def __init__(self, storage: UnifiedStorage, unified_logger):
        self.storage = storage
        # Note: unified_logger passed for compatibility but we use direct log_* functions
            
        self.tools = {}
        # Sessions now stored in Redis for persistence (key: mcp:session:{session_id})
        # Sessions have 24-hour TTL to prevent accumulation
        self.session_ttl = 86400  # 24 hours in seconds
        
        # Track active SSE connections for listChanged notifications
        self.sse_connections = {}  # session_id -> queue for notifications
        
        # The Starlette app - handle all MCP requests
        self.app = Starlette(routes=[
            Route("/", self.handle_request, methods=["GET", "POST", "DELETE", "OPTIONS", "HEAD", "PUT", "PATCH"])
        ])
        
        # Schedule periodic session cleanup (fire-and-forget)
        asyncio.create_task(self._periodic_session_cleanup())
        
        # Fire-and-forget startup log
        log_info("MCP server initialized", component="mcp")
    
    # Removed logger methods - using direct log_* functions from shared.logger
    
    async def send_list_changed_notification(self, resource_type: str, session_id: str = None):
        """Send listChanged notification to connected clients.
        
        Args:
            resource_type: One of "tools", "prompts", or "resources"
            session_id: Optional specific session, otherwise broadcast to all
        """
        notification = {
            "jsonrpc": "2.0",
            "method": f"notifications/{resource_type}/list_changed"
        }
        
        if session_id and session_id in self.sse_connections:
            # Send to specific session
            try:
                await self.sse_connections[session_id].put(notification)
                log_info(f"Sent {resource_type}/list_changed to session {session_id}", component="mcp")
            except Exception as e:
                log_error(f"Failed to send notification to {session_id}: {e}", component="mcp")
        else:
            # Broadcast to all connected sessions
            for sid, queue in self.sse_connections.items():
                try:
                    await queue.put(notification)
                except Exception as e:
                    log_error(f"Failed to send notification to {sid}: {e}", component="mcp")
            
            if self.sse_connections:
                log_info(f"Broadcast {resource_type}/list_changed to {len(self.sse_connections)} sessions", component="mcp")
    
    async def _publish_event(self, event_type: str, data: Dict[str, Any]):
        """Publish event to Redis Streams (following codebase pattern)."""
        try:
            event_data = {
                "type": event_type,
                "component": "mcp",
                "data": data,
                "timestamp": datetime.now(timezone.utc).isoformat()
            }
            # Direct Redis Streams publish
            await self.storage.redis_client.xadd(
                "events:mcp",
                {"event": json.dumps(event_data)}
            )
        except Exception as e:
            log_error(f"Failed to publish event: {e}", component="mcp")
    
    def tool(self, func: Callable) -> Callable:
        """The @tool decorator - clean and simple."""
        # Get function metadata
        name = func.__name__
        doc = inspect.getdoc(func) or f"Tool: {name}"
        description = doc.split('\n')[0]  # First line only
        
        log_debug(f"Registering tool: {name} - {description}", component="mcp")
        
        # Build schema from signature
        sig = inspect.signature(func)
        properties = {}
        required = []
        
        for param_name, param in sig.parameters.items():
            # Skip internal parameters (self, cls, and anything starting with underscore)
            if param_name in ['self', 'cls'] or param_name.startswith('_'):
                continue
            
            # Infer type from annotation
            param_type = "string"
            if param.annotation != inspect.Parameter.empty:
                annotation = param.annotation
                # Handle Optional types
                import typing
                if hasattr(annotation, '__origin__'):
                    if annotation.__origin__ is typing.Union:
                        # Get first non-None type
                        args = annotation.__args__
                        for arg in args:
                            if arg != type(None):
                                annotation = arg
                                break
                
                # Map Python types to JSON schema types
                if annotation == int:
                    param_type = "integer"
                elif annotation == bool:
                    param_type = "boolean"
                elif annotation == float:
                    param_type = "number"
                elif annotation == list:
                    param_type = "array"
                elif annotation == dict:
                    param_type = "object"
            
            properties[param_name] = {"type": param_type}
            
            # Add description from docstring if available
            if doc and f"{param_name}:" in doc:
                import re
                match = re.search(f"{param_name}:\\s*(.+?)(?:\\n|$)", doc)
                if match:
                    properties[param_name]["description"] = match.group(1).strip()
            
            # Check if required (no default value)
            if param.default == inspect.Parameter.empty:
                required.append(param_name)
        
        # Check if this is a new tool
        is_new = name not in self.tools
        
        # Register tool
        self.tools[name] = {
            "function": func,
            "description": description,
            "inputSchema": {
                "type": "object",
                "properties": properties,
                "required": required,
                "additionalProperties": False
            }
        }
        
        # Send listChanged notification if this is a new tool
        if is_new and self.sse_connections:
            asyncio.create_task(self.send_list_changed_notification("tools"))
        
        # Log registration (fire-and-forget)
        log_debug(f"Registered tool: {name}", component="mcp", tool=name)
        
        return func  # Return unchanged
    
    async def handle_request(self, request):
        """Handle MCP requests with proper logging."""
        method = request.method
        trace_id = f"mcp_{secrets.token_hex(8)}"
        
        # Extract session or generate unique ID
        session_id = request.headers.get("mcp-session-id")
        
        # Generate new session ID if not provided or if it's "default"
        # Per MCP spec: must be cryptographically secure and visible ASCII (0x21-0x7E)
        if not session_id or session_id == "default":
            # Generate a secure session ID using secrets module with high entropy
            # Use standard base64 encoding for more character variety (a-z, A-Z, 0-9, +, /)
            # Generate 32 random bytes for a longer, more secure session ID
            random_bytes = secrets.token_bytes(32)
            # Use standard base64 encoding and strip padding
            # This gives us ~43 characters with full entropy across a-z, A-Z, 0-9, +, /
            session_id = base64.b64encode(random_bytes).decode('ascii').rstrip('=')
            log_debug(f"Generated new session ID: {session_id}", component="mcp")
        
        client_ip = request.client.host if request.client else "unknown"
        user_agent = request.headers.get("user-agent", "")
        
        # Detect Claude.ai connections
        is_claude = any(indicator in user_agent.lower() for indicator in ["anthropic", "claude", "34.162.102"])
        
        # Enhanced logging for Claude.ai
        if is_claude:
            log_info(
                f"🤖 Claude.ai MCP {method} request detected",
                component="mcp",
                trace_id=trace_id,
                method=method,
                session_id=session_id,
                client_ip=client_ip,
                user_agent=user_agent,
                is_claude=True
            )
        else:
            log_info(
                f"MCP {method} request",
                component="mcp",
                trace_id=trace_id,
                method=method,
                session_id=session_id,
                client_ip=client_ip,
                user_agent=user_agent
            )
        
        # Handle HEAD for discovery
        if method == "HEAD":
            return Response("", headers={
                "Content-Type": "text/event-stream",
                "Mcp-Session-Id": session_id,
                "Cache-Control": "no-cache, no-store, must-revalidate",
                "X-Accel-Buffering": "no",
                "X-Content-Type-Options": "nosniff",
                "Access-Control-Allow-Origin": "*.anthropic.com",
                "Access-Control-Allow-Headers": "*",
                "Access-Control-Allow-Methods": "GET, POST, DELETE, HEAD, OPTIONS"
            })
        
        # Handle OPTIONS for CORS
        if method == "OPTIONS":
            return Response("", headers={
                "Allow": "GET, POST, DELETE, HEAD, OPTIONS, PUT, PATCH",
                "Access-Control-Allow-Origin": "*.anthropic.com",
                "Access-Control-Allow-Methods": "GET, POST, DELETE, HEAD, OPTIONS, PUT, PATCH",
                "Access-Control-Allow-Headers": "*",
                "Access-Control-Max-Age": "86400"  # Cache preflight for 24 hours
            })
        
        # Handle DELETE for session cleanup
        if method == "DELETE":
            session_key = f"mcp:session:{session_id}"
            deleted = await self.storage.redis_client.delete(session_key)
            if deleted:
                await self._publish_event("session_terminated", {"session_id": session_id})
                log_info(f"Deleted MCP session from Redis: {session_id}", component="mcp")
            return Response("", status_code=204)
        
        # Handle GET for SSE stream
        if method == "GET":
            log_info("Creating SSE StreamingResponse", component="mcp", trace_id=trace_id)
            
            # Create generator and log it
            generator = self._sse_stream(session_id, trace_id)
            log_info(f"Created SSE generator: {generator}", component="mcp", trace_id=trace_id)
            
            response = StreamingResponse(
                generator,
                media_type="text/event-stream",
                headers={
                    "Cache-Control": "no-cache, no-store, must-revalidate",
                    "X-Accel-Buffering": "no",
                    "Connection": "keep-alive",
                    "Mcp-Session-Id": session_id,
                    "X-Content-Type-Options": "nosniff",
                    "Access-Control-Allow-Origin": "*.anthropic.com"
                }
            )
            log_info("Returning SSE StreamingResponse", component="mcp", trace_id=trace_id)
            return response
        
        # Handle POST for JSON-RPC
        if method == "POST":
            body = await request.json()
            
            # Check if this is a notification (no id field) 
            # Per MCP spec: notifications MUST return 202 Accepted with no body
            method_name = body.get("method", "")
            if "id" not in body and method_name.startswith("notifications/"):
                # Process the notification without returning a response body
                if method_name == "notifications/initialized":
                    # Update session state in Redis
                    session_key = f"mcp:session:{session_id}"
                    session_json = await self.storage.get(session_key)
                    if session_json:
                        session_data = json.loads(session_json)
                        session_data["ready"] = True
                        await self.storage.redis_client.setex(
                            session_key,
                            self.session_ttl,
                            json.dumps(session_data)
                        )
                        log_info(f"Client ready notification processed", component="mcp", session_id=session_id, trace_id=trace_id)
                
                # Return 202 Accepted with no body for notifications
                return Response(
                    "",  # Empty body
                    status_code=202,  # 202 Accepted
                    headers={
                        "Mcp-Session-Id": session_id,
                        "Cache-Control": "no-cache, no-store, must-revalidate",
                        "X-Content-Type-Options": "nosniff",
                        "Access-Control-Allow-Origin": "*.anthropic.com"
                    }
                )
            
            # Check if session exists for non-initialize requests
            if method_name != "initialize":
                # Check if session ID was provided in header (not generated)
                provided_session_id = request.headers.get("mcp-session-id")
                if provided_session_id:
                    # Check if session exists in Redis
                    session_key = f"mcp:session:{provided_session_id}"
                    session_exists = await self.storage.redis_client.exists(session_key)
                    if not session_exists:
                        # Session doesn't exist - return 404 per MCP spec
                        log_info(f"Session not found: {provided_session_id}", component="mcp", trace_id=trace_id)
                        error_response = {
                            "jsonrpc": "2.0",
                            "id": body.get("id"),
                            "error": {
                                "code": -32001,  # Session not found
                                "message": "Session not found"
                            }
                        }
                        return Response(
                            json.dumps(error_response),
                            media_type="application/json",
                            status_code=404,
                            headers={
                                "Cache-Control": "no-cache, no-store, must-revalidate",
                                "X-Content-Type-Options": "nosniff",
                                "Access-Control-Allow-Origin": "*.anthropic.com"
                            }
                        )
            
            result = await self._handle_jsonrpc(body, session_id, trace_id)
            
            # IMPORTANT: Always return JSON for POST requests
            # SSE is only for GET requests that establish streaming connections
            # Claude.ai sends Accept: application/json, text/event-stream but expects JSON for POST
            return Response(
                json.dumps(result),
                media_type="application/json",
                headers={
                    "Mcp-Session-Id": session_id,  # Include session ID in response
                    "Cache-Control": "no-cache, no-store, must-revalidate",
                    "X-Content-Type-Options": "nosniff",
                    "Access-Control-Allow-Origin": "*.anthropic.com"
                }
            )
    
    async def _handle_jsonrpc(self, message, session_id, trace_id):
        """Handle JSON-RPC with proper error handling and logging."""
        # Validate JSON-RPC 2.0 compliance
        jsonrpc_version = message.get("jsonrpc")
        msg_id = message.get("id")
        
        # JSON-RPC 2.0 requires "jsonrpc": "2.0" field in all requests
        if jsonrpc_version != "2.0":
            log_warning(f"Invalid or missing jsonrpc field: {jsonrpc_version}", component="mcp", trace_id=trace_id)
            return {
                "jsonrpc": "2.0",
                "id": msg_id,
                "error": {
                    "code": -32600,  # Invalid Request per JSON-RPC spec
                    "message": "Invalid Request: missing or incorrect 'jsonrpc' field. Must be '2.0'"
                }
            }
        
        method = message.get("method")
        params = message.get("params", {})
        
        # Get or create session in Redis
        session_key = f"mcp:session:{session_id}"
        session_json = await self.storage.get(session_key)
        
        if not session_json:
            # Only create new session for initialize method
            if method == "initialize":
                # Create new session in Redis
                session_data = {
                    "id": session_id,
                    "created": datetime.now(timezone.utc).isoformat(),
                    "initialized": False,
                    "ready": False
                }
                await self.storage.redis_client.setex(
                    session_key,
                    self.session_ttl,  # 24 hour TTL
                    json.dumps(session_data)
                )
                await self._publish_event("session_created", {"session_id": session_id})
                log_debug(f"Created new MCP session in Redis: {session_id}", component="mcp")
            else:
                # Session doesn't exist and this isn't initialize - shouldn't happen due to check above
                log_warning(f"Session {session_id} doesn't exist for method {method}", component="mcp")
                session_data = {}
        else:
            session_data = json.loads(session_json)
        
        try:
            if method == "initialize":
                requested_version = params.get("protocolVersion", "2025-06-18")
                client_info = params.get("clientInfo", {})
                
                # Protocol version negotiation per MCP spec
                # Server supports these versions in order of preference
                supported_versions = ["2025-06-18", "2025-03-26", "2024-11-05"]
                
                # Negotiate protocol version
                if requested_version in supported_versions:
                    # Use the requested version if we support it
                    protocol_version = requested_version
                elif requested_version > "2025-06-18":
                    # Future version - negotiate down to our highest
                    protocol_version = "2025-06-18"
                elif requested_version < "2024-11-05":
                    # Too old - use oldest we support
                    protocol_version = "2024-11-05"
                else:
                    # Unknown version - default to latest stable
                    protocol_version = "2025-06-18"
                    log_warning(f"Unknown protocol version requested: {requested_version}, using {protocol_version}", component="mcp")
                
                result = {
                    "protocolVersion": protocol_version,
                    "capabilities": {
                        "tools": {"listChanged": True},
                        "prompts": {"listChanged": True},
                        "resources": {"subscribe": False, "listChanged": True}
                    },
                    "serverInfo": {
                        "name": "OAuth-HTTPS-Proxy-MCP",
                        "version": "3.0.0"
                    }
                }
                
                # Update session in Redis
                session_data["initialized"] = True
                session_data["protocol_version"] = protocol_version
                session_data["client_info"] = client_info
                await self.storage.redis_client.setex(
                    session_key,
                    self.session_ttl,  # Reset TTL
                    json.dumps(session_data)
                )
                
                await self._publish_event("session_initialized", {
                    "session_id": session_id,
                    "protocol": protocol_version,
                    "client": client_info.get("name", "unknown")
                })
                
                # Log with Claude detection
                client_name = client_info.get("name", "unknown")
                is_claude_client = "anthropic" in client_name.lower() or "claude" in client_name.lower()
                
                if is_claude_client:
                    log_info(
                        f"🤖 Claude.ai session initialized",
                        component="mcp",
                        session_id=session_id,
                        protocol=protocol_version,
                        client=client_name,
                        is_claude=True
                    )
                else:
                    log_info(
                        "Session initialized",
                        component="mcp",
                        session_id=session_id,
                        protocol=protocol_version,
                        client=client_name
                    )
            
            elif method == "tools/list":
                # Log tools list request
                # Detect if this is Claude.ai requesting tools
                is_claude_request = session_data.get("client_info", {}).get("name", "").lower() in ["anthropic/claudeai", "claude"]
                
                if is_claude_request:
                    log_info(
                        f"🤖 Claude.ai requesting tools list - found {len(self.tools)} tools",
                        component="mcp",
                        trace_id=trace_id,
                        session_id=session_id,
                        tools=list(self.tools.keys()),
                        is_claude=True
                    )
                else:
                    log_info(
                        f"Tools list requested - found {len(self.tools)} tools",
                        component="mcp",
                        trace_id=trace_id,
                        session_id=session_id,
                        tools=list(self.tools.keys())
                    )
                
                result = {
                    "tools": [
                        {
                            "name": name,
                            "description": tool["description"],
                            "inputSchema": tool["inputSchema"]
                        }
                        for name, tool in self.tools.items()
                    ]
                }
                
                log_info(
                    f"Returning tools list with {len(result['tools'])} tools",
                    component="mcp",
                    trace_id=trace_id
                )
            
            elif method == "tools/call":
                tool_name = params["name"]
                tool_args = params.get("arguments", {})
                
                # Log tool call
                log_info(
                    f"Calling tool: {tool_name}",
                    component="mcp",
                    tool=tool_name,
                    trace_id=trace_id,
                    session_id=session_id
                )
                
                if tool_name in self.tools:
                    func = self.tools[tool_name]["function"]
                    
                    # Pass context to tools that need it
                    sig = inspect.signature(func)
                    if "_storage" in sig.parameters:
                        tool_args["_storage"] = self.storage
                    if "_session_id" in sig.parameters:
                        tool_args["_session_id"] = session_id
                    if "_server" in sig.parameters:
                        tool_args["_server"] = self
                    
                    # Execute tool
                    tool_result = await func(**tool_args)
                    
                    # Wrap tool result in proper MCP format
                    result = {
                        "content": [
                            {
                                "type": "text",
                                "text": tool_result if isinstance(tool_result, str) else json.dumps(tool_result)
                            }
                        ]
                    }
                    
                    # Publish tool execution event
                    await self._publish_event("tool_executed", {
                        "session_id": session_id,
                        "tool": tool_name,
                        "success": True
                    })
                else:
                    raise ValueError(f"Unknown tool: {tool_name}")
            
            elif method == "ping":
                # Keepalive ping
                result = {"pong": True}
            
            else:
                raise ValueError(f"Unknown method: {method}")
            
            # Return success response
            return {"jsonrpc": "2.0", "id": msg_id, "result": result}
            
        except Exception as e:
            log_error(f"MCP error: {e}", component="mcp", trace_id=trace_id, method=method)
            await self._publish_event("mcp_error", {
                "session_id": session_id,
                "method": method,
                "error": str(e)
            })
            return {
                "jsonrpc": "2.0",
                "id": msg_id,
                "error": {"code": -32603, "message": str(e)}
            }
    
    async def _sse_stream(self, session_id, trace_id):
        """Generate SSE keepalive stream with listChanged notification support."""
        log_info(f"SSE stream generator started", component="mcp", session_id=session_id, trace_id=trace_id)
        
        # Create notification queue for this session
        notification_queue = asyncio.Queue()
        self.sse_connections[session_id] = notification_queue
        
        try:
            # Send initial hello immediately with proper encoding
            hello_msg = f"data: {{\"type\":\"hello\",\"session_id\":\"{session_id}\"}}\n\n"
            log_info(f"SSE about to yield hello: {repr(hello_msg)}", component="mcp", session_id=session_id)
            yield hello_msg.encode('utf-8')
            log_info(f"SSE sent hello message", component="mcp", session_id=session_id)
            
            # Force immediate flush with multiple newlines and a comment
            # This helps ensure the proxy flushes the data immediately
            yield b"\n\n: init\n\n"
            log_debug(f"SSE sent init flush", component="mcp", session_id=session_id)
            
            # Then send periodic keepalives and notifications
            keep_alive_count = 0
            
            while True:
                try:
                    # Wait for notification or timeout for keepalive
                    notification = await asyncio.wait_for(
                        notification_queue.get(), 
                        timeout=3.0  # Reduced from 15s to 3s for even faster response
                    )
                    
                    # Send notification as JSON-RPC notification
                    notification_msg = f"data: {json.dumps(notification)}\n\n"
                    yield notification_msg.encode()
                    log_debug(f"SSE sent notification: {notification.get('method')}", component="mcp", session_id=session_id)
                    
                except asyncio.TimeoutError:
                    # Send keepalive
                    yield b": keepalive\n\n"
                    keep_alive_count += 1
                    log_debug(f"SSE sent keepalive #{keep_alive_count}", component="mcp", session_id=session_id)
                    
        except asyncio.CancelledError:
            log_info(f"SSE stream cancelled after {keep_alive_count} keepalives", component="mcp", session_id=session_id, trace_id=trace_id)
            raise
        except Exception as e:
            log_error(f"SSE stream error: {e}", component="mcp", session_id=session_id, trace_id=trace_id, exc_info=True)
            raise
        finally:
            # Clean up connection tracking
            if session_id in self.sse_connections:
                del self.sse_connections[session_id]
                log_debug(f"SSE connection cleaned up", component="mcp", session_id=session_id)
    
    async def _sse_response(self, data):
        """Convert response to SSE format."""
        yield f"data: {json.dumps(data)}\n\n".encode()
    
    async def _periodic_session_cleanup(self):
        """Background task to cleanup expired MCP sessions periodically."""
        while True:
            try:
                # Wait 1 hour between cleanups
                await asyncio.sleep(3600)
                
                log_debug("Starting MCP session cleanup", component="mcp")
                
                # Get all MCP session keys
                pattern = "mcp:session:*"
                keys = await self.storage.redis_client.keys(pattern)
                
                cleaned_count = 0
                for key in keys:
                    # Check if session still exists (Redis TTL will auto-delete expired ones)
                    # This is mainly for logging and tracking
                    if not await self.storage.redis_client.exists(key):
                        session_id = key.split(":")[-1]
                        log_debug(f"Session {session_id} already expired by TTL", component="mcp")
                        cleaned_count += 1
                
                if cleaned_count > 0:
                    log_info(
                        f"MCP session cleanup completed: {cleaned_count} expired sessions",
                        component="mcp",
                        cleaned_count=cleaned_count
                    )
            except Exception as e:
                log_error(f"Error in MCP session cleanup: {e}", component="mcp", exc_info=True)
                # Continue running even if cleanup fails
                await asyncio.sleep(60)  # Wait a minute before retrying


# Global instance
_mcp_server: Optional[MCPServer] = None


def get_mcp_server() -> MCPServer:
    """Get the global MCP server instance."""
    if _mcp_server is None:
        raise RuntimeError("MCP server not initialized")
    return _mcp_server


def init_mcp_server(storage: UnifiedStorage, unified_logger) -> MCPServer:
    """Initialize the global MCP server."""
    global _mcp_server
    _mcp_server = MCPServer(storage, unified_logger)
    return _mcp_server