"""MCP Server - Clean, integrated with unified logging and Redis Streams."""

import asyncio
import base64
import json
import secrets
import socket
import time
import inspect
from typing import Dict, Any, Callable, Optional
from datetime import datetime, timezone
from starlette.applications import Starlette
from starlette.responses import StreamingResponse, Response
from starlette.routing import Route

from ....storage import UnifiedStorage
from ....shared.logger import log_info, log_debug, log_warning, log_error, log_trace
from ....shared.client_ip import get_real_client_ip


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
            Route("/", self.handle_request, methods=["GET", "POST", "DELETE", "OPTIONS", "HEAD", "PUT", "PATCH"]),
            Route("/debug", self.handle_debug, methods=["GET"])
        ])
        
        # Schedule periodic session cleanup (fire-and-forget)
        asyncio.create_task(self._periodic_session_cleanup())
        
        # Schedule logging verification (fire-and-forget)
        asyncio.create_task(self._verify_logging())
        
        # Fire-and-forget startup log
        log_info("MCP server initialized", component="mcp")
    
    # Removed logger methods - using direct log_* functions from shared.logger
    
    async def _reverse_dns_lookup(self, ip: str) -> str:
        """Perform reverse DNS lookup with timeout."""
        try:
            # Run in executor to avoid blocking
            loop = asyncio.get_event_loop()
            hostname = await asyncio.wait_for(
                loop.run_in_executor(None, socket.gethostbyaddr, ip),
                timeout=0.5
            )
            return hostname[0] if hostname else ip
        except (socket.herror, socket.gaierror, asyncio.TimeoutError, Exception):
            return ip
    
    async def _get_request_context(self, request) -> Dict[str, Any]:
        """Extract comprehensive request context for logging."""
        # Get proxy hostname (which proxy is being accessed)
        proxy_hostname = request.headers.get("x-forwarded-host", "")
        if not proxy_hostname:
            proxy_hostname = request.headers.get("host", "unknown")
        if ":" in proxy_hostname:
            proxy_hostname = proxy_hostname.split(":")[0]
        
        # Get client IP (who is making the request)
        client_ip = get_real_client_ip(request)
        
        # Get client hostname (reverse DNS or from headers)
        client_hostname = request.headers.get("x-client-hostname", "")
        if not client_hostname and client_ip and client_ip != "unknown":
            # Check for known IPs
            if client_ip == "34.162.102.82":
                client_hostname = "claude.ai"
            else:
                # Attempt reverse DNS lookup (with timeout)
                try:
                    client_hostname = await self._reverse_dns_lookup(client_ip)
                except:
                    client_hostname = client_ip
        
        if not client_hostname:
            client_hostname = client_ip
        
        # Get request path
        path = request.url.path
        
        # Get user agent for additional context
        user_agent = request.headers.get("user-agent", "")
        
        # Detect if this is Claude.ai
        is_claude = (
            client_ip == "34.162.102.82" or
            "claude" in client_hostname.lower() or
            "anthropic" in user_agent.lower()
        )
        
        return {
            "proxy_hostname": proxy_hostname,
            "client_ip": client_ip,
            "client_hostname": client_hostname,
            "path": path,
            "method": request.method,
            "user_agent": user_agent[:100],  # Truncate long user agents
            "is_claude": is_claude
        }
    
    async def _verify_logging(self):
        """Verify logging is working correctly to Redis."""
        await asyncio.sleep(2)  # Wait for system to stabilize
        
        try:
            import uuid
            test_id = str(uuid.uuid4())
            
            # Write a test log with unique identifier
            log_info(
                f"MCP logging verification test: {test_id}",
                component="mcp_test",
                test_id=test_id,
                verification=True
            )
            
            # Wait a bit for log to be written
            await asyncio.sleep(0.5)
            
            # Try to verify the log was written to Redis
            try:
                # Check if we can access Redis streams
                result = await self.storage.redis_client.xrevrange(
                    "log:stream",
                    count=100
                )
                
                # Look for our test log
                found = False
                for entry_id, data in result:
                    if test_id in str(data):
                        found = True
                        break
                
                if found:
                    log_info(
                        "✅ MCP logging verification PASSED - Redis writes working",
                        component="mcp",
                        test_id=test_id
                    )
                else:
                    log_warning(
                        "⚠️ MCP logging verification UNCERTAIN - test log not found in recent entries",
                        component="mcp",
                        test_id=test_id
                    )
                    # Try alternate log location
                    try:
                        # Check if logs might be in a different stream
                        keys = await self.storage.redis_client.keys("log:*")
                        log_info(f"Available log streams: {keys}", component="mcp")
                    except:
                        pass
                        
            except Exception as e:
                log_error(
                    f"❌ MCP logging verification FAILED - Cannot read from Redis: {e}",
                    component="mcp",
                    error=str(e)
                )
                # Fallback logging to stderr
                import sys
                print(f"[MCP FALLBACK] Logging verification failed: {e}", file=sys.stderr)
                
        except Exception as e:
            log_error(
                f"❌ MCP logging verification ERROR: {e}",
                component="mcp",
                error=str(e)
            )
            # Fallback to stderr
            import sys
            print(f"[MCP FALLBACK] Logging verification error: {e}", file=sys.stderr)
    
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
        
        # Get comprehensive request context
        context = await self._get_request_context(request)
        
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
            log_debug(
                f"Generated new session ID: {session_id}",
                component="mcp",
                **context,
                session_id=session_id
            )
        
        # Enhanced logging with full context
        if context.get("is_claude"):
            log_info(
                f"🤖 Claude.ai MCP {method} {context['path']} from {context['client_hostname']}",
                component="mcp",
                trace_id=trace_id,
                session_id=session_id,
                **context
            )
        else:
            log_info(
                f"MCP {method} {context['path']} from {context['client_hostname']}",
                component="mcp",
                trace_id=trace_id,
                session_id=session_id,
                **context
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
                log_info(
                    f"Deleted MCP session from {context['client_hostname']}: {session_id}",
                    component="mcp",
                    **context,
                    session_id=session_id,
                    trace_id=trace_id
                )
            return Response("", status_code=204)
        
        # Handle GET for SSE stream
        if method == "GET":
            log_info(
                f"Creating SSE stream for {context['client_hostname']}",
                component="mcp",
                **context,
                session_id=session_id,
                trace_id=trace_id
            )
            
            # Create generator and log it
            generator = self._sse_stream(session_id, trace_id, context)
            log_debug(
                f"Created SSE generator for {context['client_hostname']}",
                component="mcp",
                **context,
                session_id=session_id,
                trace_id=trace_id
            )
            
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
            log_info(
                f"SSE stream started for {context['client_hostname']}",
                component="mcp",
                **context,
                session_id=session_id,
                trace_id=trace_id
            )
            return response
        
        # Handle POST for JSON-RPC
        if method == "POST":
            body = await request.json()
            
            # CRITICAL DEBUG: Log the exact request from Claude.ai
            if context.get("is_claude"):
                log_info(
                    f"🤖 Claude.ai POST request - Method: {body.get('method', 'NONE')}",
                    component="mcp",
                    **context,
                    session_id=session_id,
                    trace_id=trace_id,
                    request_method=body.get('method'),
                    has_id=('id' in body),
                    has_params=('params' in body)
                )
            
            # Check if this is a notification (no id field) 
            # Per MCP spec: notifications MUST return 202 Accepted with no body
            method_name = body.get("method", "")
            
            # DEBUG: Track what methods are being called
            log_debug(
                f"Processing {method_name} from {context['client_hostname']}",
                component="mcp",
                **context,
                session_id=session_id,
                is_notification=("id" not in body),
                method_name=method_name
            )
            
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
                        log_info(
                            f"Client ready notification from {context['client_hostname']}",
                            component="mcp",
                            **context,
                            session_id=session_id,
                            trace_id=trace_id
                        )
                        
                        # CRITICAL: Send proactive tool announcement for Claude.ai
                        # Claude.ai expects tools to be pushed, not pulled
                        if session_id in self.sse_connections:
                            log_info(
                                f"🔧 PROACTIVELY sending tool list to {context['client_hostname']} (Claude.ai compatibility)",
                                component="mcp",
                                **context,
                                session_id=session_id,
                                tools_count=len(self.tools)
                            )
                            
                            # Create tools notification with all available tools
                            tools_notification = {
                                "jsonrpc": "2.0",
                                "method": "notifications/tools/list",
                                "params": {
                                    "tools": [
                                        {
                                            "name": name,
                                            "description": tool["description"],
                                            "inputSchema": tool["inputSchema"]
                                        }
                                        for name, tool in self.tools.items()
                                    ]
                                }
                            }
                            
                            try:
                                await self.sse_connections[session_id].put(tools_notification)
                                log_info(
                                    f"✅ Proactively sent {len(self.tools)} tools to {context['client_hostname']}",
                                    component="mcp",
                                    **context,
                                    session_id=session_id
                                )
                            except Exception as e:
                                log_error(
                                    f"Failed to send proactive tools to {session_id}: {e}",
                                    component="mcp",
                                    **context
                                )
                
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
                        log_info(
                            f"Session not found for {context['client_hostname']}: {provided_session_id}",
                            component="mcp",
                            **context,
                            trace_id=trace_id
                        )
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
            
            result = await self._handle_jsonrpc(body, session_id, trace_id, context)
            
            # Handle notification responses (no ID = notification)
            if result is None:
                # This was a notification that shouldn't return a body
                return Response(
                    "",
                    status_code=202,
                    headers={
                        "Mcp-Session-Id": session_id,
                        "Cache-Control": "no-cache, no-store, must-revalidate",
                        "X-Content-Type-Options": "nosniff",
                        "Access-Control-Allow-Origin": "*.anthropic.com"
                    }
                )
            
            # DEBUG: Log what we're returning to Claude.ai
            if context.get("is_claude") and result and "result" in result:
                if method_name == "tools/list":
                    tools_in_result = len(result.get("result", {}).get("tools", []))
                    log_info(
                        f"🤖✅ Returning {tools_in_result} tools to Claude.ai",
                        component="mcp",
                        **context,
                        session_id=session_id,
                        tools_count=tools_in_result
                    )
            
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
    
    async def handle_debug(self, request):
        """Debug endpoint to verify MCP server state."""
        try:
            # Get request context
            context = await self._get_request_context(request)
            
            # Get session information
            session_keys = await self.storage.redis_client.keys("mcp:session:*")
            session_count = len(session_keys)
            
            # Get recent sessions (last 5)
            recent_sessions = []
            for key in session_keys[:5]:
                session_data = await self.storage.redis_client.get(key)
                if session_data:
                    try:
                        data = json.loads(session_data)
                        recent_sessions.append({
                            "id": data.get("id", "unknown")[:20] + "...",
                            "created": data.get("created", "unknown"),
                            "initialized": data.get("initialized", False),
                            "ready": data.get("ready", False)
                        })
                    except:
                        pass
            
            # Build debug response
            debug_info = {
                "status": "operational",
                "request_context": context,
                "tools": {
                    "registered": len(self.tools),
                    "names": list(self.tools.keys())
                },
                "sessions": {
                    "total": session_count,
                    "active_streams": len(self.sse_connections),
                    "recent": recent_sessions
                },
                "server_info": {
                    "name": "OAuth-HTTPS-Proxy-MCP",
                    "version": "3.0.0",
                    "protocol_versions": ["2025-06-18", "2025-03-26", "2024-11-05"]
                },
                "endpoints": {
                    "main": "/mcp",
                    "debug": "/mcp/debug"
                }
            }
            
            # Log debug access
            log_info(
                f"MCP debug accessed from {context['client_hostname']}",
                component="mcp",
                **context
            )
            
            return Response(
                json.dumps(debug_info, indent=2),
                media_type="application/json",
                headers={
                    "Cache-Control": "no-cache, no-store, must-revalidate",
                    "X-Content-Type-Options": "nosniff"
                }
            )
            
        except Exception as e:
            log_error(f"MCP debug error: {e}", component="mcp", exc_info=True)
            return Response(
                json.dumps({"error": str(e)}),
                status_code=500,
                media_type="application/json"
            )
    
    async def _handle_jsonrpc(self, message, session_id, trace_id, context):
        """Handle JSON-RPC with proper error handling and logging."""
        # Validate JSON-RPC 2.0 compliance
        jsonrpc_version = message.get("jsonrpc")
        msg_id = message.get("id")
        
        # JSON-RPC 2.0 requires "jsonrpc": "2.0" field in all requests
        if jsonrpc_version != "2.0":
            log_warning(
                f"Invalid jsonrpc field from {context['client_hostname']}: {jsonrpc_version}",
                component="mcp",
                **context,
                trace_id=trace_id
            )
            return {
                "jsonrpc": "2.0",
                "id": msg_id if msg_id is not None else None,
                "error": {
                    "code": -32600,  # Invalid Request per JSON-RPC spec
                    "message": "Invalid Request: missing or incorrect 'jsonrpc' field. Must be '2.0'"
                }
            }
        
        method = message.get("method")
        
        # Method is required for all JSON-RPC requests
        if not method:
            return {
                "jsonrpc": "2.0",
                "id": msg_id if msg_id is not None else None,
                "error": {
                    "code": -32600,  # Invalid Request
                    "message": "Invalid Request: 'method' field is required"
                }
            }
        
        # Handle params - should be object or array (we accept missing as empty object)
        params = message.get("params", {})
        if params is None:
            params = {}
        
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
                log_warning(
                    f"Session {session_id} doesn't exist for {context['client_hostname']}, method: {method}",
                    component="mcp",
                    **context
                )
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
                    log_warning(
                        f"Unknown protocol version from {context['client_hostname']}: {requested_version}, using {protocol_version}",
                        component="mcp",
                        **context
                    )
                
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
                session_data["methods_called"] = session_data.get("methods_called", []) + ["initialize"]
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
                
                if is_claude_client or context.get("is_claude"):
                    log_info(
                        f"🤖 Claude.ai session initialized from {context['client_hostname']}",
                        component="mcp",
                        **context,
                        session_id=session_id,
                        protocol=protocol_version,
                        client=client_name,
                        trace_id=trace_id
                    )
                else:
                    log_info(
                        f"Session initialized from {context['client_hostname']}",
                        component="mcp",
                        **context,
                        session_id=session_id,
                        protocol=protocol_version,
                        client=client_name,
                        trace_id=trace_id
                    )
            
            elif method == "tools/list":
                # Track that tools/list was called
                if session_data:
                    session_data["methods_called"] = session_data.get("methods_called", []) + ["tools/list"]
                    await self.storage.redis_client.setex(
                        session_key,
                        self.session_ttl,
                        json.dumps(session_data)
                    )
                # Log tools list request with ENHANCED logging for debugging
                # Detect if this is Claude.ai requesting tools
                is_claude_request = session_data.get("client_info", {}).get("name", "").lower() in ["anthropic/claudeai", "claude"]
                
                if is_claude_request or context.get("is_claude"):
                    log_info(
                        f"🤖 Claude.ai EXPLICITLY requesting tools from {context['proxy_hostname']} - found {len(self.tools)} tools",
                        component="mcp",
                        **context,
                        trace_id=trace_id,
                        session_id=session_id,
                        tools_count=len(self.tools),
                        tool_names=list(self.tools.keys())
                    )
                else:
                    log_info(
                        f"Tools list requested from {context['client_hostname']} at {context['proxy_hostname']} - found {len(self.tools)} tools",
                        component="mcp",
                        **context,
                        trace_id=trace_id,
                        session_id=session_id,
                        tools_count=len(self.tools),
                        tool_names=list(self.tools.keys())
                    )
                
                # CRITICAL DEBUG: Log exactly what we're about to return
                log_info(
                    f"📋 SENDING TOOLS RESPONSE with {len(self.tools)} tools to {context['client_hostname']}",
                    component="mcp",
                    **context,
                    trace_id=trace_id,
                    session_id=session_id,
                    first_5_tools=list(self.tools.keys())[:5] if self.tools else []
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
                    f"Returning {len(result['tools'])} tools to {context['client_hostname']} at {context['proxy_hostname']}",
                    component="mcp",
                    **context,
                    trace_id=trace_id,
                    session_id=session_id,
                    response_size=len(json.dumps(result))
                )
            
            elif method == "tools/call":
                tool_name = params["name"]
                tool_args = params.get("arguments", {})
                
                # Log tool call
                log_info(
                    f"Tool '{tool_name}' called by {context['client_hostname']} at {context['proxy_hostname']}",
                    component="mcp",
                    **context,
                    tool=tool_name,
                    tool_args=tool_args,
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
            
            elif method == "prompts/list":
                # Track that prompts/list was called
                if session_data:
                    session_data["methods_called"] = session_data.get("methods_called", []) + ["prompts/list"]
                    await self.storage.redis_client.setex(
                        session_key,
                        self.session_ttl,
                        json.dumps(session_data)
                    )
                    
                    # CRITICAL: Log the method sequence to understand Claude.ai's behavior
                    methods_sequence = session_data.get("methods_called", [])
                    log_info(
                        f"🔍 Claude.ai method sequence so far: {' -> '.join(methods_sequence)}",
                        component="mcp",
                        **context,
                        trace_id=trace_id,
                        session_id=session_id,
                        methods_called=methods_sequence,
                        has_called_tools_list=("tools/list" in methods_sequence)
                    )
                
                # Return empty prompts list (we don't have prompts)
                log_info(
                    f"Prompts list requested from {context['client_hostname']} - returning empty list",
                    component="mcp",
                    **context,
                    trace_id=trace_id,
                    session_id=session_id
                )
                result = {
                    "prompts": []  # Empty list since we don't have prompts
                }
            
            elif method == "resources/list":
                # Return empty resources list (we don't have resources)
                log_info(
                    f"Resources list requested from {context['client_hostname']} - returning empty list",
                    component="mcp",
                    **context,
                    trace_id=trace_id,
                    session_id=session_id
                )
                result = {
                    "resources": []  # Empty list since we don't have resources
                }
            
            elif method == "ping":
                # Keepalive ping
                result = {"pong": True}
            
            else:
                # Unknown method - return proper JSON-RPC error
                return {
                    "jsonrpc": "2.0",
                    "id": msg_id,
                    "error": {
                        "code": -32601,  # Method not found
                        "message": f"Method not found: {method}"
                    }
                }
            
            # Return success response
            # If no ID provided (notification), don't return a response per JSON-RPC spec
            if msg_id is None:
                # This is a notification - no response should be sent
                # Signal to caller to return 202 with no body
                return None  # This will be handled by the caller
            
            return {
                "jsonrpc": "2.0",
                "id": msg_id if msg_id is not None else None,
                "result": result
            }
            
        except ValueError as e:
            # Application-level errors (e.g., tool not found)
            log_warning(
                f"MCP application error from {context['client_hostname']}: {e}",
                component="mcp",
                **context,
                trace_id=trace_id,
                mcp_method=method,
                error=str(e)
            )
            return {
                "jsonrpc": "2.0",
                "id": msg_id if msg_id is not None else None,
                "error": {
                    "code": -32602,  # Invalid params
                    "message": str(e)
                }
            }
        except Exception as e:
            log_error(
                f"MCP internal error from {context['client_hostname']}: {e}",
                component="mcp",
                **context,
                trace_id=trace_id,
                mcp_method=method,  # Renamed to avoid conflict with context['method']
                error=str(e)
            )
            await self._publish_event("mcp_error", {
                "session_id": session_id,
                "method": method,
                "error": str(e)
            })
            return {
                "jsonrpc": "2.0",
                "id": msg_id if msg_id is not None else None,
                "error": {
                    "code": -32603,  # Internal error
                    "message": "Internal error",
                    "data": str(e)
                }
            }
    
    async def _sse_stream(self, session_id, trace_id, context):
        """Generate SSE keepalive stream with listChanged notification support."""
        log_info(
            f"SSE stream started for {context['client_hostname']} at {context['proxy_hostname']}",
            component="mcp",
            **context,
            session_id=session_id,
            trace_id=trace_id
        )
        
        # Create notification queue for this session
        notification_queue = asyncio.Queue()
        self.sse_connections[session_id] = notification_queue
        
        try:
            # Send initial hello with tool count for Claude.ai
            hello_data = {
                "type": "hello",
                "session_id": session_id,
                "tools_available": len(self.tools),
                "server": "OAuth-HTTPS-Proxy-MCP v3.0.0"
            }
            hello_msg = f"data: {json.dumps(hello_data)}\n\n"
            log_debug(f"SSE yielding hello with {len(self.tools)} tools for {context['client_hostname']}", component="mcp", **context, session_id=session_id)
            yield hello_msg.encode('utf-8')
            log_debug(f"SSE sent hello to {context['client_hostname']}", component="mcp", **context, session_id=session_id)
            
            # Force immediate flush with multiple newlines and a comment
            # This helps ensure the proxy flushes the data immediately
            yield b"\n\n: init\n\n"
            log_debug(f"SSE sent init flush", component="mcp", session_id=session_id)
            
            # CRITICAL: Immediately send tools announcement for Claude.ai
            # Claude.ai may not call tools/list explicitly
            if len(self.tools) > 0:
                tools_announcement = {
                    "jsonrpc": "2.0",
                    "method": "notifications/tools/available",
                    "params": {
                        "count": len(self.tools),
                        "tools": [
                            {
                                "name": name,
                                "description": tool["description"][:100]  # Brief description
                            }
                            for name, tool in list(self.tools.items())[:5]  # First 5 as preview
                        ],
                        "message": f"{len(self.tools)} tools available. Call tools/list for complete details."
                    }
                }
                announcement_msg = f"data: {json.dumps(tools_announcement)}\n\n"
                yield announcement_msg.encode('utf-8')
                
                log_info(
                    f"🔔 PROACTIVELY announced {len(self.tools)} tools availability to {context['client_hostname']} via SSE",
                    component="mcp",
                    **context,
                    session_id=session_id,
                    tools_sent=list(self.tools.keys())[:5]
                )
            
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
            log_info(
                f"SSE stream cancelled for {context['client_hostname']} after {keep_alive_count} keepalives",
                component="mcp",
                **context,
                session_id=session_id,
                trace_id=trace_id
            )
            raise
        except Exception as e:
            log_error(
                f"SSE stream error for {context['client_hostname']}: {e}",
                component="mcp",
                **context,
                session_id=session_id,
                trace_id=trace_id,
                exc_info=True
            )
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