"""Minimal ASGI wrapper to intercept MCP requests before FastAPI.

This wrapper is needed to bypass the BaseHTTPMiddleware SSE bug by
intercepting /mcp requests at the ASGI level before they reach FastAPI.
"""

import sys
import json
from datetime import datetime
from ....shared.logger import log_info, log_debug, log_error, log_warning


class MCPASGIWrapper:
    """Minimal wrapper to intercept /mcp before FastAPI middleware."""
    
    def __init__(self, fastapi_app, mcp_starlette_app):
        """Initialize the wrapper.
        
        Args:
            fastapi_app: The main FastAPI application
            mcp_starlette_app: The MCP Starlette application
        """
        self.fastapi_app = fastapi_app
        self.mcp_app = mcp_starlette_app
        self.request_count = 0
        log_info("MCPASGIWrapper initialized", component="mcp")
        print(f"[{datetime.now().isoformat()}] MCPASGIWrapper initialized", file=sys.stderr, flush=True)
        
    async def __call__(self, scope, receive, send):
        """Route /mcp to MCP app, everything else to FastAPI.
        
        Args:
            scope: ASGI scope dictionary
            receive: ASGI receive callable
            send: ASGI send callable
        """
        # Increment request counter
        self.request_count += 1
        
        # Log every request to see what's happening - use multiple methods to ensure visibility
        if scope["type"] == "http":
            path = scope.get("path", "unknown")
            method = scope.get("method", "unknown")
            headers = dict(scope.get("headers", []))
            
            # Extract client info
            client = scope.get("client", ("unknown", 0))
            client_ip = client[0] if client else "unknown"
            
            # Extract key headers
            user_agent = headers.get(b"user-agent", b"").decode("utf-8", errors="ignore")
            session_id = headers.get(b"mcp-session-id", b"").decode("utf-8", errors="ignore")
            
            # Check if this might be Claude.ai
            is_claude = "Claude" in user_agent or "claude" in user_agent.lower() or "anthropic" in user_agent.lower()
            
            # Use multiple logging methods to ensure visibility
            log_msg = f"ASGI Request #{self.request_count}: {method} {path} from {client_ip}"
            if is_claude:
                log_msg = f"🤖 CLAUDE.AI {log_msg}"
            
            # Log to Redis-based logger
            log_info(log_msg, component="mcp_wrapper", 
                    path=path, method=method, client_ip=client_ip, 
                    user_agent=user_agent, session_id=session_id if session_id else None)
            
            # Also print to stderr for Docker logs
            print(f"[{datetime.now().isoformat()}] {log_msg}", file=sys.stderr, flush=True)
            if session_id:
                print(f"[{datetime.now().isoformat()}]   Session: {session_id[:20]}...", file=sys.stderr, flush=True)
            if is_claude:
                print(f"[{datetime.now().isoformat()}]   🚨 Claude.ai detected!", file=sys.stderr, flush=True)
        
        # Check if this is an /mcp request
        if scope["type"] == "http" and scope["path"] == "/mcp":
            # Log the interception
            method = scope.get("method", "UNKNOWN")
            headers = dict(scope.get("headers", []))
            
            # Extract key headers for logging
            session_id = headers.get(b"mcp-session-id", b"").decode("utf-8", errors="ignore")
            user_agent = headers.get(b"user-agent", b"").decode("utf-8", errors="ignore")
            accept_header = headers.get(b"accept", b"").decode("utf-8", errors="ignore")
            content_type = headers.get(b"content-type", b"").decode("utf-8", errors="ignore")
            
            # Enhanced logging for MCP interception
            interception_msg = f"🎯 MCP INTERCEPTED: {method} /mcp"
            if "Claude" in user_agent or "claude" in user_agent.lower():
                interception_msg = f"🤖 CLAUDE.AI {interception_msg}"
            
            log_info(
                interception_msg,
                component="mcp_wrapper",
                method=method,
                session_id=session_id if session_id else None,
                user_agent=user_agent,
                accept=accept_header,
                content_type=content_type
            )
            
            # Also print for visibility
            print(f"[{datetime.now().isoformat()}] {interception_msg}", file=sys.stderr, flush=True)
            print(f"[{datetime.now().isoformat()}]   Method: {method}", file=sys.stderr, flush=True)
            print(f"[{datetime.now().isoformat()}]   Session: {session_id if session_id else 'None'}", file=sys.stderr, flush=True)
            print(f"[{datetime.now().isoformat()}]   User-Agent: {user_agent[:50]}...", file=sys.stderr, flush=True)
            
            # Modify scope to set path to / for the Starlette app
            mcp_scope = dict(scope)
            mcp_scope["path"] = "/"
            mcp_scope["raw_path"] = b"/"
            
            log_debug(f"Passing request to MCP app", component="mcp_wrapper")
            print(f"[{datetime.now().isoformat()}]   -> Routing to MCP app", file=sys.stderr, flush=True)
            
            try:
                # Direct passthrough to MCP app - no buffering!
                await self.mcp_app(mcp_scope, receive, send)
                
                log_debug(f"MCP app finished handling request", component="mcp_wrapper")
                print(f"[{datetime.now().isoformat()}]   <- MCP app completed", file=sys.stderr, flush=True)
            except Exception as e:
                log_error(f"MCP app error: {e}", component="mcp_wrapper", exc_info=True)
                print(f"[{datetime.now().isoformat()}]   ❌ MCP ERROR: {e}", file=sys.stderr, flush=True)
                raise
        else:
            # Everything else goes to FastAPI
            await self.fastapi_app(scope, receive, send)