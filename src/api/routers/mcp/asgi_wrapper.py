"""Minimal ASGI wrapper to intercept MCP requests before FastAPI.

This wrapper is needed to bypass the BaseHTTPMiddleware SSE bug by
intercepting /mcp requests at the ASGI level before they reach FastAPI.
"""

from ....shared.logger import log_info, log_debug


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
        log_info("MCPASGIWrapper initialized", component="mcp")
        
    async def __call__(self, scope, receive, send):
        """Route /mcp to MCP app, everything else to FastAPI.
        
        Args:
            scope: ASGI scope dictionary
            receive: ASGI receive callable
            send: ASGI send callable
        """
        # Log every request to see what's happening
        if scope["type"] == "http":
            path = scope.get("path", "unknown")
            method = scope.get("method", "unknown")
            log_info(f"ASGI Wrapper called: {method} {path}", component="mcp_wrapper")
        
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
            
            log_info(
                f"ASGI Wrapper intercepting {method} /mcp request",
                component="mcp_wrapper",
                method=method,
                session_id=session_id if session_id else None,
                user_agent=user_agent,
                accept=accept_header,
                content_type=content_type
            )
            
            # Modify scope to set path to / for the Starlette app
            mcp_scope = dict(scope)
            mcp_scope["path"] = "/"
            mcp_scope["raw_path"] = b"/"
            
            log_debug(f"Passing request to MCP app", component="mcp_wrapper")
            
            # Direct passthrough to MCP app - no buffering!
            await self.mcp_app(mcp_scope, receive, send)
            
            log_debug(f"MCP app finished handling request", component="mcp_wrapper")
        else:
            # Everything else goes to FastAPI
            await self.fastapi_app(scope, receive, send)