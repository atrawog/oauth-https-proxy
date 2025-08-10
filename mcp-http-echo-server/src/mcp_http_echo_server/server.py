"""MCP Echo Server with dual-mode (stateful/stateless) support using FastMCP."""

import os
import logging
from typing import Optional
from fastmcp import FastMCP

from .session_manager import SessionManager
from .utils.state_adapter import StateAdapter
from .tools.echo_tools import register_echo_tools
from .tools.debug_tools import register_debug_tools
from .tools.auth_tools import register_auth_tools
from .tools.system_tools import register_system_tools
from .tools.state_tools import register_state_tools

logger = logging.getLogger(__name__)


class MCPEchoServer:
    """Dual-mode MCP Echo Server with comprehensive debugging tools."""
    
    SERVER_NAME = "mcp-http-echo-server"
    SERVER_VERSION = "1.0.0"
    PROTOCOL_VERSION = "2025-06-18"
    
    def __init__(
        self,
        stateless_mode: bool = False,
        session_timeout: int = 3600,
        debug: bool = False,
        supported_versions: Optional[list[str]] = None
    ):
        """Initialize the MCP Echo Server.
        
        Args:
            stateless_mode: Run in stateless mode (no session persistence)
            session_timeout: Session timeout in seconds (stateful mode only)
            debug: Enable debug logging
            supported_versions: List of supported protocol versions
        """
        self.stateless_mode = stateless_mode
        self.debug = debug
        self.supported_versions = supported_versions or [self.PROTOCOL_VERSION]
        self.session_timeout = session_timeout
        
        # Create FastMCP instance
        mode_desc = "stateless" if stateless_mode else "stateful"
        self.mcp = FastMCP(
            name=self.SERVER_NAME,
            version=self.SERVER_VERSION,
            instructions=f"""A {mode_desc} MCP echo server with 21 comprehensive debugging tools.
            
Mode: {'STATELESS - No session persistence' if stateless_mode else 'STATEFUL - Full session management'}
Protocol: {', '.join(self.supported_versions)}
            
Available tool categories:
- Echo Tools: echo, replayLastEcho
- Debug Tools: printHeader, requestTiming, corsAnalysis, environmentDump
- Auth Tools: bearerDecode, authContext, whoIStheGOAT
- System Tools: healthProbe, sessionInfo
- State Tools: stateInspector, sessionHistory, stateManipulator, sessionCompare, 
               sessionTransfer, stateBenchmark, sessionLifecycle, stateValidator,
               requestTracer, modeDetector"""
        )
        
        # Initialize session manager for stateful mode
        self.session_manager = None if stateless_mode else SessionManager(session_timeout)
        
        # Register middleware
        self._register_middleware()
        
        # Register all tools
        self._register_tools()
        
        if debug:
            logger.info(
                "MCP Echo Server initialized in %s mode",
                "STATELESS" if stateless_mode else "STATEFUL"
            )
    
    def _register_middleware(self):
        """Register middleware for request processing."""
        from fastmcp.server.middleware import Middleware
        import time
        import uuid
        
        # Create custom middleware class for mode-specific behavior
        class ModeMiddleware(Middleware):
            def __init__(self, server_instance):
                self.server = server_instance
                super().__init__()
            
            async def on_message(self, ctx, call_next):
                """Set up mode-specific behavior and request context."""
                # Set mode and server config in context
                ctx.set_state("stateless_mode", self.server.stateless_mode)
                ctx.set_state("server_debug", self.server.debug)
                ctx.set_state("server_name", self.server.SERVER_NAME)
                ctx.set_state("server_version", self.server.SERVER_VERSION)
                ctx.set_state("supported_versions", self.server.supported_versions)
                
                # Store request-scoped data (works in both modes)
                ctx.set_state("request_start_time", time.time())
                request_id = str(uuid.uuid4())
                if hasattr(ctx, "request_id") and ctx.request_id:
                    request_id = ctx.request_id
                ctx.set_state("request_id", request_id)
                
                # Extract and store headers if available
                if hasattr(ctx, "_request") and hasattr(ctx._request, "headers"):
                    headers = dict(ctx._request.headers)
                    ctx.set_state("request_headers", headers)
                
                if not self.server.stateless_mode and self.server.session_manager:
                    # Stateful mode: manage sessions
                    session_id = None
                    
                    # Try to get session ID from headers or context
                    if hasattr(ctx, "session_id") and ctx.session_id:
                        session_id = ctx.session_id
                    elif hasattr(ctx, "_request") and hasattr(ctx._request, "headers"):
                        session_id = ctx._request.headers.get("mcp-session-id")
                    
                    # Create or get session
                    if not session_id:
                        session_id = self.server.session_manager.create_session()
                        if self.server.debug:
                            logger.debug(f"Created new session: {session_id}")
                    
                    # Store session ID in context
                    ctx.set_state("session_id", session_id)
                    
                    # Update session activity
                    session = self.server.session_manager.get_session(session_id)
                    if session:
                        session["last_activity"] = time.time()
                        session["request_count"] = session.get("request_count", 0) + 1
                        
                        # Store session data in context for easy access
                        ctx.set_state(f"session_{session_id}_data", session)
                
                # Track request in history (for both modes)
                await self.server._track_request(ctx)
                
                # Call next handler
                result = await call_next(ctx)
                
                # Track response
                await self.server._track_response(ctx, result)
                
                return result
        
        # Create error handling middleware class
        class ErrorHandlingMiddleware(Middleware):
            def __init__(self, server_instance):
                self.server = server_instance
                super().__init__()
            
            async def on_message(self, ctx, call_next):
                """Handle errors gracefully."""
                try:
                    return await call_next(ctx)
                except Exception as e:
                    logger.error(f"Error processing request: {e}", exc_info=True)
                    
                    # Track error in context
                    errors = ctx.get_state("request_errors", [])
                    errors.append({
                        "error": str(e),
                        "type": type(e).__name__,
                        "timestamp": time.time()
                    })
                    ctx.set_state("request_errors", errors)
                    
                    raise
        
        # Add middleware to the FastMCP server
        self.mcp.add_middleware(ModeMiddleware(self))
        self.mcp.add_middleware(ErrorHandlingMiddleware(self))
    
    async def _track_request(self, ctx):
        """Track request in history."""
        import time
        
        # Build request event
        event = {
            "timestamp": time.time(),
            "event": "request_received",
            "request_id": ctx.get_state("request_id"),
            "mode": "stateless" if self.stateless_mode else "stateful"
        }
        
        # Add session info if stateful
        if not self.stateless_mode:
            event["session_id"] = ctx.get_state("session_id")
        
        # Store in appropriate history
        if self.stateless_mode:
            # In stateless mode, only track in request scope
            ctx.set_state("request_history", [event])
        else:
            # In stateful mode, add to session history
            history = await StateAdapter.get_state(ctx, "session_history", [])
            history.append(event)
            await StateAdapter.set_state(ctx, "session_history", history)
    
    async def _track_response(self, ctx, result):
        """Track response in history."""
        import time
        
        # Calculate timing
        start_time = ctx.get_state("request_start_time")
        elapsed = (time.time() - start_time) * 1000 if start_time else 0
        
        # Build response event
        event = {
            "timestamp": time.time(),
            "event": "response_sent",
            "request_id": ctx.get_state("request_id"),
            "elapsed_ms": elapsed
        }
        
        # Add to history if stateful
        if not self.stateless_mode:
            history = await StateAdapter.get_state(ctx, "session_history", [])
            history.append(event)
            await StateAdapter.set_state(ctx, "session_history", history)
    
    def _register_tools(self):
        """Register all tools with the server."""
        # Register tool groups
        register_echo_tools(self.mcp, self.stateless_mode)
        register_debug_tools(self.mcp, self.stateless_mode)
        register_auth_tools(self.mcp, self.stateless_mode)
        register_system_tools(self.mcp, self.stateless_mode, self.session_manager)
        register_state_tools(self.mcp, self.stateless_mode)
        
        if self.debug:
            # Count registered tools
            tool_count = len(self.mcp._tools) if hasattr(self.mcp, "_tools") else 0
            logger.info(f"Registered {tool_count} tools")
    
    def run(
        self,
        host: str = "0.0.0.0",
        port: int = 3000,
        transport: str = "http",
        **kwargs
    ):
        """Run the MCP server.
        
        Args:
            host: Host to bind to
            port: Port to bind to
            transport: Transport type (http, stdio, sse)
            **kwargs: Additional transport-specific options
        """
        logger.info(
            "Starting %s in %s mode on %s:%d with %s transport",
            self.SERVER_NAME,
            "STATELESS" if self.stateless_mode else "STATEFUL",
            host,
            port,
            transport
        )
        
        # Configure transport options
        transport_options = {
            "host": host,
            "port": port,
            **kwargs
        }
        
        # For HTTP transport, set stateless mode
        if transport == "http":
            transport_options["stateless_http"] = self.stateless_mode
        
        # Run the server
        self.mcp.run(
            transport=transport,
            **transport_options
        )


def create_server(
    stateless_mode: bool = False,
    session_timeout: int = 3600,
    debug: bool = False,
    supported_versions: Optional[list[str]] = None
) -> MCPEchoServer:
    """Factory function to create an MCP Echo Server instance.
    
    Args:
        stateless_mode: Run in stateless mode
        session_timeout: Session timeout in seconds
        debug: Enable debug logging
        supported_versions: List of supported protocol versions
    
    Returns:
        MCPEchoServer instance
    """
    return MCPEchoServer(
        stateless_mode=stateless_mode,
        session_timeout=session_timeout,
        debug=debug,
        supported_versions=supported_versions
    )