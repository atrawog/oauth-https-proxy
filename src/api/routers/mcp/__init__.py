"""MCP module - Clean integration with codebase patterns."""

import asyncio
import json
from datetime import datetime, timezone
from .server import init_mcp_server
from . import tools


def mount_mcp(app, storage, unified_logger):
    """Mount MCP with ASGI wrapper to bypass FastAPI middleware.
    
    Args:
        app: FastAPI application
        storage: UnifiedStorage instance
        unified_logger: UnifiedAsyncLogger instance
    
    Returns:
        MCPASGIWrapper that intercepts /mcp before FastAPI
    """
    from ....shared.logger import log_info, log_debug, log_error
    
    try:
        log_info("Initializing MCP server...", component="mcp")
        
        # Initialize server with proper dependencies
        server = init_mcp_server(storage, unified_logger)
        log_debug(f"MCP server created: {server}", component="mcp")
        
        # Setup all tools
        log_info("Setting up MCP tools...", component="mcp")
        tool_count = tools.setup_tools(server)
        log_info(f"Setup {tool_count} tools", component="mcp")
        
        # Log tool names
        tool_names = list(server.tools.keys()) if server.tools else []
        log_info(
            f"MCP server initialized with {tool_count} tools: {tool_names}",
            component="mcp",
            tools=tool_names[:10]  # Log first 10 tool names
        )
        
        # Verify tools are actually registered
        if not server.tools:
            log_error("WARNING: No tools registered with MCP server!", component="mcp")
        else:
            log_info(f"Tools successfully registered: {', '.join(tool_names)}", component="mcp")
        
        # Create ASGI wrapper instead of mounting directly
        from .asgi_wrapper import MCPASGIWrapper
        wrapper = MCPASGIWrapper(app, server.app)
        log_info("Created ASGI wrapper to bypass FastAPI middleware for /mcp", component="mcp")
        
        # Publish startup event (fire-and-forget)
        try:
            asyncio.create_task(
                storage.redis_client.xadd(
                    "events:system",
                    {"event": json.dumps({
                        "type": "mcp_started",
                        "tools_count": tool_count,
                        "timestamp": datetime.now(timezone.utc).isoformat()
                    })}
                )
            )
        except RuntimeError:
            # No event loop yet, that's OK
            log_debug("No event loop for Redis event publish", component="mcp")
        
        # Return the wrapper instead of the app
        return wrapper
        
    except Exception as e:
        log_error(f"Failed to create MCP wrapper: {e}", component="mcp", exc_info=True)
        raise


__all__ = ["mount_mcp"]