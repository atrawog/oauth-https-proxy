"""MCP module - Clean integration with codebase patterns."""

import asyncio
import json
import sys
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
        # Use multiple logging methods for visibility
        separator = "=" * 60
        log_info(separator, component="mcp")
        log_info("MCP SERVER INITIALIZATION STARTING", component="mcp")
        log_info(separator, component="mcp")
        
        # Also print to stderr for Docker logs
        print(f"\n{separator}", file=sys.stderr, flush=True)
        print(f"MCP SERVER INITIALIZATION STARTING at {datetime.now(timezone.utc).isoformat()}", file=sys.stderr, flush=True)
        print(separator, file=sys.stderr, flush=True)
        
        # Initialize server with proper dependencies
        server = init_mcp_server(storage, unified_logger)
        log_info(f"MCP server instance created successfully", component="mcp")
        
        # Setup all tools
        log_info("Registering MCP tools...", component="mcp")
        tool_count = tools.setup_tools(server)
        
        # Get tool names after registration
        tool_names = list(server.tools.keys()) if server.tools else []
        
        # Log detailed tool registration with enhanced visibility
        log_info("=" * 60, component="mcp")
        log_info(f"MCP TOOLS REGISTERED: {tool_count} tools", component="mcp")
        log_info("=" * 60, component="mcp")
        
        # Print to stderr for visibility
        print(f"\n{separator}", file=sys.stderr, flush=True)
        print(f"🔧 MCP TOOLS REGISTERED: {tool_count} tools", file=sys.stderr, flush=True)
        print(separator, file=sys.stderr, flush=True)
        
        # Log each tool name individually for clarity
        if tool_names:
            for i, name in enumerate(tool_names, 1):
                log_info(f"  {i:2d}. {name}", component="mcp", tool_name=name)
                if i <= 5:  # Print first 5 to stderr for visibility
                    print(f"  {i:2d}. {name}", file=sys.stderr, flush=True)
            if len(tool_names) > 5:
                print(f"  ... and {len(tool_names) - 5} more tools", file=sys.stderr, flush=True)
        else:
            log_error("  ❌ NO TOOLS REGISTERED!", component="mcp")
            print("  ❌ NO TOOLS REGISTERED!", file=sys.stderr, flush=True)
        
        log_info("=" * 60, component="mcp")
        
        # Verify tools are actually registered
        if not server.tools:
            log_error("CRITICAL: No tools registered with MCP server!", component="mcp")
            log_error("This will prevent Claude.ai from seeing any tools!", component="mcp")
        else:
            log_info(f"✅ All {tool_count} tools successfully registered and ready", component="mcp")
        
        # Create ASGI wrapper instead of mounting directly
        from .asgi_wrapper import MCPASGIWrapper
        wrapper = MCPASGIWrapper(app, server.app)
        log_info("Created ASGI wrapper to bypass FastAPI middleware", component="mcp")
        
        log_info("=" * 60, component="mcp")
        log_info("✅ MCP SERVER READY AT /mcp", component="mcp")
        log_info(f"✅ {tool_count} tools available for LLM integration", component="mcp")
        log_info("=" * 60, component="mcp")
        
        # Print final status to stderr
        print(f"{separator}", file=sys.stderr, flush=True)
        print(f"✅ MCP SERVER READY AT /mcp", file=sys.stderr, flush=True)
        print(f"✅ {tool_count} tools available for LLM integration", file=sys.stderr, flush=True)
        print(f"{separator}\n", file=sys.stderr, flush=True)
        
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