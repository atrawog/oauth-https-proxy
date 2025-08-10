"""Echo tools for MCP Echo Server."""

import logging
from fastmcp import FastMCP, Context
from ..utils.state_adapter import StateAdapter

logger = logging.getLogger(__name__)


def register_echo_tools(mcp: FastMCP, stateless_mode: bool):
    """Register echo-related tools.
    
    Args:
        mcp: FastMCP instance
        stateless_mode: Whether server is in stateless mode
    """
    
    @mcp.tool
    async def echo(ctx: Context, message: str) -> str:
        """Echo back the provided message with context information.
        
        Works in both stateful and stateless modes. In stateful mode,
        the message is stored for potential replay.
        
        Args:
            message: The message to echo back
            
        Returns:
            The echoed message with mode/session context
        """
        if not message:
            return "Please provide a message to echo"
        
        # Store for potential replay (only useful in stateful mode)
        await StateAdapter.set_state(ctx, "last_echo", message)
        
        # Track in history
        history = await StateAdapter.get_state(ctx, "echo_history", [])
        history.append({
            "message": message,
            "timestamp": ctx.get_state("request_start_time")
        })
        # Keep only last 10 echoes
        if len(history) > 10:
            history = history[-10:]
        await StateAdapter.set_state(ctx, "echo_history", history)
        
        # Format response based on mode
        mode = "stateless" if ctx.get_state("stateless_mode") else "stateful"
        
        if ctx.get_state("stateless_mode"):
            # Stateless mode - simple echo with mode indicator
            return f"[{mode}] {message}"
        else:
            # Stateful mode - include session context
            session_id = ctx.get_state("session_id")
            if session_id:
                # Get session data for additional context
                session_data = ctx.get_state(f"session_{session_id}_data", {})
                client_info = session_data.get("client_info", {})
                client_name = client_info.get("name", "unknown") if client_info else "unknown"
                
                return f"[{mode}:{session_id[:8]}...:{client_name}] {message}"
            else:
                return f"[{mode}:no-session] {message}"
    
    @mcp.tool
    async def replayLastEcho(ctx: Context) -> str:
        """Replay the last message that was echoed.
        
        This tool demonstrates stateful behavior - it only works
        in stateful mode where session history is maintained.
        
        Returns:
            The last echoed message or an appropriate error/info message
        """
        # Check if in stateless mode
        if ctx.get_state("stateless_mode"):
            return (
                "❌ Replay not available in stateless mode\n"
                "This tool requires session history which is only available in stateful mode.\n"
                "Start the server without --stateless flag to enable this feature."
            )
        
        # Get the last echo message from session state
        last_message = await StateAdapter.get_state(ctx, "last_echo")
        
        if not last_message:
            # Check if there's any echo history
            history = await StateAdapter.get_state(ctx, "echo_history", [])
            if history:
                # Use the last item from history
                last_message = history[-1]["message"]
            else:
                return (
                    "No previous echo message found in this session.\n"
                    "Use the 'echo' tool first to store a message for replay."
                )
        
        # Format the replay message with session context
        session_id = ctx.get_state("session_id")
        if session_id:
            session_data = ctx.get_state(f"session_{session_id}_data", {})
            client_info = session_data.get("client_info", {})
            client_name = client_info.get("name", "unknown") if client_info else "unknown"
            
            # Get echo count from history
            history = await StateAdapter.get_state(ctx, "echo_history", [])
            echo_count = len(history)
            
            return (
                f"[REPLAY - Session {session_id[:8]}... - {client_name}]\n"
                f"Last echo (#{echo_count}): {last_message}"
            )
        else:
            return f"[REPLAY] {last_message}"
    
    logger.debug(f"Registered echo tools (stateless_mode={stateless_mode})")