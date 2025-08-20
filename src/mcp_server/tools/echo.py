"""Echo tools for MCP server."""

import logging
import time
from typing import Optional

# Try to import from MCP SDK, fall back to simple implementation
try:
    from mcp.server import FastMCP
except ImportError:
    from ..simple_mcp import FastMCP

logger = logging.getLogger(__name__)


def register_echo_tools(mcp: FastMCP, context: dict):
    """Register echo-related tools.
    
    Args:
        mcp: FastMCP instance
        context: Dictionary containing dependencies (storage, logger, state_manager, etc.)
    """
    
    storage = context["storage"]
    unified_logger = context["logger"]
    state_manager = context["state_manager"]
    stateless_mode = context["stateless_mode"]
    
    @mcp.tool()
    async def echo(message: str, session_id: Optional[str] = None) -> str:
        """Echo back the provided message with context information.
        
        Works in both stateful and stateless modes. In stateful mode,
        the message is stored for potential replay.
        
        Args:
            message: The message to echo back
            session_id: Optional session ID (auto-generated if not provided)
            
        Returns:
            The echoed message with mode/session context
        """
        if not message:
            return "Please provide a message to echo"
        
        # Use provided session_id or generate one
        if not session_id:
            session_id = "default"
        
        # Store for potential replay (only useful in stateful mode)
        await state_manager.set_state(session_id, "last_echo", message)
        
        # Track in history
        history = await state_manager.get_state(session_id, "echo_history", [])
        history.append({
            "message": message,
            "timestamp": time.time()
        })
        
        # Keep only last 10 echoes
        if len(history) > 10:
            history = history[-10:]
        await state_manager.set_state(session_id, "echo_history", history)
        
        # Log event via unified logger
        await unified_logger.event("mcp_echo", {
            "session_id": session_id,
            "message": message,
            "mode": "stateless" if stateless_mode else "stateful"
        })
        
        # Format response based on mode
        mode = "stateless" if stateless_mode else "stateful"
        
        # In stateful mode, include session info
        if not stateless_mode:
            session_info = await state_manager.get_session(session_id)
            if not session_info:
                # Create session if it doesn't exist
                session_info = await state_manager.create_session(session_id)
            
            return f"[{mode}:{session_id[:8]}] Echo: {message}"
        else:
            return f"[{mode}] Echo: {message}"
    
    @mcp.tool()
    async def replayLastEcho(session_id: Optional[str] = None) -> str:
        """Replay the last echoed message.
        
        Only available in stateful mode. Returns an error message in stateless mode.
        
        Args:
            session_id: Optional session ID (uses 'default' if not provided)
            
        Returns:
            The last echoed message or an appropriate status message
        """
        if stateless_mode:
            return "replayLastEcho is not available in stateless mode"
        
        # Use provided session_id or default
        if not session_id:
            session_id = "default"
        
        # Get the last echo from state
        last_echo = await state_manager.get_state(session_id, "last_echo")
        
        if last_echo:
            # Log the replay event
            await unified_logger.event("mcp_replay_echo", {
                "session_id": session_id,
                "message": last_echo
            })
            
            return f"Replaying last echo from session {session_id[:8]}: {last_echo}"
        
        # Check if session exists
        session_info = await state_manager.get_session(session_id)
        if not session_info:
            return f"No session found with ID: {session_id}"
        
        return f"No previous echo found in session {session_id[:8]}"
    
    logger.info("Registered echo tools: echo, replayLastEcho")