"""State adapter for dual-mode (stateful/stateless) operation."""

import logging
from typing import Any, Optional
from fastmcp import Context

logger = logging.getLogger(__name__)


class StateAdapter:
    """Adapts state operations for both stateful and stateless modes."""
    
    @staticmethod
    async def get_state(
        ctx: Context,
        key: str,
        default: Any = None
    ) -> Any:
        """Get state with appropriate scoping for current mode.
        
        Args:
            ctx: FastMCP context
            key: State key
            default: Default value if key not found
            
        Returns:
            State value or default
        """
        is_stateless = ctx.get_state("stateless_mode", False)
        
        if is_stateless:
            # In stateless mode, use request-scoped state only
            return ctx.get_state(f"request_{key}", default)
        else:
            # In stateful mode, use session-scoped state
            session_id = ctx.get_state("session_id")
            if not session_id:
                logger.warning(f"No session ID available for stateful key: {key}")
                return default
            
            return ctx.get_state(f"session_{session_id}_{key}", default)
    
    @staticmethod
    async def set_state(
        ctx: Context,
        key: str,
        value: Any
    ) -> None:
        """Set state with appropriate scoping for current mode.
        
        Args:
            ctx: FastMCP context
            key: State key
            value: State value
        """
        is_stateless = ctx.get_state("stateless_mode", False)
        
        if is_stateless:
            # In stateless mode, store in request scope only
            ctx.set_state(f"request_{key}", value)
        else:
            # In stateful mode, store in session scope
            session_id = ctx.get_state("session_id")
            if not session_id:
                logger.warning(f"No session ID available for stateful key: {key}")
                # Fall back to request scope
                ctx.set_state(f"request_{key}", value)
            else:
                ctx.set_state(f"session_{session_id}_{key}", value)
    
    @staticmethod
    async def delete_state(
        ctx: Context,
        key: str
    ) -> bool:
        """Delete state with appropriate scoping for current mode.
        
        Args:
            ctx: FastMCP context
            key: State key
            
        Returns:
            True if deleted, False if not found
        """
        is_stateless = ctx.get_state("stateless_mode", False)
        
        if is_stateless:
            # In stateless mode, delete from request scope
            full_key = f"request_{key}"
        else:
            # In stateful mode, delete from session scope
            session_id = ctx.get_state("session_id")
            if not session_id:
                logger.warning(f"No session ID available for stateful key: {key}")
                return False
            full_key = f"session_{session_id}_{key}"
        
        # Check if key exists before deletion
        if ctx.get_state(full_key) is not None:
            # FastMCP doesn't have delete_state, so we set to None
            ctx.set_state(full_key, None)
            return True
        return False
    
    @staticmethod
    async def get_state_for_session(
        ctx: Context,
        session_id: str,
        key: str,
        default: Any = None
    ) -> Any:
        """Get state for a specific session (stateful mode only).
        
        Args:
            ctx: FastMCP context
            session_id: Target session ID
            key: State key
            default: Default value if key not found
            
        Returns:
            State value or default
        """
        if ctx.get_state("stateless_mode", False):
            logger.warning("get_state_for_session called in stateless mode")
            return default
        
        return ctx.get_state(f"session_{session_id}_{key}", default)
    
    @staticmethod
    async def set_state_for_session(
        ctx: Context,
        session_id: str,
        key: str,
        value: Any
    ) -> None:
        """Set state for a specific session (stateful mode only).
        
        Args:
            ctx: FastMCP context
            session_id: Target session ID
            key: State key
            value: State value
        """
        if ctx.get_state("stateless_mode", False):
            logger.warning("set_state_for_session called in stateless mode")
            return
        
        ctx.set_state(f"session_{session_id}_{key}", value)
    
    @staticmethod
    def list_state_keys(
        ctx: Context,
        pattern: Optional[str] = None
    ) -> list[str]:
        """List all state keys matching pattern.
        
        Args:
            ctx: FastMCP context
            pattern: Optional pattern to filter keys
            
        Returns:
            List of matching state keys
        """
        # Note: This would require access to internal state storage
        # which may not be directly available in FastMCP
        # This is a placeholder implementation
        logger.warning("list_state_keys is not fully implemented in FastMCP")
        return []
    
    @staticmethod
    async def clear_session_state(
        ctx: Context,
        session_id: Optional[str] = None
    ) -> int:
        """Clear all state for a session.
        
        Args:
            ctx: FastMCP context
            session_id: Session ID to clear (uses current if None)
            
        Returns:
            Number of keys cleared
        """
        if ctx.get_state("stateless_mode", False):
            logger.warning("clear_session_state called in stateless mode")
            return 0
        
        if not session_id:
            session_id = ctx.get_state("session_id")
        
        if not session_id:
            logger.warning("No session ID available for clearing state")
            return 0
        
        # This would require iteration over all keys
        # which may not be directly available in FastMCP
        logger.warning("clear_session_state is not fully implemented in FastMCP")
        return 0
    
    @staticmethod
    def get_scope_prefix(ctx: Context) -> str:
        """Get the current state scope prefix.
        
        Args:
            ctx: FastMCP context
            
        Returns:
            Scope prefix string
        """
        is_stateless = ctx.get_state("stateless_mode", False)
        
        if is_stateless:
            return "request_"
        else:
            session_id = ctx.get_state("session_id")
            if session_id:
                return f"session_{session_id}_"
            else:
                return "request_"  # Fallback to request scope