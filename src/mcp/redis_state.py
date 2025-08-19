"""Redis-backed state management for MCP server."""

import json
import logging
import time
from typing import Any, Dict, List, Optional

from src.storage.async_redis_storage import AsyncRedisStorage

logger = logging.getLogger(__name__)


class RedisStateManager:
    """Manage MCP state in Redis with session support."""
    
    def __init__(
        self,
        storage: AsyncRedisStorage,
        stateless_mode: bool = False,
        session_timeout: int = 3600
    ):
        """Initialize Redis state manager.
        
        Args:
            storage: AsyncRedisStorage instance
            stateless_mode: Whether to run in stateless mode
            session_timeout: Session timeout in seconds
        """
        self.storage = storage
        self.stateless_mode = stateless_mode
        self.session_timeout = session_timeout
        
        # Key prefixes for different storage scopes
        self.session_prefix = "mcp:session"
        self.request_prefix = "mcp:request"
        self.state_prefix = "mcp:state"
        
        logger.debug(
            "RedisStateManager initialized (mode=%s, timeout=%d)",
            "stateless" if stateless_mode else "stateful",
            session_timeout
        )
    
    def _get_key_prefix(self, session_id: str) -> str:
        """Get the appropriate key prefix based on mode."""
        if self.stateless_mode:
            return f"{self.request_prefix}:{session_id}"
        return f"{self.session_prefix}:{session_id}"
    
    async def get_state(
        self,
        session_id: str,
        key: str,
        default: Any = None
    ) -> Any:
        """Get state value from Redis.
        
        Args:
            session_id: Session or request ID
            key: State key
            default: Default value if key not found
            
        Returns:
            State value or default
        """
        redis_key = f"{self._get_key_prefix(session_id)}:{key}"
        
        try:
            value = await self.storage.redis_client.get(redis_key)
            if value:
                # Try to deserialize JSON
                try:
                    return json.loads(value)
                except (json.JSONDecodeError, TypeError):
                    # Return as string if not JSON
                    return value
        except Exception as e:
            logger.error(f"Error getting state for {redis_key}: {e}")
        
        return default
    
    async def set_state(
        self,
        session_id: str,
        key: str,
        value: Any
    ) -> bool:
        """Set state value in Redis.
        
        Args:
            session_id: Session or request ID
            key: State key
            value: State value
            
        Returns:
            True if successful
        """
        redis_key = f"{self._get_key_prefix(session_id)}:{key}"
        
        # Determine TTL based on mode
        if self.stateless_mode:
            ttl = 300  # 5 minutes for request state
        else:
            ttl = self.session_timeout
        
        try:
            # Serialize value if needed
            if isinstance(value, (dict, list, tuple)):
                value = json.dumps(value)
            elif value is None:
                value = "null"
            else:
                value = str(value)
            
            result = await self.storage.redis_client.set(redis_key, value, ex=ttl)
            return result
        except Exception as e:
            logger.error(f"Error setting state for {redis_key}: {e}")
            return False
    
    async def delete_state(
        self,
        session_id: str,
        key: str
    ) -> bool:
        """Delete state value from Redis.
        
        Args:
            session_id: Session or request ID
            key: State key
            
        Returns:
            True if key was deleted
        """
        redis_key = f"{self._get_key_prefix(session_id)}:{key}"
        
        try:
            result = await self.storage.redis_client.delete(redis_key)
            return result > 0
        except Exception as e:
            logger.error(f"Error deleting state for {redis_key}: {e}")
            return False
    
    async def list_state_keys(
        self,
        session_id: str
    ) -> List[str]:
        """List all state keys for a session.
        
        Args:
            session_id: Session or request ID
            
        Returns:
            List of state keys
        """
        pattern = f"{self._get_key_prefix(session_id)}:*"
        
        try:
            keys = await self.storage.redis_client.keys(pattern)
            # Extract just the key names without prefix
            prefix_len = len(f"{self._get_key_prefix(session_id)}:")
            return [key[prefix_len:] for key in keys]
        except Exception as e:
            logger.error(f"Error listing state keys for {session_id}: {e}")
            return []
    
    async def clear_state(self, session_id: str) -> int:
        """Clear all state for a session.
        
        Args:
            session_id: Session or request ID
            
        Returns:
            Number of keys deleted
        """
        pattern = f"{self._get_key_prefix(session_id)}:*"
        
        try:
            keys = await self.storage.redis_client.keys(pattern)
            if keys:
                deleted = 0
                for key in keys:
                    result = await self.storage.redis_client.delete(key)
                    deleted += result
                return deleted
            return 0
        except Exception as e:
            logger.error(f"Error clearing state for {session_id}: {e}")
            return 0
    
    # Session management methods (for stateful mode)
    
    async def create_session(self, session_id: str) -> Dict[str, Any]:
        """Create a new session in Redis.
        
        Args:
            session_id: Session ID
            
        Returns:
            Session data
        """
        session_data = {
            "id": session_id,
            "created_at": time.time(),
            "last_accessed": time.time(),
            "state": {},
            "mode": "stateless" if self.stateless_mode else "stateful"
        }
        
        session_key = f"{self.session_prefix}:{session_id}"
        
        try:
            await self.storage.redis_client.set(
                session_key,
                json.dumps(session_data),
                ex=self.session_timeout
            )
            
            # Add to active sessions set
            await self.storage.redis_client.sadd("mcp:active_sessions", session_id)
            
            logger.debug(f"Created session: {session_id}")
            return session_data
        except Exception as e:
            logger.error(f"Error creating session {session_id}: {e}")
            return session_data
    
    async def get_session(self, session_id: str) -> Optional[Dict[str, Any]]:
        """Get session from Redis.
        
        Args:
            session_id: Session ID
            
        Returns:
            Session data or None
        """
        session_key = f"{self.session_prefix}:{session_id}"
        
        try:
            data = await self.storage.redis_client.get(session_key)
            if data:
                session = json.loads(data)
                
                # Update last accessed time
                session["last_accessed"] = time.time()
                await self.storage.redis_client.set(
                    session_key,
                    json.dumps(session),
                    ex=self.session_timeout
                )
                
                return session
        except Exception as e:
            logger.error(f"Error getting session {session_id}: {e}")
        
        return None
    
    async def delete_session(self, session_id: str) -> bool:
        """Delete a session and all its state.
        
        Args:
            session_id: Session ID
            
        Returns:
            True if session was deleted
        """
        try:
            # Clear all state
            await self.clear_state(session_id)
            
            # Delete session data
            session_key = f"{self.session_prefix}:{session_id}"
            result = await self.storage.redis_client.delete(session_key)
            
            # Remove from active sessions
            await self.storage.redis_client.srem("mcp:active_sessions", session_id)
            
            logger.debug(f"Deleted session: {session_id}")
            return result > 0
        except Exception as e:
            logger.error(f"Error deleting session {session_id}: {e}")
            return False
    
    async def list_active_sessions(self) -> List[str]:
        """List all active session IDs.
        
        Returns:
            List of session IDs
        """
        try:
            sessions = await self.storage.redis_client.smembers("mcp:active_sessions")
            return list(sessions) if sessions else []
        except Exception as e:
            logger.error(f"Error listing active sessions: {e}")
            return []
    
    async def get_session_count(self) -> int:
        """Get count of active sessions.
        
        Returns:
            Number of active sessions
        """
        try:
            count = await self.storage.redis_client.scard("mcp:active_sessions")
            return count or 0
        except Exception as e:
            logger.error(f"Error getting session count: {e}")
            return 0
    
    async def cleanup_expired_sessions(self) -> int:
        """Clean up expired sessions.
        
        Returns:
            Number of sessions cleaned up
        """
        cleaned = 0
        
        try:
            sessions = await self.list_active_sessions()
            for session_id in sessions:
                session_key = f"{self.session_prefix}:{session_id}"
                
                # Check if session still exists
                exists = await self.storage.redis_client.exists(session_key)
                if not exists:
                    # Remove from active set
                    await self.storage.redis_client.srem("mcp:active_sessions", session_id)
                    cleaned += 1
                    logger.debug(f"Cleaned up expired session: {session_id}")
        except Exception as e:
            logger.error(f"Error cleaning up sessions: {e}")
        
        return cleaned