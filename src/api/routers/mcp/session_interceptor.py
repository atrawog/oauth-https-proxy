"""Session interceptor to bridge FastMCP sessions with Redis storage.

This module intercepts FastMCP's internal session management and ensures
sessions are properly stored in Redis and tracked via Redis Streams.
"""

import time
import json
import logging
from typing import Any, Dict, Optional

logger = logging.getLogger(__name__)


class MCPSessionInterceptor:
    """Intercepts and stores MCP sessions in Redis."""
    
    def __init__(self, session_manager, event_publisher):
        """Initialize the session interceptor.
        
        Args:
            session_manager: MCPSessionManager instance for Redis storage
            event_publisher: MCPEventPublisher for Redis Streams events
        """
        self.session_manager = session_manager
        self.event_publisher = event_publisher
        self.redis = session_manager.redis
        
    async def on_session_created(self, session_id: str, client_info: Dict[str, Any]):
        """Called when a new session is created by FastMCP.
        
        Args:
            session_id: The session ID created by FastMCP
            client_info: Information about the client
        """
        logger.info(f"[SESSION INTERCEPTOR] Session created: {session_id}")
        
        try:
            # Store session in Redis
            session_key = f"mcp:session:{session_id}"
            session_data = {
                "session_id": session_id,
                "created_at": str(time.time()),
                "last_activity": str(time.time()),
                "client_info": json.dumps(client_info),
                "state": "active",
                "initialized": "true"
            }
            
            # Store in Redis hash
            await self.redis.hset(session_key, mapping=session_data)
            await self.redis.expire(session_key, 3600)  # 1 hour TTL
            
            # Add to active sessions index
            await self.redis.zadd("mcp:session:index:active", {session_id: time.time()})
            
            # Publish to Redis Stream
            await self.redis.xadd(
                "stream:mcp:sessions",
                {
                    "event": "session_created",
                    "session_id": session_id,
                    "timestamp": str(time.time()),
                    "client_info": json.dumps(client_info)
                }
            )
            
            # Log the event as audit
            await self.event_publisher.publish_audit_event(
                action="session_created",
                session_id=session_id,
                details={"client_info": client_info}
            )
            
            logger.info(f"[SESSION INTERCEPTOR] Session {session_id} stored in Redis")
            
        except Exception as e:
            logger.error(f"[SESSION INTERCEPTOR] Failed to store session {session_id}: {e}")
    
    async def on_session_used(self, session_id: str):
        """Called when a session is used for a request.
        
        Args:
            session_id: The session ID being used
        """
        try:
            session_key = f"mcp:session:{session_id}"
            
            # Update last activity
            await self.redis.hset(session_key, "last_activity", str(time.time()))
            
            # Refresh TTL
            await self.redis.expire(session_key, 3600)
            
            # Update index
            await self.redis.zadd("mcp:session:index:active", {session_id: time.time()})
            
        except Exception as e:
            logger.error(f"[SESSION INTERCEPTOR] Failed to update session {session_id}: {e}")
    
    async def on_session_ended(self, session_id: str):
        """Called when a session ends.
        
        Args:
            session_id: The session ID that ended
        """
        logger.info(f"[SESSION INTERCEPTOR] Session ended: {session_id}")
        
        try:
            session_key = f"mcp:session:{session_id}"
            
            # Update state
            await self.redis.hset(session_key, "state", "ended")
            await self.redis.hset(session_key, "ended_at", str(time.time()))
            
            # Remove from active index
            await self.redis.zrem("mcp:session:index:active", session_id)
            
            # Add to ended index
            await self.redis.zadd("mcp:session:index:ended", {session_id: time.time()})
            
            # Publish to Redis Stream
            await self.redis.xadd(
                "stream:mcp:sessions",
                {
                    "event": "session_ended",
                    "session_id": session_id,
                    "timestamp": str(time.time())
                }
            )
            
            # Log the event as audit
            await self.event_publisher.publish_audit_event(
                action="session_ended",
                session_id=session_id
            )
            
            logger.info(f"[SESSION INTERCEPTOR] Session {session_id} marked as ended in Redis")
            
        except Exception as e:
            logger.error(f"[SESSION INTERCEPTOR] Failed to end session {session_id}: {e}")
    
    async def get_session(self, session_id: str) -> Optional[Dict[str, Any]]:
        """Get session data from Redis.
        
        Args:
            session_id: The session ID to retrieve
            
        Returns:
            Session data or None if not found
        """
        try:
            session_key = f"mcp:session:{session_id}"
            session_data = await self.redis.hgetall(session_key)
            
            if session_data:
                # Update last activity
                await self.on_session_used(session_id)
                
                # Parse JSON fields
                if session_data.get("client_info"):
                    session_data["client_info"] = json.loads(session_data["client_info"])
                
                return session_data
            
            return None
            
        except Exception as e:
            logger.error(f"[SESSION INTERCEPTOR] Failed to get session {session_id}: {e}")
            return None