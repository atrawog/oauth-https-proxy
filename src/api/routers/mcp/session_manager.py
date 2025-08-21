"""Redis-backed session management for MCP protocol.

This module provides session state management for MCP connections,
storing session data in Redis for persistence and distribution across
multiple server instances.
"""

import json
import time
import uuid
from typing import Any, Dict, List, Optional

from ....shared.unified_logger import UnifiedAsyncLogger
from ....storage.async_redis_storage import AsyncRedisStorage


class MCPSessionManager:
    """Manage MCP sessions with Redis backing for distributed state."""

    # Session configuration
    SESSION_TTL = 3600  # 1 hour default TTL
    SESSION_PREFIX = "mcp:session:"
    SESSION_INDEX = "mcp:session:index:active"

    def __init__(
        self,
        async_storage: AsyncRedisStorage,
        unified_logger: UnifiedAsyncLogger
    ):
        """Initialize the session manager.

        Args:
            async_storage: Async Redis storage instance
            unified_logger: Unified async logger for events and logs
        """
        self.storage = async_storage
        self.logger = unified_logger
        self.redis = async_storage.redis_client

        # Set component name for logging
        self.logger.set_component("mcp_session_manager")

    def generate_session_id(self) -> str:
        """Generate a unique session ID.

        Returns:
            A unique session identifier
        """
        return f"mcp-{uuid.uuid4().hex}"

    async def create_session(
        self,
        client_info: Dict[str, Any],
        ttl: int = None
    ) -> str:
        """Create a new MCP session.

        Args:
            client_info: Information about the client (IP, user agent, etc.)
            ttl: Optional TTL in seconds (defaults to SESSION_TTL)

        Returns:
            The created session ID
        """
        session_id = self.generate_session_id()
        ttl = ttl or self.SESSION_TTL

        async with self.logger.trace_context(
            "mcp_session_create",
            session_id=session_id,
            client_ip=client_info.get("ip"),
            user_agent=client_info.get("user_agent")
        ) as trace_id:
            # Create session data
            session_data = {
                "session_id": session_id,
                "created_at": time.time(),
                "last_activity": time.time(),
                "client_info": json.dumps(client_info),
                "trace_id": trace_id,
                "state": "active",
                "capabilities": "{}",  # Will be set during initialization
                "tool_executions": "0",
                "messages_sent": "0",
                "messages_received": "0"
            }

            # Store session in Redis
            session_key = f"{self.SESSION_PREFIX}{session_id}"
            await self.redis.hset(session_key, mapping=session_data)
            await self.redis.expire(session_key, ttl)

            # Add to active sessions index
            await self.redis.zadd(
                self.SESSION_INDEX,
                {session_id: time.time()}
            )

            # Add to user index if user is known
            if client_info.get("user"):
                user_index = f"mcp:session:index:user:{client_info['user']}"
                await self.redis.zadd(user_index, {session_id: time.time()})
                await self.redis.expire(user_index, ttl)

            # Publish session created event
            await self.logger.event(
                "mcp_session_created",
                {
                    "session_id": session_id,
                    "client_ip": client_info.get("ip"),
                    "user_agent": client_info.get("user_agent"),
                    "ttl": ttl
                },
                trace_id=trace_id
            )

            # Log to request stream
            await self.redis.xadd(
                "stream:mcp:sessions",
                {
                    "event": "session_created",
                    "session_id": session_id,
                    "timestamp": str(time.time()),
                    "client_info": json.dumps(client_info)
                }
            )

            return session_id

    async def get_session(
        self,
        session_id: str
    ) -> Optional[Dict[str, Any]]:
        """Get session data by ID.

        Args:
            session_id: The session ID to retrieve

        Returns:
            Session data dictionary or None if not found
        """
        session_key = f"{self.SESSION_PREFIX}{session_id}"
        session_data = await self.redis.hgetall(session_key)

        if not session_data:
            return None

        # Update last activity
        await self.redis.hset(session_key, "last_activity", str(time.time()))

        # Refresh TTL on access
        ttl = await self.redis.ttl(session_key)
        if ttl > 0:
            await self.redis.expire(session_key, max(ttl, 300))  # At least 5 minutes

        # Parse JSON fields
        if session_data.get("client_info"):
            session_data["client_info"] = json.loads(session_data["client_info"])
        if session_data.get("capabilities"):
            session_data["capabilities"] = json.loads(session_data["capabilities"])

        return session_data

    async def update_session(
        self,
        session_id: str,
        updates: Dict[str, Any]
    ) -> bool:
        """Update session data.

        Args:
            session_id: The session ID to update
            updates: Dictionary of fields to update

        Returns:
            True if session was updated, False if not found
        """
        session_key = f"{self.SESSION_PREFIX}{session_id}"

        # Check if session exists
        if not await self.redis.exists(session_key):
            return False

        # Prepare updates (convert complex types to JSON)
        processed_updates = {}
        for key, value in updates.items():
            if isinstance(value, (dict, list)):
                processed_updates[key] = json.dumps(value)
            else:
                processed_updates[key] = str(value)

        # Update last activity
        processed_updates["last_activity"] = str(time.time())

        # Apply updates
        await self.redis.hset(session_key, mapping=processed_updates)

        # Log significant updates
        if "capabilities" in updates:
            await self.logger.event(
                "mcp_session_initialized",
                {
                    "session_id": session_id,
                    "capabilities": updates["capabilities"]
                }
            )

        return True

    async def end_session(
        self,
        session_id: str,
        reason: str = "normal"
    ) -> bool:
        """End a session and clean up resources.

        Args:
            session_id: The session ID to end
            reason: Reason for ending the session

        Returns:
            True if session was ended, False if not found
        """
        session_key = f"{self.SESSION_PREFIX}{session_id}"

        # Get session data for logging
        session_data = await self.redis.hgetall(session_key)
        if not session_data:
            return False

        async with self.logger.trace_context(
            "mcp_session_end",
            session_id=session_id,
            reason=reason
        ) as trace_id:
            # Calculate session duration
            created_at = float(session_data.get("created_at", 0))
            duration_seconds = time.time() - created_at if created_at else 0

            # Update session state
            await self.redis.hset(
                session_key,
                mapping={
                    "state": "ended",
                    "ended_at": str(time.time()),
                    "end_reason": reason,
                    "duration_seconds": str(duration_seconds)
                }
            )

            # Remove from active index
            await self.redis.zrem(self.SESSION_INDEX, session_id)

            # Remove from user index if applicable
            client_info = json.loads(session_data.get("client_info", "{}"))
            if client_info.get("user"):
                user_index = f"mcp:session:index:user:{client_info['user']}"
                await self.redis.zrem(user_index, session_id)

            # Set shorter TTL for ended session (keep for audit)
            await self.redis.expire(session_key, 300)  # 5 minutes

            # Publish session ended event
            await self.logger.event(
                "mcp_session_ended",
                {
                    "session_id": session_id,
                    "reason": reason,
                    "duration_seconds": duration_seconds,
                    "tool_executions": int(session_data.get("tool_executions", 0)),
                    "messages_sent": int(session_data.get("messages_sent", 0)),
                    "messages_received": int(session_data.get("messages_received", 0))
                },
                trace_id=trace_id
            )

            # Log to stream
            await self.redis.xadd(
                "stream:mcp:sessions",
                {
                    "event": "session_ended",
                    "session_id": session_id,
                    "timestamp": str(time.time()),
                    "reason": reason,
                    "duration_seconds": str(duration_seconds)
                }
            )

            return True

    async def touch_session(
        self,
        session_id: str
    ) -> bool:
        """Update session's last activity timestamp.

        Args:
            session_id: The session ID to touch

        Returns:
            True if session was touched, False if not found
        """
        session_key = f"{self.SESSION_PREFIX}{session_id}"

        if not await self.redis.exists(session_key):
            return False

        await self.redis.hset(session_key, "last_activity", str(time.time()))

        # Refresh TTL
        await self.redis.expire(session_key, self.SESSION_TTL)

        return True

    async def increment_counter(
        self,
        session_id: str,
        counter: str,
        amount: int = 1
    ) -> int:
        """Increment a session counter.

        Args:
            session_id: The session ID
            counter: Counter name (e.g., "tool_executions", "messages_sent")
            amount: Amount to increment by

        Returns:
            New counter value, or -1 if session not found
        """
        session_key = f"{self.SESSION_PREFIX}{session_id}"

        if not await self.redis.exists(session_key):
            return -1

        new_value = await self.redis.hincrby(session_key, counter, amount)
        return new_value

    async def get_active_sessions(
        self,
        hours: int = 1
    ) -> List[Dict[str, Any]]:
        """Get active sessions from the last N hours.

        Args:
            hours: Number of hours to look back

        Returns:
            List of active session summaries
        """
        cutoff = time.time() - (hours * 3600)

        # Get session IDs from index
        session_ids = await self.redis.zrangebyscore(
            self.SESSION_INDEX,
            cutoff,
            "+inf"
        )

        sessions = []
        for session_id in session_ids:
            session_data = await self.get_session(session_id)
            if session_data:
                sessions.append({
                    "session_id": session_id,
                    "created_at": session_data.get("created_at"),
                    "last_activity": session_data.get("last_activity"),
                    "state": session_data.get("state"),
                    "tool_executions": session_data.get("tool_executions", 0)
                })

        return sessions

    async def cleanup_expired_sessions(self) -> int:
        """Clean up expired sessions.

        Returns:
            Number of sessions cleaned up
        """
        # Redis handles expiration automatically, but we clean up indexes
        now = time.time()
        cutoff = now - (self.SESSION_TTL * 2)  # 2x TTL for safety

        # Remove old entries from active index
        removed = await self.redis.zremrangebyscore(
            self.SESSION_INDEX,
            0,
            cutoff
        )

        if removed > 0:
            await self.logger.event(
                "mcp_sessions_cleaned",
                {"count": removed}
            )

        return removed
