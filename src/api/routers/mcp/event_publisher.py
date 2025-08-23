"""Event publisher for MCP operations to Redis Streams.

This module publishes MCP-related events to Redis Streams for consumption
by the workflow orchestrator and logging systems.
"""

import json
import time
from typing import Any, Dict, Optional

from ....shared.unified_logger import UnifiedAsyncLogger
from ....storage.async_redis_storage import AsyncRedisStorage
from ....storage.redis_clients import RedisClients


class MCPEventPublisher:
    """Publish MCP events to Redis Streams for workflow orchestration."""

    def __init__(
        self,
        async_storage: AsyncRedisStorage,
        redis_clients: RedisClients
    ):
        """Initialize the event publisher.

        Args:
            async_storage: Async Redis storage instance
            redis_clients: Redis clients for creating component logger
        """
        self.storage = async_storage
        self.redis = async_storage.redis_client
        
        # Create component-specific logger
        self.logger = UnifiedAsyncLogger(redis_clients, component="mcp_event_publisher")

    async def publish_workflow_event(
        self,
        event_type: str,
        proxy_hostname: str,
        data: Dict[str, Any],
        trace_id: Optional[str] = None
    ) -> str:
        """Publish an event to the workflow orchestrator stream.

        Args:
            event_type: Type of event (e.g., "proxy_created", "certificate_requested")
            hostname: Hostname associated with the event
            data: Event-specific data
            trace_id: Optional trace ID for correlation

        Returns:
            The event ID from Redis Stream
        """
        event_data = {
            "event_type": event_type,
            "proxy_hostname": proxy_hostname,
            "data": json.dumps(data),
            "timestamp": str(time.time()),
            "source": "mcp"
        }

        if trace_id:
            event_data["trace_id"] = trace_id

        # Publish to workflow stream
        event_id = await self.redis.xadd("events:workflow", event_data)

        # Log the event publication
        await self.logger.debug(
            f"Published workflow event: {event_type} for {proxy_hostname}",
            event_id=event_id,
            trace_id=trace_id
        )

        return event_id

    async def publish_audit_event(
        self,
        action: str,
        session_id: Optional[str] = None,
        user: str = "anonymous",
        details: Optional[Dict[str, Any]] = None
    ) -> str:
        """Publish an audit event for MCP operations.

        Args:
            action: The action performed (e.g., "list_proxies", "create_proxy")
            session_id: Optional MCP session ID
            user: User or token name performing the action
            details: Additional details about the action

        Returns:
            The event ID from Redis Stream
        """
        audit_data = {
            "timestamp": str(time.time()),
            "action": action,
            "user": user,
            "source": "mcp"
        }

        if session_id:
            audit_data["session_id"] = session_id

        if details:
            audit_data["details"] = json.dumps(details)

        # Publish to audit stream
        event_id = await self.redis.xadd("stream:audit:mcp", audit_data)

        # Also add to general audit index
        await self.redis.zadd(
            f"idx:audit:mcp:{action}",
            {event_id: time.time()}
        )

        # Set TTL on index (30 days)
        await self.redis.expire(f"idx:audit:mcp:{action}", 2592000)

        return event_id

    async def publish_tool_execution(
        self,
        tool_name: str,
        session_id: str,
        exec_id: str,
        args: Dict[str, Any],
        result: Optional[Any] = None,
        error: Optional[str] = None,
        duration_ms: Optional[float] = None
    ) -> str:
        """Publish a tool execution event.

        Args:
            tool_name: Name of the tool executed
            session_id: MCP session ID
            exec_id: Execution ID
            args: Tool arguments
            result: Tool result (if successful)
            error: Error message (if failed)
            duration_ms: Execution duration in milliseconds

        Returns:
            The event ID from Redis Stream
        """
        execution_data = {
            "timestamp": str(time.time()),
            "tool": tool_name,
            "session_id": session_id,
            "exec_id": exec_id,
            "args": json.dumps(args),
            "status": "success" if result is not None else "error"
        }

        if result is not None:
            execution_data["result"] = json.dumps(result) if not isinstance(result, str) else result

        if error:
            execution_data["error"] = error

        if duration_ms is not None:
            execution_data["duration_ms"] = str(duration_ms)

        # Publish to tool execution stream
        event_id = await self.redis.xadd("stream:mcp:tools", execution_data)

        # Add to tool index
        await self.redis.zadd(
            f"idx:mcp:tool:{tool_name}",
            {exec_id: time.time()}
        )

        # Add to session tool index
        await self.redis.zadd(
            f"idx:mcp:session:{session_id}:tools",
            {exec_id: time.time()}
        )

        # Update tool usage statistics
        hour_key = f"stats:mcp:tools:{time.strftime('%Y%m%d:%H')}"
        await self.redis.hincrby(hour_key, tool_name, 1)
        await self.redis.hincrby(hour_key, "total", 1)

        if error:
            await self.redis.hincrby(hour_key, f"{tool_name}:errors", 1)
            await self.redis.hincrby(hour_key, "total:errors", 1)

        # Set TTL on statistics (7 days)
        await self.redis.expire(hour_key, 604800)

        return event_id

    async def publish_request(
        self,
        session_id: str,
        method: str,
        params: Dict[str, Any],
        request_id: Optional[Any] = None
    ) -> str:
        """Publish an MCP request to the stream.

        Args:
            session_id: MCP session ID
            method: MCP method name
            params: Method parameters
            request_id: Optional request ID from the protocol

        Returns:
            The event ID from Redis Stream
        """
        request_data = {
            "timestamp": str(time.time()),
            "session_id": session_id,
            "method": method,
            "params": json.dumps(params)
        }

        if request_id is not None:
            request_data["request_id"] = str(request_id)

        # Publish to request stream
        event_id = await self.redis.xadd("stream:mcp:requests", request_data)

        # Update session activity index
        await self.redis.zadd(
            f"idx:mcp:session:{session_id}:requests",
            {event_id: time.time()}
        )

        return event_id

    async def publish_response(
        self,
        session_id: str,
        response: Dict[str, Any],
        request_id: Optional[Any] = None,
        duration_ms: Optional[float] = None
    ) -> str:
        """Publish an MCP response to the stream.

        Args:
            session_id: MCP session ID
            response: Response data
            request_id: Optional request ID from the protocol
            duration_ms: Request processing duration in milliseconds

        Returns:
            The event ID from Redis Stream
        """
        response_data = {
            "timestamp": str(time.time()),
            "session_id": session_id,
            "response": json.dumps(response)
        }

        if request_id is not None:
            response_data["request_id"] = str(request_id)

        if duration_ms is not None:
            response_data["duration_ms"] = str(duration_ms)

        # Publish to response stream
        event_id = await self.redis.xadd("stream:mcp:responses", response_data)

        # Update response time statistics
        if duration_ms is not None:
            stats_key = f"stats:mcp:response_times:{time.strftime('%Y%m%d:%H')}"
            await self.redis.lpush(stats_key, str(duration_ms))
            await self.redis.ltrim(stats_key, 0, 999)  # Keep last 1000
            await self.redis.expire(stats_key, 86400)  # 1 day TTL

        return event_id

    async def publish_notification(
        self,
        session_id: str,
        notification_type: str,
        data: Dict[str, Any]
    ) -> str:
        """Publish an MCP notification (server -> client).

        Args:
            session_id: MCP session ID
            notification_type: Type of notification
            data: Notification data

        Returns:
            The event ID from Redis Stream
        """
        notification_data = {
            "timestamp": str(time.time()),
            "session_id": session_id,
            "type": notification_type,
            "data": json.dumps(data)
        }

        # Publish to notification stream
        event_id = await self.redis.xadd("stream:mcp:notifications", notification_data)

        return event_id
