"""Unified stream publisher for both events and logs.

This module provides a unified interface for publishing to Redis Streams,
handling both operational events and logging with consistent schemas and
trace correlation.
"""

import asyncio
import json
import logging
import secrets
import time
from typing import Any, Dict, List, Optional
from datetime import datetime, timezone
import redis.asyncio as redis_async

from ..shared.log_levels import TRACE

logger = logging.getLogger(__name__)


class UnifiedStreamPublisher:
    """Publishes both events and logs to Redis Streams with unified schema."""
    
    def __init__(self, redis_client: redis_async.Redis = None, redis_url: str = None):
        """Initialize the unified publisher.
        
        Args:
            redis_client: Existing async Redis client
            redis_url: Redis URL if no client provided
        """
        self.redis = redis_client
        self.redis_url = redis_url
        
        # Stream configuration
        self.master_event_stream = "events:all:stream"
        self.master_log_stream = "logs:all:stream"
        
        # Stream size limits
        self.event_stream_maxlen = 100000  # Keep last 100k events
        self.log_stream_maxlen = 1000000   # Keep last 1M logs
        
        # Batching for performance
        self.batch_queue: List[tuple] = []
        self.batch_lock = asyncio.Lock()
        self.batch_task: Optional[asyncio.Task] = None
        self.batch_max_size = 100
        self.batch_max_wait = 0.1  # 100ms
    
    async def _ensure_connection(self):
        """Ensure Redis connection is available."""
        if not self.redis and self.redis_url:
            self.redis = await redis_async.from_url(
                self.redis_url,
                decode_responses=True
            )
    
    def generate_trace_id(self, prefix: str = "trace") -> str:
        """Generate a unique trace ID.
        
        Args:
            prefix: Prefix for the trace ID
            
        Returns:
            Unique trace ID
        """
        return f"{prefix}-{secrets.token_hex(8)}"
    
    async def publish(self, stream_key: str, data: Dict[str, Any], 
                     trace_id: Optional[str] = None,
                     batch: bool = True) -> Optional[str]:
        """Core publish method for any stream.
        
        Args:
            stream_key: Target Redis stream
            data: Event/log data to publish
            trace_id: Optional trace ID for correlation
            batch: Whether to batch this publish
            
        Returns:
            Event ID or None if batched
        """
        try:
            await self._ensure_connection()
            
            if not self.redis:
                logger.error("No Redis connection available")
                return None
            
            # Add common fields - use epoch milliseconds as integer
            enriched_data = {
                "timestamp": int(time.time() * 1000),
                "trace_id": trace_id or "",
                **data
            }
            
            # Flatten for Redis Streams
            flat_data = self._flatten_for_redis(enriched_data)
            
            if batch:
                # Add to batch queue
                async with self.batch_lock:
                    self.batch_queue.append((stream_key, flat_data))
                    
                    # Start batch processor if not running
                    if not self.batch_task or self.batch_task.done():
                        self.batch_task = asyncio.create_task(self._process_batch())
                
                return None  # Batched items don't get immediate IDs
            else:
                # Publish immediately
                return await self._publish_single(stream_key, flat_data)
                
        except Exception as e:
            logger.error(f"Failed to publish to {stream_key}: {e}")
            return None
    
    async def _publish_single(self, stream_key: str, data: dict) -> Optional[str]:
        """Publish a single entry to a stream.
        
        Args:
            stream_key: Target stream
            data: Flattened data dictionary
            
        Returns:
            Event ID from Redis
        """
        # Determine maxlen based on stream type
        if "events:" in stream_key:
            maxlen = self.event_stream_maxlen
        elif "logs:" in stream_key:
            maxlen = self.log_stream_maxlen
        else:
            maxlen = 100000  # Default
        
        event_id = await self.redis.xadd(
            stream_key,
            data,
            maxlen=maxlen,
            approximate=True
        )
        
        # Add to indexes if this is the master log stream
        if stream_key == "logs:all:stream" and event_id:
            # Get timestamp for indexing
            timestamp_ms = int(data.get('timestamp', time.time() * 1000))
            await self._add_to_indexes(event_id, data, timestamp_ms)
        
        return event_id
    
    async def _process_batch(self):
        """Process batched publishes efficiently."""
        try:
            # Wait for batch window
            await asyncio.sleep(self.batch_max_wait)
            
            async with self.batch_lock:
                if not self.batch_queue:
                    return
                
                # Take items to process
                to_process = self.batch_queue[:self.batch_max_size]
                self.batch_queue = self.batch_queue[self.batch_max_size:]
                
            # Group by stream for efficient pipelining
            by_stream: Dict[str, List[dict]] = {}
            for stream_key, data in to_process:
                if stream_key not in by_stream:
                    by_stream[stream_key] = []
                by_stream[stream_key].append(data)
            
            # Pipeline publishes per stream
            pipe = self.redis.pipeline()
            for stream_key, entries in by_stream.items():
                # Determine maxlen
                if "events:" in stream_key:
                    maxlen = self.event_stream_maxlen
                elif "logs:" in stream_key:
                    maxlen = self.log_stream_maxlen
                else:
                    maxlen = 100000
                
                for entry in entries:
                    pipe.xadd(stream_key, entry, maxlen=maxlen, approximate=True)
            
            results = await pipe.execute()
            
            # Add to indexes for logs:all:stream entries
            if "logs:all:stream" in by_stream:
                stream_entries = by_stream["logs:all:stream"]
                # Find the results for logs:all:stream entries
                result_idx = 0
                for stream_key in by_stream.keys():
                    if stream_key == "logs:all:stream":
                        for i, entry in enumerate(stream_entries):
                            event_id = results[result_idx + i]
                            if event_id:
                                timestamp_ms = int(entry.get('timestamp', time.time() * 1000))
                                await self._add_to_indexes(event_id, entry, timestamp_ms)
                        break
                    result_idx += len(by_stream[stream_key])
            
            logger.log(TRACE, f"Batch published {len(to_process)} entries to {len(by_stream)} streams")
            
        except Exception as e:
            logger.error(f"Batch processing error: {e}")
    
    async def _add_to_indexes(self, stream_id: str, stream_data: Dict[str, str], timestamp_ms: int):
        """Add log entry to Redis indexes for efficient querying.
        
        Creates sorted set indexes by:
        - All logs (global)
        - Client IP
        - Proxy hostname
        - User ID
        - HTTP status code
        - HTTP method
        - Errors (4xx/5xx)
        - Log level
        - Component
        
        Args:
            stream_id: Redis stream entry ID
            stream_data: Log entry data
            timestamp_ms: Timestamp in milliseconds (used as score)
        """
        try:
            # Use pipeline for efficiency
            pipe = self.redis.pipeline()
            
            # TTL for indexes (30 days)
            ttl_seconds = 30 * 24 * 60 * 60
            
            # Global index - all logs
            pipe.zadd("log:idx:all", {stream_id: timestamp_ms})
            pipe.expire("log:idx:all", ttl_seconds)
            
            # Index by client IP
            client_ip = stream_data.get('client_ip')
            if client_ip and client_ip != '127.0.0.1':
                pipe.zadd(f"log:idx:ip:{client_ip}", {stream_id: timestamp_ms})
                pipe.expire(f"log:idx:ip:{client_ip}", ttl_seconds)
            
            # Index by proxy hostname
            proxy_hostname = stream_data.get('proxy_hostname')
            if proxy_hostname:
                pipe.zadd(f"log:idx:host:{proxy_hostname}", {stream_id: timestamp_ms})
                pipe.expire(f"log:idx:host:{proxy_hostname}", ttl_seconds)
            
            # Index by user ID (check both user_id and auth_user fields)
            user_id = stream_data.get('user_id') or stream_data.get('auth_user')
            if user_id and user_id != 'anonymous':
                pipe.zadd(f"log:idx:user:{user_id}", {stream_id: timestamp_ms})
                pipe.expire(f"log:idx:user:{user_id}", ttl_seconds)
            
            # Index by HTTP status code (check both status_code and status fields)
            status_code = stream_data.get('status_code') or stream_data.get('status')
            if status_code and status_code != '0':
                pipe.zadd(f"log:idx:status:{status_code}", {stream_id: timestamp_ms})
                pipe.expire(f"log:idx:status:{status_code}", ttl_seconds)
                
                # Special index for errors
                try:
                    status_int = int(status_code)
                    if status_int >= 400:
                        pipe.zadd("log:idx:errors", {stream_id: timestamp_ms})
                        pipe.expire("log:idx:errors", ttl_seconds)
                except:
                    pass
            
            # Index by HTTP method (support multiple field names)
            method = stream_data.get('request_method') or stream_data.get('method')
            if method:
                pipe.zadd(f"log:idx:method:{method}", {stream_id: timestamp_ms})
                pipe.expire(f"log:idx:method:{method}", ttl_seconds)
            
            # Index by log level
            level = stream_data.get('level')
            if level:
                pipe.zadd(f"log:idx:level:{level}", {stream_id: timestamp_ms})
                pipe.expire(f"log:idx:level:{level}", ttl_seconds)
            
            # Index by component
            component = stream_data.get('component')
            if component:
                pipe.zadd(f"log:idx:component:{component}", {stream_id: timestamp_ms})
                pipe.expire(f"log:idx:component:{component}", ttl_seconds)
            
            # Execute pipeline
            await pipe.execute()
            logger.log(TRACE, f"Added entry {stream_id} to indexes")
            
        except Exception as e:
            logger.error(f"Error adding to indexes: {e}")
    
    def _flatten_for_redis(self, data: dict) -> dict:
        """Flatten data for Redis Streams compatibility.
        
        Args:
            data: Nested data dictionary
            
        Returns:
            Flattened dictionary with string values
        """
        flat = {}
        for key, value in data.items():
            if isinstance(value, (dict, list)):
                flat[key] = json.dumps(value)
            elif isinstance(value, bool):
                flat[key] = "true" if value else "false"
            elif value is None:
                flat[key] = "null"
            else:
                flat[key] = str(value)
        return flat
    
    # Event publishing methods
    
    async def publish_event(self, event_type: str, data: Dict[str, Any],
                          trace_id: Optional[str] = None,
                          component: Optional[str] = None) -> Optional[str]:
        """Publish an operational event.
        
        Args:
            event_type: Type of event (e.g., proxy_created, certificate_ready)
            data: Event-specific data
            trace_id: Optional trace ID for correlation
            component: Component that generated the event
            
        Returns:
            Event ID or None if batched
        """
        # Determine specific stream based on event type
        prefix = event_type.split('_')[0] if '_' in event_type else event_type
        specific_stream = f"events:{prefix}:stream"
        
        event_data = {
            "type": "event",
            "event_type": event_type,
            "component": component or "unknown",
            **data
        }
        
        # Publish to specific stream
        event_id = await self.publish(specific_stream, event_data, trace_id, batch=True)
        
        # Also publish to master event stream (non-batched for immediate visibility)
        await self.publish(self.master_event_stream, event_data, trace_id, batch=False)
        
        logger.log(TRACE, f"Published {event_type} event for trace {trace_id}")
        return event_id
    
    # Log publishing methods
    
    async def publish_log(self, level: str, message: str,
                        component: str,
                        trace_id: Optional[str] = None,
                        log_type: Optional[str] = None,
                        **extra) -> Optional[str]:
        """Publish a log entry.
        
        Args:
            level: Log level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
            message: Log message
            component: Component that generated the log
            trace_id: Optional trace ID for correlation
            log_type: Type of log (http_request, system_event, audit_event, error)
            **extra: Additional log fields
            
        Returns:
            Log ID or None if batched
        """
        # Determine log stream based on type or level
        if log_type:
            if log_type.startswith("http"):
                specific_stream = "logs:request:stream"
            elif log_type == "audit_event":
                specific_stream = "logs:audit:stream"
            elif log_type == "error" or level in ["ERROR", "CRITICAL"]:
                specific_stream = "logs:error:stream"
            else:
                specific_stream = "logs:system:stream"
        elif level in ["ERROR", "CRITICAL"]:
            specific_stream = "logs:error:stream"
        else:
            specific_stream = "logs:system:stream"
        
        log_data = {
            "type": "log",
            "level": level,
            "message": message,
            "component": component,
            "log_type": log_type or "system_event",
            **extra
        }
        
        # Publish to specific stream
        log_id = await self.publish(specific_stream, log_data, trace_id, batch=True)
        
        # Also publish to master log stream
        await self.publish(self.master_log_stream, log_data, trace_id, batch=True)
        
        return log_id
    
    # Specialized publishing methods
    
    async def publish_http_request(self, request_data: dict,
                                  trace_id: Optional[str] = None,
                                  component: Optional[str] = None) -> Optional[str]:
        """Publish HTTP request log.
        
        Args:
            request_data: Request details (method, path, ip, etc.)
            trace_id: Request trace ID
            component: Component that generated this log
            
        Returns:
            Log ID
        """
        # Extract component from request_data if not provided
        if not component:
            component = request_data.pop('component', 'unknown')
        else:
            # Always remove component from request_data to avoid duplicate
            request_data.pop('component', None)
            
        return await self.publish_log(
            level="INFO",
            message=f"{request_data.get('request_method', request_data.get('method', 'UNKNOWN'))} {request_data.get('request_path', request_data.get('path', '/'))}",
            component=component,
            trace_id=trace_id,
            log_type="http_request",
            **request_data
        )
    
    async def publish_http_response(self, response_data: dict,
                                   trace_id: Optional[str] = None,
                                   component: Optional[str] = None) -> Optional[str]:
        """Publish HTTP response log.
        
        Args:
            response_data: Response details (status, duration_ms, etc.)
            trace_id: Request trace ID
            component: Component that generated this log
            
        Returns:
            Log ID
        """
        # Extract component from response_data if not provided
        if not component:
            component = response_data.pop('component', 'unknown')
        else:
            # Always remove component from response_data to avoid duplicate
            response_data.pop('component', None)
            
        return await self.publish_log(
            level="INFO",
            message=f"Response: {response_data['status']} in {response_data.get('duration_ms', 0):.2f}ms",
            component=component,
            trace_id=trace_id,
            log_type="http_response",
            **response_data
        )
    
    async def publish_audit_event(self, actor: str, action: str,
                                 resource: str, result: str,
                                 trace_id: Optional[str] = None,
                                 **extra) -> Optional[str]:
        """Publish audit event.
        
        Args:
            actor: User or system performing the action
            action: Action performed
            resource: Resource affected
            result: Result of the action (success/failure)
            trace_id: Optional trace ID
            **extra: Additional audit fields
            
        Returns:
            Event ID
        """
        return await self.publish_log(
            level="INFO",
            message=f"{actor} {action} {resource}: {result}",
            component="audit",
            trace_id=trace_id,
            log_type="audit_event",
            actor=actor,
            action=action,
            resource=resource,
            result=result,
            **extra
        )
    
    async def publish_error(self, error: Exception,
                          component: str,
                          context: dict,
                          trace_id: Optional[str] = None) -> Optional[str]:
        """Publish error log.
        
        Args:
            error: Exception that occurred
            component: Component where error occurred
            context: Additional context
            trace_id: Optional trace ID
            
        Returns:
            Log ID
        """
        import traceback
        
        return await self.publish_log(
            level="ERROR",
            message=str(error),
            component=component,
            trace_id=trace_id,
            log_type="error",
            exception_type=type(error).__name__,
            traceback=traceback.format_exc(),
            **context
        )
    
    # Lifecycle management
    
    async def flush(self):
        """Flush any pending batched items."""
        if self.batch_task and not self.batch_task.done():
            await self.batch_task
        
        # Process any remaining items
        if self.batch_queue:
            await self._process_batch()
    
    async def close(self):
        """Close the publisher and flush pending items."""
        await self.flush()
        
        if self.batch_task:
            self.batch_task.cancel()
        
        if self.redis:
            await self.redis.close()