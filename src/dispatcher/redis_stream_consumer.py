"""Redis Stream consumer for proxy events."""

import asyncio
import json
import logging
import os
from typing import Any, Callable, Dict, List, Optional
import redis.asyncio as redis_async
from redis.exceptions import ResponseError
from ..shared.logger import log_debug, log_info, log_warning, log_error, log_trace
from ..shared.dual_logger import create_dual_logger

# Set up Python standard logger for debugging
logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

# Create dual logger for redis_stream_consumer
dual_logger = create_dual_logger('redis_stream_consumer')


class RedisStreamConsumer:
    """Consumer for Redis Stream events."""
    
    def __init__(self, redis_url: str, group_name: str = "dispatcher-group"):
        """
        Initialize the Redis Stream consumer.
        
        Args:
            redis_url: Redis connection URL
            group_name: Consumer group name
        """
        self.redis_url = redis_url
        self.stream_key = "events:all:stream"  # Changed to use unified event stream
        self.group_name = group_name
        # Use group-specific consumer name
        if group_name == "workflow-orchestrator":
            self.consumer_name = f"workflow-{os.getpid()}"
        else:
            self.consumer_name = f"dispatcher-{os.getpid()}"
        self.redis: Optional[redis_async.Redis] = None
        self.running = False
        
    async def initialize(self):
        """Initialize Redis connection and consumer group."""
        try:
            # Create Redis connection
            self.redis = await redis_async.from_url(
                self.redis_url,
                decode_responses=True
            )
            
            # Test connection
            await self.redis.ping()
            dual_logger.info(f"[STREAM_CONSUMER] Connected to Redis for stream consumption")
            
            # Create consumer group (ignore if exists)
            try:
                await self.redis.xgroup_create(
                    name=self.stream_key,
                    groupname=self.group_name,
                    id="0",  # Start from beginning
                    mkstream=True  # Create stream if it doesn't exist
                )
                dual_logger.info(f"[STREAM_CONSUMER] Created consumer group: {self.group_name}")
            except ResponseError as e:
                if "BUSYGROUP" in str(e):
                    dual_logger.info(f"[STREAM_CONSUMER] Consumer group {self.group_name} already exists")
                else:
                    raise
                    
        except Exception as e:
            dual_logger.error(f"[STREAM_CONSUMER] Failed to initialize: {e}", error=e)
            raise
    
    async def consume_events(self, handler: Callable[[Dict[str, Any]], Any]):
        """
        Consume events from the stream and process them.
        
        Args:
            handler: Async function to handle each event
        """
        if not self.redis:
            await self.initialize()
        
        self.running = True
        logger.info(f"[STREAM_CONSUMER] Starting event consumption as {self.consumer_name} for group {self.group_name}")
        dual_logger.info(f"[STREAM_CONSUMER] Starting event consumption as {self.consumer_name}")
        
        while self.running:
            try:
                # Read new messages for this consumer
                # ">" means only new messages not yet delivered to any consumer
                messages = await self.redis.xreadgroup(
                    groupname=self.group_name,
                    consumername=self.consumer_name,
                    streams={self.stream_key: ">"},
                    count=10,  # Process up to 10 messages at once
                    block=1000  # Block for 1 second if no messages
                )
                
                if not messages:
                    continue
                
                logger.debug(f"[STREAM_CONSUMER] Received {len(messages)} message batches")
                
                # Process messages
                for stream_name, stream_messages in messages:
                    logger.debug(f"[STREAM_CONSUMER] Processing {len(stream_messages)} messages from stream {stream_name}")
                    for message_id, data in stream_messages:
                        try:
                            # Parse event data
                            event = self._parse_event(data)
                            event['_message_id'] = message_id  # Add message ID for tracking
                            
                            dual_logger.trace(f"[STREAM_CONSUMER] Processing event {message_id}: {event.get('event_type', event.get('type', 'unknown'))} for {event.get('hostname', event.get('cert_name', 'N/A'))}")
                            
                            # Process event
                            await handler(event)
                            
                            # Acknowledge successful processing
                            await self.redis.xack(
                                self.stream_key,
                                self.group_name,
                                message_id
                            )
                            
                            dual_logger.trace(f"[STREAM_CONSUMER] Successfully processed event {message_id}")
                            
                        except Exception as e:
                            dual_logger.error(f"[STREAM_CONSUMER] Failed to process event {message_id}: {e}", error=e)
                            # Message stays in PEL for retry
                            # Could implement retry counter here
                            
            except asyncio.CancelledError:
                dual_logger.info("[STREAM_CONSUMER] Consumption cancelled")
                break
            except Exception as e:
                dual_logger.error(f"[STREAM_CONSUMER] Consumer error: {e}", error=e)
                await asyncio.sleep(5)  # Wait before retry
    
    async def claim_pending_messages(self, idle_time_ms: int = 60000):
        """
        Claim and retry pending messages from dead/slow consumers.
        
        Args:
            idle_time_ms: Minimum idle time before claiming a message (default 60 seconds)
        """
        if not self.redis:
            await self.initialize()
        
        dual_logger.info(f"[STREAM_CONSUMER] Starting pending message handler")
        
        while self.running:
            try:
                # Get summary of pending messages
                pending_info = await self.redis.xpending(
                    name=self.stream_key,
                    groupname=self.group_name
                )
                
                if pending_info and pending_info['pending'] > 0:
                    dual_logger.trace(f"[STREAM_CONSUMER] Found {pending_info['pending']} pending messages")
                    
                    # Get detailed pending messages
                    pending_messages = await self.redis.xpending_range(
                        name=self.stream_key,
                        groupname=self.group_name,
                        min="-",
                        max="+",
                        count=10  # Process up to 10 at a time
                    )
                    
                    for msg in pending_messages:
                        # Check if message has been idle long enough
                        if msg['time_since_delivered'] > idle_time_ms:
                            try:
                                # Claim the message for this consumer
                                claimed = await self.redis.xclaim(
                                    name=self.stream_key,
                                    groupname=self.group_name,
                                    consumername=self.consumer_name,
                                    min_idle_time=idle_time_ms,
                                    message_ids=[msg['message_id']]
                                )
                                
                                if claimed:
                                    dual_logger.trace(f"[STREAM_CONSUMER] Claimed pending message: {msg['message_id']} from {msg['consumer']}")
                                    
                            except Exception as e:
                                dual_logger.error(f"[STREAM_CONSUMER] Failed to claim message {msg['message_id']}: {e}", error=e)
                
                await asyncio.sleep(30)  # Check every 30 seconds
                
            except asyncio.CancelledError:
                dual_logger.info("[STREAM_CONSUMER] Pending handler cancelled")
                break
            except Exception as e:
                dual_logger.error(f"[STREAM_CONSUMER] Pending handler error: {e}", error=e)
                await asyncio.sleep(60)  # Wait longer on error
    
    def _parse_event(self, data: Dict[str, str]) -> Dict[str, Any]:
        """
        Parse event data from Redis Stream.
        
        Args:
            data: Raw event data from Redis
            
        Returns:
            Parsed event dictionary
        """
        event = {}
        for key, value in data.items():
            try:
                # Handle special cases
                if value == "null":
                    event[key] = None
                elif value == "true":
                    event[key] = True
                elif value == "false":
                    event[key] = False
                elif value.startswith('[') or value.startswith('{'):
                    # Try to parse JSON
                    event[key] = json.loads(value)
                else:
                    event[key] = value
            except (json.JSONDecodeError, TypeError):
                # Keep as string if parsing fails
                event[key] = value
        
        return event
    
    async def get_stream_info(self) -> Dict[str, Any]:
        """Get information about the stream and consumer group."""
        if not self.redis:
            return {}
        
        try:
            info = {
                "stream_length": await self.redis.xlen(self.stream_key),
                "groups": await self.redis.xinfo_groups(self.stream_key),
                "consumers": []
            }
            
            # Get consumer info for our group
            for group in info['groups']:
                if group['name'] == self.group_name:
                    info['lag'] = group.get('lag', 0)
                    info['pending'] = group.get('pending', 0)
                    
                    # Get consumers in this group
                    consumers = await self.redis.xinfo_consumers(
                        name=self.stream_key,
                        groupname=self.group_name
                    )
                    info['consumers'] = consumers
                    break
            
            return info
            
        except Exception as e:
            dual_logger.error(f"[STREAM_CONSUMER] Failed to get stream info: {e}", error=e)
            return {}
    
    async def stop(self):
        """Stop the consumer gracefully."""
        dual_logger.info(f"[STREAM_CONSUMER] Stopping consumer {self.consumer_name}")
        self.running = False
        
        if self.redis:
            await self.redis.close()
            self.redis = None