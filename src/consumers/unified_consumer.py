"""Unified stream consumer base class for Redis Streams.

This module provides a base class for building specialized consumers
that process events and logs from Redis Streams with exactly-once
semantics using consumer groups.
"""

import asyncio
import json
import time
from typing import Any, Callable, Dict, List, Optional, Set
from abc import ABC, abstractmethod
import redis.asyncio as redis_async
from ..shared.logger import log_debug, log_info, log_warning, log_error, log_trace


class UnifiedStreamConsumer(ABC):
    """Base class for all stream consumers with exactly-once processing."""
    
    def __init__(self, redis_client: redis_async.Redis,
                 group_name: str,
                 consumer_name: str):
        """Initialize the consumer.
        
        Args:
            redis_client: Async Redis client
            group_name: Consumer group name
            consumer_name: Unique consumer name within the group
        """
        self.redis = redis_client
        self.group_name = group_name
        self.consumer_name = consumer_name
        
        # Handler registry
        self.handlers: Dict[str, Callable] = {}
        
        # Streams to consume from
        self.streams: Set[str] = set()
        
        # Consumer configuration
        self.batch_size = 100
        self.block_ms = 1000
        self.idle_claim_ms = 30000  # Claim messages idle for 30s
        
        # Metrics
        self.messages_processed = 0
        self.messages_failed = 0
        self.last_activity = time.time()
        
        # Control
        self.running = False
        self.consumer_task: Optional[asyncio.Task] = None
        self.pending_task: Optional[asyncio.Task] = None
    
    def register_handler(self, pattern: str, handler: Callable):
        """Register a handler for events matching a pattern.
        
        Args:
            pattern: Event type prefix to match
            handler: Async function to handle matching events
        """
        self.handlers[pattern] = handler
        log_info(f"Registered handler for pattern: {pattern}", component="stream_consumer")
    
    def add_stream(self, stream_key: str):
        """Add a stream to consume from.
        
        Args:
            stream_key: Redis stream key
        """
        self.streams.add(stream_key)
        log_info(f"Added stream: {stream_key}", component="stream_consumer")
    
    async def initialize(self):
        """Initialize consumer groups for all streams."""
        for stream in self.streams:
            try:
                # Create consumer group (idempotent)
                await self.redis.xgroup_create(
                    stream,
                    self.group_name,
                    id='0',  # Start from beginning
                    mkstream=True  # Create stream if it doesn't exist
                )
                log_info(f"Created consumer group {self.group_name} for stream {stream}", component="stream_consumer")
            except redis_async.ResponseError as e:
                if "BUSYGROUP" in str(e):
                    # Group already exists
                    log_debug(f"Consumer group {self.group_name} already exists for {stream}", component="stream_consumer")
                else:
                    raise
    
    async def start(self):
        """Start consuming from streams."""
        if self.running:
            log_warning("Consumer already running", component="stream_consumer")
            return
        
        self.running = True
        
        # Initialize consumer groups
        await self.initialize()
        
        # Start main consumer task
        self.consumer_task = asyncio.create_task(self._consume_loop())
        
        # Start pending message processor
        self.pending_task = asyncio.create_task(self._process_pending_loop())
        
        log_info(f"Started consumer {self.consumer_name} in group {self.group_name}", component="stream_consumer")
    
    async def stop(self):
        """Stop consuming and clean up."""
        self.running = False
        
        # Cancel tasks
        if self.consumer_task:
            self.consumer_task.cancel()
            try:
                await self.consumer_task
            except asyncio.CancelledError:
                pass
        
        if self.pending_task:
            self.pending_task.cancel()
            try:
                await self.pending_task
            except asyncio.CancelledError:
                pass
        
        log_info(f"Stopped consumer {self.consumer_name}", component="stream_consumer")
    
    async def _consume_loop(self):
        """Main consumption loop."""
        while self.running:
            try:
                # Read from all streams
                stream_dict = {stream: '>' for stream in self.streams}
                
                messages = await self.redis.xreadgroup(
                    self.group_name,
                    self.consumer_name,
                    stream_dict,
                    count=self.batch_size,
                    block=self.block_ms
                )
                
                # Process messages
                for stream, stream_messages in messages:
                    for msg_id, data in stream_messages:
                        try:
                            # Parse data
                            parsed_data = self._parse_message(data)
                            
                            # Process message
                            await self._process_message(stream, msg_id, parsed_data)
                            
                            # Acknowledge
                            await self.redis.xack(stream, self.group_name, msg_id)
                            
                            self.messages_processed += 1
                            self.last_activity = time.time()
                            
                        except Exception as e:
                            log_error(f"Failed to process message {msg_id}: {e}", component="stream_consumer", error=e)
                            self.messages_failed += 1
                            # Message remains unacknowledged for retry
                
            except asyncio.CancelledError:
                break
            except Exception as e:
                log_error(f"Consumer loop error: {e}", component="stream_consumer", error=e)
                await asyncio.sleep(1)  # Brief pause before retry
    
    async def _process_pending_loop(self):
        """Process pending (unacknowledged) messages."""
        while self.running:
            try:
                # Wait before checking for pending messages
                await asyncio.sleep(self.idle_claim_ms / 1000)
                
                for stream in self.streams:
                    await self._claim_pending_messages(stream)
                    
            except asyncio.CancelledError:
                break
            except Exception as e:
                log_error(f"Pending processor error: {e}", component="stream_consumer", error=e)
    
    async def _claim_pending_messages(self, stream: str):
        """Claim and process pending messages from other consumers.
        
        Args:
            stream: Stream to claim messages from
        """
        try:
            # Get pending messages
            pending = await self.redis.xpending_range(
                stream,
                self.group_name,
                min='-',
                max='+',
                count=10  # Process up to 10 pending at a time
            )
            
            if not pending:
                return
            
            # Claim messages idle for too long
            current_time = int(time.time() * 1000)
            messages_to_claim = []
            
            for msg_info in pending:
                msg_id = msg_info['message_id']
                idle_time = msg_info['time_since_delivered']
                
                if idle_time > self.idle_claim_ms:
                    messages_to_claim.append(msg_id)
            
            if not messages_to_claim:
                return
            
            # Claim the messages
            claimed = await self.redis.xclaim(
                stream,
                self.group_name,
                self.consumer_name,
                min_idle_time=self.idle_claim_ms,
                message_ids=messages_to_claim
            )
            
            # Process claimed messages
            for msg_id, data in claimed:
                try:
                    parsed_data = self._parse_message(data)
                    await self._process_message(stream, msg_id, parsed_data)
                    await self.redis.xack(stream, self.group_name, msg_id)
                    
                    log_info(f"Successfully processed pending message {msg_id}", component="stream_consumer")
                    self.messages_processed += 1
                    
                except Exception as e:
                    log_error(f"Failed to process claimed message {msg_id}: {e}", component="stream_consumer", error=e)
                    self.messages_failed += 1
                    
        except Exception as e:
            log_error(f"Failed to claim pending messages: {e}", component="stream_consumer", error=e)
    
    def _parse_message(self, data: dict) -> dict:
        """Parse message data from Redis.
        
        Args:
            data: Raw message data from Redis
            
        Returns:
            Parsed message dictionary
        """
        parsed = {}
        for key, value in data.items():
            # Handle JSON fields
            if value.startswith('{') or value.startswith('['):
                try:
                    parsed[key] = json.loads(value)
                except json.JSONDecodeError:
                    parsed[key] = value
            # Handle booleans
            elif value in ['true', 'false']:
                parsed[key] = value == 'true'
            # Handle null
            elif value == 'null':
                parsed[key] = None
            # Handle numbers
            elif key in ['timestamp', 'duration_ms', 'status', 'port']:
                try:
                    if '.' in value:
                        parsed[key] = float(value)
                    else:
                        parsed[key] = int(value)
                except ValueError:
                    parsed[key] = value
            else:
                parsed[key] = value
        
        return parsed
    
    async def _process_message(self, stream: str, msg_id: str, data: dict):
        """Process a single message.
        
        Args:
            stream: Stream the message came from
            msg_id: Message ID
            data: Parsed message data
        """
        # Get event type
        event_type = data.get('event_type') or data.get('type') or data.get('log_type')
        
        if not event_type:
            log_warning(f"Message {msg_id} has no event type", component="stream_consumer")
            return
        
        # Find matching handler
        handler = None
        for pattern, handler_func in self.handlers.items():
            if event_type.startswith(pattern):
                handler = handler_func
                break
        
        if handler:
            await handler(stream, msg_id, data)
        else:
            # Call default handler
            await self.handle_unknown(stream, msg_id, data)
    
    @abstractmethod
    async def handle_unknown(self, stream: str, msg_id: str, data: dict):
        """Handle messages with no matching handler.
        
        Args:
            stream: Stream the message came from
            msg_id: Message ID
            data: Parsed message data
        """
        pass
    
    async def get_stats(self) -> dict:
        """Get consumer statistics.
        
        Returns:
            Dictionary with consumer stats
        """
        return {
            "consumer_name": self.consumer_name,
            "group_name": self.group_name,
            "streams": list(self.streams),
            "messages_processed": self.messages_processed,
            "messages_failed": self.messages_failed,
            "last_activity": self.last_activity,
            "uptime_seconds": time.time() - self.last_activity if self.running else 0,
            "handlers_registered": len(self.handlers),
            "running": self.running
        }
    
    async def get_lag(self) -> Dict[str, int]:
        """Get consumer lag for each stream.
        
        Returns:
            Dictionary mapping stream to lag count
        """
        lag = {}
        
        for stream in self.streams:
            try:
                # Get pending messages count
                pending_info = await self.redis.xpending(
                    stream,
                    self.group_name
                )
                
                if pending_info:
                    lag[stream] = pending_info['pending']
                else:
                    lag[stream] = 0
                    
            except Exception as e:
                log_error(f"Failed to get lag for {stream}: {e}", component="stream_consumer", error=e)
                lag[stream] = -1
        
        return lag