"""Lazy initialization wrapper for UnifiedAsyncLogger.

This module provides a lazy-loading logger that queues messages until
Redis is initialized, ensuring no logs are lost during startup.
"""

import asyncio
import os
from typing import Optional, Any, Dict, List
import logging

logger = logging.getLogger(__name__)


class LazyUnifiedAsyncLogger:
    """Lazy-loading wrapper for UnifiedAsyncLogger with message queuing.
    
    This logger queues messages before Redis is initialized and flushes
    them once the connection is established. This ensures no logs are lost
    during the sync-to-async initialization transition.
    """
    
    def __init__(self, redis_url: str = None, component: str = "unknown"):
        """Initialize the lazy logger.
        
        Args:
            redis_url: Redis connection URL (defaults to REDIS_URL env var)
            component: Component name for this logger instance
        """
        self.redis_url = redis_url or os.getenv('REDIS_URL', 'redis://localhost:6379/0')
        self.component = component
        self._real_logger = None
        self._redis_clients = None
        self._init_lock = None  # Will be created when needed
        self._message_queue: List[Dict[str, Any]] = []
        self._initialized = False
        self._initialization_attempted = False
        
    async def _ensure_initialized(self):
        """Initialize on first use when event loop is available."""
        if self._initialized:
            return True
            
        # Create lock if not exists (can't create in __init__ without event loop)
        if self._init_lock is None:
            self._init_lock = asyncio.Lock()
            
        async with self._init_lock:
            # Double-check after acquiring lock
            if self._initialized:
                return True
                
            # Prevent multiple initialization attempts
            if self._initialization_attempted:
                return False
            self._initialization_attempted = True
                
            try:
                # Initialize Redis clients
                from ..storage.redis_clients import RedisClients
                self._redis_clients = RedisClients(self.redis_url)
                await self._redis_clients.initialize()
                
                # Create real logger
                from .unified_logger import UnifiedAsyncLogger
                self._real_logger = UnifiedAsyncLogger(self._redis_clients, self.component)
                
                # Flush queued messages
                for msg in self._message_queue:
                    level = msg.pop("level", "INFO")
                    message = msg.pop("message", "")
                    component = msg.pop("component", None)
                    trace_id = msg.pop("trace_id", None)
                    
                    # Call the appropriate log method
                    await self._real_logger.log(level, message, trace_id, component, **msg)
                    
                self._message_queue.clear()
                self._initialized = True
                logger.info(f"LazyUnifiedAsyncLogger initialized for component: {self.component}")
                return True
                
            except Exception as e:
                logger.error(f"Failed to initialize LazyUnifiedAsyncLogger: {e}")
                self._initialization_attempted = False  # Allow retry
                return False
    
    def _create_log_task(self, level: str, message: str, component: Optional[str] = None, 
                        trace_id: Optional[str] = None, **kwargs):
        """Create an async task to log a message."""
        async def _log_task():
            """Async task to ensure initialization and log."""
            if await self._ensure_initialized():
                # Logger is initialized, use it directly
                if hasattr(self._real_logger, level.lower()):
                    # Use convenience method (debug, info, etc.)
                    getattr(self._real_logger, level.lower())(message, trace_id, component, **kwargs)
                else:
                    # Use generic log method
                    await self._real_logger.log(level, message, trace_id, component, **kwargs)
            # If initialization failed, message stays in queue
        
        try:
            # Try to create task if event loop exists
            loop = asyncio.get_running_loop()
            asyncio.create_task(_log_task())
        except RuntimeError:
            # No event loop - queue for later
            pass
    
    def _queue_message(self, level: str, message: str, component: Optional[str] = None,
                      trace_id: Optional[str] = None, **kwargs):
        """Queue a message for later logging."""
        self._message_queue.append({
            "level": level,
            "message": message,
            "component": component,
            "trace_id": trace_id,
            **kwargs
        })
        
        # Try to initialize and flush
        self._create_log_task(level, message, component, trace_id, **kwargs)
    
    # Convenience methods matching UnifiedAsyncLogger interface
    
    def debug(self, message: str, trace_id: Optional[str] = None, component: Optional[str] = None, **kwargs):
        """Fire-and-forget debug log."""
        if self._initialized and self._real_logger:
            self._real_logger.debug(message, trace_id, component, **kwargs)
        else:
            self._queue_message("DEBUG", message, component, trace_id, **kwargs)
    
    def info(self, message: str, trace_id: Optional[str] = None, component: Optional[str] = None, **kwargs):
        """Fire-and-forget info log."""
        if self._initialized and self._real_logger:
            self._real_logger.info(message, trace_id, component, **kwargs)
        else:
            self._queue_message("INFO", message, component, trace_id, **kwargs)
    
    def warning(self, message: str, trace_id: Optional[str] = None, component: Optional[str] = None, **kwargs):
        """Fire-and-forget warning log."""
        if self._initialized and self._real_logger:
            self._real_logger.warning(message, trace_id, component, **kwargs)
        else:
            self._queue_message("WARNING", message, component, trace_id, **kwargs)
    
    def error(self, message: str, trace_id: Optional[str] = None, component: Optional[str] = None, **kwargs):
        """Fire-and-forget error log."""
        if self._initialized and self._real_logger:
            self._real_logger.error(message, trace_id, component, **kwargs)
        else:
            self._queue_message("ERROR", message, component, trace_id, **kwargs)
    
    def critical(self, message: str, trace_id: Optional[str] = None, component: Optional[str] = None, **kwargs):
        """Fire-and-forget critical log."""
        if self._initialized and self._real_logger:
            self._real_logger.critical(message, trace_id, component, **kwargs)
        else:
            self._queue_message("CRITICAL", message, component, trace_id, **kwargs)
    
    def trace(self, message: str, trace_id: Optional[str] = None, component: Optional[str] = None, **kwargs):
        """Fire-and-forget trace log (very verbose debugging)."""
        if self._initialized and self._real_logger:
            self._real_logger.trace(message, trace_id, component, **kwargs)
        else:
            self._queue_message("TRACE", message, component, trace_id, **kwargs)
    
    def set_real_logger(self, real_logger):
        """Set the real UnifiedAsyncLogger instance once it's initialized.
        
        This allows the async_init process to provide a properly initialized
        logger that shares Redis clients with other components.
        
        Args:
            real_logger: Initialized UnifiedAsyncLogger instance
        """
        self._real_logger = real_logger
        self._initialized = True
        
        # Flush any queued messages using the real logger
        if self._message_queue:
            async def flush_queue():
                for msg in self._message_queue:
                    level = msg.pop("level", "INFO")
                    message = msg.pop("message", "")
                    component = msg.pop("component", None)
                    trace_id = msg.pop("trace_id", None)
                    await self._real_logger.log(level, message, trace_id, component, **msg)
                self._message_queue.clear()
            
            # Try to flush if event loop exists
            try:
                loop = asyncio.get_running_loop()
                asyncio.create_task(flush_queue())
            except RuntimeError:
                # Can't flush now, will flush on next log attempt
                pass
    
    # Specialized logging methods for HTTP requests/responses
    
    async def log_request(self, method: str, path: str, client_ip: str, proxy_hostname: str, 
                         trace_id=None, **kwargs):
        """Log an HTTP request."""
        if self._initialized and self._real_logger:
            return await self._real_logger.log_request(method, path, client_ip, proxy_hostname, 
                                                      trace_id=trace_id, **kwargs)
        else:
            # Queue for later
            self._queue_message("INFO", f"REQUEST: {method} {path}", 
                              request_method=method, request_path=path, 
                              client_ip=client_ip, proxy_hostname=proxy_hostname,
                              trace_id=trace_id, **kwargs)
    
    async def log_response(self, status: int, duration_ms: float, trace_id=None, **kwargs):
        """Log an HTTP response."""
        if self._initialized and self._real_logger:
            return await self._real_logger.log_response(status, duration_ms, trace_id, **kwargs)
        else:
            # Queue for later
            self._queue_message("INFO", f"RESPONSE: {status} in {duration_ms:.2f}ms", 
                              status=status, duration_ms=duration_ms,
                              trace_id=trace_id, **kwargs)
    
    async def event(self, event_type: str, data: dict, trace_id=None):
        """Log an event."""
        if self._initialized and self._real_logger:
            return await self._real_logger.event(event_type, data, trace_id)
        else:
            # Queue for later
            self._queue_message("INFO", f"EVENT: {event_type}", 
                              event_type=event_type, event_data=data,
                              trace_id=trace_id)
    
    def start_trace(self, operation: str, **metadata):
        """Start a trace."""
        if self._initialized and self._real_logger:
            return self._real_logger.start_trace(operation, **metadata)
        return None  # Can't generate trace IDs without Redis
    
    async def end_trace(self, trace_id: str, status: str = "success", **metadata):
        """End a trace."""
        if self._initialized and self._real_logger:
            await self._real_logger.end_trace(trace_id, status, **metadata)