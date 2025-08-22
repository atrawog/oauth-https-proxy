"""Global unified logger helper for fire-and-forget async logging.

This module provides a simple interface to the UnifiedAsyncLogger that can be
used throughout the codebase without needing to manage the logger instance.

Usage:
    from src.shared.logger import log_info, log_error, log_debug, log_warning
    
    # Fire-and-forget logging - no await needed!
    log_info("Server started", port=8080)
    log_error("Connection failed", error=str(e))
    log_debug("Processing request", path="/api/data")
    log_warning("Rate limit approaching", current=95, max=100)
"""

import asyncio
from typing import Optional, Any, Dict, TYPE_CHECKING

if TYPE_CHECKING:
    from .unified_logger import UnifiedAsyncLogger

# Global logger instance
_logger: Optional['UnifiedAsyncLogger'] = None


def set_global_logger(logger: 'UnifiedAsyncLogger'):
    """Set the global unified logger instance.
    
    This should be called once during application initialization.
    
    Args:
        logger: Initialized UnifiedAsyncLogger instance
    """
    global _logger
    _logger = logger


def get_logger() -> Optional['UnifiedAsyncLogger']:
    """Get the global unified logger instance.
    
    Returns:
        UnifiedAsyncLogger instance if initialized, None otherwise
    """
    return _logger


# Fire-and-forget logging functions
# These functions create async tasks so they return immediately

def log_debug(message: str, component: Optional[str] = None, **kwargs):
    """Fire-and-forget debug log.
    
    Args:
        message: Log message
        component: Optional component name override
        **kwargs: Additional structured data
    """
    if _logger:
        if component:
            # Temporarily set component
            original = _logger.component
            _logger.set_component(component)
            asyncio.create_task(_logger.debug(message, **kwargs))
            _logger.component = original
        else:
            asyncio.create_task(_logger.debug(message, **kwargs))


def log_info(message: str, component: Optional[str] = None, **kwargs):
    """Fire-and-forget info log.
    
    Args:
        message: Log message
        component: Optional component name override
        **kwargs: Additional structured data
    """
    if _logger:
        if component:
            # Temporarily set component
            original = _logger.component
            _logger.set_component(component)
            asyncio.create_task(_logger.info(message, **kwargs))
            _logger.component = original
        else:
            asyncio.create_task(_logger.info(message, **kwargs))


def log_warning(message: str, component: Optional[str] = None, **kwargs):
    """Fire-and-forget warning log.
    
    Args:
        message: Log message
        component: Optional component name override
        **kwargs: Additional structured data
    """
    if _logger:
        if component:
            # Temporarily set component
            original = _logger.component
            _logger.set_component(component)
            asyncio.create_task(_logger.warning(message, **kwargs))
            _logger.component = original
        else:
            asyncio.create_task(_logger.warning(message, **kwargs))


def log_error(message: str, component: Optional[str] = None, error: Optional[Exception] = None, **kwargs):
    """Fire-and-forget error log.
    
    Args:
        message: Log message
        component: Optional component name override
        error: Optional exception to log
        **kwargs: Additional structured data
    """
    if _logger:
        if error:
            kwargs['error'] = str(error)
            kwargs['error_type'] = type(error).__name__
        
        if component:
            # Temporarily set component
            original = _logger.component
            _logger.set_component(component)
            asyncio.create_task(_logger.error(message, **kwargs))
            _logger.component = original
        else:
            asyncio.create_task(_logger.error(message, **kwargs))


def log_critical(message: str, component: Optional[str] = None, **kwargs):
    """Fire-and-forget critical log.
    
    Args:
        message: Log message
        component: Optional component name override
        **kwargs: Additional structured data
    """
    if _logger:
        if component:
            # Temporarily set component
            original = _logger.component
            _logger.set_component(component)
            asyncio.create_task(_logger.critical(message, **kwargs))
            _logger.component = original
        else:
            asyncio.create_task(_logger.critical(message, **kwargs))


# Specialized logging helpers

def log_request(method: str, path: str, ip: str, proxy_hostname: str, **kwargs):
    """Fire-and-forget HTTP request log.
    
    Args:
        method: HTTP method
        path: Request path
        ip: Client IP
        proxy_hostname: Target hostname being accessed
        **kwargs: Additional request data
    """
    if _logger:
        asyncio.create_task(_logger.log_request(method, path, ip, proxy_hostname, **kwargs))


def log_response(status: int, duration_ms: float, trace_id: Optional[str] = None, **kwargs):
    """Fire-and-forget HTTP response log.
    
    Args:
        status: HTTP status code
        duration_ms: Request duration in milliseconds
        trace_id: Optional trace ID for correlation
        **kwargs: Additional response data
    """
    if _logger:
        asyncio.create_task(_logger.log_response(status, duration_ms, trace_id, **kwargs))


def log_event(event_type: str, data: Dict[str, Any], trace_id: Optional[str] = None):
    """Fire-and-forget event log.
    
    Args:
        event_type: Type of event
        data: Event data
        trace_id: Optional trace ID for correlation
    """
    if _logger:
        asyncio.create_task(_logger.event(event_type, data, trace_id))


# Trace management helpers

def start_trace(operation: str, **metadata) -> Optional[str]:
    """Start a new trace for an operation.
    
    Args:
        operation: Name of the operation
        **metadata: Additional metadata for the trace
        
    Returns:
        Trace ID for correlation, or None if logger not initialized
    """
    if _logger:
        return _logger.start_trace(operation, **metadata)
    return None


async def end_trace(trace_id: str, status: str = "success", **metadata):
    """End an active trace.
    
    Args:
        trace_id: Trace ID to end
        status: Final status of the trace
        **metadata: Additional metadata
    """
    if _logger and trace_id:
        await _logger.end_trace(trace_id, status, **metadata)


# Backwards compatibility wrapper for gradual migration
class LoggerCompat:
    """Compatibility wrapper for old logger interface.
    
    This provides a logger-like interface that uses the unified logger
    underneath, allowing gradual migration of existing code.
    """
    
    def __init__(self, component: str):
        self.component = component
    
    def debug(self, message: str, *args, **kwargs):
        log_debug(message % args if args else message, component=self.component, **kwargs)
    
    def info(self, message: str, *args, **kwargs):
        log_info(message % args if args else message, component=self.component, **kwargs)
    
    def warning(self, message: str, *args, **kwargs):
        log_warning(message % args if args else message, component=self.component, **kwargs)
    
    def error(self, message: str, *args, **kwargs):
        log_error(message % args if args else message, component=self.component, **kwargs)
    
    def critical(self, message: str, *args, **kwargs):
        log_critical(message % args if args else message, component=self.component, **kwargs)


def get_logger_compat(name: str) -> LoggerCompat:
    """Get a compatibility logger for gradual migration.
    
    This can be used as a drop-in replacement for logging.getLogger()
    to ease migration to the unified logger.
    
    Args:
        name: Logger name (used as component)
        
    Returns:
        LoggerCompat instance that mimics standard logger interface
    """
    return LoggerCompat(name)