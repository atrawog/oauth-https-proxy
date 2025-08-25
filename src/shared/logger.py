"""Global unified logger helper for fire-and-forget async logging.

This module provides a simple interface to the UnifiedAsyncLogger that can be
used throughout the codebase without needing to manage the logger instance.

Usage:
    from src.shared.logger import log_info, log_error, log_debug, log_warning, log_trace
    
    # Fire-and-forget logging - no await needed!
    log_info("Server started", port=8080)
    log_error("Connection failed", error=str(e))
    log_debug("Processing request", path="/api/data")
    log_warning("Rate limit approaching", current=95, max=100)
    log_trace("Detailed internal state", data=complex_object)
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
        _logger.debug(message, component=component, **kwargs)


def log_info(message: str, component: Optional[str] = None, **kwargs):
    """Fire-and-forget info log.
    
    Args:
        message: Log message
        component: Optional component name override
        **kwargs: Additional structured data
    """
    if _logger:
        _logger.info(message, component=component, **kwargs)


def log_warning(message: str, component: Optional[str] = None, **kwargs):
    """Fire-and-forget warning log.
    
    Args:
        message: Log message
        component: Optional component name override
        **kwargs: Additional structured data
    """
    if _logger:
        _logger.warning(message, component=component, **kwargs)


def log_error(message: str, component: Optional[str] = None, error: Optional[Exception] = None, trace_id: Optional[str] = None, **kwargs):
    """Fire-and-forget error log.
    
    Args:
        message: Log message
        component: Optional component name override
        error: Optional exception to log
        trace_id: Optional trace ID for correlation
        **kwargs: Additional structured data
    """
    if _logger:
        if error:
            kwargs['error'] = str(error)
            kwargs['error_type'] = type(error).__name__
        
        if trace_id:
            kwargs['trace_id'] = trace_id
        
        _logger.error(message, component=component, **kwargs)


def log_critical(message: str, component: Optional[str] = None, **kwargs):
    """Fire-and-forget critical log.
    
    Args:
        message: Log message
        component: Optional component name override
        **kwargs: Additional structured data
    """
    if _logger:
        _logger.critical(message, component=component, **kwargs)


def log_trace(message: str, component: Optional[str] = None, **kwargs):
    """Fire-and-forget trace log (very verbose debugging).
    
    Args:
        message: Log message
        component: Optional component name override
        **kwargs: Additional structured data
    """
    if _logger:
        _logger.trace(message, component=component, **kwargs)


# Specialized logging helpers

def log_request(method: str, path: str, client_ip: str, proxy_hostname: str, trace_id: Optional[str] = None, **kwargs):
    """Fire-and-forget HTTP request log.
    
    Args:
        method: HTTP method
        path: Request path
        client_ip: Client IP address
        proxy_hostname: Target hostname being accessed
        trace_id: Request trace ID
        **kwargs: Additional request data
    """
    if _logger:
        asyncio.create_task(_logger.log_request(method, path, client_ip, proxy_hostname, trace_id=trace_id, **kwargs))


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

