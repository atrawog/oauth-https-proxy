"""Dual logger that writes to both Python logger and Redis.

This module provides a logger that can write to both the Python logging system
(for console/file output) and the Redis-based UnifiedAsyncLogger for persistence
and querying.

Usage:
    from src.shared.dual_logger import create_dual_logger
    
    # For dispatcher and main components
    logger = create_dual_logger("dispatcher")
    logger.info("Server started", port=8080)
    logger.error("Connection failed", error=str(e))
"""

import asyncio
import logging
from typing import Optional, Any, Dict

from .unified_logger import UnifiedAsyncLogger
from .log_levels import TRACE


class DualLogger:
    """Logger that writes to both Python logger and Redis."""
    
    def __init__(self, component: str, python_logger: Optional[logging.Logger] = None, 
                 redis_logger: Optional[UnifiedAsyncLogger] = None):
        """Initialize the dual logger.
        
        Args:
            component: Component name for logging context
            python_logger: Python logger instance (if None, uses module logger)
            redis_logger: Redis logger instance (if None, only logs to Python)
        """
        self.component = component
        self.python_logger = python_logger or logging.getLogger(f"oauth_proxy.{component}")
        self.redis_logger = redis_logger
        
    def _format_message(self, message: str, **kwargs) -> str:
        """Format message with additional context for Python logger.
        
        Args:
            message: Base message
            **kwargs: Additional context fields
            
        Returns:
            Formatted message string
        """
        if not kwargs:
            return f"[{self.component}] {message}"
            
        # Add important context fields to the message
        context_parts = []
        for key, value in kwargs.items():
            if key in ['error', 'trace_id', 'client_ip', 'proxy_hostname', 'status']:
                context_parts.append(f"{key}={value}")
        
        if context_parts:
            context_str = " | " + " ".join(context_parts)
            return f"[{self.component}] {message}{context_str}"
        return f"[{self.component}] {message}"
    
    def trace(self, message: str, **kwargs):
        """Log at TRACE level (very verbose debugging).
        
        Args:
            message: Log message
            **kwargs: Additional structured data
        """
        formatted_msg = self._format_message(message, **kwargs)
        
        # Log to Python logger if it supports TRACE
        if hasattr(self.python_logger, 'trace'):
            self.python_logger.trace(formatted_msg)
        elif self.python_logger.isEnabledFor(TRACE):
            self.python_logger.log(TRACE, formatted_msg)
        
        # Log to Redis (fire-and-forget)
        if self.redis_logger:
            self.redis_logger.trace(message, component=self.component, **kwargs)
    
    def debug(self, message: str, **kwargs):
        """Log at DEBUG level.
        
        Args:
            message: Log message
            **kwargs: Additional structured data
        """
        formatted_msg = self._format_message(message, **kwargs)
        self.python_logger.debug(formatted_msg)
        
        # Log to Redis (fire-and-forget)
        if self.redis_logger:
            self.redis_logger.debug(message, component=self.component, **kwargs)
    
    def info(self, message: str, **kwargs):
        """Log at INFO level.
        
        Args:
            message: Log message
            **kwargs: Additional structured data
        """
        formatted_msg = self._format_message(message, **kwargs)
        self.python_logger.info(formatted_msg)
        
        # Log to Redis (fire-and-forget)
        if self.redis_logger:
            self.redis_logger.info(message, component=self.component, **kwargs)
    
    def warning(self, message: str, **kwargs):
        """Log at WARNING level.
        
        Args:
            message: Log message
            **kwargs: Additional structured data
        """
        formatted_msg = self._format_message(message, **kwargs)
        self.python_logger.warning(formatted_msg)
        
        # Log to Redis (fire-and-forget)
        if self.redis_logger:
            self.redis_logger.warning(message, component=self.component, **kwargs)
    
    def error(self, message: str, error: Optional[Exception] = None, **kwargs):
        """Log at ERROR level.
        
        Args:
            message: Log message
            error: Optional exception to log
            **kwargs: Additional structured data
        """
        if error:
            kwargs['error'] = str(error)
            kwargs['error_type'] = type(error).__name__
        
        formatted_msg = self._format_message(message, **kwargs)
        self.python_logger.error(formatted_msg)
        
        # Log to Redis (fire-and-forget)
        if self.redis_logger:
            self.redis_logger.error(message, component=self.component, **kwargs)
    
    def critical(self, message: str, **kwargs):
        """Log at CRITICAL level.
        
        Args:
            message: Log message
            **kwargs: Additional structured data
        """
        formatted_msg = self._format_message(message, **kwargs)
        self.python_logger.critical(formatted_msg)
        
        # Log to Redis (fire-and-forget)
        if self.redis_logger:
            self.redis_logger.critical(message, component=self.component, **kwargs)
    
    # Async methods for compatibility with async code
    async def alog(self, level: str, message: str, **kwargs):
        """Async log method for compatibility.
        
        Args:
            level: Log level
            message: Log message
            **kwargs: Additional structured data
        """
        # Call the appropriate sync method
        level_method = getattr(self, level.lower(), self.info)
        level_method(message, **kwargs)
    
    # Specialized logging methods
    def log_request(self, method: str, path: str, client_ip: str, proxy_hostname: str, **kwargs):
        """Log an HTTP request.
        
        Args:
            method: HTTP method
            path: Request path
            client_ip: Client IP address
            proxy_hostname: Target hostname
            **kwargs: Additional request data
        """
        message = f"Request: {method} {path}"
        self.info(message, method=method, path=path, client_ip=client_ip, 
                 proxy_hostname=proxy_hostname, **kwargs)
    
    def log_response(self, status: int, duration_ms: float, **kwargs):
        """Log an HTTP response.
        
        Args:
            status: HTTP status code
            duration_ms: Request duration in milliseconds
            **kwargs: Additional response data
        """
        message = f"Response: {status} ({duration_ms:.2f}ms)"
        level = 'error' if status >= 500 else 'warning' if status >= 400 else 'info'
        getattr(self, level)(message, status=status, duration_ms=duration_ms, **kwargs)


# Global dual loggers for specific components
_dual_loggers: Dict[str, DualLogger] = {}


def create_dual_logger(component: str, redis_logger: Optional[UnifiedAsyncLogger] = None) -> DualLogger:
    """Create or get a dual logger for a component.
    
    Args:
        component: Component name
        redis_logger: Optional Redis logger instance
        
    Returns:
        DualLogger instance for the component
    """
    if component not in _dual_loggers:
        _dual_loggers[component] = DualLogger(component, redis_logger=redis_logger)
    elif redis_logger and not _dual_loggers[component].redis_logger:
        # Update with Redis logger if it wasn't set before
        _dual_loggers[component].redis_logger = redis_logger
    return _dual_loggers[component]


def set_redis_logger_for_component(component: str, redis_logger: UnifiedAsyncLogger):
    """Set the Redis logger for a component's dual logger.
    
    Args:
        component: Component name
        redis_logger: Redis logger instance
    """
    if component in _dual_loggers:
        _dual_loggers[component].redis_logger = redis_logger
    else:
        _dual_loggers[component] = DualLogger(component, redis_logger=redis_logger)


# Helper functions for easy migration
def get_dual_logger(component: str) -> Optional[DualLogger]:
    """Get the dual logger for a component if it exists.
    
    Args:
        component: Component name
        
    Returns:
        DualLogger instance or None
    """
    return _dual_loggers.get(component)