"""Unified async logger for events and logs.

This module provides a unified logging interface that publishes both
operational events and traditional logs to Redis Streams with consistent
schemas and trace correlation.
"""

import asyncio
import json
import logging
import os
import time
from typing import Any, Dict, Optional
from contextlib import asynccontextmanager

from ..storage.redis_clients import RedisClients
from ..storage.unified_stream_publisher import UnifiedStreamPublisher
from ..shared.dns_resolver import get_dns_resolver

logger = logging.getLogger(__name__)

# Configuration from environment
LOG_REQUEST_HEADERS = os.getenv('LOG_REQUEST_HEADERS', 'true').lower() == 'true'
LOG_RESPONSE_HEADERS = os.getenv('LOG_RESPONSE_HEADERS', 'true').lower() == 'true'
LOG_REQUEST_BODY = os.getenv('LOG_REQUEST_BODY', 'true').lower() == 'true'
LOG_RESPONSE_BODY = os.getenv('LOG_RESPONSE_BODY', 'false').lower() == 'true'
LOG_BODY_MAX_SIZE = int(os.getenv('LOG_BODY_MAX_SIZE', '10240'))
LOG_MASK_SENSITIVE = os.getenv('LOG_MASK_SENSITIVE', 'true').lower() == 'true'

# Sensitive headers to mask
SENSITIVE_HEADERS = ['authorization', 'cookie', 'x-api-key', 'x-auth-token', 'x-csrf-token']

def mask_sensitive_headers(headers: Dict[str, str]) -> Dict[str, str]:
    """Mask sensitive header values for security."""
    if not LOG_MASK_SENSITIVE:
        return headers
    
    masked = {}
    for key, value in headers.items():
        if key.lower() in SENSITIVE_HEADERS:
            # Keep first 8 chars for debugging, mask rest
            if len(value) > 8:
                masked[key] = value[:8] + "***MASKED***"
            else:
                masked[key] = "***MASKED***"
        else:
            masked[key] = value
    return masked


class UnifiedAsyncLogger:
    """Unified logger for both events and logs with trace correlation."""
    
    def __init__(self, redis_clients: RedisClients):
        """Initialize the unified logger.
        
        Args:
            redis_clients: RedisClients instance with multiple connections
        """
        self.redis_clients = redis_clients
        self.publisher = UnifiedStreamPublisher(redis_clients.stream_redis)
        
        # Component name for this instance
        self.component = "unknown"
        
        # Active traces for correlation
        self.active_traces: Dict[str, Dict[str, Any]] = {}
    
    def set_component(self, component: str):
        """Set the component name for this logger instance.
        
        Args:
            component: Component name (e.g., "proxy_handler", "cert_manager")
        """
        self.component = component
    
    # Trace management
    
    def start_trace(self, operation: str, **metadata) -> str:
        """Start a new trace for an operation.
        
        Args:
            operation: Name of the operation
            **metadata: Additional metadata for the trace
            
        Returns:
            Trace ID for correlation
        """
        trace_id = self.publisher.generate_trace_id(operation)
        
        self.active_traces[trace_id] = {
            "operation": operation,
            "start_time": int(time.time() * 1000),  # Use milliseconds
            "metadata": metadata,
            "spans": []
        }
        
        # Store trace metadata in Redis for later resolution
        trace_metadata = {
            "client_id": trace_id,  # trace_id IS the client_id
            "start_time": int(time.time() * 1000),
            "operation": operation,
            **metadata
        }
        
        # Store with TTL (24 hours) using asyncio task
        asyncio.create_task(
            self.redis_clients.stream_redis.setex(
                f"trace:metadata:{trace_id}",
                86400,  # 24 hour TTL
                json.dumps(trace_metadata)
            )
        )
        
        # Log trace start
        asyncio.create_task(self.log(
            "DEBUG",
            f"Started trace for {operation}",
            trace_id=trace_id,
            **metadata
        ))
        
        return trace_id
    
    async def end_trace(self, trace_id: str, status: str = "success", **metadata):
        """End an active trace.
        
        Args:
            trace_id: Trace ID to end
            status: Final status of the trace
            **metadata: Additional metadata
        """
        if trace_id not in self.active_traces:
            return
        
        trace_data = self.active_traces[trace_id]
        duration_ms = int(time.time() * 1000) - trace_data["start_time"]
        
        # Log trace completion
        await self.log(
            "DEBUG" if status == "success" else "WARNING",
            f"Completed trace for {trace_data['operation']}: {status}",
            trace_id=trace_id,
            duration_ms=duration_ms,
            status=status,
            **metadata
        )
        
        # Clean up
        del self.active_traces[trace_id]
    
    @asynccontextmanager
    async def trace_context(self, operation: str, **metadata):
        """Context manager for automatic trace management.
        
        Args:
            operation: Name of the operation
            **metadata: Additional metadata
            
        Yields:
            Trace ID for use within the context
        """
        trace_id = self.start_trace(operation, **metadata)
        try:
            yield trace_id
            await self.end_trace(trace_id, "success")
        except Exception as e:
            await self.end_trace(trace_id, "error", error=str(e))
            raise
    
    def add_span(self, trace_id: str, span_name: str, **data):
        """Add a span to an active trace.
        
        Args:
            trace_id: Trace ID
            span_name: Name of the span
            **data: Span data
        """
        if trace_id in self.active_traces:
            self.active_traces[trace_id]["spans"].append({
                "name": span_name,
                "timestamp": int(time.time() * 1000),  # Use milliseconds
                "data": data
            })
    
    # Event publishing
    
    async def event(self, event_type: str, data: Dict[str, Any],
                   trace_id: Optional[str] = None) -> Optional[str]:
        """Publish an operational event.
        
        Args:
            event_type: Type of event (e.g., proxy_created, certificate_ready)
            data: Event-specific data
            trace_id: Optional trace ID for correlation
            
        Returns:
            Event ID
        """
        # Add span if trace is active
        if trace_id and trace_id in self.active_traces:
            self.add_span(trace_id, event_type, **data)
        
        return await self.publisher.publish_event(
            event_type=event_type,
            data=data,
            trace_id=trace_id,
            component=self.component
        )
    
    # Log publishing
    
    async def log(self, level: str, message: str,
                 trace_id: Optional[str] = None,
                 **kwargs) -> Optional[str]:
        """Publish a log entry.
        
        Args:
            level: Log level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
            message: Log message
            trace_id: Optional trace ID for correlation
            **kwargs: Additional log fields
            
        Returns:
            Log ID
        """
        # Add span if trace is active
        if trace_id and trace_id in self.active_traces:
            self.add_span(trace_id, "log", level=level, message=message)
        
        return await self.publisher.publish_log(
            level=level,
            message=message,
            component=self.component,
            trace_id=trace_id,
            **kwargs
        )
    
    # Convenience methods for different log levels
    
    async def debug(self, message: str, trace_id: Optional[str] = None, **kwargs):
        """Log a debug message."""
        return await self.log("DEBUG", message, trace_id, **kwargs)
    
    async def info(self, message: str, trace_id: Optional[str] = None, **kwargs):
        """Log an info message."""
        return await self.log("INFO", message, trace_id, **kwargs)
    
    async def warning(self, message: str, trace_id: Optional[str] = None, **kwargs):
        """Log a warning message."""
        return await self.log("WARNING", message, trace_id, **kwargs)
    
    async def error(self, message: str, trace_id: Optional[str] = None, **kwargs):
        """Log an error message."""
        return await self.log("ERROR", message, trace_id, **kwargs)
    
    async def critical(self, message: str, trace_id: Optional[str] = None, **kwargs):
        """Log a critical message."""
        return await self.log("CRITICAL", message, trace_id, **kwargs)
    
    # Specialized logging methods
    
    async def log_request(self, 
                         method: str, 
                         path: str, 
                         client_ip: str,
                         proxy_hostname: str, 
                         trace_id: Optional[str] = None,
                         headers: Optional[Dict[str, str]] = None,
                         body: Optional[bytes] = None,
                         query: Optional[str] = None,
                         user_agent: Optional[str] = None,
                         referer: Optional[str] = None,
                         client_hostname: Optional[str] = None,
                         auth_type: Optional[str] = None,
                         auth_user: Optional[str] = None,
                         **extra) -> Optional[str]:
        """Log an HTTP request with all available details.
        
        Args:
            method: HTTP method
            path: Request path
            client_ip: Client IP address
            proxy_hostname: The proxy hostname being accessed
            trace_id: Request trace ID
            headers: Request headers (optional, will be masked if configured)
            body: Request body (optional, will be truncated if configured)
            query: Query string (optional)
            user_agent: User-Agent header (optional)
            referer: Referer header (optional)
            client_hostname: Reverse DNS of client IP (optional, will be resolved if not provided)
            auth_type: Authentication type used (optional)
            auth_user: Authenticated user (optional)
            **extra: Additional request fields
            
        Returns:
            Log ID
        """
        # Resolve client hostname if not provided
        if not client_hostname:
            dns_resolver = get_dns_resolver()
            client_hostname = await dns_resolver.resolve_ptr(client_ip)
        
        # Mask sensitive headers if configured and headers provided
        masked_headers = None
        if headers and LOG_REQUEST_HEADERS:
            masked_headers = mask_sensitive_headers(headers)
        
        # Truncate body if needed and body provided
        truncated_body = None
        if body and LOG_REQUEST_BODY:
            truncated_body = body[:LOG_BODY_MAX_SIZE]
        
        request_data = {
            "method": method,
            "path": path,
            "client_ip": client_ip,
            "proxy_hostname": proxy_hostname,      # The proxy being accessed
            "client_hostname": client_hostname,     # Reverse DNS of client
            "query": query or "",
            "user_agent": user_agent or "",
            "referer": referer or "",
            "auth_type": auth_type or "",
            "auth_user": auth_user or "anonymous",
            **extra
        }
        
        # Add optional fields only if they have values
        if masked_headers:
            request_data["headers"] = json.dumps(masked_headers)
        if truncated_body:
            request_data["body"] = truncated_body.decode('utf-8', errors='ignore')
        
        return await self.publisher.publish_http_request(request_data, trace_id)
    
    async def log_response(self, 
                          status: int, 
                          duration_ms: float,
                          trace_id: Optional[str] = None,
                          headers: Optional[Dict[str, str]] = None,
                          body: Optional[bytes] = None,
                          proxy_hostname: Optional[str] = None,
                          backend_url: Optional[str] = None,
                          response_size: Optional[int] = None,
                          # Request context fields for complete logging
                          client_ip: Optional[str] = None,
                          method: Optional[str] = None,
                          path: Optional[str] = None,
                          query: Optional[str] = None,
                          user_agent: Optional[str] = None,
                          referer: Optional[str] = None,
                          client_hostname: Optional[str] = None,
                          auth_type: Optional[str] = None,
                          auth_user: Optional[str] = None,
                          **extra) -> Optional[str]:
        """Log an HTTP response with all available details.
        
        Args:
            status: HTTP status code
            duration_ms: Request duration in milliseconds
            trace_id: Request trace ID
            headers: Response headers (optional, will be masked if configured)
            body: Response body (optional, will be truncated if configured)
            proxy_hostname: The proxy hostname (optional)
            backend_url: The backend URL that was proxied to (optional)
            response_size: Size of response in bytes (optional)
            client_ip: Client IP address (optional, for context)
            method: HTTP method (optional, for context)
            path: Request path (optional, for context)
            query: Query string (optional, for context)
            user_agent: User-Agent header (optional, for context)
            referer: Referer header (optional, for context)
            client_hostname: Reverse DNS of client IP (optional)
            auth_type: Authentication type used (optional)
            auth_user: Authenticated user (optional)
            **extra: Additional response fields
            
        Returns:
            Log ID
        """
        # Resolve client hostname if client_ip provided but not hostname
        if client_ip and not client_hostname:
            dns_resolver = get_dns_resolver()
            client_hostname = await dns_resolver.resolve_ptr(client_ip)
        
        # Mask sensitive headers if configured and headers provided
        masked_headers = None
        if headers and LOG_RESPONSE_HEADERS:
            masked_headers = mask_sensitive_headers(headers)
        
        # Truncate body if needed and body provided
        truncated_body = None
        if body and LOG_RESPONSE_BODY:
            truncated_body = body[:LOG_BODY_MAX_SIZE]
        
        response_data = {
            "status": status,
            "status_code": status,  # Include both for compatibility
            "duration_ms": duration_ms,
            "response_time_ms": duration_ms,  # Include both for compatibility
            **extra
        }
        
        # Add request context fields if provided
        if client_ip:
            response_data["client_ip"] = client_ip
        if client_hostname:
            response_data["client_hostname"] = client_hostname
        if method:
            response_data["method"] = method
        if path:
            response_data["path"] = path
        if query:
            response_data["query"] = query
        if user_agent:
            response_data["user_agent"] = user_agent
        if referer:
            response_data["referer"] = referer
        if auth_type:
            response_data["auth_type"] = auth_type
        if auth_user:
            response_data["auth_user"] = auth_user
        
        # Add optional response fields
        if proxy_hostname:
            response_data["proxy_hostname"] = proxy_hostname
        if backend_url:
            response_data["backend_url"] = backend_url
        if response_size is not None:
            response_data["bytes_sent"] = response_size
        if masked_headers:
            response_data["headers"] = json.dumps(masked_headers)
        if truncated_body:
            response_data["body"] = truncated_body.decode('utf-8', errors='ignore')
        
        return await self.publisher.publish_http_response(response_data, trace_id)
    
    
    async def log_audit(self, actor: str, action: str,
                       resource: str, result: str,
                       trace_id: Optional[str] = None,
                       **extra) -> Optional[str]:
        """Log an audit event.
        
        Args:
            actor: User or system performing the action
            action: Action performed
            resource: Resource affected
            result: Result of the action
            trace_id: Optional trace ID
            **extra: Additional audit fields
            
        Returns:
            Event ID
        """
        return await self.publisher.publish_audit_event(
            actor=actor,
            action=action,
            resource=resource,
            result=result,
            trace_id=trace_id,
            **extra
        )
    
    async def log_error_exception(self, error: Exception,
                                 context: dict,
                                 trace_id: Optional[str] = None) -> Optional[str]:
        """Log an exception with full context.
        
        Args:
            error: Exception that occurred
            context: Additional context
            trace_id: Optional trace ID
            
        Returns:
            Log ID
        """
        return await self.publisher.publish_error(
            error=error,
            component=self.component,
            context=context,
            trace_id=trace_id
        )
    
    # Service lifecycle events
    
    async def log_service_event(self, service_name: str,
                               event_type: str,
                               trace_id: Optional[str] = None,
                               **data) -> Optional[str]:
        """Log a service lifecycle event.
        
        Args:
            service_name: Name of the service
            event_type: Type of event (created, started, stopped, failed)
            trace_id: Optional trace ID
            **data: Additional event data
            
        Returns:
            Event ID
        """
        return await self.event(
            f"service_{event_type}",
            {
                "service_name": service_name,
                **data
            },
            trace_id=trace_id
        )
    
    # Certificate events
    
    async def log_certificate_event(self, cert_name: str,
                                   event_type: str,
                                   domains: list,
                                   trace_id: Optional[str] = None,
                                   **data) -> Optional[str]:
        """Log a certificate lifecycle event.
        
        Args:
            cert_name: Certificate name
            event_type: Type of event (created, renewed, expiring, failed)
            domains: List of domains
            trace_id: Optional trace ID
            **data: Additional event data
            
        Returns:
            Event ID
        """
        return await self.event(
            f"certificate_{event_type}",
            {
                "cert_name": cert_name,
                "domains": domains,
                **data
            },
            trace_id=trace_id
        )
    
    # Proxy events
    
    async def log_proxy_event(self, proxy_hostname: str,
                             event_type: str,
                             trace_id: Optional[str] = None,
                             **data) -> Optional[str]:
        """Log a proxy lifecycle event.
        
        Args:
            proxy_hostname: Proxy hostname
            event_type: Type of event (created, updated, deleted, failed)
            trace_id: Optional trace ID
            **data: Additional event data
            
        Returns:
            Event ID
        """
        return await self.event(
            f"proxy_{event_type}",
            {
                "proxy_hostname": proxy_hostname,
                **data
            },
            trace_id=trace_id
        )
    
    # Route events
    
    async def log_route_event(self, route_id: str,
                             event_type: str,
                             trace_id: Optional[str] = None,
                             **data) -> Optional[str]:
        """Log a route change event.
        
        Args:
            route_id: Route ID
            event_type: Type of event (created, updated, deleted, priority_changed)
            trace_id: Optional trace ID
            **data: Additional event data
            
        Returns:
            Event ID
        """
        return await self.event(
            f"route_{event_type}",
            {
                "route_id": route_id,
                **data
            },
            trace_id=trace_id
        )
    
    # Lifecycle management
    
    async def flush(self):
        """Flush any pending log entries."""
        await self.publisher.flush()
    
    async def close(self):
        """Close the logger and flush pending entries."""
        # End any remaining traces
        for trace_id in list(self.active_traces.keys()):
            await self.end_trace(trace_id, "interrupted")
        
        await self.publisher.close()


# Global logger instance
_unified_logger: Optional[UnifiedAsyncLogger] = None


def get_unified_logger() -> UnifiedAsyncLogger:
    """Get the global unified logger instance.
    
    Returns:
        Global UnifiedAsyncLogger instance
    """
    global _unified_logger
    if not _unified_logger:
        raise RuntimeError("Unified logger not initialized. Call initialize_unified_logger() first.")
    return _unified_logger


async def initialize_unified_logger(redis_clients: RedisClients) -> UnifiedAsyncLogger:
    """Initialize the global unified logger.
    
    Args:
        redis_clients: Initialized RedisClients instance
        
    Returns:
        Initialized UnifiedAsyncLogger
    """
    global _unified_logger
    _unified_logger = UnifiedAsyncLogger(redis_clients)
    logger.info("Unified async logger initialized")
    return _unified_logger