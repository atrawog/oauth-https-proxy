"""
Request logging middleware for FastAPI applications.

This middleware automatically logs all HTTP requests and responses to Redis
using the RequestLogger for efficient querying and analysis.
"""

import time
import logging
from typing import Optional, Dict, Any
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response
from starlette.types import Receive, Scope, Send

from ..shared.client_ip import get_real_client_ip
from ..shared.dns_resolver import get_dns_resolver
from ..shared.logger import log_debug, log_info, log_warning, log_error


class RequestLoggerMiddleware(BaseHTTPMiddleware):
    """Middleware to log all HTTP requests and responses to Redis Streams."""
    
    def __init__(self, app):
        """
        Initialize the middleware.
        
        Args:
            app: The ASGI application
        """
        super().__init__(app)
    
    async def dispatch(self, request: Request, call_next):
        """Process the request and log it to Redis Streams."""
        # Get the async storage from app state
        async_storage = getattr(request.app.state, 'async_storage', None)
        
        # Skip if no async storage available
        if not async_storage:
            return await call_next(request)
        
        # Start timing
        start_time = time.time()
        
        # Extract request information
        client_ip = get_real_client_ip(request)
        
        # Get hostname from headers
        proxy_hostname = request.headers.get("x-forwarded-host", "")
        if not hostname:
            proxy_hostname = request.headers.get("host", "")
        if hostname:
            proxy_hostname=proxy_hostname.split(":")[0]
        
        # Build request data
        method = request.method
        path = request.url.path
        query = str(request.url.query) if request.url.query else None
        user_agent = request.headers.get("user-agent", "")
        referer = request.headers.get("referer", "")
        
        # Get auth info if available
        auth_user = None
        auth_type = None
        oauth_client_id = None
        oauth_username = None
        
        # Check for authorization header
        auth_header = request.headers.get("authorization", "")
        if auth_header:
            parts = auth_header.split(" ", 1)
            auth_type = parts[0].lower() if parts else ""
            
            # Try to extract user info from request state (set by auth middleware)
            if hasattr(request.state, 'auth_user'):
                auth_user = request.state.auth_user
            if hasattr(request.state, 'oauth_client_id'):
                oauth_client_id = request.state.oauth_client_id
            if hasattr(request.state, 'oauth_username'):
                oauth_username = request.state.oauth_username
        
        # Don't log the initial request - wait for complete request+response
        request_key = None
        
        # Process the request
        response = None
        error_info = None
        try:
            response = await call_next(request)
        except Exception as e:
            error_info = {
                "type": type(e).__name__,
                "message": str(e)
            }
            raise
        finally:
            # Calculate duration
            duration_ms = (time.time() - start_time) * 1000
            
            # Log the complete request+response to Redis Streams
            if async_storage:
                try:
                    from datetime import datetime, timezone
                    status = response.status_code if response else 500
                    response_size = None
                    
                    # Try to get response size from headers
                    if response and hasattr(response, 'headers'):
                        content_length = response.headers.get("content-length")
                        if content_length:
                            try:
                                response_size = int(content_length)
                            except:
                                pass
                    
                    # Resolve client hostname
                    dns_resolver = get_dns_resolver()
                    client_hostname = await dns_resolver.resolve_ptr(client_ip)
                    
                    # Build log entry for Redis Streams with proper field names
                    log_entry = {
                        "timestamp": datetime.fromtimestamp(start_time, timezone.utc).isoformat(),
                        "client_ip": client_ip,
                        "client_hostname": client_hostname,
                        "proxy_hostname": hostname or "unknown",
                        "method": method,
                        "path": path,
                        "query": query or "",
                        "status_code": status,
                        "response_time_ms": duration_ms,
                        "user_id": auth_user or "anonymous",
                        "user_agent": user_agent,
                        "referrer": referer,
                        "bytes_sent": response_size or 0,
                        "auth_type": auth_type or "",
                        "oauth_client_id": oauth_client_id or "",
                        "oauth_username": oauth_username or "",
                    }
                    
                    if error_info:
                        log_entry["error"] = error_info.get("message", "")
                        log_entry["error_type"] = error_info.get("type", "")
                    
                    # Add a message field for compatibility
                    log_entry["message"] = f"{method} {path} {status} {duration_ms:.0f}ms"
                    
                    # Log to Redis Streams using async storage
                    await async_storage.log_request(log_entry)
                except Exception as e:
                    log_error(f"Failed to log to Redis Streams: {e}", component="request_logger")
        
        return response