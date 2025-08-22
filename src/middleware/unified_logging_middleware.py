"""
Unified logging middleware for FastAPI using fire-and-forget pattern.

This middleware logs all HTTP requests and responses to Redis Streams
using the UnifiedAsyncLogger without blocking request processing.
"""

import time
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request

from ..shared.client_ip import get_real_client_ip
from ..shared.logger import log_request, log_response, log_error


class UnifiedLoggingMiddleware(BaseHTTPMiddleware):
    """Fire-and-forget logging middleware using UnifiedAsyncLogger."""
    
    async def dispatch(self, request: Request, call_next):
        """Process request with non-blocking logging."""
        
        # Start timing
        start_time = time.time()
        
        # Extract request information
        client_ip = get_real_client_ip(request)
        
        # Get hostname from headers
        hostname = request.headers.get("x-forwarded-host", "")
        if not hostname:
            hostname = request.headers.get("host", "")
        if hostname:
            hostname = hostname.split(":")[0]
        
        # Request details
        method = request.method
        path = request.url.path
        query = str(request.url.query) if request.url.query else ""
        user_agent = request.headers.get("user-agent", "")
        referer = request.headers.get("referer", "")
        
        # Get auth info if available
        auth_user = getattr(request.state, 'auth_user', None)
        oauth_client_id = getattr(request.state, 'oauth_client_id', None)
        oauth_username = getattr(request.state, 'oauth_username', None)
        
        # Process the request
        response = None
        error_info = None
        try:
            response = await call_next(request)
        except Exception as e:
            error_info = {
                "error_type": type(e).__name__,
                "error": str(e)
            }
            raise
        finally:
            # Calculate duration
            duration_ms = (time.time() - start_time) * 1000
            
            # Fire-and-forget logging - NO await!
            status = response.status_code if response else 500
            
            # Get response size if available
            response_size = None
            if response and hasattr(response, 'headers'):
                content_length = response.headers.get("content-length")
                if content_length:
                    try:
                        response_size = int(content_length)
                    except:
                        pass
            
            # Log the request (fire-and-forget, no await!)
            log_request(
                method=method,
                path=path,
                ip=client_ip,
                proxy_hostname=hostname or "unknown",
                query=query,
                user_agent=user_agent,
                referer=referer,
                user_id=auth_user or "anonymous",
                oauth_client_id=oauth_client_id or "",
                oauth_username=oauth_username or ""
            )
            
            # Log the response (fire-and-forget, no await!)
            log_response(
                status=status,
                duration_ms=duration_ms,
                bytes_sent=response_size or 0
            )
            
            # Log error if there was one (fire-and-forget, no await!)
            if error_info:
                log_error(
                    message=f"Request failed: {method} {path}",
                    component="unified_logging_middleware",
                    error_type=error_info["error_type"],
                    error_message=error_info["error"],
                    path=path,
                    method=method,
                    client_ip=client_ip
                )
        
        return response