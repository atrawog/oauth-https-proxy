"""
Unified logging middleware for FastAPI using fire-and-forget pattern.

This middleware logs all HTTP requests and responses to Redis Streams
using the UnifiedAsyncLogger without blocking request processing.
"""

import time
import os
import json
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request

from ..shared.client_ip import get_real_client_ip
from ..shared.logger import log_request, log_response, log_error


class UnifiedLoggingMiddleware(BaseHTTPMiddleware):
    """Fire-and-forget logging middleware using UnifiedAsyncLogger."""
    
    async def dispatch(self, request: Request, call_next):
        """Process request with non-blocking logging."""
        
        # SKIP ALL LOGGING for proxied requests to prevent duplicates
        if request.headers.get('x-proxied-request') == 'true':
            # This request is already being logged by the proxy layer
            # Just pass it through without any logging
            response = await call_next(request)
            return response
        
        # Start timing for direct API calls only
        start_time = time.time()
        
        # Check for existing trace_id from dispatcher (via X-Trace-Id header)
        trace_id = request.headers.get('x-trace-id')
        
        if not trace_id:
            # This is the entry point - generate new trace_id
            from ..shared.logger import start_trace
            trace_id = start_trace("http_request")
        
        # Store trace_id in request.state for all downstream use
        request.state.trace_id = trace_id
        
        # Extract request information
        client_ip = get_real_client_ip(request)
        
        # Get proxy hostname from headers (the hostname being proxied to)
        proxy_hostname = request.headers.get("x-forwarded-host", "")
        if not proxy_hostname:
            proxy_hostname = request.headers.get("host", "")
        if proxy_hostname:
            proxy_hostname = proxy_hostname.split(":")[0]
        
        # Resolve client hostname (reverse DNS of client IP)
        from ..shared.dns_resolver import get_dns_resolver
        dns_resolver = get_dns_resolver()
        import asyncio
        try:
            client_hostname = await dns_resolver.resolve_ptr(client_ip)
        except:
            client_hostname = client_ip  # Fallback to IP if resolution fails
        
        # Request details
        method = request.method
        path = request.url.path
        query = str(request.url.query) if request.url.query else ""
        user_agent = request.headers.get("user-agent", "")
        referer = request.headers.get("referer", "")
        
        # ALWAYS capture headers for comprehensive logging (not just DEBUG mode)
        # This is critical for diagnosing OAuth issues with Claude.ai
        headers = dict(request.headers)
        
        # Always capture body for comprehensive logging (for non-GET requests)
        body = None
        if method != 'GET':
            try:
                # Store body for later use since we can only read it once
                body_bytes = await request.body()
                # Create a new request with the body we read
                from starlette.datastructures import Headers
                async def receive():
                    return {"type": "http.request", "body": body_bytes}
                request._receive = receive
                body = body_bytes
            except:
                pass
        
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
            
            # Get response size, headers, and body if available
            response_size = None
            response_headers = None
            response_body = None
            if response and hasattr(response, 'headers'):
                content_length = response.headers.get("content-length")
                if content_length:
                    try:
                        response_size = int(content_length)
                    except:
                        pass
                # Capture response headers for debugging (especially WWW-Authenticate)
                response_headers = dict(response.headers)
                
                # Try to capture response body if it's available
                # Note: This works for standard Response objects
                if hasattr(response, 'body'):
                    response_body = response.body
            
            # Log the request with trace_id (fire-and-forget, no await!)
            log_request(
                method=method,
                path=path,
                client_ip=client_ip,
                proxy_hostname=proxy_hostname or "unknown",
                trace_id=trace_id,
                client_hostname=client_hostname,
                query=query,
                user_agent=user_agent,
                referer=referer,
                user_id=auth_user or "anonymous",
                client_id=oauth_client_id or "",  # OAuth client ID when present
                oauth_user=oauth_username or "",
                headers=headers,
                body=body
            )
            
            # Log the response with same trace_id, headers, and body (fire-and-forget, no await!)
            log_response(
                status=status,
                duration_ms=duration_ms,
                trace_id=trace_id,
                bytes_sent=response_size or 0,
                client_ip=client_ip,
                client_hostname=client_hostname,
                proxy_hostname=proxy_hostname or "unknown",
                headers=response_headers,  # Fixed: Use 'headers' parameter name to match function signature
                body=response_body  # Pass response body for logging
            )
            
            # Log error if there was one with trace_id (fire-and-forget, no await!)
            if error_info:
                log_error(
                    message=f"Request failed: {method} {path}",
                    component="unified_logging_middleware",
                    trace_id=trace_id,
                    error_type=error_info["error_type"],
                    error_message=error_info["error"],
                    path=path,
                    method=method,
                    client_ip=client_ip,
                    client_hostname=client_hostname,
                    proxy_hostname=proxy_hostname or "unknown"
                )
        
        return response