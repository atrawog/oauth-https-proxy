"""Middleware for capturing full request paths and managing auth configuration."""

from typing import Optional
from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware
from ..shared.logger import log_debug, log_info, log_warning, log_error, log_trace


class AuthConfigMiddleware(BaseHTTPMiddleware):
    """Middleware to capture full request paths for authentication configuration.
    
    This middleware runs before routing and stores the original request path
    and method in request.state, allowing the auth system to apply different
    configurations for the same endpoint mounted at different paths.
    """
    
    async def dispatch(self, request: Request, call_next):
        """Process the request and capture path information.
        
        Args:
            request: The incoming request
            call_next: The next middleware or endpoint handler
            
        Returns:
            The response from the next handler
        """
        # Normalize the path (remove duplicate slashes, etc.)
        full_path = self._normalize_path(str(request.url.path))
        
        # Store the full path and method in request state
        request.state.full_path = full_path
        request.state.method = request.method
        
        # Log the captured path for debugging
        log_debug(
            f"AuthConfigMiddleware captured request",
            component="auth_middleware",
            full_path=full_path,
            method=request.method,
            url=str(request.url),
            headers=dict(request.headers)
        )
        
        # Continue with the request
        response = await call_next(request)
        
        # Optionally add auth info to response headers for debugging
        if hasattr(request.state, 'auth_context'):
            response.headers["X-Auth-Type"] = request.state.auth_context.get("auth_type", "none")
            if request.state.auth_context.get("matched_pattern"):
                response.headers["X-Auth-Pattern"] = request.state.auth_context["matched_pattern"]
        
        return response
    
    def _normalize_path(self, path: str) -> str:
        """Normalize a request path.
        
        Args:
            path: The raw request path
            
        Returns:
            Normalized path
        """
        # Remove duplicate slashes
        while "//" in path:
            path = path.replace("//", "/")
        
        # Ensure path starts with /
        if not path.startswith("/"):
            path = "/" + path
        
        # Don't remove trailing slash - it may be significant
        # (FastAPI treats /path and /path/ differently)
        
        return path