"""Helper to extract real client IP from request headers."""

from fastapi import Request


def get_real_client_ip(request: Request) -> str:
    """Get real client IP from headers or connection.
    
    Checks in order:
    1. X-Real-IP header (set by PROXY protocol handler)
    2. X-Forwarded-For header (first IP if multiple)
    3. request.client.host (fallback to connection info)
    """
    # Check X-Real-IP first (set by our PROXY protocol handler)
    real_ip = request.headers.get("x-real-ip")
    if real_ip:
        return real_ip
    
    # Check X-Forwarded-For (may contain multiple IPs)
    forwarded_for = request.headers.get("x-forwarded-for")
    if forwarded_for:
        # Take the first IP if multiple
        return forwarded_for.split(",")[0].strip()
    
    # Fallback to connection info
    if request.client:
        return request.client.host
    
    return "unknown"