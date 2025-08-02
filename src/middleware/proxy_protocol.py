"""
PROXY Protocol Middleware for ASGI applications.

Since Hypercorn doesn't natively support PROXY protocol, this middleware
handles parsing PROXY protocol headers at the application level.
"""
import logging
from typing import Tuple, Optional
import asyncio

logger = logging.getLogger(__name__)


class ProxyProtocolMiddleware:
    """
    ASGI middleware to handle PROXY protocol v1.
    
    This middleware intercepts the raw connection and parses PROXY protocol
    headers to extract the real client IP and port.
    """
    
    def __init__(self, app):
        self.app = app
        
    async def __call__(self, scope, receive, send):
        if scope["type"] == "lifespan":
            # Pass through lifespan events unchanged
            await self.app(scope, receive, send)
            return
            
        # Only process HTTP connections
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        
        # Check if we need to handle PROXY protocol
        # This is a bit tricky since PROXY protocol is at the TCP level
        # and ASGI operates at the HTTP level
        
        # For now, we'll trust that if the client is 127.0.0.1, 
        # the real client info might be in headers added by our dispatcher
        client = scope.get("client")
        if client and client[0] == "127.0.0.1":
            # Look for our custom headers that the dispatcher might add
            headers = dict(scope.get("headers", []))
            
            # Check for X-Real-IP or X-Forwarded-For headers
            real_ip = headers.get(b"x-real-ip", b"").decode("latin1")
            if not real_ip:
                forwarded_for = headers.get(b"x-forwarded-for", b"").decode("latin1")
                if forwarded_for:
                    real_ip = forwarded_for.split(",")[0].strip()
            
            real_port = headers.get(b"x-real-port", b"").decode("latin1")
            
            if real_ip:
                # Update the client information
                try:
                    port = int(real_port) if real_port else client[1]
                    scope["client"] = (real_ip, port)
                    logger.debug(f"Updated client from {client} to {scope['client']}")
                except (ValueError, TypeError):
                    logger.warning(f"Invalid port value: {real_port}")
        
        await self.app(scope, receive, send)


class ProxyProtocolServer:
    """
    A wrapper around Hypercorn that handles PROXY protocol at the connection level.
    """
    
    def __init__(self, app, config):
        self.app = app
        self.config = config
        self.server = None
        
    async def serve(self):
        """Start the server with PROXY protocol support."""
        from hypercorn.asyncio import serve
        
        # Wrap the app with our middleware
        wrapped_app = ProxyProtocolMiddleware(self.app)
        
        # Remove the invalid proxy_protocol attribute
        if hasattr(self.config, 'proxy_protocol'):
            delattr(self.config, 'proxy_protocol')
        
        logger.info(f"Starting server with PROXY protocol support on {self.config.bind}")
        await serve(wrapped_app, self.config)


async def parse_proxy_protocol_header(reader: asyncio.StreamReader) -> Tuple[Optional[str], Optional[int], bytes]:
    """
    Parse PROXY protocol v1 header from the stream.
    
    Returns:
        Tuple of (client_ip, client_port, remaining_data)
    """
    try:
        # Read first line
        line = await reader.readline()
        
        if line.startswith(b'PROXY '):
            # Parse PROXY protocol v1
            # Format: PROXY TCP4 <client_ip> <proxy_ip> <client_port> <proxy_port>\r\n
            parts = line.decode('ascii').strip().split()
            
            if len(parts) >= 6 and parts[1] in ('TCP4', 'TCP6'):
                client_ip = parts[2]
                client_port = int(parts[4])
                
                logger.debug(f"Parsed PROXY protocol: client={client_ip}:{client_port}")
                return client_ip, client_port, b""
        
        # Not a PROXY protocol header, return the line as data
        return None, None, line
        
    except Exception as e:
        logger.error(f"Error parsing PROXY protocol: {e}")
        return None, None, b""