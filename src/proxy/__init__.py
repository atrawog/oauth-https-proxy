"""Proxy component for request forwarding and routing."""

from .handler import EnhancedProxyHandler
from .app import create_proxy_app
from .models import ProxyTarget
from .routes import Route, RouteTargetType, DEFAULT_ROUTES

# For backward compatibility
ProxyHandler = EnhancedProxyHandler

__all__ = [
    'EnhancedProxyHandler',
    'ProxyHandler',
    'create_proxy_app',
    'Route',
    'RouteTargetType',
    'DEFAULT_ROUTES',
    'ProxyTarget'
]