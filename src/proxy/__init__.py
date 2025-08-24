"""Proxy module - Single unified handler for all proxy operations."""

from .unified_handler import UnifiedProxyHandler
from .app import create_proxy_app
from .models import ProxyTarget
from .routes import Route, RouteTargetType, RouteScope, DEFAULT_ROUTES

# For backward compatibility during transition (will be removed after testing)
ProxyHandler = UnifiedProxyHandler
EnhancedProxyHandler = UnifiedProxyHandler  # Temporary alias
EnhancedAsyncProxyHandler = UnifiedProxyHandler  # Temporary alias

__all__ = [
    'UnifiedProxyHandler',
    'ProxyHandler',  # Backward compatibility
    'EnhancedProxyHandler',  # Backward compatibility
    'EnhancedAsyncProxyHandler',  # Backward compatibility
    'create_proxy_app',
    'Route',
    'RouteTargetType',
    'RouteScope',
    'DEFAULT_ROUTES',
    'ProxyTarget'
]