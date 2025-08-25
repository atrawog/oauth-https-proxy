"""Proxy module - Single unified handler for all proxy operations."""

# Import models and routes directly (no circular dependency)
from .app import create_proxy_app
from .models import ProxyTarget
from .routes import Route, RouteTargetType, RouteScope, DEFAULT_ROUTES

# Lazy import for handler to avoid circular dependency
def __getattr__(name):
    """Lazy import of handler classes to avoid circular imports."""
    if name in ['UnifiedProxyHandler', 'ProxyHandler', 'EnhancedProxyHandler', 'EnhancedAsyncProxyHandler']:
        from .unified_handler import UnifiedProxyHandler
        
        # For backward compatibility during transition
        if name == 'ProxyHandler':
            return UnifiedProxyHandler
        elif name == 'EnhancedProxyHandler':
            return UnifiedProxyHandler
        elif name == 'EnhancedAsyncProxyHandler':
            return UnifiedProxyHandler
        else:
            return UnifiedProxyHandler
    raise AttributeError(f"module '{__name__}' has no attribute '{name}'")

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