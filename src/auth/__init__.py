"""Flexible authentication and authorization system.

This module provides a unified authentication system that supports multiple
authentication types (none, bearer, admin, oauth) configurable at different
layers (API endpoints, routes, proxies).
"""

from .models import (
    AuthConfig,
    EndpointAuthConfig,
    RouteAuthConfig,
    ProxyAuthConfig,
    AuthResult,
    TokenValidation,
    OAuthValidation
)
from .service import FlexibleAuthService
from .dependencies import AuthDep

__all__ = [
    "AuthConfig",
    "EndpointAuthConfig",
    "RouteAuthConfig", 
    "ProxyAuthConfig",
    "AuthResult",
    "TokenValidation",
    "OAuthValidation",
    "FlexibleAuthService",
    "AuthDep"
]