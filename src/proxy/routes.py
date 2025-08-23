"""Route models and management for HTTP request routing."""

import json
import logging
from datetime import datetime, timezone
from typing import Dict, List, Optional, Union, TYPE_CHECKING, Any
from enum import Enum
from pydantic import BaseModel, Field, field_validator, ValidationInfo
import re

logger = logging.getLogger(__name__)

if TYPE_CHECKING:
    from .models import ProxyTarget


class RouteTargetType(str, Enum):
    """Types of routing targets."""
    PORT = "port"  # Forward to localhost:port
    SERVICE = "service"  # Forward to named service (e.g., 'api', 'auth')
    HOSTNAME = "hostname"  # Forward to service handling specific hostname
    URL = "url"  # Forward to any URL (http://service:port or https://example.com)


class RouteScope(str, Enum):
    """Scope of route applicability."""
    GLOBAL = "global"  # Applies to all proxies
    PROXY = "proxy"    # Applies to specific proxies only


class Route(BaseModel):
    """Represents a routing rule."""
    route_id: str = Field(..., description="Unique identifier for the route")
    path_pattern: str = Field(..., description="Path prefix or regex pattern")
    target_type: RouteTargetType = Field(..., description="Type of routing target")
    target_value: Union[int, str] = Field(..., description="Port number or service/hostname name")
    priority: int = Field(50, ge=0, le=999, description="Higher priority routes are checked first")
    methods: Optional[List[str]] = Field(None, description="HTTP methods to match (None = all)")
    is_regex: bool = Field(False, description="Whether path_pattern is a regex")
    description: str = Field("", description="Human-readable description")
    enabled: bool = Field(True, description="Whether this route is active")
    scope: RouteScope = Field(RouteScope.GLOBAL, description="Route scope (global or proxy-specific)")
    proxy_hostnames: List[str] = Field(default_factory=list, description="Proxies this route applies to (when scope=proxy)")
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    owner_token_hash: Optional[str] = Field(None, description="Hash of token that owns this route")
    created_by: Optional[str] = Field(None, description="Token name that created this route")
    
    # Authentication configuration
    auth_config: Optional[Dict[str, Any]] = Field(None, description="Authentication configuration for this route")
    override_proxy_auth: bool = Field(False, description="Whether route auth overrides proxy auth")
    
    @field_validator('methods')
    @classmethod
    def uppercase_methods(cls, v: Optional[List[str]]) -> Optional[List[str]]:
        """Ensure HTTP methods are uppercase."""
        if v:
            return [method.upper() for method in v]
        return v
    
    @field_validator('path_pattern')
    @classmethod
    def validate_pattern(cls, v: str, info: ValidationInfo) -> str:
        """Validate regex patterns."""
        if info.data.get('is_regex', False):
            try:
                re.compile(v)
            except re.error as e:
                raise ValueError(f"Invalid regex pattern: {e}")
        return v
    
    @field_validator('target_value')
    @classmethod
    def validate_target_value(cls, v: Union[int, str], info: ValidationInfo) -> Union[int, str]:
        """Validate target value based on target type."""
        target_type = info.data.get('target_type')
        if target_type == RouteTargetType.PORT:
            if isinstance(v, str):
                try:
                    port = int(v)
                    if not (1 <= port <= 65535):
                        raise ValueError("Port must be between 1 and 65535")
                    return port
                except ValueError:
                    raise ValueError("Port must be a valid integer")
            elif isinstance(v, int):
                if not (1 <= v <= 65535):
                    raise ValueError("Port must be between 1 and 65535")
                return v
            else:
                raise ValueError("Port must be an integer or string")
        elif target_type == RouteTargetType.URL:
            # Validate URL format
            if not isinstance(v, str):
                raise ValueError("URL must be a string")
            # Allow both internal service names and full URLs
            if not (v.startswith('http://') or v.startswith('https://')):
                # For internal services, prepend http://
                return f"http://{v}"
            return v
        return v
    
    @field_validator('proxy_hostnames')
    @classmethod
    def validate_proxy_hostnames(cls, v: List[str], info: ValidationInfo) -> List[str]:
        """Validate proxy proxy_hostnames are only set for proxy-scoped routes."""
        scope = info.data.get('scope', RouteScope.GLOBAL)
        if scope == RouteScope.PROXY and not v:
            raise ValueError("proxy_hostnames must be specified for proxy-scoped routes")
        elif scope == RouteScope.GLOBAL and v:
            raise ValueError("proxy_hostnames should not be set for global routes")
        return v
    
    def matches(self, path: str, method: Optional[str] = None) -> bool:
        """Check if this route matches the given path and method."""
        if not self.enabled:
            return False
            
        # Check method if specified
        # "*" means all methods are allowed
        if self.methods and method:
            if "*" not in self.methods and method.upper() not in self.methods:
                return False
        
        # Check path
        if self.is_regex:
            result = bool(re.match(self.path_pattern, path))
        else:
            result = path.startswith(self.path_pattern)
        
        # Log for debugging using unified async logger
        if self.path_pattern == "/.well-known/oauth-authorization-server":
            from ..shared.logger import log_trace
            log_trace(f"Route match check: path='{path}' pattern='{self.path_pattern}' result={result}", component="route_manager")
        
        return result
    
    def to_redis(self) -> str:
        """Convert to JSON for Redis storage."""
        return self.json()
    
    @classmethod
    def from_redis(cls, data: str) -> 'Route':
        """Create from Redis JSON data."""
        return cls.parse_raw(data)


class RouteCreateRequest(BaseModel):
    """Request model for creating a route."""
    path_pattern: str = Field(..., description="Path prefix or regex pattern")
    target_type: RouteTargetType = Field(..., description="Type of routing target")
    target_value: Union[int, str] = Field(..., description="Port number or service/hostname name")
    priority: int = Field(50, ge=0, le=999, description="Higher priority routes are checked first")
    methods: Optional[List[str]] = Field(None, description="HTTP methods to match (None = all)")
    is_regex: bool = Field(False, description="Whether path_pattern is a regex")
    description: str = Field("", description="Human-readable description")
    auth_config: Optional[Dict[str, Any]] = Field(None, description="Authentication configuration for this route")
    override_proxy_auth: bool = Field(False, description="Whether route auth overrides proxy auth")
    enabled: bool = Field(True, description="Whether this route is active")
    scope: RouteScope = Field(RouteScope.GLOBAL, description="Route scope (global or proxy-specific)")
    proxy_hostnames: List[str] = Field(default_factory=list, description="Proxies this route applies to (when scope=proxy)")


class RouteUpdateRequest(BaseModel):
    """Request model for updating a route."""
    path_pattern: Optional[str] = None
    target_type: Optional[RouteTargetType] = None
    target_value: Optional[Union[int, str]] = None
    priority: Optional[int] = Field(None, ge=0, le=999)
    methods: Optional[List[str]] = None
    is_regex: Optional[bool] = None
    description: Optional[str] = None
    enabled: Optional[bool] = None
    scope: Optional[RouteScope] = None
    proxy_hostnames: Optional[List[str]] = None


# Default routes that should always exist
DEFAULT_ROUTES = [
    {
        "route_id": "acme-challenge",
        "path_pattern": "/.well-known/acme-challenge/",
        "target_type": RouteTargetType.SERVICE,
        "target_value": "api",
        "priority": 100,
        "description": "ACME challenge validation",
        "enabled": True
    },
    {
        "route_id": "oauth-protected-resource",
        "path_pattern": "/.well-known/oauth-protected-resource",
        "target_type": RouteTargetType.SERVICE,
        "target_value": "api",
        "priority": 100,
        "description": "MCP OAuth protected resource metadata",
        "enabled": True
    },
    {
        "route_id": "oauth-authorization-server",
        "path_pattern": "/.well-known/oauth-authorization-server",
        "target_type": RouteTargetType.SERVICE,
        "target_value": "api",
        "priority": 95,
        "description": "OAuth authorization server metadata",
        "enabled": True
    }
]

# OAuth routes that need to be created for OAuth functionality
OAUTH_ROUTES = [
    {
        "path_pattern": "/authorize",
        "target_type": RouteTargetType.HOSTNAME,
        "priority": 95,
        "description": "OAuth authorization endpoint"
    },
    {
        "path_pattern": "/token",
        "target_type": RouteTargetType.HOSTNAME,
        "priority": 95,
        "description": "OAuth token endpoint"
    },
    {
        "path_pattern": "/callback",
        "target_type": RouteTargetType.HOSTNAME,
        "priority": 95,
        "description": "OAuth callback endpoint"
    },
    {
        "path_pattern": "/register",
        "target_type": RouteTargetType.HOSTNAME,
        "priority": 95,
        "description": "OAuth client registration"
    },
    {
        "path_pattern": "/verify",
        "target_type": RouteTargetType.HOSTNAME,
        "priority": 95,
        "description": "ForwardAuth verification"
    },
    {
        "path_pattern": "/.well-known/oauth-authorization-server",
        "target_type": RouteTargetType.HOSTNAME,
        "priority": 95,
        "description": "OAuth server metadata"
    },
    {
        "path_pattern": "/jwks",
        "target_type": RouteTargetType.HOSTNAME,
        "priority": 95,
        "description": "JSON Web Key Set"
    },
    {
        "path_pattern": "/revoke",
        "target_type": RouteTargetType.HOSTNAME,
        "priority": 95,
        "description": "Token revocation"
    },
    {
        "path_pattern": "/introspect",
        "target_type": RouteTargetType.HOSTNAME,
        "priority": 95,
        "description": "Token introspection"
    }
]


# Cache for routes with TTL
_route_cache = {}
_route_cache_time = {}
ROUTE_CACHE_TTL = 300  # 5 minutes

async def get_applicable_routes_async(async_storage, proxy_config: 'ProxyTarget') -> List[Route]:
    """Get routes applicable to a specific proxy with caching (async version)."""
    import time
    
    # Check cache first
    cache_key = f"routes:{proxy_config.proxy_hostname if proxy_config else 'global'}"
    now = time.time()
    
    if cache_key in _route_cache and cache_key in _route_cache_time:
        if now - _route_cache_time[cache_key] < ROUTE_CACHE_TTL:
            return _route_cache[cache_key]
    
    # Load all routes from storage
    all_routes = []
    if not async_storage or not hasattr(async_storage, 'redis_client') or not async_storage.redis_client:
        logger.warning("No async Redis client available for loading routes")
        return []
    
    async for key in async_storage.redis_client.scan_iter(match="route:*", count=100):
        # Skip priority and unique index keys
        if key.startswith("route:priority:") or key.startswith("route:unique:"):
            continue
        route_data = await async_storage.redis_client.get(key)
        if route_data:
            try:
                route = Route.from_redis(route_data)
                if route.enabled:
                    all_routes.append(route)
            except Exception as e:
                # Handle old routes without scope field
                try:
                    route_dict = json.loads(route_data)
                    if 'scope' not in route_dict:
                        route_dict['scope'] = RouteScope.GLOBAL.value
                        route_dict['proxy_hostnames'] = []
                    route = Route(**route_dict)
                    if route.enabled:
                        all_routes.append(route)
                except Exception:
                    pass
    
    # Filter routes by scope (same logic as sync version)
    applicable_routes = _filter_routes_by_scope(all_routes, proxy_config)
    
    # Cache the results
    _route_cache[cache_key] = applicable_routes
    _route_cache_time[cache_key] = now
    
    return applicable_routes

def get_applicable_routes(storage, proxy_config: 'ProxyTarget') -> List[Route]:
    """Get routes applicable to a specific proxy based on its configuration and scope (sync version)."""
    # Load all routes from storage
    all_routes = []
    if not storage or not hasattr(storage, 'redis_client') or not storage.redis_client:
        logger.warning("No Redis client available for loading routes")
        return []
    
    for key in storage.redis_client.scan_iter(match="route:*"):
        # Skip priority and unique index keys
        if key.startswith("route:priority:") or key.startswith("route:unique:"):
            continue
        route_data = storage.redis_client.get(key)
        if route_data:
            try:
                route = Route.from_redis(route_data)
                if route.enabled:
                    all_routes.append(route)
            except Exception as e:
                # Handle old routes without scope field
                try:
                    route_dict = json.loads(route_data)
                    if 'scope' not in route_dict:
                        route_dict['scope'] = RouteScope.GLOBAL.value
                        route_dict['proxy_hostnames'] = []
                    route = Route(**route_dict)
                    if route.enabled:
                        all_routes.append(route)
                except Exception:
                    pass
    
    # Filter routes by scope
    return _filter_routes_by_scope(all_routes, proxy_config)

def _filter_routes_by_scope(all_routes: List[Route], proxy_config: 'ProxyTarget') -> List[Route]:
    """Helper to filter routes by scope."""
    
    applicable_routes = []
    for route in all_routes:
        if route.scope == RouteScope.GLOBAL:
            # Global routes apply to all proxies
            applicable_routes.append(route)
        elif route.scope == RouteScope.PROXY and proxy_config.proxy_hostname in route.proxy_hostnames:
            # Proxy-specific routes only apply to listed proxies
            applicable_routes.append(route)
    
    # Sort by priority (higher first)
    applicable_routes.sort(key=lambda r: r.priority, reverse=True)
    
    # Apply existing route filtering based on route_mode
    if proxy_config.route_mode == "none":
        # No routes apply
        return []
    elif proxy_config.route_mode == "selective":
        # Only enabled routes apply
        return [r for r in applicable_routes if r.route_id in proxy_config.enabled_routes]
    else:  # route_mode == "all" (default)
        # All routes except disabled ones
        return [r for r in applicable_routes if r.route_id not in proxy_config.disabled_routes]