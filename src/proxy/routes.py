"""Route models and management for HTTP request routing."""

import json
from datetime import datetime, timezone
from typing import Dict, List, Optional, Union, TYPE_CHECKING
from enum import Enum
from pydantic import BaseModel, Field, field_validator, ValidationInfo
import re

if TYPE_CHECKING:
    from .models import ProxyTarget


class RouteTargetType(str, Enum):
    """Types of routing targets."""
    PORT = "port"  # Forward to localhost:port
    INSTANCE = "instance"  # Forward to named instance (e.g., 'localhost', 'api')
    HOSTNAME = "hostname"  # Forward to instance handling specific hostname
    URL = "url"  # Forward to any URL (http://service:port or https://example.com)


class Route(BaseModel):
    """Represents a routing rule."""
    route_id: str = Field(..., description="Unique identifier for the route")
    path_pattern: str = Field(..., description="Path prefix or regex pattern")
    target_type: RouteTargetType = Field(..., description="Type of routing target")
    target_value: Union[int, str] = Field(..., description="Port number or instance/hostname name")
    priority: int = Field(50, ge=0, le=999, description="Higher priority routes are checked first")
    methods: Optional[List[str]] = Field(None, description="HTTP methods to match (None = all)")
    is_regex: bool = Field(False, description="Whether path_pattern is a regex")
    description: str = Field("", description="Human-readable description")
    enabled: bool = Field(True, description="Whether this route is active")
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    owner_token_hash: Optional[str] = Field(None, description="Hash of token that owns this route")
    created_by: Optional[str] = Field(None, description="Token name that created this route")
    
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
    
    def matches(self, path: str, method: Optional[str] = None) -> bool:
        """Check if this route matches the given path and method."""
        if not self.enabled:
            return False
            
        # Check method if specified
        if self.methods and method and method.upper() not in self.methods:
            return False
        
        # Check path
        if self.is_regex:
            result = bool(re.match(self.path_pattern, path))
        else:
            result = path.startswith(self.path_pattern)
        
        # Log for debugging
        import logging
        logger = logging.getLogger(__name__)
        if self.path_pattern == "/.well-known/oauth-authorization-server":
            logger.info(f"Route match check: path='{path}' pattern='{self.path_pattern}' result={result}")
        
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
    target_value: Union[int, str] = Field(..., description="Port number or instance/hostname name")
    priority: int = Field(50, ge=0, le=999, description="Higher priority routes are checked first")
    methods: Optional[List[str]] = Field(None, description="HTTP methods to match (None = all)")
    is_regex: bool = Field(False, description="Whether path_pattern is a regex")
    description: str = Field("", description="Human-readable description")
    enabled: bool = Field(True, description="Whether this route is active")


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


# Default routes that should always exist
DEFAULT_ROUTES = [
    {
        "route_id": "acme-challenge",
        "path_pattern": "/.well-known/acme-challenge/",
        "target_type": RouteTargetType.INSTANCE,
        "target_value": "localhost",
        "priority": 100,
        "description": "ACME challenge validation",
        "enabled": True
    },
    {
        "route_id": "health",
        "path_pattern": "/health",
        "target_type": RouteTargetType.INSTANCE,
        "target_value": "localhost",
        "priority": 80,
        "description": "Health check endpoint",
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


def get_applicable_routes(storage, proxy_config: 'ProxyTarget') -> List[Route]:
    """Get routes applicable to a specific proxy based on its configuration."""
    # Load all routes from storage
    routes = []
    for key in storage.redis_client.scan_iter(match="route:*"):
        # Skip priority and unique index keys
        if key.startswith("route:priority:") or key.startswith("route:unique:"):
            continue
        route_data = storage.redis_client.get(key)
        if route_data:
            try:
                route = Route.from_redis(route_data)
                if route.enabled:
                    routes.append(route)
            except Exception:
                pass
    
    # Sort by priority (higher first)
    routes.sort(key=lambda r: r.priority, reverse=True)
    
    # Apply route filtering based on route_mode
    if proxy_config.route_mode == "none":
        # No routes apply
        return []
    elif proxy_config.route_mode == "selective":
        # Only enabled routes apply
        return [r for r in routes if r.route_id in proxy_config.enabled_routes]
    else:  # route_mode == "all" (default)
        # All routes except disabled ones
        return [r for r in routes if r.route_id not in proxy_config.disabled_routes]