"""Route models and management for HTTP request routing."""

import json
from datetime import datetime, timezone
from typing import Dict, List, Optional, Union
from enum import Enum
from pydantic import BaseModel, Field, validator
import re


class RouteTargetType(str, Enum):
    """Types of routing targets."""
    PORT = "port"  # Forward to localhost:port
    INSTANCE = "instance"  # Forward to named instance (e.g., 'localhost', 'api')
    HOSTNAME = "hostname"  # Forward to instance handling specific hostname


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
    
    @validator('methods')
    def uppercase_methods(cls, v):
        """Ensure HTTP methods are uppercase."""
        if v:
            return [method.upper() for method in v]
        return v
    
    @validator('path_pattern')
    def validate_pattern(cls, v, values):
        """Validate regex patterns."""
        if values.get('is_regex', False):
            try:
                re.compile(v)
            except re.error as e:
                raise ValueError(f"Invalid regex pattern: {e}")
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
            return bool(re.match(self.path_pattern, path))
        else:
            return path.startswith(self.path_pattern)
    
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
        "route_id": "api",
        "path_pattern": "/api/",
        "target_type": RouteTargetType.INSTANCE,
        "target_value": "api",
        "priority": 90,
        "description": "API endpoints",
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