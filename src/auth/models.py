"""Authentication and authorization models.

This module defines the data models for the flexible auth system.
"""

from typing import Optional, List, Dict, Any, Literal
from datetime import datetime
from pydantic import BaseModel, Field


class AuthConfig(BaseModel):
    """Base authentication configuration for any layer.
    
    This can be used for API endpoints, routes, or proxies.
    """
    
    auth_type: Literal["none", "bearer", "admin", "oauth"] = Field(
        ...,
        description="Type of authentication required"
    )
    
    # OAuth-specific settings
    oauth_scopes: Optional[List[str]] = Field(
        default=None,
        description="Required OAuth scopes"
    )
    oauth_audiences: Optional[List[str]] = Field(
        default=None,
        description="Required OAuth audiences (resource URIs)"
    )
    oauth_allowed_users: Optional[List[str]] = Field(
        default=None,
        description="Allowed GitHub usernames (null=default, ['*']=all)"
    )
    oauth_allowed_emails: Optional[List[str]] = Field(
        default=None,
        description="Allowed email patterns"
    )
    oauth_allowed_groups: Optional[List[str]] = Field(
        default=None,
        description="Allowed groups/organizations"
    )
    
    # Bearer token settings
    bearer_allow_admin: bool = Field(
        default=True,
        description="Allow admin tokens to access bearer-protected resources"
    )
    bearer_check_owner: bool = Field(
        default=False,
        description="Verify token owns the resource"
    )
    
    # Additional settings
    fallback_auth: Optional[Literal["none", "bearer", "admin", "oauth"]] = Field(
        default=None,
        description="Fallback auth type if primary fails"
    )
    cache_ttl: int = Field(
        default=60,
        description="Cache auth decisions for this many seconds"
    )
    
    class Config:
        extra = "allow"  # Allow additional fields for extensibility


class EndpointAuthConfig(AuthConfig):
    """Authentication configuration for API endpoints.
    
    Extends AuthConfig with endpoint-specific fields.
    """
    
    config_id: Optional[str] = Field(
        default=None,
        description="Unique configuration ID"
    )
    path_pattern: str = Field(
        ...,
        description="Path pattern to match (e.g., '/api/v1/tokens/*')"
    )
    methods: List[str] = Field(
        default=["*"],
        description="HTTP methods this config applies to"
    )
    priority: int = Field(
        default=50,
        description="Priority for pattern matching (higher = checked first)"
    )
    owner_param: Optional[str] = Field(
        default=None,
        description="Path parameter name for ownership checks"
    )
    description: str = Field(
        default="",
        description="Human-readable description"
    )
    enabled: bool = Field(
        default=True,
        description="Whether this config is active"
    )
    created_at: Optional[datetime] = Field(
        default=None,
        description="When this config was created"
    )
    created_by: Optional[str] = Field(
        default=None,
        description="Who created this config"
    )


class RouteAuthConfig(AuthConfig):
    """Authentication configuration for routes.
    
    Extends AuthConfig with route-specific fields.
    """
    
    route_id: str = Field(
        ...,
        description="ID of the route this config applies to"
    )
    override_proxy_auth: bool = Field(
        default=False,
        description="Whether this route auth overrides proxy-level auth"
    )


class ProxyAuthConfig(AuthConfig):
    """Authentication configuration for proxies.
    
    Extends AuthConfig with proxy-specific fields.
    """
    
    hostname: str = Field(
        ...,
        description="Proxy hostname this config applies to"
    )
    excluded_paths: List[str] = Field(
        default_factory=list,
        description="Paths to exclude from authentication"
    )
    auth_mode: Literal["enforce", "redirect", "pass-through"] = Field(
        default="enforce",
        description="How to handle unauthenticated requests"
    )
    redirect_url: Optional[str] = Field(
        default=None,
        description="URL to redirect to for authentication (if mode=redirect)"
    )
    auth_cookie_name: str = Field(
        default="unified_auth_token",
        description="Name of authentication cookie"
    )
    auth_header_prefix: str = Field(
        default="X-Auth-",
        description="Prefix for auth headers passed to backend"
    )
    pass_auth_headers: bool = Field(
        default=True,
        description="Whether to pass auth headers to backend"
    )


class AuthResult(BaseModel):
    """Result of an authentication check.
    
    Standardized response from all auth validation methods.
    """
    
    authenticated: bool = Field(
        ...,
        description="Whether authentication succeeded"
    )
    auth_type: Optional[str] = Field(
        default=None,
        description="Type of auth that succeeded (none/bearer/admin/oauth)"
    )
    principal: Optional[str] = Field(
        default=None,
        description="Authenticated principal (username/token name)"
    )
    token_hash: Optional[str] = Field(
        default=None,
        description="Hash of the authenticated token"
    )
    scopes: Optional[List[str]] = Field(
        default=None,
        description="OAuth scopes if OAuth auth"
    )
    audiences: Optional[List[str]] = Field(
        default=None,
        description="OAuth audiences if OAuth auth"
    )
    metadata: Dict[str, Any] = Field(
        default_factory=dict,
        description="Additional auth metadata"
    )
    
    # Error information for failed auth
    error: Optional[str] = Field(
        default=None,
        description="Error code (e.g., 'invalid_token')"
    )
    error_description: Optional[str] = Field(
        default=None,
        description="Human-readable error description"
    )
    www_authenticate: Optional[str] = Field(
        default=None,
        description="WWW-Authenticate header value for 401 responses"
    )
    
    # Cache information
    cached: bool = Field(
        default=False,
        description="Whether this result was from cache"
    )
    cache_key: Optional[str] = Field(
        default=None,
        description="Cache key if cached"
    )


class TokenValidation(BaseModel):
    """Result of bearer token validation."""
    
    valid: bool
    token_hash: Optional[str] = None
    token_name: Optional[str] = None
    is_admin: bool = False
    owns_resource: Optional[bool] = None
    cert_email: Optional[str] = None
    created_at: Optional[datetime] = None
    error: Optional[str] = None


class OAuthValidation(BaseModel):
    """Result of OAuth token validation."""
    
    valid: bool
    username: Optional[str] = None
    user_id: Optional[str] = None
    email: Optional[str] = None
    scopes: List[str] = Field(default_factory=list)
    audiences: List[str] = Field(default_factory=list)
    expires_at: Optional[datetime] = None
    client_id: Optional[str] = None
    error: Optional[str] = None