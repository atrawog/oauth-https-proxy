"""Proxy-specific data models."""

from datetime import datetime
from typing import Dict, List, Optional, Any
from pydantic import BaseModel, field_validator, field_serializer


class ProxyTarget(BaseModel):
    """Proxy target configuration."""
    proxy_hostname: str
    target_url: str
    cert_name: Optional[str] = None
    created_by: Optional[str] = None
    created_at: datetime
    enabled: bool = True
    enable_http: bool = True
    enable_https: bool = True
    preserve_host_header: bool = True
    custom_headers: Optional[Dict[str, str]] = None
    custom_response_headers: Optional[Dict[str, str]] = None
    
    # Configuration versioning for drift detection
    config_version: int = 1  # Incremented on each update
    updated_at: Optional[datetime] = None  # Last update timestamp
    
    # Unified Auth Configuration
    auth_enabled: bool = False
    auth_proxy: Optional[str] = None
    auth_mode: str = "forward"  # forward, redirect, or passthrough
    auth_required_users: Optional[List[str]] = None  # Required users (None=use oauth_admin_users+oauth_user_users, ["user1", "user2"]=specific users)
    auth_required_emails: Optional[List[str]] = None
    auth_required_groups: Optional[List[str]] = None
    auth_allowed_scopes: Optional[List[str]] = None  # Allowed token scopes (if None, any scope is allowed)
    auth_allowed_audiences: Optional[List[str]] = None  # Allowed token audiences (if None, any audience is allowed)
    auth_pass_headers: bool = True
    auth_cookie_name: str = "unified_auth_token"
    auth_header_prefix: str = "X-Auth-"
    auth_excluded_paths: Optional[List[str]] = None  # Paths to exclude from authentication
    
    # Route control fields
    route_mode: str = "all"  # all, selective, none
    enabled_routes: List[str] = []
    disabled_routes: List[str] = []
    
    # Protected Resource Metadata fields (set by proxy-resource-set)
    resource_endpoint: Optional[str] = None  # Resource endpoint path (e.g., "/api")
    resource_scopes: Optional[List[str]] = None  # Supported scopes
    resource_stateful: bool = False  # Whether the resource maintains state
    resource_versions: Optional[List[str]] = None  # Supported protocol versions
    resource_server_info: Optional[Dict[str, Any]] = None  # Additional server information
    resource_override_backend: bool = False  # If True, always use proxy-generated metadata
    resource_bearer_methods: Optional[List[str]] = None  # Bearer token methods supported
    resource_documentation_suffix: Optional[str] = None  # Documentation URL suffix
    resource_custom_metadata: Optional[Dict[str, Any]] = None  # Custom metadata fields
    
    # OAuth Authorization Server Metadata fields (configurable per-proxy)
    oauth_server_issuer: Optional[str] = None  # Custom issuer URL
    oauth_server_scopes: Optional[List[str]] = None  # Supported scopes
    oauth_server_grant_types: Optional[List[str]] = None  # Grant types
    oauth_server_response_types: Optional[List[str]] = None  # Response types
    oauth_server_token_auth_methods: Optional[List[str]] = None  # Token auth methods
    oauth_server_claims: Optional[List[str]] = None  # Supported claims
    oauth_server_pkce_required: bool = False  # Require PKCE
    oauth_server_custom_metadata: Optional[Dict[str, Any]] = None  # Custom fields
    oauth_server_override_defaults: bool = False  # Use proxy config instead of defaults
    
    # GitHub OAuth Configuration (per-proxy)
    github_client_id: Optional[str] = None  # GitHub OAuth App Client ID
    github_client_secret: Optional[str] = None  # GitHub OAuth App Client Secret (encrypted)
    
    # OAuth scope-based user lists (for scope assignment)
    oauth_admin_users: Optional[List[str]] = None  # GitHub users who get admin scope
    oauth_user_users: Optional[List[str]] = None   # GitHub users who get user scope (* = all)
    oauth_mcp_users: Optional[List[str]] = None    # GitHub users who get mcp scope
    
    # WWW-Authenticate configuration (per-proxy)
    auth_realm: Optional[str] = None  # Custom realm (defaults to auth_proxy)
    auth_include_metadata_urls: bool = True  # Include as_uri and resource_uri
    auth_error_description: Optional[str] = None  # Custom error description
    auth_scope_required: Optional[str] = None  # Required scope hint
    auth_additional_params: Optional[Dict[str, str]] = None  # Extra WWW-Authenticate params
    
    @field_validator('auth_mode')
    @classmethod
    def validate_auth_mode(cls, v):
        valid_modes = ["forward", "redirect", "passthrough"]
        if v not in valid_modes:
            raise ValueError(f"auth_mode must be one of {valid_modes}")
        return v
    
    @field_validator('route_mode')
    @classmethod
    def validate_route_mode(cls, v):
        valid_modes = ["all", "selective", "none"]
        if v not in valid_modes:
            raise ValueError(f"route_mode must be one of {valid_modes}")
        return v
    
    @field_validator('auth_proxy')
    @classmethod
    def validate_auth_proxy(cls, v):
        if v is not None:
            v = v.strip().lower()
            if not v:
                raise ValueError('Auth proxy hostname cannot be empty')
        return v
    
    @field_serializer('created_at')
    def serialize_datetime(self, dt: datetime) -> str:
        return dt.isoformat() if dt else None


class ProxyTargetRequest(BaseModel):
    """Request model for creating proxy target."""
    proxy_hostname: str
    target_url: str
    cert_email: Optional[str] = None
    acme_directory_url: Optional[str] = None
    enable_http: bool = True
    enable_https: bool = True
    preserve_host_header: bool = True
    custom_headers: Optional[Dict[str, str]] = None
    custom_response_headers: Optional[Dict[str, str]] = None
    
    @field_validator('proxy_hostname')
    @classmethod
    def validate_proxy_hostname(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError('proxy_hostname cannot be empty')
        if v.startswith('.') or v.endswith('.'):
            raise ValueError('proxy_hostname cannot start or end with a dot')
        return v.lower()
    
    @field_validator('target_url')
    @classmethod
    def validate_target_url(cls, v):
        if not v or not (v.startswith('http://') or v.startswith('https://')):
            raise ValueError('Target URL must start with http:// or https://')
        return v


class ProxyTargetUpdate(BaseModel):
    """Request model for updating proxy target."""
    target_url: Optional[str] = None
    cert_name: Optional[str] = None
    enabled: Optional[bool] = None
    enable_http: Optional[bool] = None
    enable_https: Optional[bool] = None
    preserve_host_header: Optional[bool] = None
    custom_headers: Optional[Dict[str, str]] = None
    custom_response_headers: Optional[Dict[str, str]] = None
    # Auth fields
    auth_enabled: Optional[bool] = None
    auth_proxy: Optional[str] = None
    auth_mode: Optional[str] = None
    auth_required_users: Optional[List[str]] = None
    auth_required_emails: Optional[List[str]] = None
    auth_required_groups: Optional[List[str]] = None
    auth_allowed_scopes: Optional[List[str]] = None
    auth_allowed_audiences: Optional[List[str]] = None
    auth_pass_headers: Optional[bool] = None
    auth_cookie_name: Optional[str] = None
    auth_header_prefix: Optional[str] = None
    auth_excluded_paths: Optional[List[str]] = None
    # Route control fields
    route_mode: Optional[str] = None
    enabled_routes: Optional[List[str]] = None
    disabled_routes: Optional[List[str]] = None
    # Protected Resource Metadata fields
    resource_endpoint: Optional[str] = None
    resource_scopes: Optional[List[str]] = None
    resource_stateful: Optional[bool] = None
    resource_versions: Optional[List[str]] = None
    resource_server_info: Optional[Dict[str, Any]] = None
    resource_override_backend: Optional[bool] = None
    resource_bearer_methods: Optional[List[str]] = None
    resource_documentation_suffix: Optional[str] = None
    resource_custom_metadata: Optional[Dict[str, Any]] = None
    # OAuth Authorization Server Metadata fields
    oauth_server_issuer: Optional[str] = None
    oauth_server_scopes: Optional[List[str]] = None
    oauth_server_grant_types: Optional[List[str]] = None
    oauth_server_response_types: Optional[List[str]] = None
    oauth_server_token_auth_methods: Optional[List[str]] = None
    oauth_server_claims: Optional[List[str]] = None
    oauth_server_pkce_required: Optional[bool] = None
    oauth_server_custom_metadata: Optional[Dict[str, Any]] = None
    oauth_server_override_defaults: Optional[bool] = None
    # GitHub OAuth Configuration fields
    github_client_id: Optional[str] = None
    github_client_secret: Optional[str] = None
    # OAuth scope-based user lists
    oauth_admin_users: Optional[List[str]] = None
    oauth_user_users: Optional[List[str]] = None
    oauth_mcp_users: Optional[List[str]] = None
    
    @field_validator('target_url')
    @classmethod
    def validate_target_url(cls, v):
        if v is not None and not (v.startswith('http://') or v.startswith('https://')):
            raise ValueError('Target URL must start with http:// or https://')
        return v
    
    @field_validator('route_mode')
    @classmethod
    def validate_route_mode(cls, v):
        if v is not None:
            valid_modes = ["all", "selective", "none"]
            if v not in valid_modes:
                raise ValueError(f"route_mode must be one of {valid_modes}")
        return v
    
    @field_validator('auth_mode')
    @classmethod
    def validate_auth_mode(cls, v):
        if v is not None:
            valid_modes = ["forward", "redirect", "passthrough"]
            if v not in valid_modes:
                raise ValueError(f"auth_mode must be one of {valid_modes}")
        return v
    
    @field_validator('auth_proxy')
    @classmethod
    def validate_auth_proxy(cls, v):
        if v is not None:
            v = v.strip().lower()
            if not v:
                raise ValueError('Auth proxy hostname cannot be empty')
        return v


class ProxyRoutesConfig(BaseModel):
    """Request model for configuring proxy routes."""
    route_mode: str  # all, selective, or none
    enabled_routes: List[str] = []
    disabled_routes: List[str] = []
    
    @field_validator('route_mode')
    @classmethod
    def validate_route_mode(cls, v):
        valid_modes = ["all", "selective", "none"]
        if v not in valid_modes:
            raise ValueError(f"route_mode must be one of {valid_modes}")
        return v


class ProxyAuthConfig(BaseModel):
    """Request model for configuring proxy authentication."""
    enabled: bool = True
    auth_proxy: str
    mode: str = "forward"  # forward, redirect, or passthrough
    required_users: Optional[List[str]] = None  # Required users (None=use global, ["*"]=all users, ["user1", "user2"]=specific GitHub users)
    required_emails: Optional[List[str]] = None
    required_groups: Optional[List[str]] = None
    allowed_scopes: Optional[List[str]] = None  # Allowed token scopes
    allowed_audiences: Optional[List[str]] = None  # Allowed token audiences
    pass_headers: bool = True
    cookie_name: str = "unified_auth_token"
    header_prefix: str = "X-Auth-"
    excluded_paths: Optional[List[str]] = None
    
    @field_validator('auth_proxy')
    @classmethod
    def validate_auth_proxy(cls, v):
        v = v.strip().lower()
        if not v or not '.' in v:
            raise ValueError('Invalid auth proxy hostname')
        return v
    
    @field_validator('mode')
    @classmethod
    def validate_mode(cls, v: str) -> str:
        valid_modes = ["forward", "redirect", "passthrough"]
        if v not in valid_modes:
            raise ValueError(f"mode must be one of {valid_modes}")
        return v


class ProxyResourceConfig(BaseModel):
    """Request model for configuring proxy protected resource metadata."""
    endpoint: str = "/api"
    scopes: List[str] = ["read", "write"]
    stateful: bool = False
    versions: List[str] = ["2025-06-18"]
    server_info: Optional[Dict[str, Any]] = None
    override_backend: bool = False
    bearer_methods: List[str] = ["header"]
    documentation_suffix: str = "/docs"
    custom_metadata: Optional[Dict[str, Any]] = None
    hacker_one_research_header: Optional[str] = None
    
    @field_validator('endpoint')
    @classmethod
    def validate_endpoint(cls, v):
        if not v.startswith('/'):
            raise ValueError('Endpoint must start with /')
        return v
    
    @field_validator('scopes')
    @classmethod
    def validate_scopes(cls, v):
        # Allow any scope format for maximum flexibility
        # OAuth 2.0 doesn't restrict scope formats
        for scope in v:
            if not scope or not isinstance(scope, str):
                raise ValueError(f"Invalid scope: {scope}")
        return v
    
    @field_validator('bearer_methods')
    @classmethod
    def validate_bearer_methods(cls, v):
        valid_methods = ["header", "body", "query"]
        for method in v:
            if method not in valid_methods:
                raise ValueError(f"Invalid bearer method: {method}")
        return v


class ProxyGitHubOAuthConfig(BaseModel):
    """Request model for configuring proxy GitHub OAuth credentials."""
    github_client_id: str
    github_client_secret: str
    
    @field_validator('github_client_id')
    @classmethod
    def validate_github_client_id(cls, v):
        v = v.strip()
        if not v:
            raise ValueError('GitHub Client ID cannot be empty')
        return v
    
    @field_validator('github_client_secret')
    @classmethod
    def validate_github_client_secret(cls, v):
        v = v.strip()
        if not v:
            raise ValueError('GitHub Client Secret cannot be empty')
        return v


class ProxyOAuthServerConfig(BaseModel):
    """Request model for configuring proxy OAuth authorization server metadata."""
    issuer: Optional[str] = None
    scopes: Optional[List[str]] = None
    grant_types: Optional[List[str]] = None
    response_types: Optional[List[str]] = None
    token_auth_methods: Optional[List[str]] = None
    claims: Optional[List[str]] = None
    pkce_required: bool = False
    custom_metadata: Optional[Dict[str, Any]] = None
    override_defaults: bool = False
    
    @field_validator('scopes')
    @classmethod
    def validate_scopes(cls, v):
        # Allow any scope format for maximum flexibility
        # OAuth 2.0 doesn't restrict scope formats
        if v is not None:
            for scope in v:
                if not scope or not isinstance(scope, str):
                    raise ValueError(f"Invalid scope: {scope}")
        return v
    
    @field_validator('grant_types')
    @classmethod
    def validate_grant_types(cls, v):
        if v is not None:
            valid_types = ["authorization_code", "refresh_token", "client_credentials", "implicit"]
            for grant_type in v:
                if grant_type not in valid_types:
                    raise ValueError(f"Invalid grant type: {grant_type}")
        return v
    
    @field_validator('response_types')
    @classmethod
    def validate_response_types(cls, v):
        if v is not None:
            valid_types = ["code", "token", "id_token"]
            for response_type in v:
                if response_type not in valid_types:
                    raise ValueError(f"Invalid response type: {response_type}")
        return v


# Default proxy configurations that should always exist
DEFAULT_PROXIES = [
    {
        "proxy_hostname": "localhost",
        "target_url": "http://api:9000",
        "cert_name": "",
        "enabled": True,
        "enable_http": True,
        "enable_https": False,
        "preserve_host_header": False,
        "custom_headers": {},
        "owner_token_hash": "",
        "auth_enabled": False,
        "auth_excluded_paths": [
            "/token",          # Token refresh endpoint - CRITICAL
            "/device/",        # Device flow endpoints (/device/code, /device/token)
            "/authorize",      # OAuth authorization
            "/callback",       # OAuth callback
            "/jwks",          # Public keys
            "/.well-known/",  # All well-known endpoints
            "/register",      # Dynamic client registration
            "/health",        # Health check
            "/revoke",        # Token revocation
            "/introspect"     # Token introspection
        ],
        "route_mode": "all",
        "enabled_routes": [],
        "disabled_routes": [],
        # Protected Resource Metadata
        "resource_endpoint": "/",
        "resource_scopes": ["admin", "user"],
        "resource_stateful": False,
        "resource_versions": ["2025-06-18", "2024-11-05"],
        "resource_server_info": {
            "name": "OAuth HTTPS Proxy API",
            "version": "1.0.0",
            "description": "OAuth-secured API and proxy management system"
        },
        "resource_bearer_methods": ["header"],
        "resource_documentation_suffix": "/docs",
        "resource_custom_metadata": {
            "supports_oauth": True,
            "supports_device_flow": True
        }
    }
]