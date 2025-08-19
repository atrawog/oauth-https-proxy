"""API-specific models and data structures."""

from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field
from datetime import datetime


class HealthStatus(BaseModel):
    """Health check response model."""
    status: str
    scheduler: bool
    redis: str
    certificates_loaded: int
    https_enabled: bool
    orphaned_resources: int = 0


class EndpointAuthConfig(BaseModel):
    """Configuration for endpoint authentication.
    
    Defines authentication requirements for specific API endpoints,
    supporting different auth types for the same endpoint at different paths.
    """
    
    # Pattern matching
    path_pattern: str = Field(
        ...,
        description="Full path pattern from root (e.g., '/api/v1/tokens/*' or '/tokens/*')"
    )
    method: str = Field(
        default="*",
        description="HTTP method(s): GET, POST, PUT, DELETE, PATCH, or * for all"
    )
    
    # Authentication configuration
    auth_type: str = Field(
        ...,
        description="Authentication type: none, bearer, admin, or oauth"
    )
    oauth_scopes: List[str] = Field(
        default_factory=list,
        description="Required OAuth scopes if auth_type is 'oauth'"
    )
    oauth_resource: Optional[str] = Field(
        default=None,
        description="OAuth resource URI for audience validation"
    )
    oauth_allowed_users: List[str] = Field(
        default_factory=list,
        description="Allowed GitHub usernames for OAuth auth (empty = allow all authenticated)"
    )
    
    # Additional validation
    owner_validation: bool = Field(
        default=False,
        description="Enable resource ownership validation"
    )
    owner_param: Optional[str] = Field(
        default=None,
        description="Path parameter name containing resource ID for ownership check"
    )
    
    # Metadata
    priority: int = Field(
        default=50,
        description="Priority for pattern matching (higher wins)"
    )
    description: str = Field(
        default="",
        description="Human-readable description of this configuration"
    )
    enabled: bool = Field(
        default=True,
        description="Whether this configuration is active"
    )
    created_at: Optional[datetime] = Field(
        default=None,
        description="When this configuration was created"
    )
    updated_at: Optional[datetime] = Field(
        default=None,
        description="When this configuration was last updated"
    )
    created_by: Optional[str] = Field(
        default=None,
        description="Token name that created this configuration"
    )
    
    class Config:
        json_encoders = {
            datetime: lambda v: v.isoformat() if v else None
        }


class UnifiedAuthContext(BaseModel):
    """Unified authentication context returned by all auth methods.
    
    Provides a consistent interface regardless of authentication type used.
    """
    
    # Authentication details
    authenticated: bool = Field(
        description="Whether the request is authenticated"
    )
    auth_type: str = Field(
        description="Type of authentication used: none, bearer, admin, oauth"
    )
    
    # Token information (bearer/admin auth)
    token_hash: Optional[str] = Field(
        default=None,
        description="SHA256 hash of the bearer token"
    )
    token_name: Optional[str] = Field(
        default=None,
        description="Name of the API token"
    )
    is_admin: bool = Field(
        default=False,
        description="Whether this is an admin token"
    )
    cert_email: Optional[str] = Field(
        default=None,
        description="Certificate email associated with token"
    )
    
    # OAuth information
    oauth_user: Optional[str] = Field(
        default=None,
        description="OAuth user identifier (e.g., GitHub username)"
    )
    oauth_client_id: Optional[str] = Field(
        default=None,
        description="OAuth client ID"
    )
    oauth_scopes: List[str] = Field(
        default_factory=list,
        description="OAuth scopes granted"
    )
    oauth_audience: List[str] = Field(
        default_factory=list,
        description="OAuth token audience (resources)"
    )
    oauth_token_id: Optional[str] = Field(
        default=None,
        description="OAuth token JTI (unique identifier)"
    )
    
    # Request context
    request_path: str = Field(
        description="Full request path"
    )
    request_method: str = Field(
        description="HTTP method"
    )
    matched_pattern: Optional[str] = Field(
        default=None,
        description="Auth config pattern that matched this request"
    )
    
    # Additional metadata
    client_ip: Optional[str] = Field(
        default=None,
        description="Client IP address"
    )
    user_agent: Optional[str] = Field(
        default=None,
        description="User agent string"
    )
    
    def has_scope(self, scope: str) -> bool:
        """Check if the auth context has a specific OAuth scope."""
        return scope in self.oauth_scopes
    
    def can_access_resource(self, resource_id: str, owner_hash: str) -> bool:
        """Check if the authenticated user can access a resource.
        
        Args:
            resource_id: ID of the resource being accessed
            owner_hash: Token hash of the resource owner
            
        Returns:
            True if access is allowed
        """
        # Admin can access everything
        if self.is_admin:
            return True
        
        # Check ownership for bearer tokens
        if self.auth_type == "bearer" and self.token_hash:
            return self.token_hash == owner_hash
        
        # OAuth access depends on scopes and resource configuration
        if self.auth_type == "oauth":
            # For now, allow if user has write scope
            # This can be extended with more granular checks
            return self.has_scope("mcp:write") or self.has_scope("mcp:admin")
        
        # Default deny
        return False


class AuthConfigRequest(BaseModel):
    """Request to create or update an auth configuration."""
    
    path_pattern: str
    method: str = "*"
    auth_type: str
    oauth_scopes: List[str] = Field(default_factory=list)
    oauth_resource: Optional[str] = None
    oauth_allowed_users: List[str] = Field(default_factory=list)
    owner_validation: bool = False
    owner_param: Optional[str] = None
    priority: int = 50
    description: str = ""
    enabled: bool = True


class AuthConfigTestRequest(BaseModel):
    """Request to test pattern matching."""
    
    path: str = Field(
        ...,
        description="Full request path to test"
    )
    method: str = Field(
        default="GET",
        description="HTTP method to test"
    )


class AuthConfigTestResponse(BaseModel):
    """Response from pattern matching test."""
    
    matched: bool
    matched_configs: List[EndpointAuthConfig]
    effective_config: Optional[EndpointAuthConfig]
    explanation: str