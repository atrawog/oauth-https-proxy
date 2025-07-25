"""Proxy-specific data models."""

from datetime import datetime
from typing import Dict, List, Optional
from pydantic import BaseModel, field_validator, field_serializer


class ProxyTarget(BaseModel):
    """Proxy target configuration."""
    hostname: str
    target_url: str
    cert_name: Optional[str] = None
    owner_token_hash: str
    created_by: Optional[str] = None
    created_at: datetime
    enabled: bool = True
    enable_http: bool = True
    enable_https: bool = True
    preserve_host_header: bool = True
    custom_headers: Optional[Dict[str, str]] = None
    
    # Unified Auth Configuration
    auth_enabled: bool = False
    auth_proxy: Optional[str] = None
    auth_mode: str = "forward"  # forward, redirect, or passthrough
    auth_required_users: Optional[List[str]] = None
    auth_required_emails: Optional[List[str]] = None
    auth_required_groups: Optional[List[str]] = None
    auth_pass_headers: bool = True
    auth_cookie_name: str = "unified_auth_token"
    auth_header_prefix: str = "X-Auth-"
    auth_excluded_paths: Optional[List[str]] = None  # Paths to exclude from authentication
    
    # Route control fields
    route_mode: str = "all"  # all, selective, none
    enabled_routes: List[str] = []
    disabled_routes: List[str] = []
    
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
            if not v or not '.' in v:
                raise ValueError('Invalid auth proxy hostname')
        return v
    
    @field_serializer('created_at')
    def serialize_datetime(self, dt: datetime) -> str:
        return dt.isoformat() if dt else None


class ProxyTargetRequest(BaseModel):
    """Request model for creating proxy target."""
    hostname: str
    target_url: str
    cert_email: Optional[str] = None
    acme_directory_url: Optional[str] = None
    enable_http: bool = True
    enable_https: bool = True
    preserve_host_header: bool = True
    custom_headers: Optional[Dict[str, str]] = None
    
    @field_validator('hostname')
    @classmethod
    def validate_hostname(cls, v: str) -> str:
        v = v.strip()
        if not v or not '.' in v:
            raise ValueError('Invalid hostname format')
        if v.startswith('.') or v.endswith('.'):
            raise ValueError('Hostname cannot start or end with a dot')
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
    # Auth fields
    auth_enabled: Optional[bool] = None
    auth_proxy: Optional[str] = None
    auth_mode: Optional[str] = None
    auth_required_users: Optional[List[str]] = None
    auth_required_emails: Optional[List[str]] = None
    auth_required_groups: Optional[List[str]] = None
    auth_pass_headers: Optional[bool] = None
    auth_cookie_name: Optional[str] = None
    auth_header_prefix: Optional[str] = None
    auth_excluded_paths: Optional[List[str]] = None
    # Route control fields
    route_mode: Optional[str] = None
    enabled_routes: Optional[List[str]] = None
    disabled_routes: Optional[List[str]] = None
    
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
            if not v or not '.' in v:
                raise ValueError('Invalid auth proxy hostname')
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
    required_users: Optional[List[str]] = None
    required_emails: Optional[List[str]] = None
    required_groups: Optional[List[str]] = None
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