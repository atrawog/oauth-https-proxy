"""Data models for ACME Certificate Manager."""

from datetime import datetime
from typing import List, Optional, Dict
from pydantic import BaseModel, Field, validator


class CertificateRequest(BaseModel):
    """Request model for certificate generation."""
    domain: str
    email: str
    cert_name: str
    acme_directory_url: str = Field(default="https://acme-v02.api.letsencrypt.org/directory")
    
    @validator('domain')
    def validate_domain(cls, v):
        v = v.strip()  # Remove leading/trailing whitespace
        if not v or not '.' in v:
            raise ValueError('Invalid domain format')
        return v.lower()
    
    @validator('email')
    def validate_email(cls, v):
        v = v.strip()  # Remove leading/trailing whitespace
        if not v or '@' not in v:
            raise ValueError('Invalid email format')
        return v.lower()


class MultiDomainCertificateRequest(BaseModel):
    """Request model for multi-domain certificate creation."""
    cert_name: str
    domains: List[str]
    email: str
    acme_directory_url: str
    
    @validator('cert_name')
    def validate_cert_name(cls, v):
        if not v or not v.strip():
            raise ValueError('Certificate name cannot be empty')
        # Only allow alphanumeric, dash, and underscore
        if not all(c.isalnum() or c in '-_' for c in v):
            raise ValueError('Certificate name can only contain letters, numbers, dash, and underscore')
        return v.strip()
    
    @validator('domains')
    def validate_domains(cls, v):
        if not v or len(v) == 0:
            raise ValueError("At least one domain required")
        if len(v) > 100:  # Let's Encrypt limit
            raise ValueError("Maximum 100 domains per certificate")
        
        # Clean and validate each domain
        cleaned = []
        for domain in v:
            domain = domain.strip().lower()
            if not domain:
                continue
            # Basic domain validation
            if not all(c.isalnum() or c in '-.*' for c in domain.replace('.', '')):
                raise ValueError(f'Invalid domain: {domain}')
            cleaned.append(domain)
        
        if not cleaned:
            raise ValueError("No valid domains provided")
        
        # Check for duplicates
        if len(cleaned) != len(set(cleaned)):
            raise ValueError("Duplicate domains not allowed")
        
        return cleaned
    
    @validator('email')
    def validate_email(cls, v):
        v = v.strip()
        if not v or '@' not in v:
            raise ValueError('Invalid email format')
        return v.lower()


class Certificate(BaseModel):
    """Certificate data model."""
    cert_name: str  # Certificate identifier
    domains: List[str]
    email: str
    acme_directory_url: str
    status: str = "pending"
    expires_at: Optional[datetime] = None
    issued_at: Optional[datetime] = None
    fingerprint: Optional[str] = None
    fullchain_pem: Optional[str] = None
    private_key_pem: Optional[str] = None
    owner_token_hash: Optional[str] = None  # SHA256 hash of owner token
    created_by: Optional[str] = None        # Token name for display
    
    @validator('domains', pre=True)
    def validate_domains(cls, v):
        if isinstance(v, list):
            # Strip whitespace from each domain
            return [domain.strip().lower() for domain in v if domain.strip()]
        return v
    
    @validator('email')
    def validate_email(cls, v):
        return v.strip().lower() if v else v
    
    class Config:
        json_encoders = {
            datetime: lambda v: v.isoformat() if v else None
        }


class ChallengeToken(BaseModel):
    """ACME challenge token model."""
    token: str
    authorization: str
    expires_at: datetime


class HealthStatus(BaseModel):
    """Health check response model."""
    status: str
    scheduler: bool
    redis: str
    certificates_loaded: int
    https_enabled: bool
    orphaned_resources: Optional[int] = None


class ProxyTarget(BaseModel):
    """Proxy target configuration."""
    hostname: str                    # e.g., "api.example.com"
    target_url: str                 # e.g., "http://backend:8080"
    cert_name: Optional[str] = None # Auto-generated if not provided
    owner_token_hash: str           # Reuse existing ownership model
    created_by: Optional[str] = None # Token name for display
    created_at: datetime
    enabled: bool = True
    enable_http: bool = True        # Enable HTTP (port 80) forwarding
    enable_https: bool = True       # Enable HTTPS (port 443) forwarding
    preserve_host_header: bool = True
    custom_headers: Optional[Dict[str, str]] = None
    
    # Unified Auth Configuration
    auth_enabled: bool = False
    auth_proxy: Optional[str] = None  # e.g., "auth.example.com"
    auth_mode: str = "forward"  # forward, redirect, or passthrough
    auth_required_users: Optional[List[str]] = None
    auth_required_emails: Optional[List[str]] = None
    auth_required_groups: Optional[List[str]] = None
    auth_pass_headers: bool = True  # Pass user info as headers
    auth_cookie_name: str = "unified_auth_token"
    auth_header_prefix: str = "X-Auth-"
    
    @validator('auth_mode')
    def validate_auth_mode(cls, v):
        valid_modes = ["forward", "redirect", "passthrough"]
        if v not in valid_modes:
            raise ValueError(f"auth_mode must be one of {valid_modes}")
        return v
    
    @validator('auth_proxy')
    def validate_auth_proxy(cls, v):
        if v is not None:
            v = v.strip().lower()
            if not v or not '.' in v:
                raise ValueError('Invalid auth proxy hostname')
        return v
    
    class Config:
        json_encoders = {
            datetime: lambda v: v.isoformat() if v else None
        }


class ProxyTargetRequest(BaseModel):
    """Request model for creating proxy target."""
    hostname: str
    target_url: str
    cert_email: Optional[str] = None  # Optional - uses token's cert_email if not provided
    acme_directory_url: Optional[str] = None  # Allow specifying staging URL
    enable_http: bool = True        # Enable HTTP (port 80) forwarding
    enable_https: bool = True       # Enable HTTPS (port 443) forwarding
    preserve_host_header: bool = True
    custom_headers: Optional[Dict[str, str]] = None
    
    @validator('hostname')
    def validate_hostname(cls, v):
        v = v.strip()  # Remove leading/trailing whitespace
        if not v or not '.' in v:
            raise ValueError('Invalid hostname format')
        # Basic hostname validation
        if v.startswith('.') or v.endswith('.'):
            raise ValueError('Hostname cannot start or end with a dot')
        return v.lower()
    
    @validator('target_url')
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
    
    @validator('target_url')
    def validate_target_url(cls, v):
        if v is not None and not (v.startswith('http://') or v.startswith('https://')):
            raise ValueError('Target URL must start with http:// or https://')
        return v
    
    @validator('auth_mode')
    def validate_auth_mode(cls, v):
        if v is not None:
            valid_modes = ["forward", "redirect", "passthrough"]
            if v not in valid_modes:
                raise ValueError(f"auth_mode must be one of {valid_modes}")
        return v
    
    @validator('auth_proxy')
    def validate_auth_proxy(cls, v):
        if v is not None:
            v = v.strip().lower()
            if not v or not '.' in v:
                raise ValueError('Invalid auth proxy hostname')
        return v


class ProxyAuthConfig(BaseModel):
    """Request model for configuring proxy authentication."""
    enabled: bool = True
    auth_proxy: str  # Required - e.g., "auth.example.com"
    mode: str = "forward"  # forward, redirect, or passthrough
    required_users: Optional[List[str]] = None
    required_emails: Optional[List[str]] = None
    required_groups: Optional[List[str]] = None
    pass_headers: bool = True
    cookie_name: str = "unified_auth_token"
    header_prefix: str = "X-Auth-"
    
    @validator('auth_proxy')
    def validate_auth_proxy(cls, v):
        v = v.strip().lower()
        if not v or not '.' in v:
            raise ValueError('Invalid auth proxy hostname')
        return v
    
    @validator('mode')
    def validate_mode(cls, v):
        valid_modes = ["forward", "redirect", "passthrough"]
        if v not in valid_modes:
            raise ValueError(f"mode must be one of {valid_modes}")
        return v