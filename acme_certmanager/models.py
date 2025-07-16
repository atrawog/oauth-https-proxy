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
    preserve_host_header: bool = True
    custom_headers: Optional[Dict[str, str]] = None
    
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
    enabled: Optional[bool] = None
    preserve_host_header: Optional[bool] = None
    custom_headers: Optional[Dict[str, str]] = None
    
    @validator('target_url')
    def validate_target_url(cls, v):
        if v is not None and not (v.startswith('http://') or v.startswith('https://')):
            raise ValueError('Target URL must start with http:// or https://')
        return v