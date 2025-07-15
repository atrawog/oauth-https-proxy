"""Data models for ACME Certificate Manager."""

from datetime import datetime
from typing import List, Optional
from pydantic import BaseModel, Field, validator


class CertificateRequest(BaseModel):
    """Request model for certificate generation."""
    domain: str
    email: str
    cert_name: str
    acme_directory_url: str = Field(default="https://acme-v02.api.letsencrypt.org/directory")
    
    @validator('domain')
    def validate_domain(cls, v):
        if not v or not '.' in v:
            raise ValueError('Invalid domain format')
        return v.lower()
    
    @validator('email')
    def validate_email(cls, v):
        if not v or '@' not in v:
            raise ValueError('Invalid email format')
        return v.lower()


class Certificate(BaseModel):
    """Certificate data model."""
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