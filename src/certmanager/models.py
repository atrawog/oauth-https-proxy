"""Certificate-specific data models."""

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
        v = v.strip()
        if not v or not '.' in v:
            raise ValueError('Invalid domain format')
        return v.lower()
    
    @validator('email')
    def validate_email(cls, v):
        v = v.strip()
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
        if not all(c.isalnum() or c in '-_' for c in v):
            raise ValueError('Certificate name can only contain letters, numbers, dash, and underscore')
        return v.strip()
    
    @validator('domains')
    def validate_domains(cls, v):
        if not v or len(v) == 0:
            raise ValueError("At least one domain required")
        if len(v) > 100:  # Let's Encrypt limit
            raise ValueError("Maximum 100 domains per certificate")
        
        cleaned = []
        for domain in v:
            domain = domain.strip().lower()
            if not domain:
                continue
            if not all(c.isalnum() or c in '-.*' for c in domain.replace('.', '')):
                raise ValueError(f'Invalid domain: {domain}')
            cleaned.append(domain)
        
        if not cleaned:
            raise ValueError("No valid domains provided")
        
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
    cert_name: str
    domains: List[str]
    email: str
    acme_directory_url: str
    status: str = "pending"
    expires_at: Optional[datetime] = None
    issued_at: Optional[datetime] = None
    fingerprint: Optional[str] = None
    fullchain_pem: Optional[str] = None
    private_key_pem: Optional[str] = None
    owner_token_hash: Optional[str] = None
    created_by: Optional[str] = None
    
    @validator('domains', pre=True)
    def validate_domains(cls, v):
        if isinstance(v, list):
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