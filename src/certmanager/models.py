"""Certificate-specific data models."""

import os
import re
from datetime import datetime
from typing import List, Optional
from pydantic import BaseModel, Field, field_validator, field_serializer


class CertificateRequest(BaseModel):
    """Request model for certificate generation."""
    domain: str
    email: Optional[str] = None
    cert_name: str
    acme_directory_url: str = Field(default="https://acme-v02.api.letsencrypt.org/directory")
    
    @field_validator('domain')
    @classmethod
    def validate_domain(cls, v: str) -> str:
        v = v.strip()
        if not v or not '.' in v:
            raise ValueError('Invalid domain format')
        return v.lower()
    
    @field_validator('email', mode='before')
    @classmethod
    def validate_email(cls, v: Optional[str]) -> str:
        if not v:
            # Use ACME_EMAIL from environment as default
            v = os.getenv("ACME_EMAIL")
            if not v:
                raise ValueError("Email required - set ACME_EMAIL in environment")
        v = v.strip()
        if not re.match(r'^[^@]+@[^@]+\.[^@]+$', v):
            raise ValueError('Invalid email format')
        return v.lower()


class MultiDomainCertificateRequest(BaseModel):
    """Request model for multi-domain certificate creation."""
    cert_name: str
    domains: List[str]
    email: Optional[str] = None
    acme_directory_url: str
    
    @field_validator('cert_name')
    @classmethod
    def validate_cert_name(cls, v: str) -> str:
        if not v or not v.strip():
            raise ValueError('Certificate name cannot be empty')
        if not all(c.isalnum() or c in '-_' for c in v):
            raise ValueError('Certificate name can only contain letters, numbers, dash, and underscore')
        return v.strip()
    
    @field_validator('domains')
    @classmethod
    def validate_domains(cls, v: List[str]) -> List[str]:
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
    
    @field_validator('email', mode='before')
    @classmethod
    def validate_email(cls, v: Optional[str]) -> str:
        if not v:
            # Use ACME_EMAIL from environment as default
            v = os.getenv("ACME_EMAIL")
            if not v:
                raise ValueError("Email required - set ACME_EMAIL in environment")
        v = v.strip()
        if not re.match(r'^[^@]+@[^@]+\.[^@]+$', v):
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
    created_by: Optional[str] = None
    
    @field_validator('domains', mode='before')
    @classmethod
    def validate_domains(cls, v):
        if isinstance(v, list):
            return [domain.strip().lower() for domain in v if domain.strip()]
        return v
    
    @field_validator('email')
    @classmethod
    def validate_email(cls, v: Optional[str]) -> Optional[str]:
        return v.strip().lower() if v else v
    
    @field_serializer('expires_at', 'issued_at')
    def serialize_datetime(self, dt: Optional[datetime]) -> Optional[str]:
        return dt.isoformat() if dt else None


class ChallengeToken(BaseModel):
    """ACME challenge token model."""
    token: str
    authorization: str
    expires_at: datetime