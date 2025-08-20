"""Shared models for token management endpoints."""

from datetime import datetime
from typing import List
from pydantic import BaseModel, EmailStr


class TokenCreateRequest(BaseModel):
    """Request model for creating a token."""
    name: str
    cert_email: EmailStr


class TokenGenerateRequest(BaseModel):
    """Request model for generating a display token."""
    name: str
    cert_email: EmailStr
    token: str


class TokenResponse(BaseModel):
    """Response model for token details."""
    name: str
    token: str
    cert_email: str
    created_at: datetime


class TokenGenerateResponse(BaseModel):
    """Response model for generated display token."""
    message: str
    name: str
    token: str
    cert_email: str


class TokenSummary(BaseModel):
    """Summary model for token listing."""
    name: str
    cert_email: str
    created_at: datetime
    certificate_count: int
    proxy_count: int
    is_admin: bool


class TokenDetail(BaseModel):
    """Detailed token information."""
    name: str
    token: str
    cert_email: str
    created_at: datetime
    certificate_count: int
    proxy_count: int
    is_admin: bool
    certificates: List[str]
    proxies: List[str]