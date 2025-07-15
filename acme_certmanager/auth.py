"""Authentication and authorization module."""

import hashlib
import secrets
from typing import Optional, Tuple, Union
from fastapi import HTTPException, Depends, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials

security = HTTPBearer()


def hash_token(token: str) -> str:
    """SHA256 hash of token for secure storage."""
    return hashlib.sha256(token.encode()).hexdigest()


def generate_token() -> str:
    """Generate cryptographically secure API token."""
    return f"acm_{secrets.token_urlsafe(32)}"


async def get_current_token(
    credentials: HTTPAuthorizationCredentials = Depends(security),
) -> Tuple[str, str]:
    """Extract and validate token from request.
    
    Returns:
        Tuple of (token_hash, raw_token)
    """
    token = credentials.credentials
    
    # Validate token format
    if not token.startswith("acm_"):
        raise HTTPException(401, "Invalid token format")
    
    token_hash = hash_token(token)
    return token_hash, token


async def get_current_token_info(
    credentials: HTTPAuthorizationCredentials = Depends(security),
    storage = None  # Will be injected by dependency
) -> Tuple[str, Optional[str]]:
    """Get current token hash and name from storage.
    
    Returns:
        Tuple of (token_hash, token_name)
    """
    from .server import manager  # Import here to avoid circular import
    
    token = credentials.credentials
    token_hash = hash_token(token)
    
    # Check if token exists in storage
    token_data = manager.storage.get_api_token(token_hash)
    if not token_data:
        raise HTTPException(401, "Invalid or revoked token")
    
    return token_hash, token_data.get("name")


async def require_owner(
    cert_name: str,
    token_info: Tuple[str, Optional[str]] = Depends(get_current_token_info)
) -> None:
    """Require current token to be certificate owner.
    
    Raises:
        HTTPException: If not authorized or certificate not found
    """
    from .server import manager  # Import here to avoid circular import
    
    token_hash, _ = token_info
    certificate = manager.storage.get_certificate(cert_name)
    
    if not certificate:
        raise HTTPException(404, "Certificate not found")
    
    # Check ownership
    if not hasattr(certificate, 'owner_token_hash') or certificate.owner_token_hash != token_hash:
        raise HTTPException(403, "Not authorized to modify this certificate")


async def get_optional_token_info(
    request: Request,
) -> Optional[Tuple[str, Optional[str]]]:
    """Get token info if provided, otherwise return None.
    
    This allows endpoints to work with or without authentication.
    """
    auth_header = request.headers.get("Authorization")
    if not auth_header or not auth_header.startswith("Bearer "):
        return None
    
    token = auth_header.split(" ", 1)[1]
    token_hash = hash_token(token)
    
    from .server import manager  # Import here to avoid circular import
    
    # Check if token exists in storage
    token_data = manager.storage.get_api_token(token_hash)
    if not token_data:
        # Invalid token - treat as no auth
        return None
    
    return token_hash, token_data.get("name")