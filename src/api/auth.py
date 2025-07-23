"""Authentication and authorization module."""

import hashlib
import os
import secrets
from typing import Optional, Tuple, Union
from fastapi import HTTPException, Depends, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials

security = HTTPBearer()

# Admin token from environment
ADMIN_TOKEN = os.environ.get("ADMIN_TOKEN")


def hash_token(token: str) -> str:
    """SHA256 hash of token for secure storage."""
    return f"sha256:{hashlib.sha256(token.encode()).hexdigest()}"


def generate_token() -> str:
    """Generate cryptographically secure API token."""
    return f"acm_{secrets.token_urlsafe(32)}"


def is_admin_token(token: str) -> bool:
    """Check if token is the admin token."""
    return ADMIN_TOKEN and token == ADMIN_TOKEN


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


async def get_storage(request: Request):
    """Get storage from app state."""
    return request.app.state.storage

async def get_current_token_info(
    request: Request,
    credentials: HTTPAuthorizationCredentials = Depends(security),
) -> Tuple[str, Optional[str], Optional[str]]:
    """Get current token hash, name, and cert_email from storage.
    
    Returns:
        Tuple of (token_hash, token_name, cert_email)
    """
    storage = request.app.state.storage
    
    token = credentials.credentials
    
    # Special handling for admin token
    if is_admin_token(token):
        token_hash = hash_token(token)
        # Get admin token data from storage to get the correct cert_email
        token_data = storage.get_api_token(token_hash)
        if token_data:
            return token_hash, "ADMIN", token_data.get("cert_email")
        # If ADMIN token not in storage, get email from environment
        admin_email = os.getenv("ADMIN_EMAIL")
        if not admin_email:
            raise ValueError("ADMIN_EMAIL not set in environment - cannot proceed without valid email")
        return token_hash, "ADMIN", admin_email
    
    token_hash = hash_token(token)
    
    # Check if token exists in storage
    token_data = storage.get_api_token(token_hash)
    if not token_data:
        raise HTTPException(401, "Invalid or revoked token")
    
    return token_hash, token_data.get("name"), token_data.get("cert_email")


async def require_owner(
    request: Request,
    cert_name: str,
    token_info: Tuple[str, Optional[str], Optional[str]] = Depends(get_current_token_info)
) -> None:
    """Require current token to be certificate owner.
    
    Raises:
        HTTPException: If not authorized or certificate not found
    """
    storage = request.app.state.storage
    
    token_hash, token_name, _ = token_info
    
    # Admin token has full access
    if token_name == "ADMIN":
        return
    
    certificate = storage.get_certificate(cert_name)
    
    if not certificate:
        raise HTTPException(404, "Certificate not found")
    
    # Check ownership
    if not hasattr(certificate, 'owner_token_hash') or certificate.owner_token_hash != token_hash:
        raise HTTPException(403, "Not authorized to modify this certificate")


async def get_optional_token_info(
    request: Request,
) -> Optional[Tuple[str, Optional[str], Optional[str]]]:
    """Get token info if provided, otherwise return None.
    
    This allows endpoints to work with or without authentication.
    """
    auth_header = request.headers.get("Authorization")
    if not auth_header or not auth_header.startswith("Bearer "):
        return None
    
    token = auth_header.split(" ", 1)[1]
    
    # Special handling for admin token
    storage = request.app.state.storage
    
    if is_admin_token(token):
        token_hash = hash_token(token)
        # Get admin token data from storage to get the correct cert_email
        token_data = storage.get_api_token(token_hash)
        if token_data:
            return token_hash, "ADMIN", token_data.get("cert_email")
        # If ADMIN token not in storage, get email from environment
        admin_email = os.getenv("ADMIN_EMAIL")
        if not admin_email:
            raise ValueError("ADMIN_EMAIL not set in environment - cannot proceed without valid email")
        return token_hash, "ADMIN", admin_email
    
    token_hash = hash_token(token)
    
    # Check if token exists in storage
    token_data = storage.get_api_token(token_hash)
    if not token_data:
        # Invalid token - treat as no auth
        return None
    
    return token_hash, token_data.get("name"), token_data.get("cert_email")


async def require_proxy_owner(
    request: Request,
    hostname: str,
    token_info: Tuple[str, Optional[str], Optional[str]] = Depends(get_current_token_info)
) -> None:
    """Require current token to be proxy target owner.
    
    Raises:
        HTTPException: If not authorized or proxy target not found
    """
    storage = request.app.state.storage
    
    token_hash, token_name, _ = token_info
    
    # Admin token has full access
    if token_name == "ADMIN":
        return
    
    target = storage.get_proxy_target(hostname)
    
    if not target:
        raise HTTPException(404, "Proxy target not found")
    
    if target.owner_token_hash != token_hash:
        raise HTTPException(403, "Not authorized to modify this proxy target")


async def require_route_owner(
    request: Request,
    route_id: str,
    token_info: Tuple[str, Optional[str], Optional[str]] = Depends(get_current_token_info)
) -> None:
    """Require current token to be route owner.
    
    Raises:
        HTTPException: If not authorized or route not found
    """
    storage = request.app.state.storage
    
    token_hash, token_name, _ = token_info
    
    # Admin token has full access
    if token_name == "ADMIN":
        return
    
    route = storage.get_route(route_id)
    
    if not route:
        raise HTTPException(404, "Route not found")
    
    if route.owner_token_hash != token_hash:
        raise HTTPException(403, "Not authorized to modify this route")


async def require_auth(
    request: Request,
    credentials: HTTPAuthorizationCredentials = Depends(security)
) -> dict:
    """Require valid authentication token."""
    token_hash, token_name, cert_email = await get_current_token_info(request, credentials)
    return {
        'hash': token_hash,
        'name': token_name,
        'cert_email': cert_email
    }


async def require_auth_header(
    request: Request,
    credentials: HTTPAuthorizationCredentials = Depends(security)
) -> str:
    """Require valid authentication and return token hash."""
    token_hash, _, _ = await get_current_token_info(request, credentials)
    return token_hash


async def get_token_info_from_header(
    request: Request,
    credentials: HTTPAuthorizationCredentials = Depends(security)
) -> dict:
    """Get token info from authorization header."""
    token_info = await require_auth(request, credentials)
    return token_info


async def require_admin(
    request: Request,
    credentials: HTTPAuthorizationCredentials = Depends(security)
) -> dict:
    """Require admin token for access."""
    token_info = await require_auth(request, credentials)
    
    if token_info['name'] != 'ADMIN':
        raise HTTPException(403, "Admin access required")
    
    return token_info