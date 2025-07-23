"""Enhanced token management API endpoints."""

import secrets
import logging
from typing import List, Optional, Tuple, Dict
from datetime import datetime, timezone
from fastapi import APIRouter, HTTPException, Depends, Request, Query
from pydantic import BaseModel, EmailStr

from ..auth import get_current_token_info, require_admin

logger = logging.getLogger(__name__)


class TokenCreateRequest(BaseModel):
    """Request model for creating a token."""
    name: str
    cert_email: EmailStr


class TokenResponse(BaseModel):
    """Response model for token details."""
    name: str
    token: str
    cert_email: str
    created_at: datetime


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


def create_router(storage):
    """Create enhanced token endpoints router."""
    router = APIRouter(prefix="/tokens", tags=["tokens"])
    
    @router.post("/", response_model=TokenResponse)
    async def create_token(
        request: TokenCreateRequest,
        _: dict = Depends(require_admin)  # Admin only
    ):
        """Create a new API token."""
        # Prevent creating tokens with reserved names
        if request.name.upper() == "ADMIN":
            raise HTTPException(400, "Cannot create token with reserved name 'ADMIN'")
        
        # Check if token name already exists
        existing = storage.get_api_token_by_name(request.name)
        if existing:
            raise HTTPException(409, f"Token '{request.name}' already exists")
        
        # Generate secure token
        token_value = f"acm_{secrets.token_urlsafe(32)}"
        
        # Store token
        result = storage.store_api_token(request.name, token_value, cert_email=request.cert_email)
        logger.info(f"Token storage result for '{request.name}': {result}")
        
        if not result:
            raise HTTPException(500, "Failed to create token")
        
        # Verify token was stored correctly
        token_data = storage.get_api_token_by_name(request.name)
        logger.info(f"Token verification for '{request.name}': {token_data}")
        
        logger.info(f"Created token '{request.name}' with email {request.cert_email}")
        
        return TokenResponse(
            name=request.name,
            token=token_value,
            cert_email=request.cert_email,
            created_at=datetime.now(timezone.utc)
        )
    
    @router.get("/", response_model=List[TokenSummary])
    async def list_tokens(
        _: dict = Depends(require_admin)  # Admin only
    ):
        """List all API tokens."""
        tokens = []
        
        # Get all token keys by scanning for name keys
        for key in storage.redis_client.scan_iter(match="token:*"):
            # Decode byte string if needed
            if isinstance(key, bytes):
                key = key.decode('utf-8')
            
            # Skip if it's not a direct token key (e.g., skip token:foo:bar patterns)
            parts = key.split(":")
            if len(parts) != 2:
                continue
            token_name = parts[1]
            token_data = storage.get_api_token_by_name(token_name)
            
            if token_data:
                # Count owned resources
                cert_count = storage.count_certificates_by_owner(token_data['hash'])
                proxy_count = storage.count_proxies_by_owner(token_data['hash'])
                
                # Parse created_at
                created_at = datetime.now(timezone.utc)
                if 'created_at' in token_data:
                    try:
                        created_at = datetime.fromisoformat(token_data['created_at'].replace('Z', '+00:00'))
                    except:
                        pass
                
                tokens.append(TokenSummary(
                    name=token_data['name'],
                    cert_email=token_data.get('cert_email', ''),
                    created_at=created_at,
                    certificate_count=cert_count,
                    proxy_count=proxy_count,
                    is_admin=(token_data['name'].upper() == 'ADMIN')
                ))
        
        # Sort by name
        tokens.sort(key=lambda t: t.name)
        return tokens
    
    # Keep existing endpoints for backward compatibility
    # These must be defined BEFORE /{name} to avoid route conflicts
    class EmailUpdateRequest(BaseModel):
        """Request model for updating token email."""
        email: EmailStr

    @router.put("/email")
    async def update_token_email(
        request: EmailUpdateRequest,
        token_info: Tuple[str, Optional[str], Optional[str]] = Depends(get_current_token_info)
    ):
        """Update the certificate email for the current token."""
        token_hash, token_name, current_email = token_info
        
        new_email = request.email
        
        # Get full token info
        token_data = storage.get_api_token(token_hash)
        if not token_data:
            raise HTTPException(404, "Token not found")
        
        # Update cert_email
        token_data['cert_email'] = new_email
        
        # Store both by hash and name
        if not storage.store_api_token(token_data['name'], token_data['token'], cert_email=new_email):
            raise HTTPException(500, "Failed to update token email")
        
        logger.info(f"Updated cert_email for token {token_name} to {new_email}")
        
        return {
            "message": "Certificate email updated successfully",
            "name": token_name,
            "cert_email": new_email
        }
    
    @router.get("/info")
    async def get_token_info(
        token_info: Tuple[str, Optional[str], Optional[str]] = Depends(get_current_token_info)
    ):
        """Get information about the current token."""
        token_hash, token_name, cert_email = token_info
        
        return {
            "name": token_name,
            "cert_email": cert_email,
            "hash_preview": token_hash[:16] + "..."
        }
    
    @router.get("/{name}", response_model=TokenDetail)
    async def get_token(
        name: str,
        _: dict = Depends(require_admin)  # Admin only
    ):
        """Get token details including the full token value."""
        token_data = storage.get_api_token_by_name(name)
        
        if not token_data:
            raise HTTPException(404, f"Token '{name}' not found")
        
        # Get owned resources
        cert_names = storage.list_certificate_names_by_owner(token_data['hash'])
        proxy_names = storage.list_proxy_names_by_owner(token_data['hash'])
        
        # Parse created_at
        created_at = datetime.now(timezone.utc)
        if 'created_at' in token_data:
            try:
                created_at = datetime.fromisoformat(token_data['created_at'].replace('Z', '+00:00'))
            except:
                pass
        
        return TokenDetail(
            name=token_data['name'],
            token=token_data['token'],
            cert_email=token_data.get('cert_email', ''),
            created_at=created_at,
            certificate_count=len(cert_names),
            proxy_count=len(proxy_names),
            is_admin=(token_data['name'].upper() == 'ADMIN'),
            certificates=cert_names,
            proxies=proxy_names
        )
    
    @router.delete("/{name}")
    async def delete_token(
        name: str,
        cascade: bool = Query(True, description="Delete owned resources"),
        _: dict = Depends(require_admin)  # Admin only
    ):
        """Delete a token and optionally its owned resources."""
        # Prevent deleting ADMIN token
        if name.upper() == "ADMIN":
            raise HTTPException(400, "Cannot delete ADMIN token")
        
        token_data = storage.get_api_token_by_name(name)
        if not token_data:
            raise HTTPException(404, f"Token '{name}' not found")
        
        deleted_resources = {"certificates": 0, "proxies": 0}
        
        if cascade:
            # Delete owned certificates
            cert_names = storage.list_certificate_names_by_owner(token_data['hash'])
            for cert_name in cert_names:
                if storage.delete_certificate(cert_name):
                    deleted_resources["certificates"] += 1
                    logger.info(f"Deleted certificate {cert_name} owned by token {name}")
            
            # Delete owned proxies
            proxy_names = storage.list_proxy_names_by_owner(token_data['hash'])
            for proxy_name in proxy_names:
                if storage.delete_proxy_target(proxy_name):
                    deleted_resources["proxies"] += 1
                    logger.info(f"Deleted proxy {proxy_name} owned by token {name}")
        
        # Delete token
        if not storage.delete_api_token(token_data['hash']):
            raise HTTPException(500, "Failed to delete token")
        
        logger.info(f"Deleted token '{name}' and {deleted_resources}")
        
        return {
            "message": f"Token '{name}' deleted",
            "deleted_resources": deleted_resources
        }
    
    @router.get("/{name}/certificates")
    async def list_token_certificates(
        name: str,
        _: dict = Depends(require_admin)  # Admin only
    ):
        """List all certificates owned by a token."""
        token_data = storage.get_api_token_by_name(name)
        
        if not token_data:
            raise HTTPException(404, f"Token '{name}' not found")
        
        certificates = []
        cert_names = storage.list_certificate_names_by_owner(token_data['hash'])
        
        for cert_name in cert_names:
            cert = storage.get_certificate(cert_name)
            if cert:
                certificates.append({
                    "cert_name": cert.cert_name,
                    "domains": cert.domains,
                    "status": cert.status,
                    "expires_at": cert.expires_at.isoformat() if cert.expires_at else None,
                    "environment": "staging" if "staging" in cert.acme_directory_url else "production"
                })
        
        return certificates
    
    @router.get("/{name}/proxies")
    async def list_token_proxies(
        name: str,
        _: dict = Depends(require_admin)  # Admin only
    ):
        """List all proxy targets owned by a token."""
        token_data = storage.get_api_token_by_name(name)
        
        if not token_data:
            raise HTTPException(404, f"Token '{name}' not found")
        
        proxies = []
        proxy_names = storage.list_proxy_names_by_owner(token_data['hash'])
        
        for proxy_name in proxy_names:
            proxy = storage.get_proxy_target(proxy_name)
            if proxy:
                proxies.append({
                    "hostname": proxy.hostname,
                    "target_url": proxy.target_url,
                    "enabled": proxy.enabled,
                    "cert_name": proxy.cert_name,
                    "auth_enabled": proxy.auth_enabled
                })
        
        return proxies
    
    # Special endpoint for admin token generation/update
    @router.post("/admin")
    async def create_or_update_admin_token(
        request: Request,
        _: dict = Depends(require_admin)  # Requires existing admin token
    ):
        """Create or update the ADMIN token."""
        try:
            body = await request.json()
            cert_email = body.get("cert_email")
            if not cert_email:
                raise HTTPException(400, "cert_email is required")
        except Exception as e:
            raise HTTPException(400, f"Invalid request body: {e}")
        
        # Check if ADMIN token exists
        existing = storage.get_api_token_by_name("ADMIN")
        
        if existing:
            # Update email only
            existing['cert_email'] = cert_email
            if not storage.store_api_token("ADMIN", existing['token'], cert_email=cert_email):
                raise HTTPException(500, "Failed to update ADMIN token")
            
            logger.info(f"Updated ADMIN token email to {cert_email}")
            return {
                "message": "ADMIN token updated",
                "cert_email": cert_email
            }
        else:
            # Create new ADMIN token
            token_value = f"acm_{secrets.token_urlsafe(32)}"
            
            if not storage.store_api_token("ADMIN", token_value, cert_email=cert_email):
                raise HTTPException(500, "Failed to create ADMIN token")
            
            logger.info(f"Created ADMIN token with email {cert_email}")
            return {
                "message": "ADMIN token created",
                "token": token_value,
                "cert_email": cert_email
            }
    
    return router