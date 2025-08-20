"""Token ownership query endpoints with async support."""

import logging
from typing import List, Dict
from fastapi import APIRouter, HTTPException, Depends, Request

from src.auth import AuthDep, AuthResult

logger = logging.getLogger(__name__)


def create_ownership_router(async_storage) -> APIRouter:
    """Create router for token ownership queries.
    
    All endpoints use async patterns with Request parameter.
    
    Args:
        async_storage: Redis async_storage instance (legacy)
    
    Returns:
        APIRouter with token ownership endpoints
    """
    router = APIRouter()
    
    @router.get("/{name}/certificates")
    async def get_token_certificates(
        request: Request,
        name: str,
        auth: AuthResult = Depends(AuthDep(admin=True))  # Admin only
    ):
        """Get all certificates owned by a token."""
        # Get async async_storage
        async_storage = request.app.state.async_storage
        
        # Get token data
        token_data = await async_storage.get_api_token_by_name(name)
        
        if not token_data:
            raise HTTPException(404, f"Token '{name}' not found")
        
        # Get owned certificates
        certificates = await async_storage.list_certificates_by_owner(token_data['hash'])
        
        return {
            "token_name": name,
            "certificate_count": len(certificates),
            "certificates": [
                {
                    "cert_name": cert.get('cert_name', ''),
                    "domains": cert.get('domains', []),
                    "status": cert.get('status', ''),
                    "expires_at": cert.get('expires_at', '')
                }
                for cert in certificates
            ]
        }
    
    @router.get("/{name}/proxies")
    async def get_token_proxies(
        request: Request,
        name: str,
        auth: AuthResult = Depends(AuthDep(admin=True))  # Admin only
    ):
        """Get all proxy targets owned by a token."""
        # Get async async_storage
        async_storage = request.app.state.async_storage
        
        # Get token data
        token_data = await async_storage.get_api_token_by_name(name)
        
        if not token_data:
            raise HTTPException(404, f"Token '{name}' not found")
        
        # Get owned proxies
        proxies = await async_storage.list_proxies_by_owner(token_data['hash'])
        
        return {
            "token_name": name,
            "proxy_count": len(proxies),
            "proxies": [
                {
                    "hostname": proxy.get('hostname', ''),
                    "target_url": proxy.get('target_url', ''),
                    "enabled": proxy.get('enabled', True),
                    "enable_https": proxy.get('enable_https', False),
                    "cert_name": proxy.get('cert_name', '')
                }
                for proxy in proxies
            ]
        }
    
    return router