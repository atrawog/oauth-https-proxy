"""Admin-specific token operations with async support."""

import secrets
import logging
from fastapi import APIRouter, HTTPException, Depends, Request

from src.auth import AuthDep, AuthResult

logger = logging.getLogger(__name__)


def create_admin_router(async_storage) -> APIRouter:
    """Create router for admin token operations.
    
    All endpoints use async patterns with Request parameter.
    
    Args:
        async_storage: Redis async_storage instance (legacy)
    
    Returns:
        APIRouter with admin token endpoints
    """
    router = APIRouter()
    
    @router.post("/admin")
    async def create_or_update_admin_token(
        request: Request,
        auth: AuthResult = Depends(AuthDep(admin=True))  # Requires existing admin token
    ):
        """Create or update the ADMIN token.
        
        This endpoint allows creating or updating the special ADMIN token.
        Requires an existing admin token for authorization.
        """
        # Get async async_storage
        async_storage = request.app.state.async_storage
        
        try:
            body = await request.json()
            cert_email = body.get("cert_email")
            if not cert_email:
                raise HTTPException(400, "cert_email is required")
        except Exception as e:
            raise HTTPException(400, f"Invalid request body: {e}")
        
        # Check if ADMIN token exists
        existing = await async_storage.get_api_token_by_name("ADMIN")
        
        if existing:
            # Update email only
            existing['cert_email'] = cert_email
            result = await async_storage.store_api_token(
                "ADMIN", 
                existing['token'], 
                cert_email=cert_email
            )
            
            if not result:
                raise HTTPException(500, "Failed to update ADMIN token")
            
            logger.info(f"Updated ADMIN token email to {cert_email}")
            return {
                "message": "ADMIN token updated",
                "cert_email": cert_email
            }
        else:
            # Create new ADMIN token
            token_value = f"acm_{secrets.token_urlsafe(32)}"
            
            result = await async_storage.store_api_token(
                "ADMIN", 
                token_value, 
                cert_email=cert_email
            )
            
            if not result:
                raise HTTPException(500, "Failed to create ADMIN token")
            
            logger.info(f"Created ADMIN token with email {cert_email}")
            return {
                "message": "ADMIN token created",
                "token": token_value,
                "cert_email": cert_email,
                "warning": "Save this token securely - it cannot be retrieved again"
            }
    
    return router