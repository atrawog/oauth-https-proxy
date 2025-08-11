"""Token management operations with async support."""

import logging
from datetime import datetime, timezone
from typing import Optional, Tuple
from fastapi import APIRouter, HTTPException, Depends, Request
from pydantic import BaseModel, EmailStr

from .models import TokenCreateRequest, TokenGenerateResponse
from src.api.auth import require_admin, get_current_token_info

logger = logging.getLogger(__name__)


class EmailUpdateRequest(BaseModel):
    """Request model for updating token email."""
    email: EmailStr


def create_management_router(async_storage) -> APIRouter:
    """Create router for token management operations.
    
    All endpoints use async patterns with Request parameter.
    
    Args:
        async_storage: Redis async_storage instance (legacy)
    
    Returns:
        APIRouter with token management endpoints
    """
    router = APIRouter()
    
    @router.post("/generate", response_model=TokenGenerateResponse)
    async def generate_token_display(
        request: Request,
        token_request: TokenCreateRequest,
        _: dict = Depends(require_admin)  # Admin only
    ):
        """Generate a new API token and return full value for display.
        
        This is a convenience endpoint that creates a token and formats
        the response with a security warning.
        """
        import secrets
        from datetime import datetime, timezone
        
        # Get async async_storage
        async_storage = request.app.state.async_storage
        
        # Prevent creating tokens with reserved names
        if token_request.name.upper() == "ADMIN":
            raise HTTPException(400, "Cannot create token with reserved name 'ADMIN'")
        
        # Check if token name already exists
        existing = await async_storage.get_api_token_by_name(token_request.name)
        
        if existing:
            raise HTTPException(409, f"Token '{token_request.name}' already exists")
        
        # Generate secure token
        token_value = f"acm_{secrets.token_urlsafe(32)}"
        
        # Store token
        result = await async_storage.store_api_token(
            token_request.name, 
            token_value, 
            cert_email=token_request.cert_email
        )
        
        if not result:
            raise HTTPException(500, "Failed to create token")
        
        logger.info(f"Created token '{token_request.name}' with email {token_request.cert_email}")
        
        # Return with formatted message
        return TokenGenerateResponse(
            message="Save this token securely - it cannot be retrieved again",
            name=token_request.name,
            token=token_value,
            cert_email=token_request.cert_email
        )
    
    @router.put("/email")
    async def update_token_email(
        request: Request,
        email_request: EmailUpdateRequest,
        token_info: Tuple[str, Optional[str], Optional[str]] = Depends(get_current_token_info)
    ):
        """Update the certificate email for the current token."""
        token_hash, token_name, current_email = token_info
        
        # Get async async_storage
        async_storage = request.app.state.async_storage
        
        new_email = email_request.email
        
        # Get full token info
        token_data = await async_storage.get_api_token(token_hash)
        
        if not token_data:
            raise HTTPException(404, "Token not found")
        
        # Update cert_email
        token_data['cert_email'] = new_email
        
        # Store both by hash and name
        result = await async_storage.store_api_token(
            token_data['name'], 
            token_data['token'], 
            cert_email=new_email
        )
        
        if not result:
            raise HTTPException(500, "Failed to update token email")
        
        logger.info(f"Updated cert_email for token {token_name} to {new_email}")
        
        return {
            "message": "Certificate email updated successfully",
            "name": token_name,
            "cert_email": new_email
        }
    
    @router.get("/info")
    async def get_token_info(
        request: Request,
        token_info: Tuple[str, Optional[str], Optional[str]] = Depends(get_current_token_info)
    ):
        """Get information about the current token."""
        token_hash, token_name, cert_email = token_info
        
        return {
            "name": token_name,
            "cert_email": cert_email,
            "is_admin": token_name and token_name.upper() == "ADMIN"
        }
    
    @router.get("/{name}/reveal")
    async def reveal_token(
        request: Request,
        name: str,
        _: dict = Depends(require_admin)  # Admin only
    ):
        """Reveal the full token value for a specific token.
        
        This endpoint should be used with extreme caution as it exposes
        the actual token value. Admin access required.
        """
        # Get async async_storage
        async_storage = request.app.state.async_storage
        
        # Get token data
        token_data = await async_storage.get_api_token_by_name(name)
        
        if not token_data:
            raise HTTPException(404, f"Token '{name}' not found")
        
        logger.warning(f"Token '{name}' value revealed to admin")
        
        return {
            "name": name,
            "token": token_data['token'],
            "warning": "This token value is sensitive - handle with care"
        }
    
    return router