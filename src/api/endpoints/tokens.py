"""Token management API endpoints."""

import logging
from typing import Optional, Tuple
from fastapi import APIRouter, HTTPException, Depends, Request

from ..auth import get_current_token_info

logger = logging.getLogger(__name__)


def create_router(storage):
    """Create token endpoints router."""
    router = APIRouter(prefix="/token", tags=["tokens"])
    
    @router.put("/email")
    async def update_token_email(
        request: Request,
        token_info: Tuple[str, Optional[str], Optional[str]] = Depends(get_current_token_info)
    ):
        """Update the certificate email for the current token."""
        token_hash, token_name, current_email = token_info
        
        # Parse request body
        try:
            body = await request.json()
            new_email = body.get("email")
            if not new_email:
                raise HTTPException(400, "Email field is required")
        except Exception as e:
            raise HTTPException(400, f"Invalid request body: {e}")
        
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
    
    return router