"""Token information endpoints.

This module provides OAuth token information endpoints.
"""

import logging
from typing import Dict, Optional
from fastapi import APIRouter, Request, HTTPException
from src.shared.logger import log_info, log_debug, log_warning

logger = logging.getLogger(__name__)


def create_router(async_storage) -> APIRouter:
    """Create router for token information operations.
    
    Args:
        async_storage: Redis async storage instance
    
    Returns:
        APIRouter with token endpoints
    """
    router = APIRouter()
    
    @router.get("/info", response_model=Dict)
    async def get_token_info(request: Request):
        """Get information about the current OAuth token.
        
        Returns token metadata and session information.
        """
        # Get auth info from headers (set by proxy)
        auth_user = request.headers.get("X-Auth-User")
        auth_scopes = request.headers.get("X-Auth-Scopes", "").split()
        auth_email = request.headers.get("X-Auth-Email", "")
        auth_client = request.headers.get("X-Auth-Client-Id", "")
        
        if not auth_user:
            raise HTTPException(401, "No authentication token")
        
        log_debug(f"Token info requested by {auth_user}", component="tokens")
        
        # Get session info from Redis if available
        session_info = None
        if auth_user and auth_user != "anonymous":
            # Try to get OAuth session info
            session_key = f"oauth:session:{auth_user}"
            try:
                session_data = await async_storage.get_value(session_key)
                if session_data:
                    session_info = {
                        "active": True,
                        "username": auth_user,
                        "created": session_data.get("created_at"),
                        "last_used": session_data.get("last_used")
                    }
            except Exception as e:
                log_warning(f"Failed to get session info: {e}", component="tokens")
        
        return {
            "token_type": "oauth_jwt",
            "username": auth_user,
            "scopes": auth_scopes,
            "email": auth_email,
            "client_id": auth_client,
            "session": session_info or {
                "active": True if auth_user != "anonymous" else False,
                "username": auth_user
            },
            "metadata": {
                "auth_type": "oauth",
                "provider": "github"
            }
        }
    
    @router.get("/", response_model=Dict)
    async def list_token_info(request: Request):
        """List basic token information.
        
        Returns simplified token list view.
        """
        # Get auth info from headers
        auth_user = request.headers.get("X-Auth-User")
        auth_scopes = request.headers.get("X-Auth-Scopes", "").split()
        
        if not auth_user:
            return {"tokens": [], "count": 0}
        
        log_debug(f"Token list requested by {auth_user}", component="tokens")
        
        # Return current token info in list format
        return {
            "tokens": [
                {
                    "type": "oauth",
                    "username": auth_user,
                    "scopes": auth_scopes,
                    "active": True
                }
            ],
            "count": 1
        }
    
    return router