"""System information and configuration endpoints.

This module provides system-level information endpoints.
"""

import logging
from typing import Dict
from fastapi import APIRouter, Request
from src.shared.logger import log_info, log_debug

logger = logging.getLogger(__name__)

# Version information
VERSION = "2.0.0"
BUILD_DATE = "2025-08-25"
API_VERSION = "v2"


def create_router() -> APIRouter:
    """Create router for system information operations.
    
    Returns:
        APIRouter with system endpoints
    """
    router = APIRouter()
    
    @router.get("/version", response_model=Dict)
    async def get_version(request: Request):
        """Get system version information.
        
        Returns system version, build date, and API version.
        """
        log_debug("Version information requested", component="system")
        
        return {
            "version": VERSION,
            "api_version": API_VERSION,
            "build_date": BUILD_DATE,
            "components": {
                "oauth": "2.1",
                "mcp": "2025-06-18",
                "proxy": "2.0"
            }
        }
    
    @router.get("/info", response_model=Dict)
    async def get_system_info(request: Request):
        """Get comprehensive system information.
        
        Returns detailed system status and configuration.
        """
        log_debug("System info requested", component="system")
        
        # Get auth info from headers
        auth_user = request.headers.get("X-Auth-User", "anonymous")
        auth_scopes = request.headers.get("X-Auth-Scopes", "").split()
        
        return {
            "version": VERSION,
            "api_version": API_VERSION,
            "build_date": BUILD_DATE,
            "auth": {
                "user": auth_user,
                "scopes": auth_scopes
            },
            "status": "healthy",
            "components": {
                "oauth": "enabled",
                "mcp": "enabled",
                "proxy": "enabled",
                "certificates": "enabled",
                "services": "enabled",
                "logging": "enabled"
            }
        }
    
    return router