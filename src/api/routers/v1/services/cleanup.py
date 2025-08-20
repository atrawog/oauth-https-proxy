"""Service cleanup operations with async support.

This module handles cleanup of orphaned services and resources.
"""

import logging
from typing import Dict
from fastapi import APIRouter, Depends, HTTPException, Request

from src.auth import AuthDep, AuthResult
from src.docker.manager import DockerManager

logger = logging.getLogger(__name__)


def create_cleanup_router(storage) -> APIRouter:
    """Create router for service cleanup operations.
    
    All endpoints use async patterns with Request parameter.
    
    Args:
        storage: Redis storage instance
    
    Returns:
        APIRouter with cleanup endpoints
    """
    router = APIRouter()
    
    async def get_docker_manager(request: Request) -> DockerManager:
        """Get Docker manager instance from app state."""
        # Try direct app.state first
        if hasattr(request.app.state, 'docker_manager'):
            manager = request.app.state.docker_manager
            if manager is not None:
                return manager
        
        # Try async_components
        if hasattr(request.app.state, 'async_components'):
            components = request.app.state.async_components
            if components and hasattr(components, 'docker_manager'):
                manager = components.docker_manager
                if manager is not None:
                    return manager
        
        # Docker manager is optional for cleanup
        return None
    
    @router.post("/cleanup")
    async def cleanup_orphaned_services(
        request: Request,
        auth: AuthResult = Depends(AuthDep())
    ):
        """Clean up orphaned Docker containers and services.
        
        Requires admin token.
        """
        # Admin only
        if token_info.get("name") != "ADMIN":
            raise HTTPException(403, "Admin token required")
        
        manager = await get_docker_manager(request)
        
        try:
            result = await manager.cleanup_orphaned_services()
            
            return {
                "message": "Cleanup completed",
                "containers_removed": result.get("containers_removed", 0),
                "services_cleaned": result.get("services_cleaned", 0),
                "ports_released": result.get("ports_released", 0)
            }
            
        except Exception as e:
            logger.error(f"Error during service cleanup: {e}")
            raise HTTPException(500, f"Error during cleanup: {str(e)}")
    
    return router