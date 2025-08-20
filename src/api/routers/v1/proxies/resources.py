"""Proxy MCP resource configuration with async support.

This module handles MCP (Model Context Protocol) resource metadata configuration.
"""

import logging
from fastapi import APIRouter, HTTPException, Depends, Request

from src.auth import AuthDep, AuthResult
from src.proxy.models import ProxyResourceConfig

logger = logging.getLogger(__name__)


def create_resources_router(async_storage):
    """Create router for proxy resource configuration.
    
    All endpoints use async patterns with Request parameter.
    
    Args:
        async_storage: Redis async_storage instance (legacy)
    
    Returns:
        APIRouter with proxy resource endpoints
    """
    router = APIRouter()
    
    @router.post("/{hostname}/resource")
    async def configure_proxy_resource(
        req: Request,
        hostname: str,
        config: ProxyResourceConfig,
        _=Depends(require_proxy_owner)
    ):
        """Configure protected resource metadata for a proxy target - owner only."""
        # Get async async_storage if available
        async_storage = req.app.state.async_storage if hasattr(req.app.state, 'async_storage') else None
        
        target = await async_storage.get_proxy_target(hostname)
        if not target:
            raise HTTPException(404, f"Proxy target {hostname} not found")
        
        # Update resource metadata fields directly on target
        target.resource_endpoint = config.endpoint
        target.resource_scopes = config.scopes
        target.resource_stateful = config.stateful
        target.resource_versions = config.versions
        target.resource_server_info = config.server_info
        target.resource_override_backend = config.override_backend
        target.resource_bearer_methods = config.bearer_methods
        target.resource_documentation_suffix = config.documentation_suffix
        target.resource_custom_metadata = config.custom_metadata
        
        # Handle X-HackerOne-Research header
        if config.hacker_one_research_header:
            if target.custom_response_headers is None:
                target.custom_response_headers = {}
            target.custom_response_headers["X-HackerOne-Research"] = config.hacker_one_research_header
        
        # Store updated target
        success = await async_storage.store_proxy_target(hostname, target)
        if not success:
            raise HTTPException(500, "Failed to update proxy target")
        
        logger.info(f"Protected resource metadata configured for proxy {hostname}")
        
        return {"status": "Protected resource metadata configured", "proxy_target": target}
    
    
    @router.get("/{hostname}/resource")
    async def get_proxy_resource_config(
        req: Request,
        hostname: str
    ):
        """Get protected resource metadata configuration for a proxy target."""
        # Get async async_storage if available
        async_storage = req.app.state.async_storage if hasattr(req.app.state, 'async_storage') else None
        
        target = await async_storage.get_proxy_target(hostname)
        if not target:
            raise HTTPException(404, f"Proxy target {hostname} not found")
        
        if not target.resource_endpoint:
            return {
                "configured": False,
                "message": "Protected resource metadata not configured for this proxy"
            }
        
        # Return resource configuration
        return {
            "configured": True,
            "endpoint": target.resource_endpoint,
            "scopes": target.resource_scopes or ["mcp:read", "mcp:write"],
            "stateful": target.resource_stateful,
            "versions": target.resource_versions or ["2025-06-18"],
            "server_info": target.resource_server_info,
            "override_backend": target.resource_override_backend,
            "bearer_methods": target.resource_bearer_methods or ["header"],
            "documentation_suffix": target.resource_documentation_suffix or "/docs",
            "custom_metadata": target.resource_custom_metadata
        }
    
    
    @router.delete("/{hostname}/resource")
    async def remove_proxy_resource(
        req: Request,
        hostname: str,
        _=Depends(require_proxy_owner)
    ):
        """Remove protected resource metadata from a proxy target - owner only."""
        # Get async async_storage if available
        async_storage = req.app.state.async_storage if hasattr(req.app.state, 'async_storage') else None
        
        target = await async_storage.get_proxy_target(hostname)
        if not target:
            raise HTTPException(404, f"Proxy target {hostname} not found")
        
        # Remove resource metadata fields
        target.resource_endpoint = None
        target.resource_scopes = None
        target.resource_stateful = False
        target.resource_versions = None
        target.resource_server_info = None
        target.resource_override_backend = False
        target.resource_bearer_methods = None
        target.resource_documentation_suffix = None
        target.resource_custom_metadata = None
        
        # Store updated target
        success = await async_storage.store_proxy_target(hostname, target)
        if not success:
            raise HTTPException(500, "Failed to update proxy target")
        
        logger.info(f"Protected resource metadata removed for proxy {hostname}")
        
        return {"status": "Protected resource metadata removed", "proxy_target": target}
    
    return router
