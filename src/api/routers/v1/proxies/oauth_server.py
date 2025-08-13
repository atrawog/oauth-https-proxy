"""OAuth authorization server configuration with async support.

This module handles OAuth authorization server metadata configuration for proxies.
"""

import logging
from fastapi import APIRouter, HTTPException, Depends, Request

from src.api.auth import require_proxy_owner, require_auth_header
from src.proxy.models import ProxyOAuthServerConfig

logger = logging.getLogger(__name__)


def create_oauth_server_router(async_storage):
    """Create router for OAuth server configuration.
    
    All endpoints use async patterns with Request parameter.
    
    Args:
        async_storage: Redis async_storage instance (legacy)
    
    Returns:
        APIRouter with OAuth server endpoints
    """
    router = APIRouter()
    
    @router.post("/{hostname}/oauth-server")
    async def configure_oauth_server(
        req: Request,
        hostname: str,
        config: ProxyOAuthServerConfig,
        _=Depends(require_proxy_owner)
    ):
        """Configure OAuth authorization server metadata for a proxy - owner only."""
        # Get async async_storage if available
        async_storage = req.app.state.async_storage if hasattr(req.app.state, 'async_storage') else None
        
        target = await async_storage.get_proxy_target(hostname)
        if not target:
            raise HTTPException(404, f"Proxy target {hostname} not found")
        
        # Update OAuth server configuration fields
        target.oauth_server_issuer = config.issuer
        target.oauth_server_scopes = config.scopes
        target.oauth_server_grant_types = config.grant_types
        target.oauth_server_response_types = config.response_types
        target.oauth_server_token_auth_methods = config.token_auth_methods
        target.oauth_server_claims = config.claims
        target.oauth_server_pkce_required = config.pkce_required
        target.oauth_server_custom_metadata = config.custom_metadata
        target.oauth_server_override_defaults = config.override_defaults
        
        # Store updated target
        success = await async_storage.store_proxy_target(hostname, target)
        if not success:
            raise HTTPException(500, "Failed to update proxy target")
        
        # Track configured OAuth servers
        await async_storage.redis_client.sadd("oauth_server:configured", hostname)
        
        logger.info(f"OAuth server configuration updated for {hostname}")
        
        return {
            "status": "success",
            "message": f"OAuth server configuration updated for {hostname}",
            "hostname": hostname,
            "oauth_server_config": {
                "issuer": target.oauth_server_issuer,
                "scopes": target.oauth_server_scopes,
                "grant_types": target.oauth_server_grant_types,
                "response_types": target.oauth_server_response_types,
                "token_auth_methods": target.oauth_server_token_auth_methods,
                "claims": target.oauth_server_claims,
                "pkce_required": target.oauth_server_pkce_required,
                "override_defaults": target.oauth_server_override_defaults
            }
        }
    
    @router.get("/{hostname}/oauth-server")
    async def get_oauth_server_config(
        req: Request,
        hostname: str
    ):
        """Get OAuth authorization server configuration for a proxy."""
        # Get async async_storage if available
        async_storage = req.app.state.async_storage if hasattr(req.app.state, 'async_storage') else None
        
        target = await async_storage.get_proxy_target(hostname)
        if not target:
            raise HTTPException(404, f"Proxy target {hostname} not found")
        
        # Check if OAuth server is configured
        if not target.oauth_server_override_defaults:
            return {
                "status": "not_configured",
                "message": f"No custom OAuth server configuration for {hostname}",
                "hostname": hostname
            }
        
        return {
            "status": "configured",
            "hostname": hostname,
            "oauth_server_config": {
                "issuer": target.oauth_server_issuer,
                "scopes": target.oauth_server_scopes,
                "grant_types": target.oauth_server_grant_types,
                "response_types": target.oauth_server_response_types,
                "token_auth_methods": target.oauth_server_token_auth_methods,
                "claims": target.oauth_server_claims,
                "pkce_required": target.oauth_server_pkce_required,
                "custom_metadata": target.oauth_server_custom_metadata,
                "override_defaults": target.oauth_server_override_defaults
            }
        }
    
    @router.delete("/{hostname}/oauth-server")
    async def clear_oauth_server_config(
        req: Request,
        hostname: str,
        _=Depends(require_proxy_owner)
    ):
        """Clear OAuth authorization server configuration for a proxy - owner only."""
        # Get async async_storage if available
        async_storage = req.app.state.async_storage if hasattr(req.app.state, 'async_storage') else None
        
        target = await async_storage.get_proxy_target(hostname)
        if not target:
            raise HTTPException(404, f"Proxy target {hostname} not found")
        
        # Clear OAuth server configuration fields
        target.oauth_server_issuer = None
        target.oauth_server_scopes = None
        target.oauth_server_grant_types = None
        target.oauth_server_response_types = None
        target.oauth_server_token_auth_methods = None
        target.oauth_server_claims = None
        target.oauth_server_pkce_required = False
        target.oauth_server_custom_metadata = None
        target.oauth_server_override_defaults = False
        
        # Store updated target
        success = await async_storage.store_proxy_target(hostname, target)
        if not success:
            raise HTTPException(500, "Failed to update proxy target")
        
        # Remove from configured set
        await async_storage.redis_client.srem("oauth_server:configured", hostname)
        
        logger.info(f"OAuth server configuration cleared for {hostname}")
        
        return {
            "status": "success",
            "message": f"OAuth server configuration cleared for {hostname}",
            "hostname": hostname
        }
    
    @router.get("/oauth-servers/configured")
    async def list_configured_oauth_servers(req: Request):
        """List all proxies with custom OAuth server configurations."""
        # Get async async_storage if available
        async_storage = req.app.state.async_storage if hasattr(req.app.state, 'async_storage') else None
        
        # Get all configured hostnames
        configured = await async_storage.redis_client.smembers("oauth_server:configured")
        
        proxies_with_config = []
        for hostname_bytes in configured:
            hostname = hostname_bytes.decode('utf-8') if isinstance(hostname_bytes, bytes) else hostname_bytes
            target = await async_storage.get_proxy_target(hostname)
            if target and target.oauth_server_override_defaults:
                proxies_with_config.append({
                    "hostname": hostname,
                    "issuer": target.oauth_server_issuer,
                    "scopes": target.oauth_server_scopes,
                    "override_defaults": target.oauth_server_override_defaults
                })
        
        return {
            "count": len(proxies_with_config),
            "proxies": proxies_with_config
        }
    
    return router