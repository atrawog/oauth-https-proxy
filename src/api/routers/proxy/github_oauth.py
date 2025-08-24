"""GitHub OAuth configuration for proxies with async support.

This module handles GitHub OAuth client configuration for individual proxies.
"""

import logging
from fastapi import APIRouter, HTTPException, Depends, Request

# Authentication is handled by proxy, API trusts headers
from src.proxy.models import ProxyGitHubOAuthConfig

logger = logging.getLogger(__name__)


def create_github_oauth_router(async_storage):
    """Create router for GitHub OAuth configuration.
    
    All endpoints use async patterns with Request parameter.
    
    Args:
        async_storage: Redis async_storage instance (legacy)
    
    Returns:
        APIRouter with GitHub OAuth endpoints
    """
    router = APIRouter()
    
    @router.post("/{proxy_hostname}/github-oauth")
    async def configure_github_oauth(
        req: Request,
        proxy_hostname: str,
        config: ProxyGitHubOAuthConfig
    ):
        """Configure GitHub OAuth credentials for a proxy.
        
        This allows each proxy to have its own GitHub OAuth App, providing
        better security isolation and multi-tenancy support.
        """
        # Get auth info from headers (set by proxy)
        auth_user = req.headers.get("X-Auth-User", "system")
        auth_scopes = req.headers.get("X-Auth-Scopes", "").split()
        is_admin = "admin" in auth_scopes
        
        # Check permissions - admin scope required for mutations
        if not is_admin:
            raise HTTPException(403, "Admin scope required")
        
        # Get async storage if available
        async_storage = req.app.state.async_storage if hasattr(req.app.state, 'async_storage') else None
        
        target = await async_storage.get_proxy_target(proxy_hostname)
        if not target:
            raise HTTPException(404, f"Proxy target {proxy_hostname} not found")
        
        # Update GitHub OAuth configuration
        target.github_client_id = config.github_client_id
        target.github_client_secret = config.github_client_secret
        
        # Store updated target
        success = await async_storage.store_proxy_target(proxy_hostname, target)
        if not success:
            raise HTTPException(500, "Failed to update proxy target")
        
        # Track configured GitHub OAuth proxies
        await async_storage.redis_client.sadd("github_oauth:configured", proxy_hostname)
        
        # Clear cached GitHub client for this proxy to force reload
        # This ensures the new credentials are used immediately
        from src.api.oauth.auth_authlib import AuthManager
        if hasattr(req.app.state, 'auth_manager'):
            auth_manager = req.app.state.auth_manager
            if proxy_hostname in auth_manager._github_clients:
                del auth_manager._github_clients[proxy_hostname]
        
        logger.info(f"GitHub OAuth configuration updated for {proxy_hostname}")
        
        return {
            "status": "success",
            "message": f"GitHub OAuth configuration updated for {proxy_hostname}",
            "proxy_hostname": proxy_hostname,
            "github_oauth_config": {
                "github_client_id": target.github_client_id,
                # Never return the client secret for security
                "github_client_secret": "***configured***"
            }
        }
    
    @router.get("/{proxy_hostname}/github-oauth")
    async def get_github_oauth_config(
        req: Request,
        proxy_hostname: str
    ):
        """Get GitHub OAuth configuration for a proxy (without revealing the secret)."""
        # Get async storage if available
        async_storage = req.app.state.async_storage if hasattr(req.app.state, 'async_storage') else None
        
        target = await async_storage.get_proxy_target(proxy_hostname)
        if not target:
            raise HTTPException(404, f"Proxy target {proxy_hostname} not found")
        
        # Check if GitHub OAuth is configured
        if not target.github_client_id:
            return {
                "status": "not_configured",
                "message": f"No GitHub OAuth configuration for {proxy_hostname}",
                "proxy_hostname": proxy_hostname,
                "fallback": "Using environment variables if configured"
            }
        
        return {
            "status": "configured",
            "proxy_hostname": proxy_hostname,
            "github_oauth_config": {
                "github_client_id": target.github_client_id,
                # Never return the client secret for security
                "github_client_secret": "***configured***" if target.github_client_secret else None
            }
        }
    
    @router.delete("/{proxy_hostname}/github-oauth")
    async def clear_github_oauth_config(
        req: Request,
        proxy_hostname: str
    ):
        """Clear GitHub OAuth configuration for a proxy.
        
        This will cause the proxy to fall back to using the global
        GitHub OAuth credentials from environment variables.
        """
        # Get auth info from headers (set by proxy)
        auth_user = req.headers.get("X-Auth-User", "system")
        auth_scopes = req.headers.get("X-Auth-Scopes", "").split()
        is_admin = "admin" in auth_scopes
        
        # Check permissions - admin scope required for mutations
        if not is_admin:
            raise HTTPException(403, "Admin scope required")
        
        # Get async storage if available
        async_storage = req.app.state.async_storage if hasattr(req.app.state, 'async_storage') else None
        
        target = await async_storage.get_proxy_target(proxy_hostname)
        if not target:
            raise HTTPException(404, f"Proxy target {proxy_hostname} not found")
        
        # Clear GitHub OAuth configuration
        target.github_client_id = None
        target.github_client_secret = None
        
        # Store updated target
        success = await async_storage.store_proxy_target(proxy_hostname, target)
        if not success:
            raise HTTPException(500, "Failed to update proxy target")
        
        # Remove from configured set
        await async_storage.redis_client.srem("github_oauth:configured", proxy_hostname)
        
        # Clear cached GitHub client for this proxy
        from src.api.oauth.auth_authlib import AuthManager
        if hasattr(req.app.state, 'auth_manager'):
            auth_manager = req.app.state.auth_manager
            if proxy_hostname in auth_manager._github_clients:
                del auth_manager._github_clients[proxy_hostname]
        
        logger.info(f"GitHub OAuth configuration cleared for {proxy_hostname}")
        
        return {
            "status": "success",
            "message": f"GitHub OAuth configuration cleared for {proxy_hostname}",
            "proxy_hostname": proxy_hostname,
            "fallback": "Will use environment variables if configured"
        }
    
    @router.get("/github-oauth/configured")
    async def list_configured_github_oauth(req: Request):
        """List all proxies with custom GitHub OAuth configurations."""
        # Get async storage if available
        async_storage = req.app.state.async_storage if hasattr(req.app.state, 'async_storage') else None
        
        # Get all configured proxy hostnames
        configured = await async_storage.redis_client.smembers("github_oauth:configured")
        
        proxies_with_config = []
        for hostname_bytes in configured:
            proxy_hostname = hostname_bytes.decode('utf-8') if isinstance(hostname_bytes, bytes) else hostname_bytes
            target = await async_storage.get_proxy_target(proxy_hostname)
            if target and target.github_client_id:
                proxies_with_config.append({
                    "proxy_hostname": proxy_hostname,
                    "github_client_id": target.github_client_id,
                    # Never expose the secret
                    "configured": True
                })
        
        return {
            "count": len(proxies_with_config),
            "proxies": proxies_with_config,
            "global_fallback": "Environment variables used for proxies not listed here"
        }
    
    return router