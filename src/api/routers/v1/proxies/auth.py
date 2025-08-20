"""Proxy authentication configuration with async support.

This module handles OAuth authentication configuration for proxy targets.
"""

import logging
from typing import Optional
from fastapi import APIRouter, HTTPException, Depends, Request

from src.auth import AuthDep, AuthResult
from src.proxy.models import ProxyAuthConfig

logger = logging.getLogger(__name__)


def create_auth_router(async_storage):
    """Create router for proxy authentication configuration.
    
    All endpoints use async patterns with Request parameter.
    
    Args:
        async_storage: Redis async_storage instance (legacy)
    
    Returns:
        APIRouter with proxy auth endpoints
    """
    router = APIRouter()
    
    @router.post("/{hostname}/auth")
    async def configure_proxy_auth(
        req: Request,
        hostname: str,
        config: ProxyAuthConfig,
        _=Depends(require_proxy_owner)
    ):
        """Configure unified auth for a proxy target - owner only."""
        # Get async async_storage if available
        async_storage = req.app.state.async_storage if hasattr(req.app.state, 'async_storage') else None
        
        target = await async_storage.get_proxy_target(hostname)
        if not target:
            raise HTTPException(404, f"Proxy target {hostname} not found")
        
        # Validate auth proxy exists
        if config.auth_proxy:
            auth_target = await async_storage.get_proxy_target(config.auth_proxy)
            if not auth_target:
                raise HTTPException(400, f"Auth proxy {config.auth_proxy} not found")
        
        # Update auth configuration
        target.auth_enabled = config.enabled
        target.auth_proxy = config.auth_proxy
        target.auth_mode = config.mode
        target.auth_required_users = config.required_users
        target.auth_required_emails = config.required_emails
        target.auth_required_groups = config.required_groups
        target.auth_allowed_scopes = config.allowed_scopes
        target.auth_allowed_audiences = config.allowed_audiences
        target.auth_pass_headers = config.pass_headers
        target.auth_cookie_name = config.cookie_name
        target.auth_header_prefix = config.header_prefix
        target.auth_excluded_paths = config.excluded_paths
        
        # Store updated target
        success = await async_storage.store_proxy_target(hostname, target)
        if not success:
            raise HTTPException(500, "Failed to update proxy target")
        
        # When enabling auth, create a route for OAuth metadata endpoint
        if config.enabled and config.auth_proxy:
            # Create a route to forward OAuth metadata requests to the auth instance
            from src.proxy.routes import Route, RouteTargetType
            
            route_id = f"oauth-metadata-{hostname.replace('.', '-')}"
            oauth_route = Route(
                route_id=route_id,
                path_pattern="/.well-known/oauth-authorization-server",
                target_type=RouteTargetType.SERVICE,
                target_value="auth",  # Route to auth service, not hostname
                priority=90,  # High priority but below system routes
                enabled=True,
                description=f"OAuth metadata for {hostname}",
                owner_token_hash=target.owner_token_hash
            )
            
            # Store the route
            await async_storage.store_route(oauth_route)
            logger.info(f"Created OAuth metadata route {route_id} for {hostname}")
            
            # Add to proxy's enabled routes if using selective mode
            if target.route_mode == "selective":
                if route_id not in target.enabled_routes:
                    target.enabled_routes.append(route_id)
                    await async_storage.store_proxy_target(hostname, target)
                    logger.info(f"Added route {route_id} to enabled routes for {hostname}")
        
        logger.info(f"Auth configured for proxy {hostname}: enabled={config.enabled}")
        
        return {"status": "Auth configured", "proxy_target": target}
    
    
    @router.delete("/{hostname}/auth")
    async def remove_proxy_auth(
        req: Request,
        hostname: str,
        _=Depends(require_proxy_owner)
    ):
        """Disable auth protection for a proxy target - owner only."""
        # Get async async_storage if available
        async_storage = req.app.state.async_storage if hasattr(req.app.state, 'async_storage') else None
        
        target = await async_storage.get_proxy_target(hostname)
        if not target:
            raise HTTPException(404, f"Proxy target {hostname} not found")
        
        # Disable auth
        target.auth_enabled = False
        target.auth_proxy = None
        target.auth_required_users = None
        target.auth_required_emails = None
        target.auth_required_groups = None
        
        # Store updated target
        success = await async_storage.store_proxy_target(hostname, target)
        if not success:
            raise HTTPException(500, "Failed to update proxy target")
        
        # Remove OAuth metadata route when disabling auth
        route_id = f"oauth-metadata-{hostname.replace('.', '-')}"
        route = await async_storage.get_route(route_id)
        if route:
            await async_storage.delete_route(route_id)
        logger.info(f"Auth disabled for proxy {hostname}")
        
        return {"status": "Auth protection removed", "proxy_target": target}
    
    
    @router.get("/{hostname}/auth")
    async def get_proxy_auth_config(
        req: Request,
        hostname: str
    ):
        """Get auth configuration for a proxy target."""
        # Get async async_storage if available
        async_storage = req.app.state.async_storage if hasattr(req.app.state, 'async_storage') else None
        
        target = await async_storage.get_proxy_target(hostname)
        if not target:
            raise HTTPException(404, f"Proxy target {hostname} not found")
        
        # Return auth configuration
        return {
            "auth_enabled": target.auth_enabled,
            "auth_proxy": target.auth_proxy,
            "auth_mode": target.auth_mode,
            "auth_required_users": target.auth_required_users,
            "auth_required_emails": target.auth_required_emails,
            "auth_required_groups": target.auth_required_groups,
            "auth_allowed_scopes": target.auth_allowed_scopes,
            "auth_allowed_audiences": target.auth_allowed_audiences,
            "auth_pass_headers": target.auth_pass_headers,
            "auth_cookie_name": target.auth_cookie_name,
            "auth_header_prefix": target.auth_header_prefix,
            "auth_excluded_paths": target.auth_excluded_paths
        }
    
    return router
