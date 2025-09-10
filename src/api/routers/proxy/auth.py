"""Proxy authentication configuration with async support.

This module handles OAuth authentication configuration for proxy targets.
"""

import logging
from typing import Optional
from fastapi import APIRouter, HTTPException, Depends, Request

# Authentication is handled by proxy, API trusts headers
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
    
    @router.post("/{proxy_hostname}/auth")
    async def configure_proxy_auth(
        req: Request,
        proxy_hostname: str,
        config: ProxyAuthConfig,
    ):
        """Configure unified auth for a proxy target."""
        # Get auth info from headers (set by proxy)
        auth_user = req.headers.get("X-Auth-User", "system")
        auth_scopes = req.headers.get("X-Auth-Scopes", "").split()
        is_admin = "admin" in auth_scopes
        
        # Check permissions - admin scope required for mutations
        if not is_admin:
            raise HTTPException(403, "Admin scope required")
        # Get async async_storage if available
        async_storage = req.app.state.async_storage if hasattr(req.app.state, 'async_storage') else None
        
        target = await async_storage.get_proxy_target(proxy_hostname)
        if not target:
            raise HTTPException(404, f"Proxy target {proxy_hostname} not found")
        
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
        success = await async_storage.store_proxy_target(proxy_hostname, target)
        if not success:
            raise HTTPException(500, "Failed to update proxy target")
        
        # Publish proxy_updated event for OAuth configuration change
        try:
            from src.storage.redis_stream_publisher import RedisStreamPublisher
            from src.shared.logger import log_info, log_warning, log_error
            import os
            
            redis_url = os.getenv('REDIS_URL', 'redis://:test@redis:6379/0')
            publisher = RedisStreamPublisher(redis_url=redis_url)
            
            # OAuth changes don't require instance recreation - config reloads automatically
            changes = {"oauth": True, "ssl": False, "ports": False, "config": True}
            event_id = await publisher.publish_proxy_updated(proxy_hostname, changes)
            
            if event_id:
                log_info(f"✅ Published proxy_updated event {event_id} for OAuth config change", 
                        component="proxy_api", 
                        proxy_hostname=proxy_hostname)
            else:
                log_warning(f"Failed to publish proxy_updated event for OAuth config", 
                           component="proxy_api", 
                           proxy_hostname=proxy_hostname)
                
            await publisher.close()
        except Exception as e:
            logger.error(f"Failed to publish proxy_updated event: {e}", exc_info=True)
        
        # When enabling auth, create a route for OAuth metadata endpoint
        if config.enabled and config.auth_proxy:
            # Create a route to forward OAuth metadata requests to the auth instance
            from src.proxy.routes import Route, RouteTargetType
            
            route_id = f"oauth-metadata-{proxy_hostname.replace('.', '-')}"
            oauth_route = Route(
                route_id=route_id,
                path_pattern="/.well-known/oauth-authorization-server",
                target_type=RouteTargetType.URL,
                target_value="http://api:9000",  # Use URL type with correct target
                priority=90,  # High priority but below system routes
                enabled=True,
                description=f"OAuth metadata for {proxy_hostname}",
                owner_token_hash=None  # ProxyTarget doesn't have owner_token_hash
            )
            
            # Store the route
            await async_storage.store_route(oauth_route)
            logger.info(f"Created OAuth metadata route {route_id} for {proxy_hostname}")
            
            # Add to proxy's enabled routes if using selective mode
            if target.route_mode == "selective":
                if route_id not in target.enabled_routes:
                    target.enabled_routes.append(route_id)
                    await async_storage.store_proxy_target(proxy_hostname, target)
                    logger.info(f"Added route {route_id} to enabled routes for {proxy_hostname}")
        
        logger.info(f"Auth configured for proxy {proxy_hostname}: enabled={config.enabled}")
        
        # No need to clear cache or recreate instances - proxy reads fresh from Redis on each request
        # The proxy handler's get_proxy_target() call will get the updated auth config immediately
        
        return {"status": "Auth configured", "proxy_target": target}
    
    
    @router.delete("/{proxy_hostname}/auth")
    async def remove_proxy_auth(
        req: Request,
        proxy_hostname: str,
    ):
        """Disable auth protection for a proxy target."""
        # Get auth info from headers (set by proxy)
        auth_user = req.headers.get("X-Auth-User", "system")
        auth_scopes = req.headers.get("X-Auth-Scopes", "").split()
        is_admin = "admin" in auth_scopes
        
        # Check permissions - admin scope required for mutations
        if not is_admin:
            raise HTTPException(403, "Admin scope required")
        # Get async async_storage if available
        async_storage = req.app.state.async_storage if hasattr(req.app.state, 'async_storage') else None
        
        target = await async_storage.get_proxy_target(proxy_hostname)
        if not target:
            raise HTTPException(404, f"Proxy target {proxy_hostname} not found")
        
        # Disable auth
        target.auth_enabled = False
        target.auth_proxy = None
        target.auth_required_users = None
        target.auth_required_emails = None
        target.auth_required_groups = None
        
        # Store updated target
        success = await async_storage.store_proxy_target(proxy_hostname, target)
        if not success:
            raise HTTPException(500, "Failed to update proxy target")
        
        # Publish proxy_updated event for OAuth removal
        try:
            from src.storage.redis_stream_publisher import RedisStreamPublisher
            from src.shared.logger import log_info, log_warning
            import os
            
            redis_url = os.getenv('REDIS_URL', 'redis://:test@redis:6379/0')
            publisher = RedisStreamPublisher(redis_url=redis_url)
            
            # OAuth changes don't require instance recreation - config reloads automatically
            changes = {"oauth": True, "ssl": False, "ports": False, "config": True}
            event_id = await publisher.publish_proxy_updated(proxy_hostname, changes)
            
            if event_id:
                log_info(f"✅ Published proxy_updated event {event_id} for OAuth removal", 
                        component="proxy_api", 
                        proxy_hostname=proxy_hostname)
            else:
                log_warning(f"Failed to publish proxy_updated event for OAuth removal", 
                           component="proxy_api", 
                           proxy_hostname=proxy_hostname)
                
            await publisher.close()
        except Exception as e:
            logger.error(f"Failed to publish proxy_updated event: {e}", exc_info=True)
        
        # Remove OAuth metadata route when disabling auth
        route_id = f"oauth-metadata-{proxy_hostname.replace('.', '-')}"
        route = await async_storage.get_route(route_id)
        if route:
            await async_storage.delete_route(route_id)
        logger.info(f"Auth disabled for proxy {proxy_hostname}")
        
        # No need to clear cache or recreate instances - proxy reads fresh from Redis on each request
        # The proxy handler's get_proxy_target() call will get the updated auth config immediately
        
        return {"status": "Auth protection removed", "proxy_target": target}
    
    
    @router.get("/{proxy_hostname}/auth")
    async def get_proxy_auth_config(
        req: Request,
        proxy_hostname: str
    ):
        """Get auth configuration for a proxy target."""
        # Get async async_storage if available
        async_storage = req.app.state.async_storage if hasattr(req.app.state, 'async_storage') else None
        
        target = await async_storage.get_proxy_target(proxy_hostname)
        if not target:
            raise HTTPException(404, f"Proxy target {proxy_hostname} not found")
        
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
