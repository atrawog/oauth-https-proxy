"""Proxy route management with async support.

This module handles route configuration for proxy targets.
"""

import logging
from typing import List
from fastapi import APIRouter, HTTPException, Depends, Request

from src.auth import AuthDep, AuthResult
from src.proxy.models import ProxyRoutesConfig, ProxyTargetUpdate

logger = logging.getLogger(__name__)


def create_routes_router(async_storage):
    """Create router for proxy route management.
    
    All endpoints use async patterns with Request parameter.
    
    Args:
        async_storage: Redis async_storage instance (legacy)
    
    Returns:
        APIRouter with proxy route endpoints
    """
    router = APIRouter()
    
    @router.get("/{proxy_hostname}/routes")
    async def get_proxy_routes(
        req: Request,
        proxy_hostname: str
    ):
        """Get route configuration for a proxy target."""
        # Get async async_storage if available
        async_storage = req.app.state.async_storage if hasattr(req.app.state, 'async_storage') else None
        
        target = await async_storage.get_proxy_target(proxy_hostname)
        if not target:
            raise HTTPException(404, f"Proxy target {proxy_hostname} not found")
        
        # Get all routes and filter applicable ones
        all_routes = await async_storage.list_routes()
        # Determine applicable routes based on route_mode
        if target.route_mode == "none":
            applicable_routes = []
        elif target.route_mode == "selective":
            applicable_routes = [r for r in all_routes if r.route_id in target.enabled_routes]
        else:  # route_mode == "all"
            applicable_routes = [r for r in all_routes if r.route_id not in target.disabled_routes]
        
        return {
            "route_mode": target.route_mode,
            "enabled_routes": target.enabled_routes,
            "disabled_routes": target.disabled_routes,
            "applicable_routes": applicable_routes
        }
    
    
    @router.put("/{proxy_hostname}/routes")
    async def update_proxy_routes(
        req: Request,
        proxy_hostname: str,
        config: ProxyRoutesConfig,
        auth: AuthResult = Depends(AuthDep(auth_type="bearer", check_owner=True, owner_param="proxy_hostname"))
    ):
        """Update route settings for a proxy target - owner only."""
        # Get async async_storage if available
        async_storage = req.app.state.async_storage if hasattr(req.app.state, 'async_storage') else None
        
        target = await async_storage.get_proxy_target(proxy_hostname)
        if not target:
            raise HTTPException(404, f"Proxy target {proxy_hostname} not found")
        
        # Update proxy target
        updates = ProxyTargetUpdate(
            route_mode=config.route_mode,
            enabled_routes=config.enabled_routes,
            disabled_routes=config.disabled_routes
        )
        
        success = await async_storage.update_proxy_target(proxy_hostname, updates)
        if not success:
            raise HTTPException(500, "Failed to update proxy routes")
        
        # Get updated target
        # Get async async_storage if available
        async_storage = req.app.state.async_storage if hasattr(req.app.state, 'async_storage') else None
        
        target = await async_storage.get_proxy_target(proxy_hostname)
        logger.info(f"Routes updated for proxy {proxy_hostname}: mode={config.route_mode}")
        
        return {"status": "Routes configured", "proxy_target": target}
    
    
    @router.post("/{proxy_hostname}/routes/{route_id}/enable")
    async def enable_proxy_route(
        req: Request,
        proxy_hostname: str,
        route_id: str,
        auth: AuthResult = Depends(AuthDep(auth_type="bearer", check_owner=True, owner_param="proxy_hostname"))
    ):
        """Enable a specific route for a proxy target - owner only."""
        # Get async async_storage if available
        async_storage = req.app.state.async_storage if hasattr(req.app.state, 'async_storage') else None
        
        target = await async_storage.get_proxy_target(proxy_hostname)
        if not target:
            raise HTTPException(404, f"Proxy target {proxy_hostname} not found")
        
        # Verify route exists
        route = await async_storage.get_route(route_id)
        if not route:
            raise HTTPException(404, f"Route {route_id} not found")
        
        # Update based on route_mode
        updates = ProxyTargetUpdate()
        
        if target.route_mode == "selective":
            # Add to enabled_routes
            if route_id not in target.enabled_routes:
                enabled_routes = target.enabled_routes.copy()
                enabled_routes.append(route_id)
                updates.enabled_routes = enabled_routes
        elif target.route_mode == "all":
            # Remove from disabled_routes
            if route_id in target.disabled_routes:
                disabled_routes = target.disabled_routes.copy()
                disabled_routes.remove(route_id)
                updates.disabled_routes = disabled_routes
        else:
            raise HTTPException(400, "Cannot enable routes when route_mode is 'none'")
        
        success = await async_storage.update_proxy_target(proxy_hostname, updates)
        if not success:
            raise HTTPException(500, "Failed to enable route")
        
        logger.info(f"Route {route_id} enabled for proxy {proxy_hostname}")
        
        return {"status": "Route enabled", "route_id": route_id}
    
    
    @router.post("/{proxy_hostname}/routes/{route_id}/disable")
    async def disable_proxy_route(
        req: Request,
        proxy_hostname: str,
        route_id: str,
        auth: AuthResult = Depends(AuthDep(auth_type="bearer", check_owner=True, owner_param="proxy_hostname"))
    ):
        """Disable a specific route for a proxy target - owner only."""
        # Get async async_storage if available
        async_storage = req.app.state.async_storage if hasattr(req.app.state, 'async_storage') else None
        
        target = await async_storage.get_proxy_target(proxy_hostname)
        if not target:
            raise HTTPException(404, f"Proxy target {proxy_hostname} not found")
        
        # Verify route exists
        route = await async_storage.get_route(route_id)
        if not route:
            raise HTTPException(404, f"Route {route_id} not found")
        
        # Update based on route_mode
        updates = ProxyTargetUpdate()
        
        if target.route_mode == "selective":
            # Remove from enabled_routes
            if route_id in target.enabled_routes:
                enabled_routes = target.enabled_routes.copy()
                enabled_routes.remove(route_id)
                updates.enabled_routes = enabled_routes
        elif target.route_mode == "all":
            # Add to disabled_routes
            if route_id not in target.disabled_routes:
                disabled_routes = target.disabled_routes.copy()
                disabled_routes.append(route_id)
                updates.disabled_routes = disabled_routes
        else:
            raise HTTPException(400, "Cannot disable routes when route_mode is 'none'")
        
        success = await async_storage.update_proxy_target(proxy_hostname, updates)
        if not success:
            raise HTTPException(500, "Failed to disable route")
        
        logger.info(f"Route {route_id} disabled for proxy {proxy_hostname}")
        
        return {"status": "Route disabled", "route_id": route_id}
    
    return router
