"""Route management API endpoints."""

import logging
import uuid
from typing import Optional, Tuple
from fastapi import APIRouter, HTTPException, Depends

from ..auth import get_current_token_info, require_route_owner
from ...proxy.routes import Route, RouteCreateRequest, RouteUpdateRequest

logger = logging.getLogger(__name__)


def create_router(storage):
    """Create routes endpoints router."""
    router = APIRouter(prefix="/routes", tags=["routes"])
    
    @router.post("/")
    async def create_route(
        request: RouteCreateRequest,
        token_info: Tuple[str, Optional[str], Optional[str]] = Depends(get_current_token_info)
    ):
        """Create a new routing rule."""
        token_hash, token_name, _ = token_info
        
        # Generate unique route ID
        route_id = f"{request.path_pattern.replace('/', '-').strip('-')}-{uuid.uuid4().hex[:8]}"
        
        # Create route
        route = Route(
            route_id=route_id,
            path_pattern=request.path_pattern,
            target_type=request.target_type,
            target_value=request.target_value,
            priority=request.priority,
            methods=request.methods,
            is_regex=request.is_regex,
            description=request.description,
            enabled=request.enabled,
            owner_token_hash=token_hash,
            created_by=token_name
        )
        
        # Store in Redis
        if not storage.store_route(route):
            raise HTTPException(500, "Failed to store route")
        
        return route
    
    @router.get("/")
    async def list_routes():
        """List all routing rules sorted by priority."""
        routes = storage.list_routes()
        return routes
    
    @router.get("/{route_id}")
    async def get_route(route_id: str):
        """Get specific route details."""
        route = storage.get_route(route_id)
        if not route:
            raise HTTPException(404, f"Route {route_id} not found")
        return route
    
    @router.put("/{route_id}")
    async def update_route(
        route_id: str,
        request: RouteUpdateRequest,
        _=Depends(require_route_owner)
    ):
        """Update an existing route."""
        # Get existing route
        route = storage.get_route(route_id)
        if not route:
            raise HTTPException(404, f"Route {route_id} not found")
        
        # Update fields
        update_data = request.dict(exclude_unset=True)
        for field, value in update_data.items():
            setattr(route, field, value)
        
        # Re-validate if pattern changed
        if request.path_pattern is not None or request.is_regex is not None:
            try:
                # This will trigger validation
                route = Route(**route.dict())
            except Exception as e:
                raise HTTPException(400, f"Invalid route configuration: {e}")
        
        # Update priority index if priority changed
        if request.priority is not None:
            # Delete old priority index
            storage.delete_route(route_id)
        
        # Store updated route
        if not storage.store_route(route):
            raise HTTPException(500, "Failed to update route")
        
        return route
    
    @router.delete("/{route_id}")
    async def delete_route(
        route_id: str,
        _=Depends(require_route_owner)
    ):
        """Delete a route."""
        route = storage.get_route(route_id)
        if not route:
            raise HTTPException(404, f"Route {route_id} not found")
        
        if not storage.delete_route(route_id):
            raise HTTPException(500, "Failed to delete route")
        
        return {"message": f"Route {route_id} deleted successfully"}
    
    return router