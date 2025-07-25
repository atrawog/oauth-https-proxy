"""Route management API endpoints."""

import logging
import uuid
from typing import Optional, Tuple
from fastapi import APIRouter, HTTPException, Depends, Query

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
        
        # Store in Redis - storage layer will check for duplicates
        if not storage.store_route(route):
            # Storage rejected due to duplicate path+priority
            raise HTTPException(
                409, 
                f"A route already exists with path '{request.path_pattern}' and priority {request.priority}. "
                f"Each path+priority combination must be unique."
            )
        
        logger.info(
            f"Created new route: id={route_id}, path={request.path_pattern}, "
            f"target={request.target_type}:{request.target_value}, priority={request.priority}"
        )
        
        return route
    
    @router.get("/")
    async def list_routes():
        """List all routing rules sorted by priority."""
        routes = storage.list_routes()
        return routes
    
    @router.get("/formatted")
    async def list_routes_formatted(
        format: str = Query("table", description="Output format", enum=["table", "json", "csv"])
    ):
        """List all routing rules with formatted output."""
        from fastapi.responses import PlainTextResponse
        import csv
        import io
        from tabulate import tabulate
        
        # Get routes using existing endpoint logic
        routes = await list_routes()
        
        if format == "json":
            # Return standard JSON response
            return routes
        
        # Prepare data for table/csv formatting
        rows = []
        for route in routes:
            # Format methods
            methods = ", ".join(route.methods) if route.methods else "ALL"
            
            # Format target
            target = f"{route.target_type}:{route.target_value}"
            
            # Status
            status = "enabled" if route.enabled else "disabled"
            
            rows.append([
                route.route_id,
                route.path_pattern,
                target,
                str(route.priority),
                methods,
                "regex" if route.is_regex else "prefix",
                status,
                route.description or ""
            ])
        
        if format == "csv":
            output = io.StringIO()
            writer = csv.writer(output)
            writer.writerow(["ID", "Path", "Target", "Priority", "Methods", "Type", "Status", "Description"])
            writer.writerows(rows)
            return PlainTextResponse(output.getvalue(), media_type="text/csv")
        
        # Default to table format
        headers = ["ID", "Path", "Target", "Priority", "Methods", "Type", "Status", "Description"]
        table = tabulate(rows, headers=headers, tablefmt="grid")
        return PlainTextResponse(table, media_type="text/plain")
    
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