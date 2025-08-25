"""Route management API endpoints."""

import logging
import uuid
from typing import Optional, Tuple
from fastapi import APIRouter, HTTPException, Depends, Query, Request

# Authentication is handled by proxy, API trusts headers
from src.proxy.routes import Route, RouteCreateRequest, RouteUpdateRequest

logger = logging.getLogger(__name__)


def create_router(async_storage):
    """Create routes endpoints router."""
    router = APIRouter(tags=["routes"])
    
    @router.post("/")
    async def create_route(
        request: Request,
        route_request: RouteCreateRequest
    ):
        """Create a new routing rule."""
        # Get auth info from headers (set by proxy)
        auth_user = request.headers.get("X-Auth-User")
        if not auth_user:
            raise HTTPException(401, "Authentication required")
        auth_scopes = request.headers.get("X-Auth-Scopes", "").split()
        is_admin = "admin" in auth_scopes
        
        # Check permissions - admin scope required for mutations
        if not is_admin:
            raise HTTPException(403, "Admin scope required")
        async_storage = request.app.state.async_storage
        
        # Generate unique route ID
        route_id = f"{route_request.path_pattern.replace('/', '-').strip('-')}-{uuid.uuid4().hex[:8]}"
        
        # Create route
        route = Route(
            route_id=route_id,
            path_pattern=route_request.path_pattern,
            target_type=route_request.target_type,
            target_value=route_request.target_value,
            priority=route_request.priority,
            methods=route_request.methods,
            is_regex=route_request.is_regex,
            description=route_request.description,
            enabled=route_request.enabled,
            scope=route_request.scope,
            proxy_hostnames=route_request.proxy_hostnames,
            owner_token_hash=None,  # No token ownership
            created_by=auth_user
        )
        
        # Store in Redis - storage layer will check for duplicates
        if not await async_storage.store_route(route):
            # Storage rejected due to duplicate path+priority
            raise HTTPException(
                409, 
                f"A route already exists with path '{route_request.path_pattern}' and priority {route_request.priority}. "
                f"Each path+priority combination must be unique."
            )
        
        logger.info(
            f"Created new route: id={route_id}, path={route_request.path_pattern}, "
            f"target={route_request.target_type}:{route_request.target_value}, priority={route_request.priority}"
        )
        
        return route
    
    @router.get("/")
    async def list_routes(request: Request):
        """List all routing rules sorted by priority."""
        async_storage = request.app.state.async_storage
        routes = await async_storage.list_routes()
        return routes
    
    @router.get("/formatted")
    async def list_routes_formatted(
        request: Request,
        format: str = Query("table", description="Output format", enum=["table", "json", "csv"])
    ):
        """List all routing rules with formatted output."""
        from fastapi.responses import PlainTextResponse
        import csv
        import io
        from tabulate import tabulate
        
        # Get routes using existing endpoint logic
        routes = await list_routes(request)
        
        if format == "json":
            # Return standard JSON response
            return routes
        
        # Prepare data for table/csv formatting
        rows = []
        for route in routes:
            # Format methods
            methods = ", ".join(route.methods) if route.methods else "ALL"
            
            # Format target
            target = f"{route.target_type.value if hasattr(route.target_type, 'value') else route.target_type}:{route.target_value}"
            
            # Status
            status = "enabled" if route.enabled else "disabled"
            
            # Format scope
            scope_value = route.scope.value if hasattr(route.scope, 'value') else route.scope
            scope_info = scope_value
            if scope_value == "proxy" and route.proxy_hostnames:
                # Show all proxies if 3 or fewer, otherwise show count
                if len(route.proxy_hostnames) <= 3:
                    scope_info = f"proxy: {', '.join(route.proxy_hostnames)}"
                else:
                    scope_info = f"proxy: {route.proxy_hostnames[0]} (+{len(route.proxy_hostnames)-1} more)"
            
            rows.append([
                route.route_id,
                route.path_pattern,
                target,
                str(route.priority),
                methods,
                "regex" if route.is_regex else "prefix",
                status,
                scope_info,
                route.description or ""
            ])
        
        if format == "csv":
            output = io.StringIO()
            writer = csv.writer(output)
            writer.writerow(["ID", "Path", "Target", "Priority", "Methods", "Type", "Status", "Scope", "Description"])
            writer.writerows(rows)
            return PlainTextResponse(output.getvalue(), media_type="text/csv")
        
        # Default to table format
        headers = ["ID", "Path", "Target", "Priority", "Methods", "Type", "Status", "Scope", "Description"]
        table = tabulate(rows, headers=headers, tablefmt="grid")
        return PlainTextResponse(table, media_type="text/plain")
    
    @router.get("/{route_id}")
    async def get_route(
        request: Request,
        route_id: str
    ):
        """Get specific route details."""
        async_storage = request.app.state.async_storage
        route = await async_storage.get_route(route_id)
        if not route:
            raise HTTPException(404, f"Route {route_id} not found")
        return route
    
    @router.put("/{route_id}")
    async def update_route(
        request: Request,
        route_id: str,
        route_request: RouteUpdateRequest
    ):
        """Update an existing route."""
        # Get auth info from headers (set by proxy)
        auth_user = request.headers.get("X-Auth-User")
        if not auth_user:
            raise HTTPException(401, "Authentication required")
        auth_scopes = request.headers.get("X-Auth-Scopes", "").split()
        is_admin = "admin" in auth_scopes
        
        # Check permissions - admin scope required for mutations
        if not is_admin:
            raise HTTPException(403, "Admin scope required")
        async_storage = request.app.state.async_storage
        
        # Get existing route
        route = await async_storage.get_route(route_id)
        if not route:
            raise HTTPException(404, f"Route {route_id} not found")
        
        # Update fields
        update_data = route_request.dict(exclude_unset=True)
        for field, value in update_data.items():
            setattr(route, field, value)
        
        # Re-validate if pattern changed
        if route_request.path_pattern is not None or route_request.is_regex is not None:
            try:
                # This will trigger validation
                route = Route(**route.dict())
            except Exception as e:
                raise HTTPException(400, f"Invalid route configuration: {e}")
        
        # Update priority index if priority changed
        if route_request.priority is not None:
            # Delete old priority index
            await async_storage.delete_route(route_id)
        
        # Store updated route
        if not await async_storage.store_route(route):
            raise HTTPException(500, "Failed to update route")
        
        return route
    
    @router.delete("/{route_id}")
    async def delete_route(
        request: Request,
        route_id: str
    ):
        """Delete a route."""
        # Get auth info from headers (set by proxy)
        auth_user = request.headers.get("X-Auth-User")
        if not auth_user:
            raise HTTPException(401, "Authentication required")
        auth_scopes = request.headers.get("X-Auth-Scopes", "").split()
        is_admin = "admin" in auth_scopes
        
        # Check permissions - admin scope required for mutations
        if not is_admin:
            raise HTTPException(403, "Admin scope required")
        async_storage = request.app.state.async_storage
        
        route = await async_storage.get_route(route_id)
        if not route:
            raise HTTPException(404, f"Route {route_id} not found")
        
        if not await async_storage.delete_route(route_id):
            raise HTTPException(500, "Failed to delete route")
        
        return {"message": f"Route {route_id} deleted successfully"}
    
    return router