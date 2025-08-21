"""Route management MCP tools."""

from typing import Any, Dict, List, Optional
from datetime import datetime, timezone
import logging
import uuid

from .base import BaseMCPTools

logger = logging.getLogger(__name__)


class RouteTools(BaseMCPTools):
    """MCP tools for route management."""
    
    def register_tools(self):
        """Register all route management tools."""
        
        # Note: route_list is already defined in mcp_server.py
        
        @self.mcp.tool(
            annotations={
                "title": "Create Route",
                "readOnlyHint": False,
                "destructiveHint": False,
                "idempotentHint": False,
                "openWorldHint": False
            }
        )
        async def route_create(
            path: str,
            target_type: str,
            target_value: str,
            token: str,
            priority: int = 50,
            methods: str = "ALL",
            is_regex: bool = False,
            description: Optional[str] = None
        ) -> Dict[str, Any]:
            """Create a routing rule.
            
            Args:
                path: Path pattern for the route
                target_type: Type of target (proxy, service, redirect, etc.)
                target_value: Target value (hostname, service name, URL)
                token: API token for authentication
                priority: Route priority (lower = higher priority)
                methods: HTTP methods (comma-separated or ALL)
                is_regex: Whether path is a regex pattern
                description: Optional route description
                
            Returns:
                Dictionary with route creation status
            """
            session_id = self.get_session_context()
            
            async with self.logger.trace_context(
                "mcp_tool_route_create",
                session_id=session_id,
                path=path
            ):
                # Validate token
                token_info = await self.validate_token(token)
                user = token_info.get("name", "unknown")
                
                # Generate route ID
                route_id = f"route_{uuid.uuid4().hex[:8]}"
                
                # Parse methods
                method_list = ["*"] if methods.upper() == "ALL" else [m.strip().upper() for m in methods.split(",")]
                
                # Create route configuration
                route_config = {
                    "route_id": route_id,
                    "path_pattern": path,
                    "target_type": target_type,
                    "target_value": target_value,
                    "priority": priority,
                    "methods": method_list,
                    "is_regex": is_regex,
                    "description": description or "",
                    "enabled": True,
                    "owner_token": token_info["name"],
                    "created_at": datetime.now(timezone.utc).isoformat()
                }
                
                # Store route
                await self.storage.store_route(route_id, route_config)
                
                # Log audit event
                await self.log_audit_event(
                    action="route_create",
                    session_id=session_id,
                    user=user,
                    details={"route_id": route_id, "path": path, "target": target_value}
                )
                
                return {
                    "status": "created",
                    "route_id": route_id,
                    "path": path,
                    "target_type": target_type,
                    "target_value": target_value,
                    "message": f"Route '{route_id}' created successfully"
                }
        
        @self.mcp.tool(
            annotations={
                "title": "Create Global Route",
                "readOnlyHint": False,
                "destructiveHint": False,
                "idempotentHint": False,
                "openWorldHint": False
            }
        )
        async def route_create_global(
            path: str,
            target_type: str,
            target_value: str,
            admin_token: str,
            priority: int = 50,
            methods: str = "*",
            is_regex: bool = False,
            description: Optional[str] = None
        ) -> Dict[str, Any]:
            """Create a global routing rule that applies to all proxies.
            
            Args:
                path: Path pattern for the route
                target_type: Type of target (proxy, service, redirect, etc.)
                target_value: Target value (hostname, service name, URL)
                admin_token: Admin token for authentication (required)
                priority: Route priority (lower = higher priority)
                methods: HTTP methods (comma-separated or *)
                is_regex: Whether path is a regex pattern
                description: Optional route description
                
            Returns:
                Dictionary with route creation status
            """
            session_id = self.get_session_context()
            
            async with self.logger.trace_context(
                "mcp_tool_route_create_global",
                session_id=session_id,
                path=path
            ):
                # Validate admin token
                token_info = await self.validate_token(admin_token, require_admin=True)
                user = token_info.get("name", "unknown")
                
                # Generate route ID
                route_id = f"global_route_{uuid.uuid4().hex[:8]}"
                
                # Parse methods
                method_list = ["*"] if methods == "*" else [m.strip().upper() for m in methods.split(",")]
                
                # Create route configuration
                route_config = {
                    "route_id": route_id,
                    "path_pattern": path,
                    "target_type": target_type,
                    "target_value": target_value,
                    "priority": priority,
                    "methods": method_list,
                    "is_regex": is_regex,
                    "scope": "global",
                    "description": description or "",
                    "enabled": True,
                    "owner_token": "admin",
                    "created_at": datetime.now(timezone.utc).isoformat()
                }
                
                # Store route
                await self.storage.store_route(route_id, route_config)
                
                # Log audit event
                await self.log_audit_event(
                    action="route_create_global",
                    session_id=session_id,
                    user=user,
                    details={"route_id": route_id, "path": path, "target": target_value}
                )
                
                return {
                    "status": "created",
                    "route_id": route_id,
                    "scope": "global",
                    "path": path,
                    "target_type": target_type,
                    "target_value": target_value,
                    "message": f"Global route '{route_id}' created successfully"
                }
        
        @self.mcp.tool(
            annotations={
                "title": "Show Route Details",
                "readOnlyHint": True,
                "destructiveHint": False,
                "idempotentHint": True,
                "openWorldHint": False
            }
        )
        async def route_show(
            route_id: str,
            token: Optional[str] = None
        ) -> Dict[str, Any]:
            """Show detailed route information.
            
            Args:
                route_id: Route identifier
                token: Optional API token for ownership check
                
            Returns:
                Dictionary with route details
            """
            session_id = self.get_session_context()
            
            async with self.logger.trace_context(
                "mcp_tool_route_show",
                session_id=session_id,
                route_id=route_id
            ):
                # Get route
                route = await self.storage.get_route(route_id)
                if not route:
                    raise ValueError(f"Route '{route_id}' not found")
                
                # Check ownership if token provided
                user = "anonymous"
                if token:
                    token_info = await self.validate_token(token)
                    user = token_info.get("name", "unknown")
                    
                    owner_token = getattr(route, 'owner_token', None) if hasattr(route, 'owner_token') else route.get('owner_token') if isinstance(route, dict) else None
                    if owner_token != token_info["name"] and token_info["name"].upper() != "ADMIN":
                        raise PermissionError("You can only view routes you own")
                
                # Log audit event
                await self.log_audit_event(
                    action="route_show",
                    session_id=session_id,
                    user=user,
                    details={"route_id": route_id}
                )
                
                # Return route as dictionary
                if isinstance(route, dict):
                    return route
                else:
                    # Convert Pydantic model to dict
                    return {
                        "route_id": getattr(route, 'route_id', ""),
                        "path_pattern": getattr(route, 'path_pattern', ""),
                        "target_type": getattr(route, 'target_type', ""),
                        "target_value": getattr(route, 'target_value', ""),
                        "priority": getattr(route, 'priority', 50),
                        "methods": getattr(route, 'methods', ["*"]),
                        "is_regex": getattr(route, 'is_regex', False),
                        "scope": getattr(route, 'scope', "proxy"),
                        "description": getattr(route, 'description', ""),
                        "enabled": getattr(route, 'enabled', True),
                        "owner_token": getattr(route, 'owner_token', ""),
                        "created_at": getattr(route, 'created_at', "")
                    }
        
        @self.mcp.tool(
            annotations={
                "title": "Delete Route",
                "readOnlyHint": False,
                "destructiveHint": True,
                "idempotentHint": True,
                "openWorldHint": False
            }
        )
        async def route_delete(
            route_id: str,
            token: str
        ) -> Dict[str, Any]:
            """Delete a routing rule.
            
            Args:
                route_id: Route identifier
                token: API token for authentication
                
            Returns:
                Dictionary with deletion status
            """
            session_id = self.get_session_context()
            
            async with self.logger.trace_context(
                "mcp_tool_route_delete",
                session_id=session_id,
                route_id=route_id
            ):
                # Validate token
                token_info = await self.validate_token(token)
                user = token_info.get("name", "unknown")
                
                # Get route
                route = await self.storage.get_route(route_id)
                if not route:
                    raise ValueError(f"Route '{route_id}' not found")
                
                # Check ownership
                owner_token = getattr(route, 'owner_token', '') if hasattr(route, 'owner_token') else route.get('owner_token', '') if isinstance(route, dict) else ''
                await self.check_ownership(token_info, owner_token, "route")
                
                # Delete route
                await self.storage.delete_route(route_id)
                
                # Log audit event
                await self.log_audit_event(
                    action="route_delete",
                    session_id=session_id,
                    user=user,
                    details={"route_id": route_id}
                )
                
                return {
                    "status": "deleted",
                    "route_id": route_id,
                    "message": f"Route '{route_id}' deleted successfully"
                }
        
        @self.mcp.tool(
            annotations={
                "title": "List Routes by Scope",
                "readOnlyHint": True,
                "destructiveHint": False,
                "idempotentHint": True,
                "openWorldHint": False
            }
        )
        async def route_list_by_scope(
            scope: str = "all",
            token: Optional[str] = None
        ) -> Dict[str, Any]:
            """List routes filtered by scope.
            
            Args:
                scope: Route scope (all, global, proxy, or specific proxy hostname)
                token: Optional API token for filtering
                
            Returns:
                Dictionary with filtered route list
            """
            session_id = self.get_session_context()
            
            async with self.logger.trace_context(
                "mcp_tool_route_list_by_scope",
                session_id=session_id,
                scope=scope
            ):
                user = "anonymous"
                filter_owner = None
                
                if token:
                    token_info = await self.validate_token(token)
                    user = token_info.get("name", "unknown")
                    # Non-admin users only see their own routes
                    if token_info["name"].upper() != "ADMIN":
                        filter_owner = token_info["name"]
                
                # Get all routes
                routes = await self.storage.list_routes()
                
                # Filter by scope
                filtered_routes = []
                for route in routes:
                    # Filter by owner if needed
                    owner_token = getattr(route, 'owner_token', None) if hasattr(route, 'owner_token') else route.get('owner_token') if isinstance(route, dict) else None
                    if filter_owner and owner_token != filter_owner:
                        continue
                    
                    # Get scope value
                    route_scope = getattr(route, 'scope', None) if hasattr(route, 'scope') else route.get('scope') if isinstance(route, dict) else None
                    
                    # Filter by scope
                    if scope == "all":
                        filtered_routes.append(route)
                    elif scope == "global" and route_scope == "global":
                        filtered_routes.append(route)
                    elif scope == "proxy" and route_scope != "global":
                        filtered_routes.append(route)
                    elif scope not in ["all", "global", "proxy"]:
                        # Specific proxy hostname
                        proxy_hostname = getattr(route, 'proxy_hostname', None) if hasattr(route, 'proxy_hostname') else route.get('proxy_hostname') if isinstance(route, dict) else None
                        if proxy_hostname == scope:
                            filtered_routes.append(route)
                
                # Format response
                route_list = []
                for r in filtered_routes:
                    # Handle both dict and object
                    if isinstance(r, dict):
                        route_list.append({
                            "route_id": r.get("route_id", ""),
                            "path_pattern": r.get("path_pattern", ""),
                            "target_type": r.get("target_type", ""),
                            "target_value": r.get("target_value", ""),
                            "priority": r.get("priority", 50),
                            "scope": r.get("scope", "proxy"),
                            "enabled": r.get("enabled", True)
                        })
                    else:
                        # Handle Pydantic model
                        route_list.append({
                            "route_id": getattr(r, 'route_id', ""),
                            "path_pattern": getattr(r, 'path_pattern', ""),
                            "target_type": getattr(r, 'target_type', ""),
                            "target_value": getattr(r, 'target_value', ""),
                            "priority": getattr(r, 'priority', 50),
                            "scope": getattr(r, 'scope', "proxy"),
                            "enabled": getattr(r, 'enabled', True)
                        })
                
                # Log audit event
                await self.log_audit_event(
                    action="route_list_by_scope",
                    session_id=session_id,
                    user=user,
                    details={"scope": scope, "count": len(route_list)}
                )
                
                return {
                    "routes": route_list,
                    "count": len(route_list),
                    "scope": scope
                }