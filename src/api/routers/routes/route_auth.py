"""Route authentication configuration management API.

This module provides API endpoints for managing authentication
configurations for routes using the flexible auth system.
"""

import logging
import json
from typing import Optional, Dict, Any

from fastapi import APIRouter, HTTPException, Depends, Request
from pydantic import BaseModel, Field

from src.auth import RouteAuthConfig, AuthDep
from src.storage.async_redis_storage import AsyncRedisStorage

logger = logging.getLogger(__name__)


class RouteAuthConfigRequest(BaseModel):
    """Request model for setting route authentication configuration."""
    
    auth_type: str = Field(
        ...,
        description="Authentication type: none, bearer, admin, or oauth"
    )
    override_proxy_auth: bool = Field(
        default=False,
        description="Whether this route auth overrides proxy auth"
    )
    
    # OAuth-specific settings
    oauth_scopes: Optional[list] = Field(
        default=None,
        description="Required OAuth scopes"
    )
    oauth_audiences: Optional[list] = Field(
        default=None,
        description="Required OAuth audiences"
    )
    oauth_allowed_users: Optional[list] = Field(
        default=None,
        description="Allowed GitHub usernames"
    )
    oauth_allowed_emails: Optional[list] = Field(
        default=None,
        description="Allowed email patterns"
    )
    oauth_allowed_groups: Optional[list] = Field(
        default=None,
        description="Allowed groups/organizations"
    )
    
    # Bearer token settings
    bearer_allow_admin: bool = Field(
        default=True,
        description="Allow admin tokens to access"
    )
    bearer_check_owner: bool = Field(
        default=False,
        description="Check resource ownership"
    )
    
    # General settings
    cache_ttl: int = Field(
        default=60,
        description="Cache TTL in seconds"
    )


def create_route_auth_router(async_storage: AsyncRedisStorage) -> APIRouter:
    """Create router for route auth configuration management.
    
    Args:
        async_storage: AsyncRedisStorage instance
        
    Returns:
        APIRouter with route auth endpoints
    """
    router = APIRouter(tags=["route-auth"])
    
    @router.get("/{route_id}/auth")
    async def get_route_auth(
        request: Request,
        route_id: str,
        auth: Any = Depends(AuthDep())
    ):
        """Get authentication configuration for a route.
        
        Returns the auth configuration if set, or null if using default.
        """
        storage = request.app.state.async_storage or async_storage
        
        try:
            # Get route to verify it exists
            route_data = await storage.get_route(route_id)
            if not route_data:
                raise HTTPException(404, "Route not found")
            
            # Get auth config from route data
            if route_data.auth_config:
                # Route has embedded auth config
                return route_data.auth_config
            
            # Check for separate auth config in Redis
            auth_data = await storage.redis_client.get(f"route:auth:{route_id}")
            if auth_data:
                return json.loads(auth_data)
            
            return None
            
        except HTTPException:
            raise
        except Exception as e:
            logger.error(f"Failed to get route auth: {e}")
            raise HTTPException(500, f"Failed to get auth config: {str(e)}")
    
    @router.put("/{route_id}/auth")
    async def set_route_auth(
        request: Request,
        route_id: str,
        config_request: RouteAuthConfigRequest,
        auth: Any = Depends(AuthDep(admin=True))
    ):
        """Set authentication configuration for a route.
        
        Admin access required.
        """
        storage = request.app.state.async_storage or async_storage
        
        try:
            # Get route to verify it exists
            route_data = await storage.get_route(route_id)
            if not route_data:
                raise HTTPException(404, "Route not found")
            
            # Validate auth type
            valid_auth_types = ["none", "bearer", "admin", "oauth"]
            if config_request.auth_type not in valid_auth_types:
                raise HTTPException(
                    status_code=400,
                    detail=f"Invalid auth_type. Must be one of: {', '.join(valid_auth_types)}"
                )
            
            # Create auth config
            auth_config = {
                "auth_type": config_request.auth_type,
                "override_proxy_auth": config_request.override_proxy_auth,
                "oauth_scopes": config_request.oauth_scopes,
                "oauth_audiences": config_request.oauth_audiences,
                "oauth_allowed_users": config_request.oauth_allowed_users,
                "oauth_allowed_emails": config_request.oauth_allowed_emails,
                "oauth_allowed_groups": config_request.oauth_allowed_groups,
                "bearer_allow_admin": config_request.bearer_allow_admin,
                "bearer_check_owner": config_request.bearer_check_owner,
                "cache_ttl": config_request.cache_ttl
            }
            
            # Update route with auth config
            route_data.auth_config = auth_config
            route_data.override_proxy_auth = config_request.override_proxy_auth
            
            # Save updated route
            await storage.save_route(route_data)
            
            # Also store in separate key for quick lookup
            await storage.redis_client.set(
                f"route:auth:{route_id}",
                json.dumps(auth_config)
            )
            
            # Clear auth cache
            if hasattr(request.app.state, 'auth_service'):
                request.app.state.auth_service.clear_cache()
            
            logger.info(f"Set auth config for route: {route_id}")
            
            return auth_config
            
        except HTTPException:
            raise
        except Exception as e:
            logger.error(f"Failed to set route auth: {e}")
            raise HTTPException(500, f"Failed to set auth config: {str(e)}")
    
    @router.delete("/{route_id}/auth")
    async def remove_route_auth(
        request: Request,
        route_id: str,
        auth: Any = Depends(AuthDep(admin=True))
    ):
        """Remove authentication configuration from a route.
        
        The route will use default authentication after this.
        Admin access required.
        """
        storage = request.app.state.async_storage or async_storage
        
        try:
            # Get route to verify it exists
            route_data = await storage.get_route(route_id)
            if not route_data:
                raise HTTPException(404, "Route not found")
            
            # Remove auth config from route
            route_data.auth_config = None
            route_data.override_proxy_auth = False
            
            # Save updated route
            await storage.save_route(route_data)
            
            # Remove separate auth config key
            await storage.redis_client.delete(f"route:auth:{route_id}")
            
            # Clear auth cache
            if hasattr(request.app.state, 'auth_service'):
                request.app.state.auth_service.clear_cache()
            
            logger.info(f"Removed auth config from route: {route_id}")
            
            return {"message": "Route auth configuration removed successfully"}
            
        except HTTPException:
            raise
        except Exception as e:
            logger.error(f"Failed to remove route auth: {e}")
            raise HTTPException(500, f"Failed to remove auth config: {str(e)}")
    
    @router.post("/{route_id}/auth/test")
    async def test_route_auth(
        request: Request,
        route_id: str,
        test_token: Optional[str] = None,
        auth: Any = Depends(AuthDep(admin=True))
    ):
        """Test authentication for a route.
        
        Admin access required.
        """
        storage = request.app.state.async_storage or async_storage
        
        try:
            # Get route
            route_data = await storage.get_route(route_id)
            if not route_data:
                raise HTTPException(404, "Route not found")
            
            # Get auth service
            auth_service = None
            if hasattr(request.app.state, 'auth_service'):
                auth_service = request.app.state.auth_service
            else:
                from src.auth import FlexibleAuthService
                auth_service = FlexibleAuthService(storage=storage)
                await auth_service.initialize()
            
            # Create mock credentials if token provided
            from fastapi.security import HTTPAuthorizationCredentials
            credentials = None
            if test_token:
                credentials = HTTPAuthorizationCredentials(
                    scheme="Bearer",
                    credentials=test_token
                )
            
            # Test route auth
            result = await auth_service.check_route_auth(
                request=request,
                route_id=route_id,
                credentials=credentials
            )
            
            return {
                "authenticated": result.authenticated,
                "auth_type": result.auth_type,
                "principal": result.principal,
                "error": result.error,
                "error_description": result.error_description,
                "cached": result.cached
            }
            
        except HTTPException:
            raise
        except Exception as e:
            logger.error(f"Failed to test route auth: {e}")
            raise HTTPException(500, f"Failed to test auth: {str(e)}")
    
    return router