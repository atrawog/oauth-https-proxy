"""Authentication endpoint configuration management API.

This module provides API endpoints for managing authentication
configurations for API endpoints using the flexible auth system.
"""

import logging
import hashlib
import uuid
from typing import List, Optional, Dict, Any
from datetime import datetime, timezone

from fastapi import APIRouter, HTTPException, Depends, Request, Query
from pydantic import BaseModel, Field

from src.auth import EndpointAuthConfig, AuthDep
from src.storage import AsyncRedisStorage

logger = logging.getLogger(__name__)


class EndpointAuthConfigRequest(BaseModel):
    """Request model for creating/updating endpoint auth configuration."""
    
    path_pattern: str = Field(
        ...,
        description="Path pattern to match (e.g., '/api/v1/tokens/*')"
    )
    methods: List[str] = Field(
        default=["*"],
        description="HTTP methods this config applies to"
    )
    auth_type: str = Field(
        ...,
        description="Authentication type: none, bearer, admin, or oauth"
    )
    
    # OAuth-specific settings
    oauth_scopes: Optional[List[str]] = Field(
        default=None,
        description="Required OAuth scopes"
    )
    oauth_audiences: Optional[List[str]] = Field(
        default=None,
        description="Required OAuth audiences"
    )
    oauth_allowed_users: Optional[List[str]] = Field(
        default=None,
        description="Allowed GitHub usernames"
    )
    oauth_allowed_emails: Optional[List[str]] = Field(
        default=None,
        description="Allowed email patterns"
    )
    oauth_allowed_groups: Optional[List[str]] = Field(
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
    priority: int = Field(
        default=50,
        description="Priority for pattern matching (higher = checked first)"
    )
    owner_param: Optional[str] = Field(
        default=None,
        description="Path parameter for ownership checks"
    )
    description: str = Field(
        default="",
        description="Human-readable description"
    )
    enabled: bool = Field(
        default=True,
        description="Whether this config is active"
    )
    cache_ttl: int = Field(
        default=60,
        description="Cache TTL in seconds"
    )


class EndpointAuthTestRequest(BaseModel):
    """Request model for testing endpoint auth configuration."""
    
    path: str = Field(
        ...,
        description="Path to test"
    )
    method: str = Field(
        default="GET",
        description="HTTP method to test"
    )


def create_auth_endpoints_router(async_storage: AsyncRedisStorage) -> APIRouter:
    """Create router for endpoint auth configuration management.
    
    Args:
        async_storage: AsyncRedisStorage instance
        
    Returns:
        APIRouter with auth endpoints
    """
    router = APIRouter(tags=["auth-endpoints"])
    
    @router.get("/", response_model=List[EndpointAuthConfig])
    async def list_endpoint_configs(
        request: Request,
        auth: Any = Depends(AuthDep(admin=True))
    ):
        """List all endpoint authentication configurations.
        
        Returns configurations sorted by priority (highest first).
        """
        storage = request.app.state.async_storage or async_storage
        
        configs = []
        try:
            # Scan for all endpoint auth configs
            async for key in storage.redis_client.scan_iter(match="auth:endpoint:*"):
                if isinstance(key, bytes):
                    key = key.decode('utf-8')
                
                config_data = await storage.redis_client.get(key)
                if config_data:
                    import json
                    try:
                        config_dict = json.loads(config_data)
                        config = EndpointAuthConfig(**config_dict)
                        configs.append(config)
                    except Exception as e:
                        logger.error(f"Invalid endpoint config: {e}")
        
        except Exception as e:
            logger.error(f"Error listing endpoint configs: {e}")
            raise HTTPException(500, f"Failed to list configs: {str(e)}")
        
        # Sort by priority (highest first)
        configs.sort(key=lambda c: c.priority, reverse=True)
        
        return configs
    
    @router.post("/", response_model=EndpointAuthConfig)
    async def create_endpoint_config(
        request: Request,
        config_request: EndpointAuthConfigRequest,
        auth: Any = Depends(AuthDep(admin=True))
    ):
        """Create a new endpoint authentication configuration.
        
        Admin access required.
        """
        storage = request.app.state.async_storage or async_storage
        
        # Validate auth type
        valid_auth_types = ["none", "bearer", "admin", "oauth"]
        if config_request.auth_type not in valid_auth_types:
            raise HTTPException(
                status_code=400,
                detail=f"Invalid auth_type. Must be one of: {', '.join(valid_auth_types)}"
            )
        
        # Generate unique ID
        config_id = hashlib.md5(
            f"{config_request.path_pattern}:{uuid.uuid4()}".encode()
        ).hexdigest()[:16]
        
        # Create config
        config = EndpointAuthConfig(
            config_id=config_id,
            path_pattern=config_request.path_pattern,
            methods=config_request.methods,
            auth_type=config_request.auth_type,
            oauth_scopes=config_request.oauth_scopes,
            oauth_audiences=config_request.oauth_audiences,
            oauth_allowed_users=config_request.oauth_allowed_users,
            oauth_allowed_emails=config_request.oauth_allowed_emails,
            oauth_allowed_groups=config_request.oauth_allowed_groups,
            bearer_allow_admin=config_request.bearer_allow_admin,
            bearer_check_owner=config_request.bearer_check_owner,
            priority=config_request.priority,
            owner_param=config_request.owner_param,
            description=config_request.description,
            enabled=config_request.enabled,
            cache_ttl=config_request.cache_ttl,
            created_at=datetime.now(timezone.utc),
            created_by=auth.principal
        )
        
        # Store in Redis
        try:
            import json
            await storage.redis_client.set(
                f"auth:endpoint:{config_id}",
                json.dumps(config.dict(exclude_none=True))
            )
            
            # Clear auth cache
            if hasattr(request.app.state, 'auth_service'):
                request.app.state.auth_service.clear_cache()
            
            logger.info(f"Created endpoint auth config: {config_id}")
            
        except Exception as e:
            logger.error(f"Failed to create config: {e}")
            raise HTTPException(500, f"Failed to create config: {str(e)}")
        
        return config
    
    @router.get("/{config_id}", response_model=EndpointAuthConfig)
    async def get_endpoint_config(
        request: Request,
        config_id: str,
        auth: Any = Depends(AuthDep(admin=True))
    ):
        """Get a specific endpoint authentication configuration.
        
        Admin access required.
        """
        storage = request.app.state.async_storage or async_storage
        
        try:
            config_data = await storage.redis_client.get(f"auth:endpoint:{config_id}")
            if not config_data:
                raise HTTPException(404, "Configuration not found")
            
            import json
            config_dict = json.loads(config_data)
            return EndpointAuthConfig(**config_dict)
            
        except HTTPException:
            raise
        except Exception as e:
            logger.error(f"Failed to get config: {e}")
            raise HTTPException(500, f"Failed to get config: {str(e)}")
    
    @router.put("/{config_id}", response_model=EndpointAuthConfig)
    async def update_endpoint_config(
        request: Request,
        config_id: str,
        config_request: EndpointAuthConfigRequest,
        auth: Any = Depends(AuthDep(admin=True))
    ):
        """Update an endpoint authentication configuration.
        
        Admin access required.
        """
        storage = request.app.state.async_storage or async_storage
        
        # Check if config exists
        existing = await storage.redis_client.get(f"auth:endpoint:{config_id}")
        if not existing:
            raise HTTPException(404, "Configuration not found")
        
        # Validate auth type
        valid_auth_types = ["none", "bearer", "admin", "oauth"]
        if config_request.auth_type not in valid_auth_types:
            raise HTTPException(
                status_code=400,
                detail=f"Invalid auth_type. Must be one of: {', '.join(valid_auth_types)}"
            )
        
        # Update config
        import json
        existing_dict = json.loads(existing)
        
        config = EndpointAuthConfig(
            config_id=config_id,
            path_pattern=config_request.path_pattern,
            methods=config_request.methods,
            auth_type=config_request.auth_type,
            oauth_scopes=config_request.oauth_scopes,
            oauth_audiences=config_request.oauth_audiences,
            oauth_allowed_users=config_request.oauth_allowed_users,
            oauth_allowed_emails=config_request.oauth_allowed_emails,
            oauth_allowed_groups=config_request.oauth_allowed_groups,
            bearer_allow_admin=config_request.bearer_allow_admin,
            bearer_check_owner=config_request.bearer_check_owner,
            priority=config_request.priority,
            owner_param=config_request.owner_param,
            description=config_request.description,
            enabled=config_request.enabled,
            cache_ttl=config_request.cache_ttl,
            created_at=existing_dict.get('created_at'),
            created_by=existing_dict.get('created_by')
        )
        
        # Store updated config
        try:
            await storage.redis_client.set(
                f"auth:endpoint:{config_id}",
                json.dumps(config.dict(exclude_none=True))
            )
            
            # Clear auth cache
            if hasattr(request.app.state, 'auth_service'):
                request.app.state.auth_service.clear_cache()
            
            logger.info(f"Updated endpoint auth config: {config_id}")
            
        except Exception as e:
            logger.error(f"Failed to update config: {e}")
            raise HTTPException(500, f"Failed to update config: {str(e)}")
        
        return config
    
    @router.delete("/{config_id}")
    async def delete_endpoint_config(
        request: Request,
        config_id: str,
        auth: Any = Depends(AuthDep(admin=True))
    ):
        """Delete an endpoint authentication configuration.
        
        Admin access required.
        """
        storage = request.app.state.async_storage or async_storage
        
        try:
            # Check if exists
            if not await storage.redis_client.exists(f"auth:endpoint:{config_id}"):
                raise HTTPException(404, "Configuration not found")
            
            # Delete config
            await storage.redis_client.delete(f"auth:endpoint:{config_id}")
            
            # Clear auth cache
            if hasattr(request.app.state, 'auth_service'):
                request.app.state.auth_service.clear_cache()
            
            logger.info(f"Deleted endpoint auth config: {config_id}")
            
            return {"message": "Configuration deleted successfully"}
            
        except HTTPException:
            raise
        except Exception as e:
            logger.error(f"Failed to delete config: {e}")
            raise HTTPException(500, f"Failed to delete config: {str(e)}")
    
    @router.post("/test")
    async def test_endpoint_config(
        request: Request,
        test_request: EndpointAuthTestRequest,
        auth: Any = Depends(AuthDep(admin=True))
    ):
        """Test which endpoint configuration would match a given path and method.
        
        Admin access required.
        """
        # Get auth service
        auth_service = None
        if hasattr(request.app.state, 'auth_service'):
            auth_service = request.app.state.auth_service
        else:
            from src.auth import FlexibleAuthService
            auth_service = FlexibleAuthService(
                storage=request.app.state.async_storage or async_storage
            )
            await auth_service.initialize()
        
        # Find matching config
        config = await auth_service._find_endpoint_config(
            path=test_request.path,
            method=test_request.method
        )
        
        if config:
            return {
                "matched": True,
                "config": config,
                "explanation": f"Matched pattern '{config.path_pattern}' with priority {config.priority}"
            }
        else:
            return {
                "matched": False,
                "config": None,
                "explanation": "No configuration matched the given path and method"
            }
    
    return router