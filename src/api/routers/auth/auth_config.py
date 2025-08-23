"""Authentication configuration management API endpoints."""

import logging
import hashlib
import uuid
from typing import List, Optional
from datetime import datetime, timezone

from fastapi import APIRouter, HTTPException, Depends, Request, Response
from fastapi.responses import JSONResponse

from src.api.models import (
    EndpointAuthConfig,
    AuthConfigRequest,
    AuthConfigTestRequest,
    AuthConfigTestResponse
)
from src.auth import AuthDep, AuthResult
from src.api.pattern_matcher import PathPatternMatcher
from src.api.unified_auth import invalidate_auth_cache

logger = logging.getLogger(__name__)


def create_auth_config_router(async_storage) -> APIRouter:
    """Create router for authentication configuration management.
    
    All endpoints require admin authentication for security.
    
    Args:
        async_storage: AsyncRedisStorage instance
        
    Returns:
        APIRouter with auth config endpoints
    """
    router = APIRouter(tags=["auth-config"])
    pattern_matcher = PathPatternMatcher()
    
    @router.get("/", response_model=List[EndpointAuthConfig])
    async def list_auth_configs(
        request: Request,
        auth: AuthResult = Depends(AuthDep(admin=True))
    ):
        """List all authentication configurations.
        
        Returns configurations sorted by priority (highest first).
        """
        storage = request.app.state.async_storage or async_storage
        configs_data = await storage.list_auth_configs()
        
        # Convert to model instances
        configs = []
        for config_data in configs_data:
            try:
                config = EndpointAuthConfig(**config_data)
                configs.append(config)
            except Exception as e:
                logger.error(f"Invalid auth config data: {e}")
        
        return configs
    
    @router.post("/", response_model=EndpointAuthConfig)
    async def create_auth_config(
        request: Request,
        config_request: AuthConfigRequest,
        auth: AuthResult = Depends(AuthDep(admin=True))
    ):
        """Create a new authentication configuration.
        
        This endpoint allows admins to configure authentication requirements
        for specific API endpoints, including different auth for the same
        endpoint at different mount points (e.g., / vs /api/v1/).
        """
        storage = request.app.state.async_storage or async_storage
        
        # Validate auth type
        valid_auth_types = ["none", "bearer", "admin", "oauth"]
        if config_request.auth_type not in valid_auth_types:
            raise HTTPException(
                status_code=400,
                detail=f"Invalid auth_type. Must be one of: {', '.join(valid_auth_types)}"
            )
        
        # Validate OAuth configuration
        if config_request.auth_type == "oauth":
            if not config_request.oauth_scopes and not config_request.oauth_allowed_users:
                logger.warning(
                    "OAuth configuration without scopes or allowed users - any authenticated OAuth user will have access"
                )
        
        # Generate unique ID for this configuration
        config_id = hashlib.md5(
            f"{config_request.path_pattern}:{config_request.method}:{uuid.uuid4()}".encode()
        ).hexdigest()[:16]
        
        # Create configuration data
        config_data = {
            "path_pattern": config_request.path_pattern,
            "method": config_request.method,
            "auth_type": config_request.auth_type,
            "oauth_scopes": config_request.oauth_scopes,
            "oauth_resource": config_request.oauth_resource,
            "oauth_allowed_users": config_request.oauth_allowed_users,
            "owner_validation": config_request.owner_validation,
            "owner_param": config_request.owner_param,
            "priority": config_request.priority,
            "description": config_request.description,
            "enabled": config_request.enabled,
            "created_by": auth.principal or "ADMIN",
            "created_at": datetime.now(timezone.utc).isoformat()
        }
        
        # Store configuration
        success = await storage.store_auth_config(config_id, config_data)
        if not success:
            raise HTTPException(
                status_code=500,
                detail="Failed to store authentication configuration"
            )
        
        # Invalidate auth cache
        invalidate_auth_cache()
        
        logger.info(
            f"Created auth config",
            extra={
                "config_id": config_id,
                "path_pattern": config_request.path_pattern,
                "method": config_request.method,
                "auth_type": config_request.auth_type,
                "created_by": auth.principal
            }
        )
        
        # Return the created configuration
        return EndpointAuthConfig(**config_data, id=config_id)
    
    @router.get("/endpoints")
    async def list_configurable_endpoints(
        request: Request,
        auth: AuthResult = Depends(AuthDep(admin=True))
    ):
        """List all API endpoints that can be configured.
        
        This helps admins understand what endpoints exist and can have
        authentication configured.
        """
        # Get all routes from the FastAPI app
        routes = []
        
        for route in request.app.routes:
            if hasattr(route, 'path') and hasattr(route, 'methods'):
                # Skip internal endpoints
                if route.path.startswith("/_") or route.path == "/openapi.json":
                    continue
                
                routes.append({
                    "path": route.path,
                    "methods": list(route.methods - {"HEAD", "OPTIONS"}),
                    "name": route.name,
                    "mounted_at": [
                        route.path,
                        f"/api/v1{route.path}" if not route.path.startswith("/api/") else None
                    ]
                })
        
        # Sort by path
        routes.sort(key=lambda x: x["path"])
        
        return routes
    
    @router.get("/{config_id}", response_model=EndpointAuthConfig)
    async def get_auth_config(
        request: Request,
        config_id: str,
        auth: AuthResult = Depends(AuthDep(admin=True))
    ):
        """Get a specific authentication configuration by ID."""
        storage = request.app.state.async_storage or async_storage
        
        config_data = await storage.get_auth_config(config_id)
        if not config_data:
            raise HTTPException(
                status_code=404,
                detail=f"Authentication configuration '{config_id}' not found"
            )
        
        return EndpointAuthConfig(**config_data, id=config_id)
    
    @router.put("/{config_id}", response_model=EndpointAuthConfig)
    async def update_auth_config(
        request: Request,
        config_id: str,
        updates: AuthConfigRequest,
        auth: AuthResult = Depends(AuthDep(admin=True))
    ):
        """Update an existing authentication configuration."""
        storage = request.app.state.async_storage or async_storage
        
        # Check if config exists
        existing = await storage.get_auth_config(config_id)
        if not existing:
            raise HTTPException(
                status_code=404,
                detail=f"Authentication configuration '{config_id}' not found"
            )
        
        # Prepare updates
        update_data = updates.dict(exclude_unset=True)
        update_data["updated_by"] = auth.principal or "ADMIN"
        
        # Update configuration
        success = await storage.update_auth_config(config_id, update_data)
        if not success:
            raise HTTPException(
                status_code=500,
                detail="Failed to update authentication configuration"
            )
        
        # Invalidate auth cache
        invalidate_auth_cache()
        
        logger.info(
            f"Updated auth config",
            extra={
                "config_id": config_id,
                "updates": list(update_data.keys()),
                "updated_by": auth.principal
            }
        )
        
        # Get and return updated configuration
        updated = await storage.get_auth_config(config_id)
        return EndpointAuthConfig(**updated, id=config_id)
    
    @router.delete("/{config_id}")
    async def delete_auth_config(
        request: Request,
        config_id: str,
        auth: AuthResult = Depends(AuthDep(admin=True))
    ):
        """Delete an authentication configuration.
        
        This will revert the endpoint to its default hardcoded authentication.
        """
        storage = request.app.state.async_storage or async_storage
        
        # Check if config exists
        existing = await storage.get_auth_config(config_id)
        if not existing:
            raise HTTPException(
                status_code=404,
                detail=f"Authentication configuration '{config_id}' not found"
            )
        
        # Delete configuration
        success = await storage.delete_auth_config(config_id)
        if not success:
            raise HTTPException(
                status_code=500,
                detail="Failed to delete authentication configuration"
            )
        
        # Invalidate auth cache
        invalidate_auth_cache()
        
        logger.info(
            f"Deleted auth config",
            extra={
                "config_id": config_id,
                "path_pattern": existing.get("path_pattern"),
                "deleted_by": auth.principal
            }
        )
        
        return {"message": f"Authentication configuration '{config_id}' deleted successfully"}
    
    @router.post("/test", response_model=AuthConfigTestResponse)
    async def test_auth_config(
        request: Request,
        test_request: AuthConfigTestRequest,
        auth: AuthResult = Depends(AuthDep(admin=True))
    ):
        """Test which authentication configuration would apply to a given path.
        
        This endpoint helps admins understand pattern matching and priority
        resolution for authentication configurations.
        """
        storage = request.app.state.async_storage or async_storage
        
        # Get all configurations
        configs_data = await storage.list_auth_configs()
        
        # Test pattern matching
        test_results = pattern_matcher.test_patterns(
            configs_data,
            test_request.path,
            test_request.method
        )
        
        # Build response
        matched_configs = []
        for match in test_results.get("all_matches", []):
            # Find the full config data
            for config_data in configs_data:
                if (config_data.get("path_pattern") == match["pattern"] and
                    config_data.get("method", "*") == match["method"]):
                    matched_configs.append(EndpointAuthConfig(**config_data))
                    break
        
        effective_config = None
        if test_results.get("effective"):
            effective = test_results["effective"]
            for config_data in configs_data:
                if (config_data.get("path_pattern") == effective["pattern"] and
                    config_data.get("method", "*") == effective["method"]):
                    effective_config = EndpointAuthConfig(**config_data)
                    break
        
        explanation = f"Found {len(matched_configs)} matching configuration(s) for {test_request.method} {test_request.path}"
        if effective_config:
            explanation += f". The effective configuration is '{effective_config.path_pattern}' with priority {effective_config.priority}."
        else:
            explanation += ". No matching configuration found - will use default hardcoded authentication."
        
        return AuthConfigTestResponse(
            matched=len(matched_configs) > 0,
            matched_configs=matched_configs,
            effective_config=effective_config,
            explanation=explanation
        )
    
    @router.post("/apply-defaults")
    async def apply_default_configs(
        request: Request,
        auth: AuthResult = Depends(AuthDep(admin=True))
    ):
        """Apply a sensible set of default authentication configurations.
        
        This creates configurations that demonstrate the flexibility of the system:
        - Different auth for / vs /api/v1/ paths
        - Public health endpoints
        - Admin-only token management
        - OAuth for MCP endpoints
        """
        storage = request.app.state.async_storage or async_storage
        
        # Define default configurations
        defaults = [
            # Public health endpoints
            {
                "path_pattern": "/health",
                "method": "GET",
                "auth_type": "none",
                "priority": 100,
                "description": "Public health check endpoint"
            },
            {
                "path_pattern": "/api/v1/health",
                "method": "GET",
                "auth_type": "none",
                "priority": 100,
                "description": "Public health check endpoint (API)"
            },
            
            # Token management - different auth for root vs API
            {
                "path_pattern": "/tokens/*",
                "method": "*",
                "auth_type": "admin",
                "priority": 90,
                "description": "Root token endpoints - admin only"
            },
            {
                "path_pattern": "/api/v1/tokens/",
                "method": "GET",
                "auth_type": "bearer",
                "priority": 80,
                "description": "List tokens via API - authenticated users"
            },
            {
                "path_pattern": "/api/v1/tokens/*",
                "method": "POST",
                "auth_type": "admin",
                "priority": 80,
                "description": "Create tokens via API - admin only"
            },
            {
                "path_pattern": "/api/v1/tokens/*",
                "method": "DELETE",
                "auth_type": "admin",
                "priority": 80,
                "description": "Delete tokens via API - admin only"
            },
            
            # Certificate management
            {
                "path_pattern": "/api/v1/certificates/",
                "method": "GET",
                "auth_type": "bearer",
                "priority": 70,
                "description": "List certificates - authenticated users"
            },
            {
                "path_pattern": "/api/v1/certificates/*",
                "method": "*",
                "auth_type": "bearer",
                "owner_validation": True,
                "owner_param": "cert_name",
                "priority": 70,
                "description": "Certificate operations - owner only"
            },
            
            # MCP endpoints with OAuth
            {
                "path_pattern": "/api/v1/mcp/*",
                "method": "*",
                "auth_type": "oauth",
                "oauth_scopes": ["mcp:read", "mcp:write"],
                "priority": 75,
                "description": "MCP endpoints - OAuth authentication"
            },
            
            # Auth config management - admin only
            {
                "path_pattern": "/api/v1/auth-config/*",
                "method": "*",
                "auth_type": "admin",
                "priority": 100,
                "description": "Auth configuration - admin only"
            }
        ]
        
        created = 0
        for config_data in defaults:
            try:
                # Generate ID
                config_id = hashlib.md5(
                    f"{config_data['path_pattern']}:{config_data['method']}:{uuid.uuid4()}".encode()
                ).hexdigest()[:16]
                
                # Add metadata
                config_data["created_by"] = auth.principal or "ADMIN"
                config_data["enabled"] = True
                
                # Store configuration
                if await storage.store_auth_config(config_id, config_data):
                    created += 1
                    logger.info(f"Created default auth config: {config_data['description']}")
            except Exception as e:
                logger.error(f"Failed to create default config: {e}")
        
        # Invalidate auth cache
        invalidate_auth_cache()
        
        return {
            "message": f"Applied {created} default authentication configurations",
            "created": created
        }
    
    @router.delete("/cache/clear")
    async def clear_auth_cache(
        request: Request,
        auth: AuthResult = Depends(AuthDep(admin=True))
    ):
        """Clear the authentication configuration cache.
        
        This forces all subsequent requests to reload configurations from Redis.
        """
        storage = request.app.state.async_storage or async_storage
        
        # Clear Redis cache entries
        redis_cleared = await storage.clear_auth_config_cache()
        
        # Clear in-memory cache
        invalidate_auth_cache()
        
        logger.info(
            f"Cleared auth config cache",
            extra={
                "redis_entries": redis_cleared,
                "cleared_by": auth.principal
            }
        )
        
        return {
            "message": "Authentication configuration cache cleared",
            "redis_entries_cleared": redis_cleared
        }
    
    @router.get("/effective/{path:path}")
    async def get_effective_auth(
        request: Request,
        path: str,
        method: str = "GET",
        auth: AuthResult = Depends(AuthDep(admin=True))
    ):
        """Show the effective authentication for a specific path.
        
        This shows what authentication would be applied to a request,
        including whether it comes from configuration or hardcoded defaults.
        """
        storage = request.app.state.async_storage or async_storage
        
        # Ensure path starts with /
        if not path.startswith("/"):
            path = "/" + path
        
        # Get all configurations
        configs_data = await storage.list_auth_configs()
        
        # Find the best match
        config_dict = pattern_matcher.find_best_match(configs_data, path, method)
        
        if config_dict:
            return {
                "path": path,
                "method": method,
                "source": "configuration",
                "config": EndpointAuthConfig(**config_dict),
                "explanation": f"Matched pattern '{config_dict['path_pattern']}' with priority {config_dict.get('priority', 50)}"
            }
        else:
            # Determine default auth
            default_auth = "bearer"  # Most endpoints default to bearer
            
            # Some known public endpoints
            if path in ["/", "/health", "/static", "/.well-known/acme-challenge"]:
                default_auth = "none"
            elif "auth-config" in path or "tokens" in path:
                default_auth = "admin"
            
            return {
                "path": path,
                "method": method,
                "source": "hardcoded",
                "default_auth": default_auth,
                "explanation": "No matching configuration - using hardcoded default authentication"
            }
    
    return router