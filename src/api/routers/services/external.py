"""External service registration endpoints with async support.

This module handles registration and management of external services.
"""

import logging
import json
from datetime import datetime, timezone
from typing import Dict, List, Optional
from fastapi import APIRouter, Depends, HTTPException, Request

# Authentication is handled by proxy, API trusts headers
from src.docker.models import (
    ServiceType,
    ExternalServiceConfig,
    UnifiedServiceInfo,
    UnifiedServiceListResponse
)

logger = logging.getLogger(__name__)


def create_external_router(async_storage) -> APIRouter:
    """Create router for external service operations.
    
    All endpoints use async patterns with Request parameter.
    
    Args:
        async_storage: Redis async_storage instance (legacy)
    
    Returns:
        APIRouter with external service endpoints
    """
    router = APIRouter()
    
    @router.post("/external", response_model=UnifiedServiceInfo)
    async def register_external_service(
        request: Request,
        config: ExternalServiceConfig,
    ):
        """Register an external service (replaces instance registration).
        
        This creates a named service that routes to an external URL.
        """
        # Get auth info from headers (set by proxy)
        auth_user = request.headers.get("X-Auth-User")
        if not auth_user:
            raise HTTPException(401, "Authentication required")
        auth_scopes = request.headers.get("X-Auth-Scopes", "").split()
        is_admin = "admin" in auth_scopes
        
        # Check permissions - admin scope required for create
        if not is_admin:
            raise HTTPException(403, "Admin scope required")
        try:
            # Get async storage from app state
            async_storage = request.app.state.async_storage
            
            # Check if service already exists
            existing = await async_storage.redis_client.get(f"service:external:{config.service_name}")
            if existing:
                # Check for Docker service with same name
                docker_key = f"docker_service:{config.service_name}"
                docker_exists = await async_storage.redis_client.exists(docker_key)
                if docker_exists:
                    raise HTTPException(409, f"Docker service '{config.service_name}' already exists")
                raise HTTPException(409, f"Service '{config.service_name}' already exists")
            # Create service info
            service_info = UnifiedServiceInfo(
                service_name=config.service_name,
                service_type=ServiceType.EXTERNAL,
                target_url=config.target_url,
                description=config.description,
                routing_enabled=config.routing_enabled,
                created_at=datetime.now(timezone.utc),
                owner_token_hash=None,  # No token ownership
                created_by=auth_user
            )
            
            # Store in Redis (new format)
            await async_storage.redis_client.set(f"service:external:{config.service_name}", service_info.json())
            await async_storage.redis_client.set(f"service:url:{config.service_name}", config.target_url)
            # Add to service set
            await async_storage.redis_client.sadd("services:external", config.service_name)
            logger.info(f"Registered external service '{config.service_name}' -> {config.target_url}")
            return service_info
            
        except HTTPException:
            raise
        except Exception as e:
            logger.error(f"Failed to register external service: {e}")
            raise HTTPException(500, f"Failed to register service: {str(e)}")
    
    @router.get("/external", response_model=List[UnifiedServiceInfo])
    async def list_external_services(
        request: Request,
    ):
        """List all external services."""
        # Get auth info from headers (set by proxy)
        auth_user = request.headers.get("X-Auth-User")
        if not auth_user:
            raise HTTPException(401, "Authentication required")
        auth_scopes = request.headers.get("X-Auth-Scopes", "").split()
        is_admin = "admin" in auth_scopes
        try:
            services = []
            
            # Get async storage from app state
            async_storage = request.app.state.async_storage
            
            # Get all external services
            service_names = await async_storage.redis_client.smembers("services:external") or set()
                
            for name in service_names:
                service_data = await async_storage.redis_client.get(f"service:external:{name}")
                if service_data:
                    try:
                        service_info = UnifiedServiceInfo.parse_raw(service_data)
                        services.append(service_info)
                    except Exception as e:
                        logger.error(f"Failed to parse service data for {name}: {e}")
                        # Create minimal service info
                        target_url = await async_storage.redis_client.get(f"service:url:{name}")
                        if target_url:
                            services.append(UnifiedServiceInfo(
                                service_name=name,
                                service_type=ServiceType.EXTERNAL,
                                target_url=target_url,
                                description="",
                                created_at=datetime.now(timezone.utc)
                            ))
            
            return services
        except Exception as e:
            logger.error(f"Failed to list external services: {e}")
            raise HTTPException(500, f"Failed to list services: {str(e)}")
    
    @router.delete("/external/{service_name}")
    async def delete_external_service(
        request: Request,
        service_name: str,
    ):
        """Delete an external service registration."""
        # Get auth info from headers (set by proxy)
        auth_user = request.headers.get("X-Auth-User")
        if not auth_user:
            raise HTTPException(401, "Authentication required")
        auth_scopes = request.headers.get("X-Auth-Scopes", "").split()
        is_admin = "admin" in auth_scopes
        try:
            # Get async storage from app state
            async_storage = request.app.state.async_storage
            
            # Get service info to check ownership
            service_data = await async_storage.redis_client.get(f"service:external:{service_name}")
            if not service_data:
                raise HTTPException(404, f"Service '{service_name}' not found")
            
            # Parse service info
            service_info = UnifiedServiceInfo.parse_raw(service_data)
            
            # Check permissions - admin scope required for delete
            if not is_admin:
                raise HTTPException(403, "Admin scope required to delete service")
            
            # Delete all related keys
            await async_storage.redis_client.delete(f"service:external:{service_name}")
            await async_storage.redis_client.delete(f"service:url:{service_name}")
            await async_storage.redis_client.srem("services:external", service_name)
            logger.info(f"Deleted external service '{service_name}'")
            return {"message": f"Service '{service_name}' deleted successfully"}
            
        except HTTPException:
            raise
        except Exception as e:
            logger.error(f"Failed to delete external service: {e}")
            raise HTTPException(500, f"Failed to delete service: {str(e)}")
    
    @router.get("/external/{service_name}")
    async def get_external_service(
        request: Request,
        service_name: str,
    ):
        """Get details of a specific external service."""
        # Get auth info from headers (set by proxy)
        auth_user = request.headers.get("X-Auth-User")
        if not auth_user:
            raise HTTPException(401, "Authentication required")
        auth_scopes = request.headers.get("X-Auth-Scopes", "").split()
        is_admin = "admin" in auth_scopes
        try:
            async_storage = request.app.state.async_storage
            
            # Get service URL
            service_key = f"service:url:{service_name}"
            target_url = await async_storage.redis_client.get(service_key)
            
            if not target_url:
                raise HTTPException(404, f"External service '{service_name}' not found")
            
            # Get service metadata
            service_meta_key = f"service:external:{service_name}"
            service_data = await async_storage.redis_client.get(service_meta_key)
            
            if service_data:
                service_dict = json.loads(service_data)
            else:
                service_dict = {
                    "service_name": service_name,
                    "service_type": "external",
                    "target_url": target_url
                }
            
            return service_dict
            
        except HTTPException:
            raise
        except Exception as e:
            logger.error(f"Error getting external service {service_name}: {e}")
            raise HTTPException(500, f"Error getting service: {str(e)}")
    
    @router.get("/unified", response_model=UnifiedServiceListResponse)
    async def list_all_services(
        request: Request,
        service_type: Optional[ServiceType] = None,
    ):
        """List all services (Docker and external)."""
        # Get auth info from headers (set by proxy)
        auth_user = request.headers.get("X-Auth-User")
        if not auth_user:
            raise HTTPException(401, "Authentication required")
        auth_scopes = request.headers.get("X-Auth-Scopes", "").split()
        is_admin = "admin" in auth_scopes
        try:
            all_services = []
            
            # Get Docker services
            if not service_type or service_type == ServiceType.DOCKER:
                # Try to get async Docker manager
                if hasattr(request.app.state, 'async_components'):
                    async_components = request.app.state.async_components
                    if async_components and hasattr(async_components, 'docker_manager'):
                        manager = async_components.docker_manager
                        docker_services = await manager.list_services()
                        for ds in docker_services:
                            all_services.append(UnifiedServiceInfo(
                                service_name=ds.service_name,
                                service_type=ServiceType.DOCKER,
                                docker_info=ds,
                                description=f"Docker container: {ds.image or 'custom'}",
                                created_at=ds.created_at,
                                owner_token_hash=ds.owner_token_hash,
                                created_by=None  # DockerServiceInfo doesn't have created_by field
                            ))
            
            # Get external services
            if not service_type or service_type == ServiceType.EXTERNAL:
                external_services = await list_external_services(request)
                all_services.extend(external_services)
            
            # Count by type
            by_type = {}
            for service in all_services:
                by_type[service.service_type.value] = by_type.get(service.service_type.value, 0) + 1
            
            return UnifiedServiceListResponse(
                services=all_services,
                total=len(all_services),
                by_type=by_type
            )
            
        except Exception as e:
            logger.error(f"Failed to list all services: {e}")
            raise HTTPException(500, f"Failed to list services: {str(e)}")
    
    return router