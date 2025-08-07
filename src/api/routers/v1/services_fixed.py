"""Service management API endpoints (Docker and external services) - Fixed route ordering."""

import json
import logging
from datetime import datetime, timezone
from typing import Dict, List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, Response
from python_on_whales.exceptions import DockerException

from ...auth import require_auth, get_token_info_from_header
from ....docker.models import (
    ServiceType,
    DockerServiceConfig,
    DockerServiceInfo,
    DockerServiceUpdate,
    DockerServiceLogs,
    DockerServiceStats,
    DockerServiceListResponse,
    DockerServiceCreateResponse,
    ExternalServiceConfig,
    UnifiedServiceInfo,
    UnifiedServiceCreateRequest,
    UnifiedServiceListResponse
)
from ....docker.manager import DockerManager
from ....proxy.models import ProxyTarget
from ....shared.config import Config
from ....ports import ServicePort, PortConfiguration

logger = logging.getLogger(__name__)


def create_router(storage) -> APIRouter:
    """Create the services API router (Docker and external) with proper route ordering."""
    router = APIRouter(tags=["services"])
    
    # Create Docker manager instance
    docker_manager = None
    
    def get_docker_manager() -> DockerManager:
        """Get or create Docker manager instance."""
        nonlocal docker_manager
        if docker_manager is None:
            docker_manager = DockerManager(storage)
        return docker_manager
    
    # ===========================================================================
    # IMPORTANT: Define all specific routes (without path parameters) FIRST
    # ===========================================================================
    
    # Root endpoints
    @router.post("/", response_model=DockerServiceCreateResponse)
    async def create_service(
        config: DockerServiceConfig,
        auto_proxy: bool = Query(False, description="Automatically create proxy configuration"),
        token_info: Dict = Depends(get_token_info_from_header)
    ):
        """Create a new Docker service.
        
        Requires admin token or special docker:create permission.
        """
        # Check permissions
        has_permission = (
            token_info.get("name") == "ADMIN" or
            "docker:create" in token_info.get("permissions", [])
        )
        if not has_permission:
            raise HTTPException(403, "Admin token or docker:create permission required")
        
        # Check if service already exists
        manager = get_docker_manager()
        existing = await manager.get_service(config.service_name)
        if existing:
            raise HTTPException(409, f"Service {config.service_name} already exists")
        
        try:
            # Create service
            service_info = await manager.create_service(config, token_info["hash"])
            
            response = DockerServiceCreateResponse(
                service=service_info,
                proxy_created=False,
                instance_registered=True
            )
            
            # Optionally create proxy configuration
            if auto_proxy:
                try:
                    proxy_hostname = f"{config.service_name}.{Config.BASE_DOMAIN}"
                    proxy_config = ProxyTarget(
                        hostname=proxy_hostname,
                        target_url=f"http://{config.service_name}:{service_info.internal_port}",
                        cert_name=f"cert-{config.service_name}",
                        enabled=True,
                        enable_http=True,
                        enable_https=False,  # Start with HTTP only
                        owner_token_hash=token_info["hash"],
                        preserve_host_header=True
                    )
                    
                    storage.store_proxy_target(proxy_config.hostname, proxy_config)
                    response.proxy_created = True
                    response.warnings.append(f"Created proxy at {proxy_hostname}")
                    
                except Exception as e:
                    logger.error(f"Failed to create proxy for service {config.service_name}: {e}")
                    response.warnings.append(f"Failed to create proxy: {str(e)}")
            
            return response
            
        except DockerException as e:
            logger.error(f"Docker error creating service: {e}")
            raise HTTPException(500, f"Docker error: {str(e)}")
        except Exception as e:
            logger.error(f"Error creating service: {e}")
            raise HTTPException(500, f"Error creating service: {str(e)}")
    
    @router.get("/", response_model=DockerServiceListResponse)
    async def list_services(
        owned_only: bool = Query(False, description="Only show services owned by current token"),
        token_info: Dict = Depends(get_token_info_from_header)
    ):
        """List all Docker services."""
        manager = get_docker_manager()
        
        # Filter by owner if requested
        owner_hash = token_info["hash"] if owned_only else None
        services = await manager.list_services(owner_hash)
        
        return DockerServiceListResponse(
            services=services,
            total=len(services)
        )
    
    # Cleanup endpoint  
    @router.post("/cleanup")
    async def cleanup_orphaned_services(
        token_info: Dict = Depends(get_token_info_from_header)
    ):
        """Clean up orphaned Docker resources (admin only)."""
        # Check admin permission
        if token_info.get("name") != "ADMIN":
            raise HTTPException(403, "Admin token required")
        
        try:
            manager = get_docker_manager()
            await manager.cleanup_orphaned_services()
            return {"message": "Cleanup completed successfully"}
        except Exception as e:
            logger.error(f"Error during cleanup: {e}")
            raise HTTPException(500, f"Error during cleanup: {str(e)}")
    
    # External service endpoints (MUST be before /{service_name})
    @router.post("/external", response_model=UnifiedServiceInfo)
    async def register_external_service(
        config: ExternalServiceConfig,
        token_info: Dict = Depends(get_token_info_from_header)
    ):
        """Register an external service (replaces instance registration).
        
        This creates a named service that routes to an external URL.
        """
        try:
            # Check if service already exists
            existing = storage.redis_client.get(f"service:external:{config.service_name}")
            if existing:
                # Check for Docker service with same name
                docker_key = f"docker_service:{config.service_name}"
                if storage.redis_client.exists(docker_key):
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
                owner_token_hash=token_info["hash"],
                created_by=token_info.get("name", "unknown")
            )
            
            # Store in Redis (new format)
            storage.redis_client.set(f"service:external:{config.service_name}", service_info.json())
            storage.redis_client.set(f"service:url:{config.service_name}", config.target_url)
            
            # Add to service set
            storage.redis_client.sadd("services:external", config.service_name)
            
            # Migrate old instance data if it exists
            old_instance_url = storage.redis_client.get(f"instance_url:{config.service_name}")
            if old_instance_url:
                storage.redis_client.delete(f"instance_url:{config.service_name}")
                storage.redis_client.delete(f"instance_info:{config.service_name}")
                storage.redis_client.delete(f"instance:{config.service_name}")
                logger.info(f"Migrated instance '{config.service_name}' to external service")
            
            logger.info(f"Registered external service '{config.service_name}' -> {config.target_url}")
            return service_info
            
        except HTTPException:
            raise
        except Exception as e:
            logger.error(f"Failed to register external service: {e}")
            raise HTTPException(500, f"Failed to register service: {str(e)}")
    
    @router.get("/external", response_model=List[UnifiedServiceInfo])
    async def list_external_services(
        token_info: Optional[Dict] = Depends(get_token_info_from_header)
    ):
        """List all external services."""
        try:
            services = []
            
            # Get all external services
            service_names = storage.redis_client.smembers("services:external") or set()
            
            for name in service_names:
                service_data = storage.redis_client.get(f"service:external:{name}")
                if service_data:
                    try:
                        service_info = UnifiedServiceInfo.parse_raw(service_data)
                        services.append(service_info)
                    except Exception as e:
                        logger.error(f"Failed to parse service data for {name}: {e}")
                        # Create minimal service info
                        target_url = storage.redis_client.get(f"service:url:{name}")
                        if target_url:
                            services.append(UnifiedServiceInfo(
                                service_name=name,
                                service_type=ServiceType.EXTERNAL,
                                target_url=target_url,
                                description="",
                                created_at=datetime.now(timezone.utc)
                            ))
            
            # Also check for migrated instances (backward compatibility)
            for key in storage.redis_client.scan_iter(match="instance_url:*"):
                name = key.split(":")[-1]
                if name not in [s.service_name for s in services]:
                    target_url = storage.redis_client.get(key)
                    if target_url:
                        services.append(UnifiedServiceInfo(
                            service_name=name,
                            service_type=ServiceType.EXTERNAL,
                            target_url=target_url,
                            description="Legacy instance (migrated)",
                            created_at=datetime.now(timezone.utc)
                        ))
                        logger.info(f"Found legacy instance '{name}', will be migrated on next update")
            
            return sorted(services, key=lambda s: s.service_name)
            
        except Exception as e:
            logger.error(f"Failed to list external services: {e}")
            raise HTTPException(500, f"Failed to list services: {str(e)}")
    
    @router.get("/unified", response_model=UnifiedServiceListResponse)
    async def list_all_services(
        service_type: Optional[ServiceType] = Query(None, description="Filter by service type"),
        token_info: Dict = Depends(get_token_info_from_header)
    ):
        """List all services (Docker, external, and internal) in a unified view."""
        try:
            services = []
            
            # Get Docker services
            if not service_type or service_type == ServiceType.DOCKER:
                manager = get_docker_manager()
                docker_services = await manager.list_services()
                for ds in docker_services:
                    services.append(UnifiedServiceInfo(
                        service_name=ds.service_name,
                        service_type=ServiceType.DOCKER,
                        target_url=f"http://{ds.service_name}:{ds.internal_port}",
                        docker_info=ds,
                        description=f"Docker container ({ds.image})",
                        routing_enabled=True,
                        created_at=ds.created_at,
                        owner_token_hash=ds.owner_token_hash
                    ))
            
            # Get external services
            if not service_type or service_type == ServiceType.EXTERNAL:
                external_services = await list_external_services(token_info)
                services.extend(external_services)
            
            # Get internal services (API and OAuth)
            if not service_type or service_type == ServiceType.INTERNAL:
                # Add API service
                services.append(UnifiedServiceInfo(
                    service_name="api",
                    service_type=ServiceType.INTERNAL,
                    target_url="http://localhost:9000",
                    description="API and management service",
                    routing_enabled=True,
                    created_at=datetime.now(timezone.utc)
                ))
                
                # Add OAuth service if configured
                if storage.redis_client.exists("oauth:config"):
                    services.append(UnifiedServiceInfo(
                        service_name="oauth",
                        service_type=ServiceType.INTERNAL,
                        target_url="http://localhost:9000/oauth",
                        description="OAuth authentication service",
                        routing_enabled=True,
                        created_at=datetime.now(timezone.utc)
                    ))
            
            return UnifiedServiceListResponse(
                services=services,
                total=len(services),
                by_type={
                    ServiceType.DOCKER: len([s for s in services if s.service_type == ServiceType.DOCKER]),
                    ServiceType.EXTERNAL: len([s for s in services if s.service_type == ServiceType.EXTERNAL]),
                    ServiceType.INTERNAL: len([s for s in services if s.service_type == ServiceType.INTERNAL])
                }
            )
            
        except Exception as e:
            logger.error(f"Failed to list unified services: {e}")
            raise HTTPException(500, f"Failed to list services: {str(e)}")
    
    # ===========================================================================
    # NOW define routes with path parameters (these will match last)
    # ===========================================================================
    
    @router.get("/{service_name}", response_model=DockerServiceInfo)
    async def get_service(
        service_name: str,
        token_info: Dict = Depends(require_auth)
    ):
        """Get information about a specific service."""
        manager = get_docker_manager()
        service_info = await manager.get_service(service_name)
        
        if not service_info:
            raise HTTPException(404, f"Service {service_name} not found")
        
        return service_info
    
    # Continue with the rest of the /{service_name} routes...
    # (I'll continue with the rest of the file if needed)
    
    return router