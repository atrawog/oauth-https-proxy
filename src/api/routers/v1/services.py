"""Docker service management API endpoints."""

import logging
from datetime import datetime, timezone
from typing import Dict, List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, Response
from python_on_whales.exceptions import DockerException

from ...auth import require_auth, get_token_info_from_header
from ....docker.models import (
    DockerServiceConfig,
    DockerServiceInfo,
    DockerServiceUpdate,
    DockerServiceLogs,
    DockerServiceStats,
    DockerServiceListResponse,
    DockerServiceCreateResponse
)
from ....docker.manager import DockerManager
from ....proxy.models import ProxyTarget
from ....shared.config import Config

logger = logging.getLogger(__name__)


def create_router(storage) -> APIRouter:
    """Create the Docker services API router."""
    router = APIRouter(tags=["docker-services"])
    
    # Create Docker manager instance
    docker_manager = None
    
    def get_docker_manager() -> DockerManager:
        """Get or create Docker manager instance."""
        nonlocal docker_manager
        if docker_manager is None:
            docker_manager = DockerManager(storage)
        return docker_manager
    
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
                        target_url=f"http://{service_name}:{service_info.internal_port}",
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
    
    @router.put("/{service_name}", response_model=DockerServiceInfo)
    async def update_service(
        service_name: str,
        updates: DockerServiceUpdate,
        token_info: Dict = Depends(get_token_info_from_header)
    ):
        """Update a Docker service configuration.
        
        Note: Some updates require container recreation.
        """
        manager = get_docker_manager()
        service_info = await manager.get_service(service_name)
        
        if not service_info:
            raise HTTPException(404, f"Service {service_name} not found")
        
        # Check ownership
        is_owner = service_info.owner_token_hash == token_info["hash"]
        is_admin = token_info.get("name") == "ADMIN"
        if not (is_owner or is_admin):
            raise HTTPException(403, "Not authorized to update this service")
        
        try:
            updated_service = await manager.update_service(service_name, updates)
            return updated_service
        except ValueError as e:
            raise HTTPException(404, str(e))
        except Exception as e:
            logger.error(f"Error updating service {service_name}: {e}")
            raise HTTPException(500, f"Error updating service: {str(e)}")
    
    @router.delete("/{service_name}")
    async def delete_service(
        service_name: str,
        force: bool = Query(False, description="Force delete even if running"),
        delete_proxy: bool = Query(True, description="Also delete associated proxy"),
        token_info: Dict = Depends(get_token_info_from_header)
    ):
        """Delete a Docker service and cleanup resources."""
        manager = get_docker_manager()
        service_info = await manager.get_service(service_name)
        
        if not service_info:
            raise HTTPException(404, f"Service {service_name} not found")
        
        # Check ownership
        is_owner = service_info.owner_token_hash == token_info["hash"]
        is_admin = token_info.get("name") == "ADMIN"
        if not (is_owner or is_admin):
            raise HTTPException(403, "Not authorized to delete this service")
        
        try:
            # Delete service
            await manager.delete_service(service_name, force)
            
            # Delete associated proxy if requested
            if delete_proxy:
                proxy_hostname = f"{service_name}.{Config.BASE_DOMAIN}"
                proxy_target = storage.get_proxy_target(proxy_hostname)
                if proxy_target:
                    storage.delete_proxy_target(proxy_hostname)
                    logger.info(f"Deleted proxy for service {service_name}")
            
            return Response(status_code=204)
            
        except ValueError as e:
            raise HTTPException(400, str(e))
        except Exception as e:
            logger.error(f"Error deleting service {service_name}: {e}")
            raise HTTPException(500, f"Error deleting service: {str(e)}")
    
    @router.post("/{service_name}/start")
    async def start_service(
        service_name: str,
        token_info: Dict = Depends(get_token_info_from_header)
    ):
        """Start a stopped service."""
        manager = get_docker_manager()
        service_info = await manager.get_service(service_name)
        
        if not service_info:
            raise HTTPException(404, f"Service {service_name} not found")
        
        # Check ownership
        is_owner = service_info.owner_token_hash == token_info["hash"]
        is_admin = token_info.get("name") == "ADMIN"
        if not (is_owner or is_admin):
            raise HTTPException(403, "Not authorized to control this service")
        
        try:
            await manager.start_service(service_name)
            return {"message": f"Service {service_name} started"}
        except ValueError as e:
            raise HTTPException(404, str(e))
        except Exception as e:
            logger.error(f"Error starting service {service_name}: {e}")
            raise HTTPException(500, f"Error starting service: {str(e)}")
    
    @router.post("/{service_name}/stop")
    async def stop_service(
        service_name: str,
        token_info: Dict = Depends(get_token_info_from_header)
    ):
        """Stop a running service."""
        manager = get_docker_manager()
        service_info = await manager.get_service(service_name)
        
        if not service_info:
            raise HTTPException(404, f"Service {service_name} not found")
        
        # Check ownership
        is_owner = service_info.owner_token_hash == token_info["hash"]
        is_admin = token_info.get("name") == "ADMIN"
        if not (is_owner or is_admin):
            raise HTTPException(403, "Not authorized to control this service")
        
        try:
            await manager.stop_service(service_name)
            return {"message": f"Service {service_name} stopped"}
        except ValueError as e:
            raise HTTPException(404, str(e))
        except Exception as e:
            logger.error(f"Error stopping service {service_name}: {e}")
            raise HTTPException(500, f"Error stopping service: {str(e)}")
    
    @router.post("/{service_name}/restart")
    async def restart_service(
        service_name: str,
        token_info: Dict = Depends(get_token_info_from_header)
    ):
        """Restart a service."""
        manager = get_docker_manager()
        service_info = await manager.get_service(service_name)
        
        if not service_info:
            raise HTTPException(404, f"Service {service_name} not found")
        
        # Check ownership
        is_owner = service_info.owner_token_hash == token_info["hash"]
        is_admin = token_info.get("name") == "ADMIN"
        if not (is_owner or is_admin):
            raise HTTPException(403, "Not authorized to control this service")
        
        try:
            await manager.restart_service(service_name)
            return {"message": f"Service {service_name} restarted"}
        except ValueError as e:
            raise HTTPException(404, str(e))
        except Exception as e:
            logger.error(f"Error restarting service {service_name}: {e}")
            raise HTTPException(500, f"Error restarting service: {str(e)}")
    
    @router.get("/{service_name}/logs", response_model=DockerServiceLogs)
    async def get_service_logs(
        service_name: str,
        lines: int = Query(100, description="Number of log lines to return"),
        timestamps: bool = Query(False, description="Include timestamps"),
        token_info: Dict = Depends(require_auth)
    ):
        """Get service logs."""
        manager = get_docker_manager()
        service_info = await manager.get_service(service_name)
        
        if not service_info:
            raise HTTPException(404, f"Service {service_name} not found")
        
        # Check ownership (logs may contain sensitive info)
        is_owner = service_info.owner_token_hash == token_info["hash"]
        is_admin = token_info.get("name") == "ADMIN"
        if not (is_owner or is_admin):
            raise HTTPException(403, "Not authorized to view logs for this service")
        
        try:
            logs = await manager.get_service_logs(service_name, lines, timestamps)
            return DockerServiceLogs(
                service_name=service_name,
                logs=logs,
                timestamps=timestamps
            )
        except ValueError as e:
            raise HTTPException(404, str(e))
        except Exception as e:
            logger.error(f"Error getting logs for service {service_name}: {e}")
            raise HTTPException(500, f"Error getting logs: {str(e)}")
    
    @router.get("/{service_name}/stats", response_model=DockerServiceStats)
    async def get_service_stats(
        service_name: str,
        token_info: Dict = Depends(require_auth)
    ):
        """Get service resource statistics."""
        manager = get_docker_manager()
        service_info = await manager.get_service(service_name)
        
        if not service_info:
            raise HTTPException(404, f"Service {service_name} not found")
        
        try:
            stats = await manager.get_service_stats(service_name)
            return stats
        except ValueError as e:
            raise HTTPException(404, str(e))
        except Exception as e:
            logger.error(f"Error getting stats for service {service_name}: {e}")
            raise HTTPException(500, f"Error getting stats: {str(e)}")
    
    @router.post("/{service_name}/proxy")
    async def create_service_proxy(
        service_name: str,
        hostname: Optional[str] = None,
        enable_https: bool = Query(False, description="Enable HTTPS (requires certificate)"),
        token_info: Dict = Depends(get_token_info_from_header)
    ):
        """Create a proxy configuration for the service."""
        manager = get_docker_manager()
        service_info = await manager.get_service(service_name)
        
        if not service_info:
            raise HTTPException(404, f"Service {service_name} not found")
        
        # Check ownership
        is_owner = service_info.owner_token_hash == token_info["hash"]
        is_admin = token_info.get("name") == "ADMIN"
        if not (is_owner or is_admin):
            raise HTTPException(403, "Not authorized to create proxy for this service")
        
        # Determine hostname
        if not hostname:
            hostname = f"{service_name}.{Config.BASE_DOMAIN}"
        
        # Check if proxy already exists
        if storage.get_proxy_target(hostname):
            raise HTTPException(409, f"Proxy already exists for {hostname}")
        
        try:
            # Create proxy configuration
            proxy_config = ProxyTarget(
                hostname=hostname,
                target_url=f"http://{service_name}:{service_info.internal_port}",
                cert_name=f"cert-{service_name}" if enable_https else None,
                enabled=True,
                enable_http=True,
                enable_https=enable_https,
                owner_token_hash=token_info["hash"],
                preserve_host_header=True,
                created_at=datetime.now(timezone.utc)
            )
            
            storage.store_proxy_target(proxy_config.hostname, proxy_config)
            
            return {
                "message": f"Created proxy for service {service_name}",
                "hostname": hostname,
                "target_url": proxy_config.target_url
            }
            
        except Exception as e:
            logger.error(f"Error creating proxy for service {service_name}: {e}")
            raise HTTPException(500, f"Error creating proxy: {str(e)}")
    
    
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
    
    return router