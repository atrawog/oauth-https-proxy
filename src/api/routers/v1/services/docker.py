"""Docker service management endpoints with async support.

This module handles all Docker container lifecycle operations.
"""

import logging
from datetime import datetime, timezone
from typing import Dict, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response
from python_on_whales.exceptions import DockerException

from src.auth import AuthDep, AuthResult
from src.docker.models import (
    DockerServiceConfig,
    DockerServiceInfo,
    DockerServiceUpdate,
    DockerServiceLogs,
    DockerServiceStats,
    DockerServiceListResponse,
    DockerServiceCreateResponse
)
from src.docker.manager import DockerManager
from src.proxy.models import ProxyTarget
from src.shared.config import Config

logger = logging.getLogger(__name__)


def create_docker_router(async_storage) -> APIRouter:
    """Create router for Docker service operations.
    
    All endpoints use async patterns with Request parameter.
    
    Args:
        async_storage: Async Redis storage instance

    
    Returns:
        APIRouter with Docker service endpoints
    """
    router = APIRouter()
    
    async def get_docker_manager(request: Request):
        """Get async Docker manager from app state ONLY."""
        # Try direct app.state first
        if hasattr(request.app.state, 'docker_manager'):
            manager = request.app.state.docker_manager
            if manager is not None:
                return manager
        
        # Try async_components
        if hasattr(request.app.state, 'async_components'):
            components = request.app.state.async_components
            if components and hasattr(components, 'docker_manager'):
                manager = components.docker_manager
                if manager is not None:
                    return manager
        
        # No manager available
        raise HTTPException(503, "Docker service not initialized")
    
    @router.get("/", response_model=DockerServiceListResponse)
    async def list_services(
        request: Request,
        owned_only: bool = Query(False, description="Only show services owned by current token"),
        auth: AuthResult = Depends(AuthDep())
    ):
        """List all Docker services."""
        manager = await get_docker_manager(request)
        
        # Filter by owner if requested
        owner_hash = token_info["hash"] if owned_only else None
        services = await manager.list_services(owner_hash)
        
        return DockerServiceListResponse(
            services=services,
            total=len(services)
        )
    
    @router.post("/", response_model=DockerServiceCreateResponse)
    async def create_service(
        request: Request,
        config: DockerServiceConfig,
        auto_proxy: bool = Query(False, description="Automatically create proxy configuration"),
        auth: AuthResult = Depends(AuthDep())
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
        manager = await get_docker_manager(request)
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
                    
                    # Get async async_storage if available
                    async_storage = request.app.state.async_storage
                    await async_storage.store_proxy_target(proxy_config.hostname, proxy_config)
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
    
    @router.get("/{service_name}", response_model=DockerServiceInfo)
    async def get_service(
        request: Request,
        service_name: str,
        token_info: Dict = Depends(require_auth)
    ):
        """Get information about a specific service."""
        manager = await get_docker_manager(request)
        service_info = await manager.get_service(service_name)
        
        if not service_info:
            raise HTTPException(404, f"Service {service_name} not found")
        
        return service_info
    
    @router.put("/{service_name}", response_model=DockerServiceInfo)
    async def update_service(
        request: Request,
        service_name: str,
        updates: DockerServiceUpdate,
        auth: AuthResult = Depends(AuthDep())
    ):
        """Update a Docker service configuration.
        
        Note: Some updates require container recreation.
        """
        manager = await get_docker_manager(request)
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
        request: Request,
        service_name: str,
        force: bool = Query(False, description="Force delete even if running"),
        delete_proxy: bool = Query(True, description="Also delete associated proxy"),
        auth: AuthResult = Depends(AuthDep())
    ):
        """Delete a Docker service and cleanup resources."""
        manager = await get_docker_manager(request)
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
                
                # Get async async_storage if available
                async_storage = request.app.state.async_storage
                proxy_target = await async_storage.get_proxy_target(proxy_hostname)
                if proxy_target:
                    await async_storage.delete_proxy_target(proxy_hostname)
                    logger.info(f"Deleted proxy for service {service_name}")
            return Response(status_code=204)
            
        except ValueError as e:
            raise HTTPException(400, str(e))
        except Exception as e:
            logger.error(f"Error deleting service {service_name}: {e}")
            raise HTTPException(500, f"Error deleting service: {str(e)}")
    
    @router.post("/{service_name}/start")
    async def start_service(
        request: Request,
        service_name: str,
        auth: AuthResult = Depends(AuthDep())
    ):
        """Start a stopped service."""
        manager = await get_docker_manager(request)
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
        request: Request,
        service_name: str,
        auth: AuthResult = Depends(AuthDep())
    ):
        """Stop a running service."""
        manager = await get_docker_manager(request)
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
        request: Request,
        service_name: str,
        auth: AuthResult = Depends(AuthDep())
    ):
        """Restart a service."""
        manager = await get_docker_manager(request)
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
        request: Request,
        service_name: str,
        lines: int = Query(100, description="Number of log lines to return"),
        timestamps: bool = Query(False, description="Include timestamps"),
        token_info: Dict = Depends(require_auth)
    ):
        """Get service logs."""
        manager = await get_docker_manager(request)
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
        request: Request,
        service_name: str,
        token_info: Dict = Depends(require_auth)
    ):
        """Get service resource statistics."""
        manager = await get_docker_manager(request)
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
    
    return router