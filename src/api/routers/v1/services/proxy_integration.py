"""Service proxy integration endpoints with async support.

This module handles creating proxy configurations for services.
"""

import logging
from typing import Dict, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, Request

from src.api.auth import get_token_info_from_header
from src.docker.manager import DockerManager
from src.proxy.models import ProxyTarget
from src.shared.config import Config

logger = logging.getLogger(__name__)


def create_proxy_integration_router(storage) -> APIRouter:
    """Create router for service proxy integration.
    
    All endpoints use async patterns with Request parameter.
    
    Args:
        storage: Redis storage instance
    
    Returns:
        APIRouter with proxy integration endpoints
    """
    router = APIRouter()
    
    async def get_docker_manager(request: Request) -> DockerManager:
        """Get Docker manager instance from app state."""
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
        
        # Docker manager is optional
        return None
    
    @router.post("/{service_name}/proxy")
    async def create_service_proxy(
        request: Request,
        service_name: str,
        hostname: Optional[str] = None,
        enable_https: bool = Query(False, description="Enable HTTPS (requires certificate)"),
        token_info: Dict = Depends(get_token_info_from_header)
    ):
        """Create a proxy configuration for the service."""
        manager = await get_docker_manager(request)
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
        # Get async async_storage if available
        async_storage = request.app.state.async_storage
        
        existing_proxy = await request.app.state.async_storage.get_proxy_target(hostname)
        if existing_proxy:
            raise HTTPException(409, f"Proxy for hostname {hostname} already exists")
        
        try:
            # Determine target URL - use internal port
            target_port = service_info.internal_port
            if not target_port:
                # Try to get from port configs
                ports = await manager.get_service_ports(service_name)
                if ports:
                    target_port = ports[0].container_port
                else:
                    raise ValueError("Service has no exposed ports")
            
            target_url = f"http://{service_name}:{target_port}"
            
            # Create proxy configuration
            proxy_config = ProxyTarget(
                hostname=hostname,
                target_url=target_url,
                cert_name=f"cert-{service_name}" if enable_https else None,
                enabled=True,
                enable_http=True,
                enable_https=enable_https,
                owner_token_hash=token_info["hash"],
                preserve_host_header=True,
                created_by=token_info.get("name", "unknown")
            )
            
            # Store proxy configuration
            success = await request.app.state.async_storage.store_proxy_target(hostname, proxy_config)
            if not success:
                raise HTTPException(500, "Failed to store proxy configuration")
            
            logger.info(f"Created proxy for service {service_name} at {hostname}")
            
            return {
                "message": f"Proxy created for service {service_name}",
                "hostname": hostname,
                "target_url": target_url,
                "enable_https": enable_https
            }
            
        except ValueError as e:
            raise HTTPException(400, str(e))
        except Exception as e:
            logger.error(f"Error creating proxy for service {service_name}: {e}")
            raise HTTPException(500, f"Error creating proxy: {str(e)}")
    
    return router