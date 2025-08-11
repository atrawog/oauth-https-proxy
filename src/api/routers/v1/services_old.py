"""Service management API endpoints (Docker and external services)."""

import json
import logging
from datetime import datetime, timezone
from typing import Dict, List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response
from python_on_whales.exceptions import DockerException

from src.api.auth import require_auth, get_token_info_from_header
from src.docker.models import (
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
from src.docker.manager import DockerManager
from src.proxy.models import ProxyTarget
from src.shared.config import Config
from ....ports import ServicePort, PortConfiguration

logger = logging.getLogger(__name__)


def create_router(storage) -> APIRouter:
    """Create the services API router (Docker and external)."""
    router = APIRouter(tags=["services"])
    
    # Create Docker manager instance
    docker_manager = None
    
    async def get_docker_manager(request: Request) -> DockerManager:
        """Get Docker manager instance.
        
        Try to get async manager from app state first, fallback to sync manager.
        """
        # Try to get async manager from app state
        if hasattr(request.app.state, 'async_components'):
            async_components = request.app.state.async_components
            if async_components and hasattr(async_components, 'docker_manager'):
                return async_components.docker_manager
        
        # Fallback to sync manager
        nonlocal docker_manager
        if docker_manager is None:
            docker_manager = DockerManager(storage)
        return docker_manager
    
    @router.get("/", response_model=DockerServiceListResponse)
    async def list_services(
        request: Request,
        owned_only: bool = Query(False, description="Only show services owned by current token"),
        token_info: Dict = Depends(get_token_info_from_header)
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
    

    @router.get("/unified", response_model=UnifiedServiceListResponse)
    async def list_all_services(
        request: Request,
        service_type: Optional[ServiceType] = Query(None, description="Filter by service type"),
        token_info: Optional[Dict] = Depends(get_token_info_from_header)
    ):
        """List all services (Docker and external)."""
        try:
            all_services = []
            
            # Get Docker services
            if not service_type or service_type == ServiceType.DOCKER:
                manager = await get_docker_manager(request)
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
                external_services = await list_external_services()
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
    

    @router.post("/external", response_model=UnifiedServiceInfo)
    async def register_external_service(
        request: Request,
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
            
            # Sort by name
            services.sort(key=lambda x: x.service_name)
            return services
            
        except Exception as e:
            logger.error(f"Failed to list external services: {e}")
            raise HTTPException(500, f"Failed to list services: {str(e)}")
    

    @router.post("/cleanup")
    async def cleanup_orphaned_services(
        request: Request,
        token_info: Dict = Depends(get_token_info_from_header)
    ):
        """Clean up orphaned Docker resources (admin only)."""
        # Check admin permission
        if token_info.get("name") != "ADMIN":
            raise HTTPException(403, "Admin token required")
        
        try:
            manager = await get_docker_manager(request)
            await manager.cleanup_orphaned_services()
            return {"message": "Cleanup completed successfully"}
        except Exception as e:
            logger.error(f"Error during cleanup: {e}")
            raise HTTPException(500, f"Error during cleanup: {str(e)}")
    
    # Global port management endpoints (replaces /api/v1/ports/)
    
    @router.get("/ports", response_model=Dict[int, Dict])
    async def list_all_allocated_ports(
        request: Request,
        token_info: Dict = Depends(require_auth)
    ):
        """List all allocated ports across all services."""
        try:
            from ....ports import PortManager
            port_manager = PortManager(storage)
            ports = await port_manager.get_allocated_ports()
            return ports
        except Exception as e:
            logger.error(f"Error listing allocated ports: {e}")
            raise HTTPException(500, f"Error listing ports: {str(e)}")
    
    @router.get("/ports/available", response_model=List[Dict])
    async def list_available_port_ranges(
        request: Request,
        token_info: Dict = Depends(require_auth)
    ):
        """Get ranges of available ports."""
        try:
            from ....ports import PortManager
            port_manager = PortManager(storage)
            ranges = await port_manager.get_available_port_ranges()
            
            # Format ranges for response
            result = []
            for start, end in ranges:
                if end - start >= 10:  # Only show ranges with at least 10 ports
                    result.append({
                        "start": start,
                        "end": end,
                        "count": end - start + 1
                    })
            return result
        except Exception as e:
            logger.error(f"Error getting available port ranges: {e}")
            raise HTTPException(500, f"Error getting port ranges: {str(e)}")
    
    @router.post("/ports/check")
    async def check_port_availability(
        request: Request,
        port: int = Query(..., ge=1, le=65535),
        bind_address: str = Query("127.0.0.1"),
        token_info: Dict = Depends(require_auth)
    ):
        """Check if a specific port is available."""
        try:
            from ....ports import PortManager
            port_manager = PortManager(storage)
            available = await port_manager.is_port_available(port, bind_address)
            
            response = {
                "port": port,
                "available": available,
                "bind_address": bind_address
            }
            
            if not available:
                if port in port_manager.RESTRICTED_PORTS:
                    response["reason"] = "Port is restricted by system policy"
                else:
                    response["reason"] = "Port is already allocated"
            
            return response
            
        except Exception as e:
            logger.error(f"Error checking port availability: {e}")
            raise HTTPException(500, f"Error checking port: {str(e)}")
    
    # Service-specific endpoints
    
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
        token_info: Dict = Depends(get_token_info_from_header)
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
        token_info: Dict = Depends(get_token_info_from_header)
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
        request: Request,
        service_name: str,
        token_info: Dict = Depends(get_token_info_from_header)
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
        token_info: Dict = Depends(get_token_info_from_header)
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
        token_info: Dict = Depends(get_token_info_from_header)
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
    
    

    @router.post("/{service_name}/ports", response_model=ServicePort)
    async def add_service_port(
        request: Request,
        service_name: str,
        port_config: PortConfiguration,
        token_info: Dict = Depends(get_token_info_from_header)
    ):
        """Add a port to an existing service.
        
        This will recreate the container with the new port configuration.
        """
        manager = await get_docker_manager(request)
        
        try:
            # Convert PortConfiguration to dict format expected by manager
            config_dict = {
                'name': port_config.name,
                'host': port_config.host,
                'container': port_config.container,
                'bind': port_config.bind,
                'protocol': port_config.protocol,
                'source_token': port_config.token,
                'description': port_config.description
            }
            
            # Create source token hash if token provided
            if port_config.token:
                import hashlib
                config_dict['source_token_hash'] = hashlib.sha256(port_config.token.encode()).hexdigest()
                config_dict['source_token_name'] = f"port-{port_config.name}"
            
            service_port = await manager.add_port_to_service(
                service_name, 
                config_dict, 
                token_info["hash"]
            )
            return service_port
            
        except ValueError as e:
            raise HTTPException(400, str(e))
        except Exception as e:
            logger.error(f"Error adding port to service {service_name}: {e}")
            raise HTTPException(500, f"Error adding port: {str(e)}")
    

    @router.get("/{service_name}/ports", response_model=List[ServicePort])
    async def list_service_ports(
        request: Request,
        service_name: str,
        token_info: Dict = Depends(require_auth)
    ):
        """Get all ports for a service."""
        manager = await get_docker_manager(request)
        
        # Check if service exists
        service_info = await manager.get_service(service_name)
        if not service_info:
            raise HTTPException(404, f"Service {service_name} not found")
        
        try:
            ports = await manager.get_service_ports(service_name)
            return ports
        except Exception as e:
            logger.error(f"Error getting ports for service {service_name}: {e}")
            raise HTTPException(500, f"Error getting ports: {str(e)}")
    

    @router.delete("/{service_name}/ports/{port_name}")
    async def remove_service_port(
        request: Request,
        service_name: str,
        port_name: str,
        token_info: Dict = Depends(get_token_info_from_header)
    ):
        """Remove a port from a service.
        
        This will recreate the container without the specified port.
        """
        manager = await get_docker_manager(request)
        
        try:
            success = await manager.remove_port_from_service(
                service_name, 
                port_name, 
                token_info["hash"]
            )
            if success:
                return {"message": f"Port {port_name} removed from service {service_name}"}
            else:
                raise HTTPException(404, f"Port {port_name} not found")
                
        except ValueError as e:
            raise HTTPException(400, str(e))
        except Exception as e:
            logger.error(f"Error removing port from service {service_name}: {e}")
            raise HTTPException(500, f"Error removing port: {str(e)}")
    

    @router.put("/{service_name}/ports/{port_name}")
    async def update_service_port(
        request: Request,
        service_name: str,
        port_name: str,
        port_config: PortConfiguration,
        token_info: Dict = Depends(get_token_info_from_header)
    ):
        """Update a port configuration.
        
        This will remove the old port and add a new one with updated settings.
        """
        manager = await get_docker_manager(request)
        
        try:
            # Remove old port
            await manager.remove_port_from_service(
                service_name, 
                port_name, 
                token_info["hash"]
            )
            
            # Add new port with updated config
            config_dict = {
                'name': port_config.name,
                'host': port_config.host,
                'container': port_config.container,
                'bind': port_config.bind,
                'protocol': port_config.protocol,
                'source_token': port_config.token,
                'description': port_config.description
            }
            
            if port_config.token:
                import hashlib
                config_dict['source_token_hash'] = hashlib.sha256(port_config.token.encode()).hexdigest()
                config_dict['source_token_name'] = f"port-{port_config.name}"
            
            service_port = await manager.add_port_to_service(
                service_name, 
                config_dict, 
                token_info["hash"]
            )
            
            return {"message": f"Port {port_name} updated", "port": service_port}
            
        except ValueError as e:
            raise HTTPException(400, str(e))
        except Exception as e:
            logger.error(f"Error updating port for service {service_name}: {e}")
            raise HTTPException(500, f"Error updating port: {str(e)}")
    
    # External service endpoints (replaces instance endpoints)
    

    @router.delete("/external/{service_name}")
    async def unregister_external_service(
        request: Request,
        service_name: str,
        token_info: Dict = Depends(get_token_info_from_header)
    ):
        """Unregister an external service."""
        try:
            # Check if service exists
            service_data = storage.redis_client.get(f"service:external:{service_name}")
            if not service_data:
                raise HTTPException(404, f"Service '{service_name}' not found")
            
            # Check ownership
            if service_data:
                service_info = UnifiedServiceInfo.parse_raw(service_data)
                is_owner = service_info.owner_token_hash == token_info["hash"]
                is_admin = token_info.get("name") == "ADMIN"
                if not (is_owner or is_admin):
                    raise HTTPException(403, "Not authorized to delete this service")
            
            # Check if any routes reference this service
            routes_using_service = []
            for key in storage.redis_client.scan_iter(match="route:*"):
                if key.startswith("route:priority:") or key.startswith("route:unique:"):
                    continue
                route_data = storage.redis_client.get(key)
                if route_data and f'"target_value": "{service_name}"' in route_data:
                    routes_using_service.append(key.split(":")[-1])
            
            if routes_using_service:
                raise HTTPException(
                    400, 
                    f"Cannot delete service '{service_name}' - used by routes: {', '.join(routes_using_service[:5])}"
                )
            
            # Delete service
            storage.redis_client.delete(f"service:external:{service_name}")
            storage.redis_client.delete(f"service:url:{service_name}")
            storage.redis_client.srem("services:external", service_name)
            
            logger.info(f"Unregistered external service '{service_name}'")
            return Response(status_code=204)
            
        except HTTPException:
            raise
        except Exception as e:
            logger.error(f"Failed to unregister service: {e}")
            raise HTTPException(500, f"Failed to unregister service: {str(e)}")
    

    return router