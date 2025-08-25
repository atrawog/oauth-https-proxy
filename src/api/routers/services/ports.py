"""Service port management endpoints with async support.

This module handles port allocation and management for services.
"""

import hashlib
import logging
from typing import Dict, List
from fastapi import APIRouter, Depends, HTTPException, Query, Request

from src.ports.models import ServicePort, PortConfiguration
from src.docker.manager import DockerManager

logger = logging.getLogger(__name__)


def create_ports_router(async_storage) -> APIRouter:
    """Create router for port management operations.
    
    All endpoints use async patterns with Request parameter.
    
    Args:
        async_storage: Redis async_storage instance
    
    Returns:
        APIRouter with port management endpoints
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
        
        # Docker manager is optional for ports
        return None
    
    @router.get("/ports", response_model=Dict[int, Dict])
    async def list_all_ports(
        request: Request
    ):
        """List all allocated ports across all services."""
        manager = await get_docker_manager(request)
        
        # Check if docker manager is available
        if manager is None:
            return {}  # Return empty dict if no docker manager
        
        try:
            ports = await manager.get_all_allocated_ports()
            return ports
        except Exception as e:
            logger.error(f"Error listing all ports: {e}")
            raise HTTPException(500, f"Error listing ports: {str(e)}")
    
    @router.get("/ports/available", response_model=List[Dict])
    async def get_available_port_ranges(
        request: Request
    ):
        """Get available port ranges."""
        manager = await get_docker_manager(request)
        
        # Check if docker manager is available
        if manager is None:
            return []  # Return empty list if no docker manager
        
        try:
            ranges = await manager.get_available_port_ranges()
            return ranges
        except Exception as e:
            logger.error(f"Error getting available port ranges: {e}")
            raise HTTPException(500, f"Error getting port ranges: {str(e)}")
    
    @router.post("/ports/check")
    async def check_port_availability(
        request: Request,
        port: int = Query(..., description="Port number to check"),
        bind_address: str = Query("0.0.0.0", description="Bind address")
    ):
        """Check if a specific port is available."""
        manager = await get_docker_manager(request)
        
        # Check if docker manager is available
        if manager is None:
            return {
                "port": port,
                "bind_address": bind_address,
                "available": False,
                "message": "Docker manager not available"
            }
        
        try:
            is_available = await manager.is_port_available(port, bind_address)
            return {
                "port": port,
                "bind_address": bind_address,
                "available": is_available
            }
        except Exception as e:
            logger.error(f"Error checking port availability: {e}")
            raise HTTPException(500, f"Error checking port: {str(e)}")
    
    @router.post("/{service_name}/ports", response_model=ServicePort)
    async def add_service_port(
        request: Request,
        service_name: str,
        port_config: PortConfiguration
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
                config_dict['source_token_hash'] = hashlib.sha256(port_config.token.encode()).hexdigest()
                config_dict['source_token_name'] = f"port-{port_config.name}"
            
            service_port = await manager.add_port_to_service(
                service_name, 
                config_dict, 
                None  # No token ownership
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
        service_name: str
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
        port_name: str
    ):
        """Remove a port from a service.
        
        This will recreate the container without the specified port.
        """
        manager = await get_docker_manager(request)
        
        try:
            success = await manager.remove_port_from_service(
                service_name, 
                port_name, 
                None  # No token ownership
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
        port_config: PortConfiguration
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
                None  # No token ownership
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
                config_dict['source_token_hash'] = hashlib.sha256(port_config.token.encode()).hexdigest()
                config_dict['source_token_name'] = f"port-{port_config.name}"
            
            service_port = await manager.add_port_to_service(
                service_name, 
                config_dict, 
                None  # No token ownership
            )
            
            return {"message": f"Port {port_name} updated", "port": service_port}
            
        except ValueError as e:
            raise HTTPException(400, str(e))
        except Exception as e:
            logger.error(f"Error updating port for service {service_name}: {e}")
            raise HTTPException(500, f"Error updating port: {str(e)}")
    
    return router