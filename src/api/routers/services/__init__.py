"""Service management router aggregation.

This module combines all service-related sub-routers into a single router.
"""

from fastapi import APIRouter

from .docker import create_docker_router
from .external import create_external_router
from .ports import create_ports_router
from .proxy_integration import create_proxy_integration_router
from .cleanup import create_cleanup_router


def create_services_router(async_storage):
    """Create the main services router combining all sub-routers.
    
    Args:
        async_storage: Redis async_storage instance
    
    Returns:
        APIRouter with all service endpoints
    """
    router = APIRouter()
    
    # Include sub-routers
    # IMPORTANT: External router must be included BEFORE docker router
    # because docker router has a catch-all /{service_name} pattern
    external_router = create_external_router(async_storage)
    router.include_router(external_router, tags=["external"])
    
    docker_router = create_docker_router(async_storage)
    router.include_router(docker_router, tags=["docker"])
    
    ports_router = create_ports_router(async_storage)
    router.include_router(ports_router, tags=["ports"])
    
    proxy_router = create_proxy_integration_router(async_storage)
    router.include_router(proxy_router, tags=["proxy-integration"])
    
    cleanup_router = create_cleanup_router(async_storage)
    router.include_router(cleanup_router, tags=["cleanup"])
    
    return router