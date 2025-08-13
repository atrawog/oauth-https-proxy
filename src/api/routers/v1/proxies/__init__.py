"""Proxies router module - aggregates all proxy-related endpoints.

This module splits proxy management into logical sub-modules:
- core: Basic CRUD operations for proxy targets
- auth: Authentication configuration for proxies
- routes: Route management for proxies
- resources: MCP resource configuration
- oauth_server: OAuth authorization server configuration
"""

from fastapi import APIRouter
import logging

logger = logging.getLogger(__name__)


def create_router(async_storage, cert_manager):
    """Create the aggregated proxies router.
    
    Args:
        async_storage: Redis async_storage instance (legacy, will use async from request)
        cert_manager: Certificate manager instance (legacy, will use async from request)
    
    Returns:
        APIRouter with all proxy endpoints
    """
    from .core import create_core_router
    from .auth import create_auth_router
    from .routes import create_routes_router
    from .resources import create_resources_router
    from .oauth_server import create_oauth_server_router
    
    # Create main router with /targets prefix
    router = APIRouter(prefix="/targets", tags=["proxy"])
    
    # Include sub-routers
    core_router = create_core_router(async_storage, cert_manager)
    auth_router = create_auth_router(async_storage)
    routes_router = create_routes_router(async_storage)
    resources_router = create_resources_router(async_storage)
    oauth_server_router = create_oauth_server_router(async_storage)
    
    # Mount sub-routers
    router.include_router(core_router)
    router.include_router(auth_router)
    router.include_router(routes_router)
    router.include_router(resources_router)
    router.include_router(oauth_server_router)
    
    logger.info("Proxies router initialized with modular structure")
    
    return router