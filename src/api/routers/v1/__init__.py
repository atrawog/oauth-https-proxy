"""API v1 router aggregator."""

from fastapi import APIRouter
import logging

logger = logging.getLogger(__name__)


def create_v1_router(storage, cert_manager) -> APIRouter:
    """
    Create the v1 API router that aggregates all versioned endpoints.
    
    This router will be mounted at /api/v1 in the main app.
    All sub-routers should not include their own version prefix.
    """
    # Import v1 endpoint modules
    from . import (
        certificates,
        proxies, 
        tokens,
        routes,
        instances,
        resources,
        oauth_status,
        oauth_admin
    )
    
    # Create main v1 router (no prefix here, it's added when mounting)
    v1_router = APIRouter(
        responses={
            404: {"description": "Not found"},
            401: {"description": "Unauthorized - Bearer token required"},
            403: {"description": "Forbidden - Insufficient permissions"},
        }
    )
    
    # Include all endpoint routers with their specific paths
    
    # Certificate endpoints: /api/v1/certificates/*
    v1_router.include_router(
        certificates.create_router(storage, cert_manager),
        prefix="/certificates",
        tags=["certificates"]
    )
    logger.info("Included certificates router in v1")
    
    # Proxy endpoints: /api/v1/proxy/targets/*
    # Note: proxies router already has /targets prefix, so we use /proxy
    v1_router.include_router(
        proxies.create_router(storage, cert_manager),
        prefix="/proxy",
        tags=["proxies"]
    )
    logger.info("Included proxies router in v1")
    
    # Token endpoints: /api/v1/tokens/*
    v1_router.include_router(
        tokens.create_router(storage),
        prefix="/tokens",
        tags=["tokens"]
    )
    logger.info("Included tokens router in v1")
    
    # Route endpoints: /api/v1/routes/*
    v1_router.include_router(
        routes.create_router(storage),
        prefix="/routes",
        tags=["routes"]
    )
    logger.info("Included routes router in v1")
    
    # Instance endpoints: /api/v1/instances/*
    v1_router.include_router(
        instances.create_router(storage),
        prefix="/instances",
        tags=["instances"]
    )
    logger.info("Included instances router in v1")
    
    # MCP Resource endpoints: /api/v1/resources/*
    v1_router.include_router(
        resources.create_router(storage),
        prefix="/resources",
        tags=["mcp-resources"]
    )
    logger.info("Included resources router in v1")
    
    # OAuth status endpoints: /api/v1/oauth/*
    # Note: These are management endpoints, not OAuth protocol endpoints
    try:
        oauth_status_router = oauth_status.create_oauth_status_router(storage)
        v1_router.include_router(
            oauth_status_router,
            prefix="/oauth",
            tags=["oauth-status"]
        )
        logger.info("Included OAuth status router in v1")
    except Exception as e:
        logger.warning(f"OAuth status endpoints not available: {e}")
    
    # OAuth admin endpoints: /api/v1/oauth/admin/*
    # Note: oauth_admin router already has /admin prefix, so we use /oauth
    try:
        v1_router.include_router(
            oauth_admin.create_router(storage),
            prefix="/oauth",
            tags=["oauth-admin"]
        )
        logger.info("Included OAuth admin router in v1")
    except Exception as e:
        logger.warning(f"OAuth admin endpoints not available: {e}")
    
    return v1_router