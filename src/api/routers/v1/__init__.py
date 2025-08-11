"""API v1 router aggregator."""

from fastapi import APIRouter
import logging

logger = logging.getLogger(__name__)


def create_v1_router(app) -> APIRouter:
    """
    Create the v1 API router that aggregates all versioned endpoints.
    
    This router will be mounted at /api/v1 in the main app.
    All sub-routers should not include their own version prefix.
    """
    # Get dependencies from app state
    async_storage = app.state.async_storage if hasattr(app.state, 'async_storage') else app.state.storage
    cert_manager = app.state.cert_manager
    storage = app.state.storage  # Still needed for some routers
    # Docker manager comes from async_components, not passed directly
    
    # Import v1 endpoint modules
    from . import (
        certificates,
        proxies, 
        tokens,
        routes,
        resources,
        oauth_status,
        oauth_admin,
        services,
        logs
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
        prefix="/certificates"
    )
    logger.info("Included certificates router in v1")
    
    # Proxy endpoints: /api/v1/proxy/targets/*
    # Note: proxies router already has /targets prefix, so we use /proxy
    v1_router.include_router(
        proxies.create_router(async_storage, cert_manager),
        prefix="/proxy"
    )
    logger.info("Included proxies router in v1")
    
    # Token endpoints: /api/v1/tokens/*
    v1_router.include_router(
        tokens.create_tokens_router(async_storage),
        prefix="/tokens"
    )
    logger.info("Included tokens router in v1")
    
    # Route endpoints: /api/v1/routes/*
    v1_router.include_router(
        routes.create_router(async_storage),
        prefix="/routes"
    )
    logger.info("Included routes router in v1")
    
    # Note: Instance endpoints have been deprecated and merged into services
    # Use /api/v1/services/external for external service registration (formerly instances)
    
    # MCP Resource endpoints: /api/v1/resources/*
    v1_router.include_router(
        resources.create_router(storage),
        prefix="/resources"
    )
    logger.info("Included resources router in v1")
    
    # Docker service endpoints: /api/v1/services/*
    try:
        v1_router.include_router(
            services.create_services_router(async_storage),
            prefix="/services"
        )
        logger.info("Included services router in v1")
    except Exception as e:
        logger.warning(f"Docker service endpoints not available: {e}")
    
    # OAuth status endpoints: /api/v1/oauth/*
    # Note: These are management endpoints, not OAuth protocol endpoints
    try:
        oauth_status_router = oauth_status.create_oauth_status_router(storage)
        v1_router.include_router(
            oauth_status_router,
            prefix="/oauth"
        )
        logger.info("Included OAuth status router in v1")
    except Exception as e:
        logger.warning(f"OAuth status endpoints not available: {e}")
    
    # OAuth admin endpoints: /api/v1/oauth/admin/*
    # Note: oauth_admin router already has /admin prefix, so we use /oauth
    try:
        v1_router.include_router(
            oauth_admin.create_router(storage),
            prefix="/oauth"
        )
        logger.info("Included OAuth admin router in v1")
    except Exception as e:
        logger.warning(f"OAuth admin endpoints not available: {e}")
    
    # Log query endpoints: /api/v1/logs/*
    try:
        logs_router = logs.create_logs_router(async_storage)
        v1_router.include_router(
            logs_router,
            prefix="/logs"
        )
        logger.info("Included logs router in v1")
    except Exception as e:
        logger.warning(f"Log query endpoints not available: {e}")
    
    return v1_router