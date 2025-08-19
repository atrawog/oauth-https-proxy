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
        logs,
        auth_config
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
    
    # MCP endpoints: /api/v1/mcp/*
    try:
        # Get unified logger from app if available
        unified_logger = None
        if hasattr(app.state, 'async_components') and app.state.async_components:
            unified_logger = app.state.async_components.unified_logger
        
        if unified_logger:
            logger.info("Attempting to import MCP router...")
            # Try the working router first (no auth, actually works)
            try:
                from src.mcp.mcp_working import create_mcp_working_router
                logger.info("MCP WORKING router imported successfully - NO AUTH REQUIRED")
                mcp_router = create_mcp_working_router(async_storage, unified_logger)
            except ImportError as e_working:
                logger.debug(f"Could not import working router: {e_working}")
                # Try the simple SSE router second (no auth, no SDK dependencies)
                try:
                    from src.mcp.mcp_sse_simple import create_mcp_sse_simple_router
                    logger.info("MCP simple SSE router module imported successfully - NO AUTH")
                    mcp_router = create_mcp_sse_simple_router(async_storage, unified_logger)
                except ImportError as e0:
                    logger.debug(f"Could not import simple SSE router: {e0}")
                # Try the official SDK SSE router second
                try:
                    from src.mcp.mcp_sse_official import create_mcp_sse_official_router
                    logger.info("MCP official SSE router module imported successfully")
                    mcp_router = create_mcp_sse_official_router(async_storage, unified_logger)
                except ImportError as e1:
                    logger.debug(f"Could not import official SSE router: {e1}")
                    # Try the new SSE-compliant router third
                    try:
                        from src.mcp.mcp_sse_router import create_mcp_sse_router
                        logger.info("MCP SSE router module imported successfully")
                        mcp_router = create_mcp_sse_router(async_storage, unified_logger)
                    except ImportError as e2:
                        logger.debug(f"Could not import SSE router: {e2}")
                        # Fall back to regular router
                        from src.mcp.router import create_mcp_router
                        logger.info("MCP router module imported successfully")
                        mcp_router = create_mcp_router(async_storage, unified_logger)
            
            v1_router.include_router(
                mcp_router,
                prefix="/mcp"
            )
            logger.info("Included MCP router in v1")
        else:
            logger.warning("MCP endpoints not available: unified_logger not initialized")
    except ImportError as e:
        logger.warning(f"MCP endpoints not available: {e}")
        import traceback
        logger.debug(f"Import traceback: {traceback.format_exc()}")
    except Exception as e:
        logger.warning(f"Error initializing MCP endpoints: {e}")
        import traceback
        logger.debug(f"Error traceback: {traceback.format_exc()}")
    
    # Authentication configuration endpoints: /api/v1/auth-config/*
    try:
        auth_config_router = auth_config.create_auth_config_router(async_storage)
        v1_router.include_router(
            auth_config_router,
            prefix="/auth-config"
        )
        logger.info("Included auth-config router in v1")
    except Exception as e:
        logger.warning(f"Auth config endpoints not available: {e}")
    
    return v1_router