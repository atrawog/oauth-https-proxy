"""API router aggregator."""

from fastapi import APIRouter
import logging

logger = logging.getLogger(__name__)


def create_api_router(app) -> APIRouter:
    """
    Create the main API router that aggregates all endpoints.
    
    This router organizes endpoints by their actual API paths,
    with the directory structure matching the URL structure.
    """
    # Get dependencies from app state
    async_storage = app.state.async_storage if hasattr(app.state, 'async_storage') else app.state.storage
    cert_manager = app.state.cert_manager
    storage = app.state.storage  # Still needed for some routers
    
    # Create main API router
    api_router = APIRouter(
        responses={
            404: {"description": "Not found"},
            401: {"description": "Unauthorized - Bearer token required"},
            403: {"description": "Forbidden - Insufficient permissions"},
        }
    )
    
    # Include all endpoint routers from their new locations
    
    # Certificate endpoints: /certificates/*
    from .certificates.certificates import create_router as create_certificates_router
    api_router.include_router(
        create_certificates_router(storage, cert_manager),
        prefix="/certificates"
    )
    logger.info("Included certificates router")
    
    # Proxy endpoints: /proxy/*
    from .proxy import create_router as create_proxy_router
    api_router.include_router(
        create_proxy_router(async_storage, cert_manager),
        prefix="/proxy"
    )
    logger.info("Included proxy router")
    
    # Token endpoints: /tokens/*
    from .tokens import create_tokens_router
    api_router.include_router(
        create_tokens_router(async_storage),
        prefix="/tokens"
    )
    logger.info("Included tokens router")
    
    # Route endpoints: /routes/*
    from .routes.routes import create_router as create_routes_router
    api_router.include_router(
        create_routes_router(async_storage),
        prefix="/routes"
    )
    logger.info("Included routes router")
    
    # Route auth endpoints (also under /routes)
    from .routes.route_auth import create_route_auth_router
    api_router.include_router(
        create_route_auth_router(async_storage),
        prefix="/routes"
    )
    logger.info("Included route auth router")
    
    # Resource endpoints: /resources/*
    from .resources.resources import create_router as create_resources_router
    api_router.include_router(
        create_resources_router(storage),
        prefix="/resources"
    )
    logger.info("Included resources router")
    
    # Docker service endpoints: /services/*
    try:
        from .services import create_services_router
        api_router.include_router(
            create_services_router(async_storage),
            prefix="/services"
        )
        logger.info("Included services router")
    except Exception as e:
        logger.warning(f"Docker service endpoints not available: {e}")
    
    # OAuth status endpoints: /oauth/*
    try:
        from .oauth.oauth_status import create_oauth_status_router
        oauth_status_router = create_oauth_status_router(storage)
        api_router.include_router(
            oauth_status_router,
            prefix="/oauth"
        )
        logger.info("Included OAuth status router")
    except Exception as e:
        logger.warning(f"OAuth status endpoints not available: {e}")
    
    # OAuth admin endpoints: /oauth/admin/*
    try:
        from .oauth.oauth_admin import create_router as create_oauth_admin_router
        api_router.include_router(
            create_oauth_admin_router(storage),
            prefix="/oauth"
        )
        logger.info("Included OAuth admin router")
    except Exception as e:
        logger.warning(f"OAuth admin endpoints not available: {e}")
    
    # Log query endpoints: /logs/*
    try:
        from .logs.logs import create_logs_router
        logs_router = create_logs_router(async_storage)
        api_router.include_router(
            logs_router,
            prefix="/logs"
        )
        logger.info("Included logs router")
    except Exception as e:
        logger.warning(f"Log query endpoints not available: {e}")
    
    # MCP endpoints: /mcp/*
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
                    # Try other routers...
                    from src.mcp.router import create_mcp_router
                    logger.info("MCP router module imported successfully")
                    mcp_router = create_mcp_router(async_storage, unified_logger)
            
            api_router.include_router(
                mcp_router,
                prefix="/mcp"
            )
            logger.info("Included MCP router")
        else:
            logger.warning("MCP endpoints not available: unified_logger not initialized")
    except ImportError as e:
        logger.warning(f"MCP endpoints not available: {e}")
    except Exception as e:
        logger.warning(f"Error initializing MCP endpoints: {e}")
    
    # Legacy authentication configuration endpoints: /auth-config/*
    try:
        from .auth.auth_config import create_auth_config_router
        auth_config_router = create_auth_config_router(async_storage)
        api_router.include_router(
            auth_config_router,
            prefix="/auth-config"
        )
        logger.info("Included auth-config router")
    except Exception as e:
        logger.warning(f"Auth config endpoints not available: {e}")
    
    # New flexible auth endpoints: /auth/endpoints/*
    try:
        from .auth.auth_endpoints import create_auth_endpoints_router
        auth_endpoints_router = create_auth_endpoints_router(async_storage)
        api_router.include_router(
            auth_endpoints_router,
            prefix="/auth/endpoints"
        )
        logger.info("Included flexible auth endpoints router")
    except Exception as e:
        logger.warning(f"Flexible auth endpoints not available: {e}")
    
    return api_router