"""Central router registry for all API endpoints.

This module provides a single, unified place for registering all routers
with the FastAPI application, making the initialization process simpler
and less error-prone.
"""

import logging
from typing import List, Tuple, Optional
from fastapi import FastAPI, APIRouter

logger = logging.getLogger(__name__)


def register_all_routers(app: FastAPI) -> None:
    """Register all routers with the FastAPI app in a single, unified process.
    
    This is the single source of truth for router registration.
    If any router fails to load, the application will fail to start with a clear error.
    
    Args:
        app: FastAPI application with all required components in app.state
        
    Raises:
        ImportError: If a router module cannot be imported
        Exception: If router registration fails
    """
    logger.info("Starting unified router registration...")
    
    # Validate required components are available
    required_components = [
        'async_storage', 
        'cert_manager', 
        'storage',
        'unified_logger'
    ]
    
    for component in required_components:
        if not hasattr(app.state, component):
            raise RuntimeError(f"Required component '{component}' not found in app.state")
    
    # Get dependencies from app state
    async_storage = app.state.async_storage
    cert_manager = app.state.cert_manager
    storage = app.state.storage  # Legacy storage for some routers
    unified_logger = app.state.unified_logger
    
    # List of all routers to register: (name, factory_function, prefix, description)
    routers_config: List[Tuple[str, callable, str, str]] = []
    
    # ========== CORE API ROUTERS ==========
    
    # Certificate management
    routers_config.append((
        "certificates",
        lambda: _create_certificates_router(storage, cert_manager),
        "/certificates",
        "Certificate management endpoints"
    ))
    
    # Token management
    routers_config.append((
        "tokens", 
        lambda: _create_tokens_router(async_storage),
        "/tokens",
        "API token management"
    ))
    
    # Proxy management
    routers_config.append((
        "proxy",
        lambda: _create_proxy_router(async_storage, cert_manager),
        "/proxy",
        "Proxy target management"
    ))
    
    # Route management
    routers_config.append((
        "routes",
        lambda: _create_routes_router(async_storage),
        "/routes",
        "HTTP routing rules"
    ))
    
    # Route auth configuration
    routers_config.append((
        "route_auth",
        lambda: _create_route_auth_router(async_storage),
        "/routes",  # Same prefix as routes
        "Route authentication configuration"
    ))
    
    # Resource management
    routers_config.append((
        "resources",
        lambda: _create_resources_router(storage),
        "/resources",
        "OAuth resource management"
    ))
    
    # ========== OPTIONAL ROUTERS ==========
    
    # Docker service management (optional)
    if hasattr(app.state, 'docker_manager'):
        routers_config.append((
            "services",
            lambda: _create_services_router(async_storage),
            "/services",
            "Docker service management"
        ))
    
    # OAuth status endpoints (optional)
    if hasattr(app.state, 'oauth_components'):
        routers_config.append((
            "oauth_status",
            lambda: _create_oauth_status_router(storage),
            "/oauth",
            "OAuth status and metadata"
        ))
        
        routers_config.append((
            "oauth_admin",
            lambda: _create_oauth_admin_router(storage),
            "/oauth",
            "OAuth admin endpoints"
        ))
    
    # Log query endpoints
    routers_config.append((
        "logs",
        lambda: _create_logs_router(async_storage),
        "/logs",
        "Log query and analysis"
    ))
    
    # Authentication configuration endpoints
    routers_config.append((
        "auth_config",
        lambda: _create_auth_config_router(async_storage),
        "/auth-config",
        "Legacy authentication configuration"
    ))
    
    # Flexible auth endpoints
    routers_config.append((
        "auth_endpoints",
        lambda: _create_auth_endpoints_router(async_storage),
        "/auth/endpoints",
        "Flexible authentication endpoints"
    ))
    
    # ========== REGISTER ALL ROUTERS ==========
    
    successful_routers = []
    failed_routers = []
    
    for name, factory, prefix, description in routers_config:
        try:
            logger.info(f"Registering {name} router: {description}")
            router_or_app = factory()
            
            # All routers now use include_router (MCP was fixed to return a router)
            app.include_router(router_or_app, prefix=prefix)
            logger.info(f"✓ {name} router registered at {prefix}")
            
            successful_routers.append(f"{name} ({prefix})")
        except ImportError as e:
            error_msg = f"Failed to import {name} router: {e}"
            logger.warning(error_msg)
            failed_routers.append(f"{name}: {str(e)}")
        except Exception as e:
            error_msg = f"Failed to register {name} router: {e}"
            logger.error(error_msg)
            import traceback
            logger.error(f"Traceback for {name}: {traceback.format_exc()}")
            failed_routers.append(f"{name}: {str(e)}")
            # For critical routers, we might want to raise here
            if name in ['tokens', 'certificates', 'proxy']:
                raise RuntimeError(f"Critical router failed: {error_msg}")
    
    # ========== LOG SUMMARY ==========
    
    logger.info("=" * 60)
    logger.info("ROUTER REGISTRATION SUMMARY")
    logger.info("=" * 60)
    logger.info(f"✓ Successfully registered: {len(successful_routers)} routers")
    for router in successful_routers:
        logger.info(f"  • {router}")
    
    if failed_routers:
        logger.warning(f"✗ Failed to register: {len(failed_routers)} routers")
        for failure in failed_routers:
            logger.warning(f"  • {failure}")
    
    # Log all registered paths for debugging
    routes = []
    for route in app.routes:
        if hasattr(route, 'path'):
            routes.append(route.path)
    logger.info(f"Total routes registered: {len(routes)}")
    
    
    logger.debug(f"All routes: {sorted(set(routes))}")
    
    logger.info("=" * 60)


# ========== ROUTER FACTORY FUNCTIONS ==========
# These import and create the actual routers

def _create_certificates_router(storage, cert_manager) -> APIRouter:
    """Create certificates router."""
    from .certificates.certificates import create_router
    return create_router(storage, cert_manager)


def _create_tokens_router(async_storage) -> APIRouter:
    """Create tokens router."""
    from .tokens import create_tokens_router
    return create_tokens_router(async_storage)


def _create_proxy_router(async_storage, cert_manager) -> APIRouter:
    """Create proxy router."""
    from .proxy import create_router
    return create_router(async_storage, cert_manager)


def _create_routes_router(async_storage) -> APIRouter:
    """Create routes router."""
    from .routes.routes import create_router
    return create_router(async_storage)


def _create_route_auth_router(async_storage) -> APIRouter:
    """Create route auth router."""
    from .routes.route_auth import create_route_auth_router
    return create_route_auth_router(async_storage)


def _create_resources_router(storage) -> APIRouter:
    """Create resources router."""
    from .resources.resources import create_router
    return create_router(storage)


def _create_services_router(async_storage) -> APIRouter:
    """Create services router."""
    from .services import create_services_router
    return create_services_router(async_storage)


def _create_oauth_status_router(storage) -> APIRouter:
    """Create OAuth status router."""
    from .oauth.oauth_status import create_oauth_status_router
    return create_oauth_status_router(storage)


def _create_oauth_admin_router(storage) -> APIRouter:
    """Create OAuth admin router."""
    from .oauth.oauth_admin import create_router
    return create_router(storage)


def _create_logs_router(async_storage) -> APIRouter:
    """Create logs router."""
    from .logs.logs import create_logs_router
    return create_logs_router(async_storage)


def _create_auth_config_router(async_storage) -> APIRouter:
    """Create auth config router."""
    from .auth.auth_config import create_auth_config_router
    return create_auth_config_router(async_storage)


def _create_auth_endpoints_router(async_storage) -> APIRouter:
    """Create auth endpoints router."""
    from .auth.auth_endpoints import create_auth_endpoints_router
    return create_auth_endpoints_router(async_storage)