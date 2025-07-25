"""FastAPI server setup for the API component."""

import os
import logging
from contextlib import asynccontextmanager
from typing import Optional

from fastapi import FastAPI, Request, Depends, HTTPException
from fastapi.responses import HTMLResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware

from .auth import require_auth, require_auth_header, get_token_info_from_header
from .models import HealthStatus

# OAuth imports
from .oauth.config import Settings as OAuthSettings
from .oauth.redis_client import RedisManager as OAuthRedisManager
from .oauth.auth_authlib import AuthManager
from .oauth.routes import create_oauth_router

logger = logging.getLogger(__name__)


def create_api_app(storage, cert_manager, scheduler) -> FastAPI:
    """Create the FastAPI application."""
    
    # Initialize OAuth components
    oauth_settings = OAuthSettings()
    oauth_redis_manager = OAuthRedisManager(oauth_settings)
    auth_manager = AuthManager(oauth_settings)
    
    @asynccontextmanager
    async def lifespan(app: FastAPI):
        """Manage application lifecycle."""
        logger.info("API app starting...")
        # Initialize OAuth Redis connection
        await oauth_redis_manager.initialize()
        yield
        logger.info("API app shutting down...")
        # Close OAuth Redis connection
        await oauth_redis_manager.close()
    
    app = FastAPI(
        title="MCP HTTP Proxy API",
        description="Certificate and proxy management API",
        version="1.0.0",
        lifespan=lifespan,
        redirect_slashes=False
    )
    
    # Store dependencies
    app.state.storage = storage
    app.state.cert_manager = cert_manager
    app.state.scheduler = scheduler
    
    # Add CORS middleware
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )
    
    # Mount static files
    static_path = os.path.join(os.path.dirname(__file__), "static")
    app.mount("/static", StaticFiles(directory=static_path), name="static")
    
    # Root endpoint - serve web GUI
    @app.get("/")
    async def read_root():
        """Serve the main web interface."""
        index_path = os.path.join(static_path, "index.html")
        if os.path.exists(index_path):
            with open(index_path, "r") as f:
                return HTMLResponse(content=f.read())
        return HTMLResponse(content="<h1>MCP HTTP Proxy</h1>")
    
    # Health check endpoint
    @app.get("/health", response_model=HealthStatus)
    async def health_check():
        """Health check endpoint."""
        try:
            certs = storage.list_certificates()
            
            # Count orphaned resources
            orphaned_count = 0
            # Check for orphaned proxy certificates
            proxy_certs = {target.cert_name for target in storage.list_proxy_targets() if target.cert_name}
            all_certs = {cert.cert_name for cert in certs}
            orphaned_certs = all_certs - proxy_certs - {"localhost-self-signed"}
            orphaned_count += len(orphaned_certs)
            
            return HealthStatus(
                status="healthy",
                scheduler=scheduler.is_running(),
                redis="healthy" if storage.health_check() else "unhealthy",
                certificates_loaded=len(certs),
                https_enabled=len(certs) > 0,
                orphaned_resources=orphaned_count
            )
        except Exception as e:
            logger.error(f"Health check failed: {e}")
            raise HTTPException(status_code=500, detail=str(e))
    
    # ACME challenge endpoint
    @app.get("/.well-known/acme-challenge/{token}", response_class=PlainTextResponse)
    async def acme_challenge(token: str):
        """Handle ACME challenge validation."""
        authorization = storage.get_challenge(token)
        if authorization:
            logger.info(f"ACME challenge served for token: {token}")
            return PlainTextResponse(authorization)
        else:
            logger.warning(f"ACME challenge not found for token: {token}")
            raise HTTPException(status_code=404, detail="Challenge not found")
    
    # Import and register endpoint routers
    from .endpoints import certificates, proxies, tokens, routes, instances, resources
    
    app.include_router(certificates.create_router(storage, cert_manager))
    app.include_router(proxies.create_router(storage, cert_manager))
    app.include_router(tokens.create_router(storage))
    app.include_router(routes.create_router(storage))
    app.include_router(instances.create_router(storage))
    app.include_router(resources.create_router(storage))
    
    # OAuth endpoints (if available)
    try:
        from .endpoints import oauth_status, oauth_admin
        app.include_router(oauth_status.create_oauth_status_router(storage))
        app.include_router(oauth_admin.create_router(storage))
    except ImportError as e:
        logger.warning(f"OAuth endpoints not available: {e}")
    
    # Include OAuth router
    oauth_router = create_oauth_router(oauth_settings, oauth_redis_manager, auth_manager)
    app.include_router(oauth_router)
    logger.info("OAuth router included successfully")
    
    # Include v1 API router
    try:
        from .routers.v1 import create_v1_router
        v1_router = create_v1_router(storage, cert_manager)
        app.include_router(v1_router, prefix="/api/v1")
        logger.info("API v1 router included successfully at /api/v1")
    except Exception as e:
        logger.error(f"Failed to include v1 router: {e}")
    
    return app