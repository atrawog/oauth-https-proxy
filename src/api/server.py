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
from ..shared.client_ip import get_real_client_ip

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
        redirect_slashes=True
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
    
    # Add middleware to identify instance
    @app.middleware("http")
    async def add_instance_name(request: Request, call_next):
        response = await call_next(request)
        response.headers["X-Instance-Name"] = "api"
        return response
    
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
    
    # Test endpoint
    @app.get("/test-logging")
    async def test_logging():
        """Test endpoint to verify logging works."""
        logger.info("Test logging endpoint called")
        logger.debug("Debug message")
        logger.warning("Warning message")
        return {"status": "ok", "message": "Logging test"}
    
    # MCP OAuth protected resource metadata endpoint
    @app.get("/.well-known/oauth-protected-resource")
    async def oauth_protected_resource(request: Request):
        """Generate MCP protected resource metadata based on hostname with comprehensive logging."""
        try:
            # Extract client IP using centralized function
            client_ip = get_real_client_ip(request)
            
            logger.info(f"MCP metadata endpoint requested - IP: {client_ip}, Path: {request.url.path}")
            
            # Get hostname from request - check x-forwarded-host first (set by proxy)
            hostname = request.headers.get("x-forwarded-host", "").split(":")[0]
            if not hostname:
                # Fallback to host header
                hostname = request.headers.get("host", "").split(":")[0]
            if not hostname:
                logger.error(f"MCP metadata request failed - no host header, IP: {client_ip}")
                raise HTTPException(404, "No host header")
            
            logger.debug(f"MCP metadata hostname resolved: {hostname}")
            
            # Get proxy target
            logger.info(f"Looking up proxy target for hostname: {hostname}")
            target = request.app.state.storage.get_proxy_target(hostname)
            logger.info(f"Got proxy target: {target}")
            if not target:
                # Get available proxies for debugging
                available_proxies = []
                try:
                    available_proxies = [p.hostname for p in request.app.state.storage.list_proxy_targets()][:10]
                except Exception:
                    pass
                
                logger.error(f"MCP metadata request failed - no proxy target configured for {hostname}")
                raise HTTPException(404, f"No proxy target configured for {hostname}")
            
            logger.debug(f"MCP metadata proxy target found for {hostname}")
            
            # Check if protected resource metadata is configured
            logger.info(f"Checking resource metadata - endpoint: {target.resource_endpoint}, scopes: {target.resource_scopes}")
            
            if not target.resource_endpoint:
                logger.warning(f"Protected resource metadata request failed - not configured for proxy {hostname}")
                raise HTTPException(404, "Protected resource metadata not configured for this proxy")
            
            # Build resource URI
            logger.info("Building resource URI")
            proto = request.headers.get("x-forwarded-proto", "https")
            resource_endpoint = target.resource_endpoint
            logger.info(f"Protocol: {proto}, hostname: {hostname}, endpoint: {resource_endpoint}")
            resource_uri = f"{proto}://{hostname}{resource_endpoint}"
            
            logger.debug(f"MCP metadata building resource URI: {resource_uri}")
            
            # Get authorization server URL
            logger.info(f"Getting auth servers - auth_enabled: {target.auth_enabled}, auth_proxy: {target.auth_proxy}")
            auth_servers = []
            if target.auth_enabled and target.auth_proxy:
                auth_servers.append(f"https://{target.auth_proxy}")
                logger.info(f"Added auth server: https://{target.auth_proxy}")
            
            # Build metadata response per RFC 9728
            logger.info("Building metadata response")
            resource_scopes = target.resource_scopes or ["mcp:read", "mcp:write"]
            logger.info(f"Resource scopes: {resource_scopes}")
            
            # Get bearer methods from metadata or use default
            bearer_methods = target.resource_bearer_methods or ["header"]
            
            # Get documentation suffix from metadata or use default
            doc_suffix = target.resource_documentation_suffix or "/docs"
            
            metadata = {
                "resource": resource_uri,
                "authorization_servers": auth_servers,
                "scopes_supported": resource_scopes,
                "bearer_methods_supported": bearer_methods,
                "resource_documentation": f"{resource_uri}{doc_suffix}"
            }
            logger.info(f"Created metadata dict: {metadata}")
            
            # Add JWKS URI if auth is enabled
            if auth_servers:
                metadata["jwks_uri"] = f"{auth_servers[0]}/jwks"
            
            # Add server info if configured
            if target.resource_server_info:
                logger.info(f"Adding server info: {target.resource_server_info}")
                metadata.update(target.resource_server_info)
            else:
                logger.info("No server info to add")
            
            # Add custom metadata if configured
            if target.resource_custom_metadata:
                logger.info(f"Adding custom metadata: {target.resource_custom_metadata}")
                metadata.update(target.resource_custom_metadata)
            
            logger.info(f"MCP metadata endpoint responding successfully for {hostname}")
            
            return metadata
        
        except HTTPException:
            # Re-raise HTTPException as-is
            raise
        except Exception as e:
            import traceback
            tb = traceback.format_exc()
            logger.error(f"Unexpected error in oauth-protected-resource endpoint: {str(e)}\n{tb}")
            raise HTTPException(500, "Internal Server Error")
    
    # Include OAuth protocol router (remains at root level for compliance)
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