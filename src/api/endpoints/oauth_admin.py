"""OAuth administration endpoints."""

import logging
from typing import List, Optional
from datetime import datetime, timezone
from fastapi import APIRouter, HTTPException, Depends, Query
from pydantic import BaseModel

from ..auth import require_admin
from ...proxy.routes import Route, RouteCreateRequest

logger = logging.getLogger(__name__)


class OAuthSetupRequest(BaseModel):
    """Request model for OAuth route setup."""
    oauth_domain: str
    force: bool = False


class OAuthSetupResponse(BaseModel):
    """Response model for OAuth route setup."""
    oauth_domain: str
    created_routes: List[str]
    skipped_routes: List[str]
    errors: List[str]
    success: bool


def create_router(storage):
    """Create OAuth admin endpoints router."""
    router = APIRouter(prefix="/oauth/admin", tags=["oauth-admin"])
    
    @router.post("/setup-routes", response_model=OAuthSetupResponse)
    async def setup_oauth_routes(
        request: OAuthSetupRequest,
        _: dict = Depends(require_admin)  # Admin only
    ):
        """Automatically configure all required OAuth routes."""
        
        # Define OAuth routes to create
        oauth_routes = [
            {
                "route_id": "oauth-authorize",
                "path": "/authorize",
                "target_type": "hostname",
                "target_value": request.oauth_domain,
                "priority": 95,
                "description": "OAuth authorization endpoint"
            },
            {
                "route_id": "oauth-token",
                "path": "/token",
                "target_type": "hostname", 
                "target_value": request.oauth_domain,
                "priority": 95,
                "description": "OAuth token endpoint"
            },
            {
                "route_id": "oauth-callback",
                "path": "/callback",
                "target_type": "hostname",
                "target_value": request.oauth_domain,
                "priority": 95,
                "description": "OAuth callback endpoint"
            },
            {
                "route_id": "oauth-verify",
                "path": "/verify",
                "target_type": "hostname",
                "target_value": request.oauth_domain,
                "priority": 95,
                "description": "OAuth verification endpoint"
            },
            {
                "route_id": "oauth-metadata",
                "path": "/.well-known/oauth-authorization-server",
                "target_type": "hostname",
                "target_value": request.oauth_domain,
                "priority": 95,
                "description": "OAuth server metadata"
            },
            {
                "route_id": "oauth-jwks",
                "path": "/jwks",
                "target_type": "hostname",
                "target_value": request.oauth_domain,
                "priority": 95,
                "description": "OAuth JWKS endpoint"
            },
            {
                "route_id": "oauth-revoke",
                "path": "/revoke",
                "target_type": "hostname",
                "target_value": request.oauth_domain,
                "priority": 95,
                "description": "OAuth token revocation"
            },
            {
                "route_id": "oauth-introspect",
                "path": "/introspect",
                "target_type": "hostname",
                "target_value": request.oauth_domain,
                "priority": 95,
                "description": "OAuth token introspection"
            },
            {
                "route_id": "oauth-register",
                "path": "/register",
                "target_type": "hostname",
                "target_value": request.oauth_domain,
                "priority": 95,
                "description": "OAuth client registration"
            },
            {
                "route_id": "oauth-error",
                "path": "/error",
                "target_type": "hostname",
                "target_value": request.oauth_domain,
                "priority": 90,
                "description": "OAuth error page"
            },
            {
                "route_id": "oauth-success",
                "path": "/success",
                "target_type": "hostname",
                "target_value": request.oauth_domain,
                "priority": 90,
                "description": "OAuth success page"
            },
            {
                "route_id": "oauth-clients",
                "path": "/oauth/clients",
                "target_type": "hostname",
                "target_value": request.oauth_domain,
                "priority": 90,
                "description": "OAuth client management"
            },
            {
                "route_id": "oauth-sessions",
                "path": "/oauth/sessions",
                "target_type": "hostname",
                "target_value": request.oauth_domain,
                "priority": 90,
                "description": "OAuth session management"
            },
            {
                "route_id": "oauth-resources",
                "path": "/resources",
                "target_type": "hostname",
                "target_value": request.oauth_domain,
                "priority": 90,
                "description": "MCP resource management"
            }
        ]
        
        created_routes = []
        skipped_routes = []
        errors = []
        
        for route_config in oauth_routes:
            try:
                # Check if route already exists
                existing_route = storage.get_route(route_config["route_id"])
                
                if existing_route and not request.force:
                    skipped_routes.append(route_config["route_id"])
                    continue
                
                # Create route object
                route = Route(
                    route_id=route_config["route_id"],
                    path_pattern=route_config["path"],
                    target_type=route_config["target_type"],
                    target_value=route_config["target_value"],
                    priority=route_config["priority"],
                    description=route_config["description"],
                    enabled=True,
                    methods=[],  # Empty list means all methods
                    is_regex=False,
                    created_at=datetime.now(timezone.utc),
                    owner_token_hash=f"sha256:{_['hash'].split(':')[1]}"  # Admin token hash
                )
                
                # Store route
                if storage.store_route(route):
                    created_routes.append(route_config["route_id"])
                    logger.info(f"Created OAuth route: {route_config['route_id']}")
                else:
                    errors.append(f"{route_config['route_id']}: Failed to store")
                    
            except Exception as e:
                errors.append(f"{route_config['route_id']}: {str(e)}")
                logger.error(f"Error creating OAuth route {route_config['route_id']}: {e}")
        
        # Summary
        success = len(errors) == 0
        
        if success:
            logger.info(
                f"OAuth routes setup completed: {len(created_routes)} created, "
                f"{len(skipped_routes)} skipped"
            )
        else:
            logger.warning(
                f"OAuth routes setup completed with errors: {len(created_routes)} created, "
                f"{len(skipped_routes)} skipped, {len(errors)} errors"
            )
        
        return OAuthSetupResponse(
            oauth_domain=request.oauth_domain,
            created_routes=created_routes,
            skipped_routes=skipped_routes,
            errors=errors,
            success=success
        )
    
    @router.get("/setup-status")
    async def get_oauth_setup_status(
        domain: str = Query(..., description="OAuth domain to check")
    ):
        """Check OAuth route setup status."""
        
        # Expected routes
        expected_routes = [
            "oauth-authorize", "oauth-token", "oauth-callback", "oauth-verify",
            "oauth-metadata", "oauth-jwks", "oauth-revoke", "oauth-introspect",
            "oauth-register", "oauth-error", "oauth-success", "oauth-clients",
            "oauth-sessions", "oauth-resources"
        ]
        
        # Check which routes exist and point to the correct domain
        configured_routes = []
        missing_routes = []
        misconfigured_routes = []
        
        for route_id in expected_routes:
            route = storage.get_route(route_id)
            
            if not route:
                missing_routes.append(route_id)
            elif route.target_value != domain:
                misconfigured_routes.append({
                    "route_id": route_id,
                    "current_target": route.target_value,
                    "expected_target": domain
                })
            else:
                configured_routes.append(route_id)
        
        # Check if proxy exists for the domain
        proxy_exists = storage.get_proxy_target(domain) is not None
        
        return {
            "domain": domain,
            "proxy_exists": proxy_exists,
            "total_expected": len(expected_routes),
            "configured": len(configured_routes),
            "missing": len(missing_routes),
            "misconfigured": len(misconfigured_routes),
            "is_complete": len(missing_routes) == 0 and len(misconfigured_routes) == 0,
            "configured_routes": configured_routes,
            "missing_routes": missing_routes,
            "misconfigured_routes": misconfigured_routes
        }
    
    return router