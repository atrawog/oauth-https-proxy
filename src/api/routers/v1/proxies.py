"""Proxy management API endpoints."""

import os
import logging
from datetime import datetime, timezone
from typing import Optional, Tuple
from fastapi import APIRouter, HTTPException, Depends, BackgroundTasks, Query

from ...auth import require_auth, require_auth_header, get_current_token_info, require_proxy_owner
from ....proxy.models import ProxyTarget, ProxyTargetRequest, ProxyTargetUpdate, ProxyAuthConfig, ProxyRoutesConfig, ProxyResourceConfig
from ....certmanager.models import CertificateRequest

logger = logging.getLogger(__name__)


def create_router(storage, cert_manager):
    """Create proxy endpoints router."""
    router = APIRouter(prefix="/targets", tags=["proxy"])
    
    @router.post("/")
    async def create_proxy_target(
        request: ProxyTargetRequest,
        background_tasks: BackgroundTasks,
        token_info: Tuple[str, Optional[str], Optional[str]] = Depends(get_current_token_info)
    ):
        """Create a new proxy target with optional certificate generation."""
        token_hash, token_name, cert_email = token_info
        
        # Check if target already exists
        existing = storage.get_proxy_target(request.hostname)
        if existing:
            raise HTTPException(409, f"Proxy target for {request.hostname} already exists")
        
        # Create proxy target
        cert_name = f"proxy-{request.hostname.replace('.', '-')}"
        target = ProxyTarget(
            hostname=request.hostname,
            target_url=request.target_url,
            cert_name=cert_name,
            owner_token_hash=token_hash,
            created_by=token_name,
            created_at=datetime.now(timezone.utc),
            enabled=True,
            enable_http=request.enable_http,
            enable_https=request.enable_https,
            preserve_host_header=request.preserve_host_header,
            custom_headers=request.custom_headers
        )
        
        # Store proxy target
        if not storage.store_proxy_target(request.hostname, target):
            raise HTTPException(500, "Failed to store proxy target")
        
        # Check if certificate exists and HTTPS is enabled
        cert_status = "not_required"
        if request.enable_https:
            cert = cert_manager.get_certificate(cert_name)
            if not cert:
                # Create certificate request
                acme_url = request.acme_directory_url
                if not acme_url:
                    acme_url = os.getenv("ACME_STAGING_URL")
                    if not acme_url:
                        raise HTTPException(400, "ACME directory URL required")
                
                # Use token's cert_email if not provided in request
                email = request.cert_email if request.cert_email else cert_email
                if not email:
                    raise HTTPException(400, "Certificate email required")
                
                cert_request = CertificateRequest(
                    domain=request.hostname,
                    email=email,
                    cert_name=cert_name,
                    acme_directory_url=acme_url
                )
                
                # Store initial certificate record
                from ....certmanager.models import Certificate
                cert = Certificate(
                    cert_name=cert_name,
                    domains=[request.hostname],
                    email=email,
                    acme_directory_url=acme_url,
                    status="pending",
                    owner_token_hash=token_hash,
                    created_by=token_name
                )
                storage.store_certificate(cert_name, cert)
                
                # Trigger async certificate generation
                from ....certmanager.async_acme import generate_certificate_async
                background_tasks.add_task(
                    generate_certificate_async,
                    cert_manager,
                    cert_request
                )
                cert_status = "Certificate generation started"
            else:
                cert_status = "existing"
        else:
            logger.info(f"HTTPS disabled for {request.hostname}, skipping certificate generation")
        
        # Create instance for the proxy
        # Import here to avoid circular imports at module level
        try:
            from ....dispatcher.unified_dispatcher import unified_server_instance
            if unified_server_instance:
                try:
                    await unified_server_instance.create_instance_for_proxy(request.hostname)
                    logger.info(f"Instance creation initiated for {request.hostname}")
                except Exception as e:
                    logger.error(f"Failed to create instance for {request.hostname}: {e}")
            else:
                logger.warning("Unified server not yet initialized")
        except ImportError:
            logger.warning("Unified dispatcher not available")
            
        return {
            "proxy_target": target,
            "certificate_status": cert_status,
            "cert_name": cert_name if request.enable_https else None
        }
    
    @router.get("/")
    async def list_proxy_targets(
        token_info: Tuple[str, Optional[str], Optional[str]] = Depends(get_current_token_info)
    ):
        """List proxy targets - filtered by ownership or all for admin."""
        all_targets = storage.list_proxy_targets()
        
        token_hash, token_name, _ = token_info
        
        # Admin sees all proxy targets
        if token_name == "ADMIN":
            return all_targets
        
        # Regular users see only their own targets
        return [target for target in all_targets if target.owner_token_hash == token_hash]
    
    @router.get("/formatted")
    async def list_proxy_targets_formatted(
        format: str = Query("table", description="Output format", enum=["table", "json", "csv"]),
        token_info: Tuple[str, Optional[str], Optional[str]] = Depends(get_current_token_info)
    ):
        """List proxy targets with formatted output."""
        from fastapi.responses import PlainTextResponse
        import csv
        import io
        from tabulate import tabulate
        
        # Get proxy targets using existing endpoint logic
        targets = await list_proxy_targets(token_info)
        
        if format == "json":
            # Return standard JSON response
            return targets
        
        # Prepare data for table/csv formatting
        rows = []
        for target in targets:
            # Determine status
            status = "enabled" if target.enabled else "disabled"
            
            # Format auth info
            auth_info = ""
            if hasattr(target, 'auth_enabled') and target.auth_enabled:
                auth_info = f"auth:{target.auth_mode}"
            
            # Format cert info
            cert_info = target.cert_name if target.cert_name else "no-cert"
            
            rows.append([
                target.hostname,
                target.target_url,
                status,
                cert_info,
                auth_info,
                "http" if target.enable_http else "",
                "https" if target.enable_https else ""
            ])
        
        if format == "csv":
            output = io.StringIO()
            writer = csv.writer(output)
            writer.writerow(["Hostname", "Target URL", "Status", "Certificate", "Auth", "HTTP", "HTTPS"])
            writer.writerows(rows)
            return PlainTextResponse(output.getvalue(), media_type="text/csv")
        
        # Default to table format
        headers = ["Hostname", "Target URL", "Status", "Certificate", "Auth", "HTTP", "HTTPS"]
        table = tabulate(rows, headers=headers, tablefmt="grid")
        return PlainTextResponse(table, media_type="text/plain")
    
    @router.get("/{hostname}")
    async def get_proxy_target(hostname: str):
        """Get specific proxy target details."""
        target = storage.get_proxy_target(hostname)
        if not target:
            raise HTTPException(404, f"Proxy target {hostname} not found")
        return target
    
    @router.put("/{hostname}")
    async def update_proxy_target(
        hostname: str,
        updates: ProxyTargetUpdate,
        _=Depends(require_proxy_owner)
    ):
        """Update proxy target configuration - owner only."""
        target = storage.get_proxy_target(hostname)
        if not target:
            raise HTTPException(404, f"Proxy target {hostname} not found")
        
        # Apply updates
        if updates.target_url is not None:
            target.target_url = updates.target_url
        if updates.cert_name is not None:
            target.cert_name = updates.cert_name
        if updates.enabled is not None:
            target.enabled = updates.enabled
        if updates.enable_http is not None:
            target.enable_http = updates.enable_http
        if updates.enable_https is not None:
            target.enable_https = updates.enable_https
        if updates.preserve_host_header is not None:
            target.preserve_host_header = updates.preserve_host_header
        if updates.custom_headers is not None:
            target.custom_headers = updates.custom_headers
        
        # Store updated target
        if not storage.store_proxy_target(hostname, target):
            raise HTTPException(500, "Failed to update proxy target")
        
        return target
    
    @router.delete("/{hostname}")
    async def delete_proxy_target(
        hostname: str,
        delete_certificate: bool = False,
        _=Depends(require_proxy_owner)
    ):
        """Delete proxy target and optionally its certificate - owner only."""
        target = storage.get_proxy_target(hostname)
        if not target:
            raise HTTPException(404, f"Proxy target {hostname} not found")
        
        # Delete proxy target
        if not storage.delete_proxy_target(hostname):
            raise HTTPException(500, "Failed to delete proxy target")
        
        # Remove instance for the proxy
        try:
            from ....dispatcher.unified_dispatcher import unified_server_instance
            if unified_server_instance:
                await unified_server_instance.remove_instance_for_proxy(hostname)
        except ImportError:
            logger.warning("Unified dispatcher not available")
        
        # Optionally delete certificate
        if delete_certificate and target.cert_name:
            cert_manager.delete_certificate(target.cert_name)
        
        return {"message": f"Proxy target {hostname} deleted successfully"}
    
    # Proxy auth configuration endpoints
    @router.post("/{hostname}/auth")
    async def configure_proxy_auth(
        hostname: str,
        config: ProxyAuthConfig,
        _=Depends(require_proxy_owner)
    ):
        """Configure unified auth for a proxy target - owner only."""
        target = storage.get_proxy_target(hostname)
        if not target:
            raise HTTPException(404, f"Proxy target {hostname} not found")
        
        # Validate auth proxy exists
        if config.auth_proxy:
            auth_target = storage.get_proxy_target(config.auth_proxy)
            if not auth_target:
                raise HTTPException(400, f"Auth proxy {config.auth_proxy} not found")
        
        # Update auth configuration
        target.auth_enabled = config.enabled
        target.auth_proxy = config.auth_proxy
        target.auth_mode = config.mode
        target.auth_required_users = config.required_users
        target.auth_required_emails = config.required_emails
        target.auth_required_groups = config.required_groups
        target.auth_allowed_scopes = config.allowed_scopes
        target.auth_allowed_audiences = config.allowed_audiences
        target.auth_pass_headers = config.pass_headers
        target.auth_cookie_name = config.cookie_name
        target.auth_header_prefix = config.header_prefix
        target.auth_excluded_paths = config.excluded_paths
        
        # Store updated target
        if not storage.store_proxy_target(hostname, target):
            raise HTTPException(500, "Failed to update proxy target")
        
        # When enabling auth, create a route for OAuth metadata endpoint
        if config.enabled and config.auth_proxy:
            # Create a route to forward OAuth metadata requests to the auth instance
            from ....proxy.routes import Route, RouteTargetType
            
            route_id = f"oauth-metadata-{hostname.replace('.', '-')}"
            oauth_route = Route(
                route_id=route_id,
                path_pattern="/.well-known/oauth-authorization-server",
                target_type=RouteTargetType.SERVICE,
                target_value="auth",  # Route to auth service, not hostname
                priority=90,  # High priority but below system routes
                enabled=True,
                description=f"OAuth metadata for {hostname}",
                owner_token_hash=target.owner_token_hash
            )
            
            # Store the route
            storage.store_route(oauth_route)
            logger.info(f"Created OAuth metadata route {route_id} for {hostname}")
            
            # Add to proxy's enabled routes if using selective mode
            if target.route_mode == "selective":
                if route_id not in target.enabled_routes:
                    target.enabled_routes.append(route_id)
                    storage.store_proxy_target(hostname, target)
                    logger.info(f"Added route {route_id} to enabled routes for {hostname}")
        
        logger.info(f"Auth configured for proxy {hostname}: enabled={config.enabled}")
        
        return {"status": "Auth configured", "proxy_target": target}
    
    @router.delete("/{hostname}/auth")
    async def remove_proxy_auth(
        hostname: str,
        _=Depends(require_proxy_owner)
    ):
        """Disable auth protection for a proxy target - owner only."""
        target = storage.get_proxy_target(hostname)
        if not target:
            raise HTTPException(404, f"Proxy target {hostname} not found")
        
        # Disable auth
        target.auth_enabled = False
        target.auth_proxy = None
        target.auth_required_users = None
        target.auth_required_emails = None
        target.auth_required_groups = None
        
        # Store updated target
        if not storage.store_proxy_target(hostname, target):
            raise HTTPException(500, "Failed to update proxy target")
        
        # Remove OAuth metadata route when disabling auth
        route_id = f"oauth-metadata-{hostname.replace('.', '-')}"
        if storage.get_route(route_id):
            storage.delete_route(route_id)
            logger.info(f"Removed OAuth metadata route {route_id} for {hostname}")
            
            # Also remove from proxy's enabled routes if present
            if target.route_mode == "selective" and route_id in target.enabled_routes:
                target.enabled_routes.remove(route_id)
                storage.store_proxy_target(hostname, target)
        
        logger.info(f"Auth disabled for proxy {hostname}")
        
        return {"status": "Auth protection removed", "proxy_target": target}
    
    @router.get("/{hostname}/auth")
    async def get_proxy_auth_config(hostname: str):
        """Get auth configuration for a proxy target."""
        target = storage.get_proxy_target(hostname)
        if not target:
            raise HTTPException(404, f"Proxy target {hostname} not found")
        
        # Return auth configuration
        return {
            "auth_enabled": target.auth_enabled,
            "auth_proxy": target.auth_proxy,
            "auth_mode": target.auth_mode,
            "auth_required_users": target.auth_required_users,
            "auth_required_emails": target.auth_required_emails,
            "auth_required_groups": target.auth_required_groups,
            "auth_allowed_scopes": target.auth_allowed_scopes,
            "auth_allowed_audiences": target.auth_allowed_audiences,
            "auth_pass_headers": target.auth_pass_headers,
            "auth_cookie_name": target.auth_cookie_name,
            "auth_header_prefix": target.auth_header_prefix,
            "auth_excluded_paths": target.auth_excluded_paths
        }
    
    # Proxy-specific route management endpoints
    @router.get("/{hostname}/routes")
    async def get_proxy_routes(hostname: str):
        """Get route configuration for a proxy target."""
        target = storage.get_proxy_target(hostname)
        if not target:
            raise HTTPException(404, f"Proxy target {hostname} not found")
        
        # Get all routes and filter applicable ones
        all_routes = storage.list_routes()
        
        # Determine applicable routes based on route_mode
        if target.route_mode == "none":
            applicable_routes = []
        elif target.route_mode == "selective":
            applicable_routes = [r for r in all_routes if r.route_id in target.enabled_routes]
        else:  # route_mode == "all"
            applicable_routes = [r for r in all_routes if r.route_id not in target.disabled_routes]
        
        return {
            "route_mode": target.route_mode,
            "enabled_routes": target.enabled_routes,
            "disabled_routes": target.disabled_routes,
            "applicable_routes": applicable_routes
        }
    
    @router.put("/{hostname}/routes")
    async def update_proxy_routes(
        hostname: str,
        config: ProxyRoutesConfig,
        _=Depends(require_proxy_owner)
    ):
        """Update route settings for a proxy target - owner only."""
        target = storage.get_proxy_target(hostname)
        if not target:
            raise HTTPException(404, f"Proxy target {hostname} not found")
        
        # Update proxy target
        updates = ProxyTargetUpdate(
            route_mode=config.route_mode,
            enabled_routes=config.enabled_routes,
            disabled_routes=config.disabled_routes
        )
        
        if not storage.update_proxy_target(hostname, updates):
            raise HTTPException(500, "Failed to update proxy routes")
        
        # Get updated target
        target = storage.get_proxy_target(hostname)
        
        logger.info(f"Routes updated for proxy {hostname}: mode={config.route_mode}")
        
        return {"status": "Routes configured", "proxy_target": target}
    
    @router.post("/{hostname}/routes/{route_id}/enable")
    async def enable_proxy_route(
        hostname: str,
        route_id: str,
        _=Depends(require_proxy_owner)
    ):
        """Enable a specific route for a proxy target - owner only."""
        target = storage.get_proxy_target(hostname)
        if not target:
            raise HTTPException(404, f"Proxy target {hostname} not found")
        
        # Verify route exists
        route = storage.get_route(route_id)
        if not route:
            raise HTTPException(404, f"Route {route_id} not found")
        
        # Update based on route_mode
        updates = ProxyTargetUpdate()
        
        if target.route_mode == "selective":
            # Add to enabled_routes
            if route_id not in target.enabled_routes:
                enabled_routes = target.enabled_routes.copy()
                enabled_routes.append(route_id)
                updates.enabled_routes = enabled_routes
        elif target.route_mode == "all":
            # Remove from disabled_routes
            if route_id in target.disabled_routes:
                disabled_routes = target.disabled_routes.copy()
                disabled_routes.remove(route_id)
                updates.disabled_routes = disabled_routes
        else:
            raise HTTPException(400, "Cannot enable routes when route_mode is 'none'")
        
        if not storage.update_proxy_target(hostname, updates):
            raise HTTPException(500, "Failed to enable route")
        
        logger.info(f"Route {route_id} enabled for proxy {hostname}")
        
        return {"status": "Route enabled", "route_id": route_id}
    
    @router.post("/{hostname}/routes/{route_id}/disable")
    async def disable_proxy_route(
        hostname: str,
        route_id: str,
        _=Depends(require_proxy_owner)
    ):
        """Disable a specific route for a proxy target - owner only."""
        target = storage.get_proxy_target(hostname)
        if not target:
            raise HTTPException(404, f"Proxy target {hostname} not found")
        
        # Verify route exists
        route = storage.get_route(route_id)
        if not route:
            raise HTTPException(404, f"Route {route_id} not found")
        
        # Update based on route_mode
        updates = ProxyTargetUpdate()
        
        if target.route_mode == "selective":
            # Remove from enabled_routes
            if route_id in target.enabled_routes:
                enabled_routes = target.enabled_routes.copy()
                enabled_routes.remove(route_id)
                updates.enabled_routes = enabled_routes
        elif target.route_mode == "all":
            # Add to disabled_routes
            if route_id not in target.disabled_routes:
                disabled_routes = target.disabled_routes.copy()
                disabled_routes.append(route_id)
                updates.disabled_routes = disabled_routes
        else:
            raise HTTPException(400, "Cannot disable routes when route_mode is 'none'")
        
        if not storage.update_proxy_target(hostname, updates):
            raise HTTPException(500, "Failed to disable route")
        
        logger.info(f"Route {route_id} disabled for proxy {hostname}")
        
        return {"status": "Route disabled", "route_id": route_id}
    
    # Protected Resource Metadata configuration endpoints
    @router.post("/{hostname}/resource")
    async def configure_proxy_resource(
        hostname: str,
        config: ProxyResourceConfig,
        _=Depends(require_proxy_owner)
    ):
        """Configure protected resource metadata for a proxy target - owner only."""
        target = storage.get_proxy_target(hostname)
        if not target:
            raise HTTPException(404, f"Proxy target {hostname} not found")
        
        # Update resource metadata fields directly on target
        target.resource_endpoint = config.endpoint
        target.resource_scopes = config.scopes
        target.resource_stateful = config.stateful
        target.resource_versions = config.versions
        target.resource_server_info = config.server_info
        target.resource_override_backend = config.override_backend
        target.resource_bearer_methods = config.bearer_methods
        target.resource_documentation_suffix = config.documentation_suffix
        target.resource_custom_metadata = config.custom_metadata
        
        # Handle X-HackerOne-Research header
        if config.hacker_one_research_header:
            if target.custom_response_headers is None:
                target.custom_response_headers = {}
            target.custom_response_headers["X-HackerOne-Research"] = config.hacker_one_research_header
        
        # Store updated target
        if not storage.store_proxy_target(hostname, target):
            raise HTTPException(500, "Failed to update proxy target")
        
        logger.info(f"Protected resource metadata configured for proxy {hostname}")
        
        return {"status": "Protected resource metadata configured", "proxy_target": target}
    
    @router.get("/{hostname}/resource")
    async def get_proxy_resource_config(hostname: str):
        """Get protected resource metadata configuration for a proxy target."""
        target = storage.get_proxy_target(hostname)
        if not target:
            raise HTTPException(404, f"Proxy target {hostname} not found")
        
        if not target.resource_endpoint:
            return {
                "configured": False,
                "message": "Protected resource metadata not configured for this proxy"
            }
        
        # Return resource configuration
        return {
            "configured": True,
            "endpoint": target.resource_endpoint,
            "scopes": target.resource_scopes or ["mcp:read", "mcp:write"],
            "stateful": target.resource_stateful,
            "versions": target.resource_versions or ["2025-06-18"],
            "server_info": target.resource_server_info,
            "override_backend": target.resource_override_backend,
            "bearer_methods": target.resource_bearer_methods or ["header"],
            "documentation_suffix": target.resource_documentation_suffix or "/docs",
            "custom_metadata": target.resource_custom_metadata
        }
    
    @router.delete("/{hostname}/resource")
    async def remove_proxy_resource(
        hostname: str,
        _=Depends(require_proxy_owner)
    ):
        """Remove protected resource metadata from a proxy target - owner only."""
        target = storage.get_proxy_target(hostname)
        if not target:
            raise HTTPException(404, f"Proxy target {hostname} not found")
        
        # Remove resource metadata fields
        target.resource_endpoint = None
        target.resource_scopes = None
        target.resource_stateful = False
        target.resource_versions = None
        target.resource_server_info = None
        target.resource_override_backend = False
        target.resource_bearer_methods = None
        target.resource_documentation_suffix = None
        target.resource_custom_metadata = None
        
        # Store updated target
        if not storage.store_proxy_target(hostname, target):
            raise HTTPException(500, "Failed to update proxy target")
        
        logger.info(f"Protected resource metadata removed for proxy {hostname}")
        
        return {"status": "Protected resource metadata removed", "proxy_target": target}
    
    return router