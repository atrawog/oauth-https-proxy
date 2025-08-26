"""Core proxy CRUD operations with async support.

This module handles basic Create, Read, Update, Delete operations for proxy targets.
All operations use async patterns with fallback to sync for backward compatibility.
"""

import os
import logging
from datetime import datetime, timezone
from typing import Optional, Tuple
from fastapi import APIRouter, HTTPException, Depends, BackgroundTasks, Query, Request
from fastapi.responses import PlainTextResponse
import csv
import io
from tabulate import tabulate

# Authentication is handled by proxy, API trusts headers
from src.proxy.models import ProxyTarget, ProxyTargetRequest, ProxyTargetUpdate
from src.certmanager.models import CertificateRequest, Certificate
from src.api.auth_utils import check_auth_and_scopes, require_admin, require_user

logger = logging.getLogger(__name__)


def create_core_router(storage, cert_manager):
    """Create router for core proxy CRUD operations.
    
    All endpoints use async patterns with Request parameter to access async components.
    
    Args:
        async_storage: Redis async_storage instance (legacy, for backward compatibility)
        cert_manager: Certificate manager instance (legacy, for backward compatibility)
    
    Returns:
        APIRouter with core proxy endpoints
    """
    router = APIRouter()
    
    @router.post("/")
    async def create_proxy_target(
        req: Request,
        request: ProxyTargetRequest,
        background_tasks: BackgroundTasks,
    ):
        """Create a new proxy target with optional certificate generation."""
        # Check authentication and require admin scope for creation
        auth_user, auth_scopes, is_admin = check_auth_and_scopes(req, required_scopes=["admin"])
        
        # Debug logging
        auth_scopes_header = req.headers.get("X-Auth-Scopes", "")
        logger.info(f"Auth check - User: {auth_user}, Scopes header: '{auth_scopes_header}', Parsed scopes: {auth_scopes}, Is admin: {is_admin}")
        
        # Check permissions - admin scope required for create
        if not is_admin:
            raise HTTPException(403, "Admin scope required")
        
        # Get cert_email from request
        cert_email = request.cert_email
        
        # Get async components
        async_storage = req.app.state.async_storage if hasattr(req.app.state, 'async_storage') else None
        async_cert_manager = req.app.state.cert_manager if hasattr(req.app.state, 'cert_manager') else None
        
        # Check if target already exists
        existing = await async_storage.get_proxy_target(request.proxy_hostname)
        if existing:
            raise HTTPException(409, f"Proxy target for {request.proxy_hostname} already exists")
        
        # Create proxy target - don't set cert_name yet
        cert_name = f"proxy-{request.proxy_hostname.replace('.', '-')}"  # Pattern for checking
        target = ProxyTarget(
            proxy_hostname = request.proxy_hostname,
            target_url=request.target_url,
            cert_name=None,  # Will be set later if cert exists or created
            created_by=auth_user,
            created_at=datetime.now(timezone.utc),
            enabled=True,
            enable_http=request.enable_http,
            enable_https=request.enable_https,
            preserve_host_header=request.preserve_host_header,
            custom_headers=request.custom_headers
        )
        
        # Store proxy target
        success = await async_storage.store_proxy_target(request.proxy_hostname, target)
        if not success:
            raise HTTPException(500, "Failed to store proxy target")
        
        # Check if certificate exists and HTTPS is enabled
        cert_status = "not_required"
        actual_cert_name = None  # Only set if cert exists or will be created
        
        if request.enable_https:
            if async_cert_manager:
                cert = await async_cert_manager.get_certificate(cert_name)
            else:
                cert = None  # No cert manager available
            if cert and cert.status == "active":
                # Certificate already exists and is active - use it
                cert_status = "existing"
                actual_cert_name = cert_name
                logger.info(f"Using existing certificate {cert_name} for {request.proxy_hostname}")
            else:
                # No existing certificate - check if we should create one
                acme_url = request.acme_directory_url
                if not acme_url:
                    # Try to use default ACME URL from environment
                    acme_url = os.getenv("ACME_DIRECTORY_URL")  # Production by default
                    if not acme_url:
                        acme_url = os.getenv("ACME_STAGING_URL")
                
                if acme_url:
                    # We have an ACME URL - create certificate
                    email = request.cert_email if request.cert_email else cert_email
                    if not email:
                        # Rollback proxy creation since we can't create cert
                        await async_storage.delete_proxy_target(request.proxy_hostname)
                        raise HTTPException(400, "Certificate email required for HTTPS proxy")
                    
                    cert_request = CertificateRequest(
                        domain=request.proxy_hostname,
                        email=email,
                        cert_name=cert_name,
                        acme_directory_url=acme_url
                    )
                    
                    # Store initial certificate record
                    from src.certmanager.models import Certificate
                    cert = Certificate(
                        cert_name=cert_name,
                        domains=[request.proxy_hostname],
                        email=email,
                        acme_directory_url=acme_url,
                        status="pending",
                        created_by=auth_user
                    )
                    await async_storage.store_certificate(cert_name, cert)
                    # Trigger async certificate generation with event publishing
                    # Start the task directly instead of using background_tasks
                    import asyncio
                    from src.certmanager.async_acme import create_certificate_task
                    asyncio.create_task(
                        create_certificate_task(
                            async_cert_manager,
                            cert_request,
                            None,  # https_server will be imported inside the task
                            None,  # No token ownership
                            auth_user
                        )
                    )
                    cert_status = "Certificate generation started"
                    actual_cert_name = cert_name  # Will have cert soon
                    logger.info(f"Started certificate generation for {request.proxy_hostname}")
                else:
                    # No cert exists and no ACME URL - disable HTTPS
                    logger.warning(f"No certificate exists for {request.proxy_hostname} and no ACME URL provided - disabling HTTPS")
                    target.enable_https = False
                    target.cert_name = None
                    # Update the stored proxy to reflect HTTPS disabled
                    await async_storage.store_proxy_target(request.proxy_hostname, target)
                    cert_status = "https_disabled_no_cert"
        else:
            logger.info(f"HTTPS disabled for {request.proxy_hostname}, skipping certificate generation")
        
        # Update cert_name in target if we have one
        if actual_cert_name:
            target.cert_name = actual_cert_name
            await async_storage.store_proxy_target(request.proxy_hostname, target)
        
        # UNIFIED ARCHITECTURE: Publish simple event
        from src.shared.logger import log_info, log_warning, log_error
        log_info(f"Publishing proxy created event: {request.proxy_hostname}", 
                component="proxy_api", proxy_hostname=request.proxy_hostname)
        try:
            from src.storage.redis_stream_publisher import RedisStreamPublisher
            
            redis_url = os.getenv('REDIS_URL', 'redis://:test@redis:6379/0')
            publisher = RedisStreamPublisher(redis_url=redis_url)
            
            # SIMPLIFIED: Just publish proxy_created - that's it!
            event_id = await publisher.publish_event("proxy_created", {
                "proxy_hostname": request.proxy_hostname
            })
            
            if event_id:
                log_info(f"✅ Published proxy_created event {event_id}", 
                        component="proxy_api", 
                        proxy_hostname=request.proxy_hostname)
            else:
                log_warning(f"Failed to publish event", 
                           component="proxy_api", 
                           proxy_hostname=request.proxy_hostname)
                
            await publisher.close()
        except Exception as e:
            log_error(f"Failed to publish event: {e}", 
                     component="proxy_api", 
                     proxy_hostname=request.proxy_hostname, 
                     error=str(e))
            
        return {
            "proxy_target": target,
            "certificate_status": cert_status,
            "cert_name": actual_cert_name  # Only set if cert exists or being created
        }
    
    
    @router.get("/debug")
    async def debug_endpoint():
        """Debug endpoint to test router."""
        return {"message": "Debug endpoint working", "time": str(datetime.now(timezone.utc))}
    
    @router.get("/")
    async def list_proxy_targets(
        request: Request,
    ):
        """List all proxy targets."""
        # Check authentication and require user scope for reading
        auth_user, auth_scopes, is_admin = check_auth_and_scopes(request, required_scopes=["user"], allow_any=True)
        
        import logging
        logger = logging.getLogger(__name__)
        
        async_storage = request.app.state.async_storage
        all_targets = await async_storage.list_proxy_targets()
        
        logger.info(f"list_proxy_targets: user={auth_user}, scopes={auth_scopes}, found {len(all_targets)} total targets")
        
        # Return all targets (no ownership filtering anymore)
        return all_targets
    
    
    @router.get("/formatted")
    async def list_proxy_targets_formatted(
        request: Request,
        format: str = Query("table", description="Output format", enum=["table", "json", "csv"]),
    ):
        """List proxy targets with formatted output."""
        # Check authentication and require user scope for reading
        auth_user, auth_scopes, is_admin = check_auth_and_scopes(request, required_scopes=["user"], allow_any=True)
        is_admin = "admin" in auth_scopes
        from fastapi.responses import PlainTextResponse
        import csv
        import io
        from tabulate import tabulate
        
        # Get proxy targets using existing endpoint logic
        targets = await list_proxy_targets(request)
        
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
                target.proxy_hostname,
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
    
    
    @router.get("/{proxy_hostname}")
    async def get_proxy_target(
        request: Request,
        proxy_hostname: str
    ):
        """Get specific proxy target details."""
        # Check authentication and require user scope for reading
        auth_user, auth_scopes, is_admin = check_auth_and_scopes(request, required_scopes=["user"], allow_any=True)
        
        # Get async_storage from app state
        async_storage = request.app.state.async_storage
        target = await async_storage.get_proxy_target(proxy_hostname)
        if not target:
            raise HTTPException(404, f"Proxy target {proxy_hostname} not found")
        return target
    
    
    @router.put("/{proxy_hostname}")
    async def update_proxy_target(
        request: Request,
        proxy_hostname: str,
        updates: ProxyTargetUpdate,
    ):
        """Update proxy target configuration - admin only."""
        # Check authentication and require admin scope for updates
        auth_user, auth_scopes, is_admin = check_auth_and_scopes(request, required_scopes=["admin"])
        
        # Get async_storage from app state
        async_storage = request.app.state.async_storage
        target = await async_storage.get_proxy_target(proxy_hostname)
        if not target:
            raise HTTPException(404, f"Proxy target {proxy_hostname} not found")
        
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
        if not await async_storage.store_proxy_target(proxy_hostname, target):
            raise HTTPException(500, "Failed to update proxy target")
        
        return target
    
    
    @router.delete("/{proxy_hostname}")
    async def delete_proxy_target(
        request: Request,
        proxy_hostname: str,
        delete_certificate: bool = False,
    ):
        """Delete proxy target and optionally its certificate."""
        # Check authentication and require admin scope for deletion
        auth_user, auth_scopes, is_admin = check_auth_and_scopes(request, required_scopes=["admin"])
        
        # Check permissions - admin scope required for mutations
        if not is_admin:
            raise HTTPException(403, "Admin scope required")
        # Get async_storage from app state
        async_storage = request.app.state.async_storage
        target = await async_storage.get_proxy_target(proxy_hostname)
        if not target:
            raise HTTPException(404, f"Proxy target {proxy_hostname} not found")
        
        # Delete proxy target
        if not await async_storage.delete_proxy_target(proxy_hostname):
            raise HTTPException(500, "Failed to delete proxy target")
        
        # UNIFIED ARCHITECTURE: Publish simple proxy_deleted event
        logger.info(f"Publishing proxy_deleted event for {proxy_hostname}")
        try:
            from src.storage.redis_stream_publisher import RedisStreamPublisher
            
            redis_url = os.getenv('REDIS_URL', 'redis://:test@redis:6379/0')
            publisher = RedisStreamPublisher(redis_url=redis_url)
            
            # SIMPLIFIED: Just publish proxy_deleted
            event_id = await publisher.publish_event("proxy_deleted", {
                "proxy_hostname": proxy_hostname
            })
            
            if event_id:
                logger.info(f"✅ Published proxy_deleted event {event_id} for {proxy_hostname}")
            else:
                logger.warning(f"Failed to publish proxy_deleted event for {proxy_hostname}")
                
            await publisher.close()
        except Exception as e:
            logger.error(f"Failed to publish proxy_deleted event for {proxy_hostname}: {e}", exc_info=True)
        
        # Optionally delete certificate
        if delete_certificate and target.cert_name:
            cert_manager.delete_certificate(target.cert_name)
        
        return {"message": f"Proxy target {proxy_hostname} deleted successfully"}
    
    # Proxy auth configuration endpoints
    
    return router
