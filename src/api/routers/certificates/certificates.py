"""Certificate management API endpoints."""

import os
from typing import List, Optional
from fastapi import APIRouter, HTTPException, Depends, BackgroundTasks, Query, Request

from src.shared.logger import log_info, log_debug, log_error, log_warning


def create_router(storage, cert_manager):
    """Create certificate endpoints router.
    
    Note: storage and cert_manager parameters are legacy.
    The actual async components are retrieved from request.app.state.
    """
    router = APIRouter(tags=["certificates"])
    
    @router.post("/")
    async def create_certificate(
        req: Request,
        request: dict,
        background_tasks: BackgroundTasks
    ):
        """Create a new certificate (async operation)."""
        from src.certmanager.models import CertificateRequest
        
        # Get auth info from headers (set by proxy)
        auth_user = req.headers.get("X-Auth-User", "system")
        auth_scopes = req.headers.get("X-Auth-Scopes", "").split()
        
        try:
            # Add cert_name if not provided
            if 'cert_name' not in request:
                request['cert_name'] = f"proxy-{request['domain'].replace('.', '-')}"
            cert_request = CertificateRequest(**request)
            
            # Get async components
            async_storage = req.app.state.async_storage if hasattr(req.app.state, 'async_storage') else None
            async_cert_manager = req.app.state.cert_manager if hasattr(req.app.state, 'cert_manager') else None
            
            # Use async storage if available, otherwise fallback to sync
            cert = await async_storage.get_certificate(cert_request.cert_name)
            if cert:
                raise HTTPException(
                    409,
                    f"Certificate '{cert_request.cert_name}' already exists"
                )
            
            # Create new certificate
            from src.certmanager.models import Certificate
            cert = Certificate(
                cert_name=cert_request.cert_name,
                domains=[cert_request.domain],
                email=cert_request.email,
                acme_directory_url=cert_request.acme_directory_url,
                status="pending",
                owner_token_hash=None,  # No more token ownership
                created_by=auth_user
            )
            
            # Store certificate
            success = await async_storage.store_certificate(cert_request.cert_name, cert)
            if not success:
                # Storage rejected due to domain conflict
                raise HTTPException(
                    409,
                    f"A certificate already exists for domain '{cert_request.domain}'. "
                    f"Each domain can only have one active certificate."
                )
            
            # Start async generation
            from src.certmanager.async_acme import generate_certificate_async
            log_info(f"[API] Queuing background task for certificate {cert_request.cert_name}", component="api.certificates")
            log_info(f"[API] AsyncCertManager type: {type(async_cert_manager).__name__ if async_cert_manager else 'None'}", component="api.certificates")
            background_tasks.add_task(
                generate_certificate_async,
                async_cert_manager,
                cert_request,
                None,  # No more token hash
                auth_user
            )
            log_info(f"[API] Background task queued successfully for {cert_request.cert_name}", component="api.certificates")
            
            return {
                "message": f"Certificate generation started for {cert_request.domain}",
                "cert_name": cert_request.cert_name,
                "status": "pending"
            }
        except HTTPException:
            # Re-raise HTTPException without modification
            raise
        except Exception as e:
            log_error(f"Failed to create certificate: {e}", component="api.certificates", error=e)
            raise HTTPException(status_code=400, detail=str(e))
    
    @router.post("/multi-domain")
    async def create_multi_domain_certificate(
        req: Request,
        request: dict,
        background_tasks: BackgroundTasks
    ):
        """Create a multi-domain certificate (async operation)."""
        from src.certmanager.models import MultiDomainCertificateRequest
        
        # Get auth info from headers (set by proxy)
        auth_user = req.headers.get("X-Auth-User", "system")
        auth_scopes = req.headers.get("X-Auth-Scopes", "").split()
        
        try:
            cert_request = MultiDomainCertificateRequest(**request)
            
            # Get async components
            async_storage = req.app.state.async_storage if hasattr(req.app.state, 'async_storage') else None
            async_cert_manager = req.app.state.cert_manager if hasattr(req.app.state, 'cert_manager') else None
            
            # Check if certificate with this name already exists
            existing_cert = await async_storage.get_certificate(cert_request.cert_name)
            if existing_cert:
                raise HTTPException(
                    409,
                    f"Certificate '{cert_request.cert_name}' already exists"
                )
            
            # Store initial certificate record
            from src.certmanager.models import Certificate
            cert = Certificate(
                cert_name=cert_request.cert_name,
                domains=cert_request.domains,
                email=cert_request.email,
                acme_directory_url=cert_request.acme_directory_url,
                status="pending",
                owner_token_hash=None,  # No more token ownership
                created_by=auth_user
            )
            
            # Store certificate
            success = await async_storage.store_certificate(cert_request.cert_name, cert)
            if not success:
                # Storage rejected due to domain conflict
                # Find which domain already has a certificate
                conflicting_domains = []
                for domain in cert_request.domains:
                    existing_cert_name = async_storage.redis_client.get(f"cert:domain:{domain}")
                    if existing_cert_name and existing_cert_name != cert_request.cert_name:
                        conflicting_domains.append(domain)
                
                raise HTTPException(
                    409,
                    f"Certificate(s) already exist for domain(s): {', '.join(conflicting_domains)}. "
                    f"Each domain can only have one active certificate."
                )
            
            # Start async generation
            from src.certmanager.async_acme import generate_certificate_async
            log_info(f"[API] Queuing background task for multi-domain certificate {cert_request.cert_name}", component="api.certificates")
            log_info(f"[API] AsyncCertManager type: {type(async_cert_manager).__name__ if async_cert_manager else 'None'}", component="api.certificates")
            background_tasks.add_task(
                generate_certificate_async,
                async_cert_manager,
                cert_request,
                None,  # No more token hash
                auth_user
            )
            log_info(f"[API] Background task queued successfully for multi-domain {cert_request.cert_name}", component="api.certificates")
            
            return {
                "message": f"Multi-domain certificate generation started",
                "cert_name": cert_request.cert_name,
                "domains": cert_request.domains,
                "status": "pending"
            }
        except HTTPException:
            # Re-raise HTTPException without modification
            raise
        except Exception as e:
            log_error(f"Failed to create multi-domain certificate: {e}", component="api.certificates", error=e)
            raise HTTPException(status_code=400, detail=str(e))
    
    @router.get("/")
    async def list_certificates(
        req: Request
    ):
        """List all certificates."""
        # Get auth info from headers (set by proxy)
        auth_user = req.headers.get("X-Auth-User", "system")
        auth_scopes = req.headers.get("X-Auth-Scopes", "").split()
        is_admin = "admin" in auth_scopes
        try:
            # Debug: Check if auth_service exists
            has_auth_service = hasattr(req.app.state, 'auth_service')
            auth_service_type = type(req.app.state.auth_service).__name__ if has_auth_service else "None"
            
            # Get async storage
            async_storage = req.app.state.async_storage if hasattr(req.app.state, 'async_storage') else None
            
            # Get all certificates
            all_certs = await async_storage.list_certificates()
            log_debug(f"list_certificates: Found {len(all_certs)} certificates total", component="api.certificates")
            log_debug(f"list_certificates: has_auth_service={has_auth_service}, auth_service_type={auth_service_type}", component="api.certificates")
            log_debug(f"list_certificates: Auth user={auth_user}, is_admin={is_admin}, scopes={auth_scopes}", component="api.certificates")
            
            # No ownership filtering without tokens - return all for users with read access
            if is_admin or "user" in auth_scopes:
                certs_to_return = all_certs
            else:
                certs_to_return = []
            
            # Remove private keys from all certificates in the list
            filtered_certs = []
            for cert in certs_to_return:
                # Create a copy without the private key
                if isinstance(cert, dict):
                    cert_copy = cert.copy()
                else:
                    # Pydantic model - use model_dump
                    cert_copy = cert.model_dump() if hasattr(cert, 'model_dump') else cert.dict()
                # Remove sensitive/large fields
                cert_copy.pop('private_key_pem', None)
                cert_copy.pop('fullchain_pem', None)
                filtered_certs.append(cert_copy)
            
            return filtered_certs
        except Exception as e:
            log_error(f"Failed to list certificates: {e}", component="api.certificates", error=e)
            raise HTTPException(status_code=500, detail=str(e))
    
    @router.get("/{cert_name}")
    async def get_certificate(
        req: Request,
        cert_name: str
    ):
        """Get certificate details."""
        # Get auth info from headers (set by proxy)
        auth_user = req.headers.get("X-Auth-User", "system")
        auth_scopes = req.headers.get("X-Auth-Scopes", "").split()
        is_admin = "admin" in auth_scopes
        # Get async storage
        async_storage = req.app.state.async_storage if hasattr(req.app.state, 'async_storage') else None
        
        cert = await async_storage.get_certificate(cert_name)
        if not cert:
            raise HTTPException(status_code=404, detail="Certificate not found")
        
        # No ownership check without tokens - just check if user has read access
        if not (is_admin or "user" in auth_scopes):
            raise HTTPException(status_code=403, detail="Access denied")
        
        return cert
    
    @router.get("/{cert_name}/status")
    async def get_certificate_status(
        req: Request,
        cert_name: str,
        wait: bool = Query(default=False)
    ):
        """Get certificate generation status."""
        # Get auth info from headers (set by proxy)
        auth_user = req.headers.get("X-Auth-User", "system")
        auth_scopes = req.headers.get("X-Auth-Scopes", "").split()
        is_admin = "admin" in auth_scopes
        import asyncio
        import json
        
        # Get async storage
        async_storage = req.app.state.async_storage if hasattr(req.app.state, 'async_storage') else None
        
        # Check status with optional waiting
        max_attempts = 60 if wait else 1
        
        for attempt in range(max_attempts):
            status_data = await async_storage.redis_client.get(f"cert:status:{cert_name}")
            if status_data:
                import json
                status = json.loads(status_data)
                if status.get('status') in ['completed', 'failed'] or not wait:
                    return status
            
            if wait and attempt < max_attempts - 1:
                await asyncio.sleep(2)
        
        # Return current certificate status if no generation status
        cert = await async_storage.get_certificate(cert_name)
        if cert:
            return {
                "status": cert.status,
                "message": "Certificate exists"
            }
        
        raise HTTPException(status_code=404, detail="Status not found")
    
    @router.post("/{cert_name}/renew")
    async def renew_certificate(
        req: Request,
        cert_name: str,
        background_tasks: BackgroundTasks,
        force: bool = Query(default=False)
    ):
        """Manually trigger certificate renewal."""
        # Get auth info from headers (set by proxy)
        auth_user = req.headers.get("X-Auth-User", "system")
        auth_scopes = req.headers.get("X-Auth-Scopes", "").split()
        is_admin = "admin" in auth_scopes
        # Get async storage
        async_storage = req.app.state.async_storage if hasattr(req.app.state, 'async_storage') else None
        
        cert = await async_storage.get_certificate(cert_name)
        if not cert:
            raise HTTPException(status_code=404, detail="Certificate not found")
        
        # Check if user has admin scope for renewal
        if not is_admin:
            raise HTTPException(status_code=403, detail="Admin access required for renewal")
        
        # Check if renewal is needed
        cert_expires = cert.get('expires_at') if isinstance(cert, dict) else getattr(cert, 'expires_at', None)
        if not force and cert_expires:
            from datetime import datetime, timedelta
            if cert_expires > datetime.now() + timedelta(days=30):
                return {
                    "message": "Certificate does not need renewal yet",
                    "expires_at": cert_expires.isoformat()
                }
        
        # Start renewal
        background_tasks.add_task(cert_manager.renew_certificate, cert_name)
        
        return {
            "message": f"Certificate renewal started for {cert_name}",
            "status": "pending"
        }
    
    @router.post("/{cert_name}/convert-to-production")
    async def convert_to_production(
        req: Request,
        cert_name: str,
        background_tasks: BackgroundTasks
    ):
        """Convert a staging certificate to production."""
        # Get auth info from headers (set by proxy)
        auth_user = req.headers.get("X-Auth-User", "system")
        auth_scopes = req.headers.get("X-Auth-Scopes", "").split()
        is_admin = "admin" in auth_scopes
        # Get async storage
        async_storage = req.app.state.async_storage if hasattr(req.app.state, 'async_storage') else None
        
        cert = await async_storage.get_certificate(cert_name)
        if not cert:
            raise HTTPException(status_code=404, detail="Certificate not found")
        
        # Check if user has admin scope for renewal
        if not is_admin:
            raise HTTPException(status_code=403, detail="Admin access required for renewal")
        
        # Check if it's actually a staging certificate
        cert_acme_url = cert.get('acme_directory_url') if isinstance(cert, dict) else getattr(cert, 'acme_directory_url', None)
        if not cert_acme_url or 'staging' not in cert_acme_url.lower():
            return {
                "message": "Certificate is already a production certificate",
                "acme_url": cert_acme_url
            }
        
        # Get production ACME URL
        production_url = os.getenv('ACME_DIRECTORY_URL', 'https://acme-v02.api.letsencrypt.org/directory')
        
        # Create certificate request with production URL
        from src.certmanager.models import CertificateRequest
        cert_domains = cert.get('domains') if isinstance(cert, dict) else getattr(cert, 'domains', [])
        cert_email = cert.get('email') if isinstance(cert, dict) else getattr(cert, 'email', None)
        cert_created_by = cert.get('created_by') if isinstance(cert, dict) else getattr(cert, 'created_by', None)
        
        cert_request = CertificateRequest(
            domain=cert_domains[0] if cert_domains else "",
            domains=cert_domains,
            email=cert_email,
            acme_directory_url=production_url,
            cert_name=cert_name
        )
        
        # Mark old certificate as pending replacement
        if isinstance(cert, dict):
            cert['status'] = "replacing"
        else:
            cert.status = "replacing"
        await async_storage.store_certificate(cert_name, cert)
        # Generate new production certificate (will replace the staging one)
        from src.certmanager.async_acme import generate_certificate_async
        background_tasks.add_task(
            generate_certificate_async,
            cert_manager,
            cert_request,
            cert_owner,
            cert_created_by
        )
        
        # Also trigger SSL context reload after certificate is generated
        # This ensures the HTTPS instance uses the new production certificate
        import asyncio
        async def publish_cert_update_after_generation():
            # Wait a bit for certificate generation to complete
            await asyncio.sleep(60)
            try:
                # Publish event to update SSL context
                await req.app.state.async_storage.redis_client.xadd(
                    "events:all:stream",
                    {
                        "event_type": "certificate_updated",
                        "proxy_hostname": cert_domains[0] if cert_domains else "",
                        "cert_name": cert_name,
                        "action": "reload_ssl_context"
                    }
                )
            except Exception as e:
                log_error(f"Failed to publish certificate_updated event: {e}", component="api.certificates", error=e)
        
        # Schedule the update event
        asyncio.create_task(publish_cert_update_after_generation())
        
        return {
            "message": f"Converting {cert_name} from staging to production",
            "status": "pending",
            "production_url": production_url
        }
    
    @router.delete("/{cert_name}")
    async def delete_certificate(
        req: Request,
        cert_name: str
    ):
        """Delete a certificate."""
        # Get auth info from headers (set by proxy)
        auth_user = req.headers.get("X-Auth-User", "system")
        auth_scopes = req.headers.get("X-Auth-Scopes", "").split()
        is_admin = "admin" in auth_scopes
        # Get async storage and cert manager
        async_storage = req.app.state.async_storage if hasattr(req.app.state, 'async_storage') else None
        async_cert_manager = req.app.state.cert_manager if hasattr(req.app.state, 'cert_manager') else None
        
        cert = await async_storage.get_certificate(cert_name)
        if not cert:
            raise HTTPException(status_code=404, detail="Certificate not found")
        
        # Check if user has admin scope for renewal
        if not is_admin:
            raise HTTPException(status_code=403, detail="Admin access required for renewal")
        
        # Delete certificate
        success = await async_storage.delete_certificate(cert_name)
        if success:
            # Update cert manager if it has ssl_contexts
            if async_cert_manager and hasattr(async_cert_manager, 'ssl_contexts'):
                if cert_name in async_cert_manager.ssl_contexts:
                    del async_cert_manager.ssl_contexts[cert_name]
            
            return {"message": f"Certificate {cert_name} deleted successfully"}
        else:
            raise HTTPException(status_code=500, detail="Failed to delete certificate")
    
    return router
    
