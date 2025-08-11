"""Certificate management API endpoints."""

import logging
import os
from typing import List, Optional
from fastapi import APIRouter, HTTPException, Depends, BackgroundTasks, Query, Request

from src.api.auth import require_auth, require_auth_header

logger = logging.getLogger(__name__)


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
        background_tasks: BackgroundTasks,
        token_info: dict = Depends(require_auth)
    ):
        """Create a new certificate (async operation)."""
        from src.certmanager.models import CertificateRequest
        
        try:
            cert_request = CertificateRequest(**request)
            cert_request.cert_name = f"proxy-{cert_request.domain.replace('.', '-')}"
            
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
                owner_token_hash=token_info['hash'],
                created_by=token_info['name']
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
            background_tasks.add_task(
                generate_certificate_async,
                cert_manager,
                cert_request
            )
            
            return {
                "message": f"Certificate generation started for {cert_request.domain}",
                "cert_name": cert_request.cert_name,
                "status": "pending"
            }
        except HTTPException:
            # Re-raise HTTPException without modification
            raise
        except Exception as e:
            logger.error(f"Failed to create certificate: {e}")
            raise HTTPException(status_code=400, detail=str(e))
    
    @router.post("/multi-domain")
    async def create_multi_domain_certificate(
        request: dict,
        background_tasks: BackgroundTasks,
        token_info: dict = Depends(require_auth)
    ):
        """Create a multi-domain certificate (async operation)."""
        from src.certmanager.models import MultiDomainCertificateRequest
        
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
                owner_token_hash=token_info['hash'],
                created_by=token_info['name']
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
            background_tasks.add_task(
                generate_certificate_async,
                cert_manager,
                cert_request
            )
            
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
            logger.error(f"Failed to create multi-domain certificate: {e}")
            raise HTTPException(status_code=400, detail=str(e))
    
    @router.get("/")
    async def list_certificates(
        req: Request,
        token_hash: str = Depends(require_auth_header)
    ):
        """List all certificates."""
        try:
            # Get async storage
            async_storage = req.app.state.async_storage if hasattr(req.app.state, 'async_storage') else None
            
            # Get all certificates
            all_certs = await async_storage.list_certificates()
            
            # Filter by ownership
            certs_to_return = []
            if token_hash:
                token_info = await async_storage.get_api_token(token_hash)
                if token_info and token_info.get('name') == 'ADMIN':
                    certs_to_return = all_certs
                else:
                    certs_to_return = [cert for cert in all_certs if cert.get('owner_token_hash') == token_hash]
            
            # Remove private keys from all certificates in the list
            filtered_certs = []
            for cert in certs_to_return:
                # Create a copy without the private key
                cert_copy = cert.copy() if isinstance(cert, dict) else cert.__dict__.copy()
                # Remove sensitive/large fields
                cert_copy.pop('private_key_pem', None)
                cert_copy.pop('fullchain_pem', None)
                filtered_certs.append(cert_copy)
            
            return filtered_certs
        except Exception as e:
            logger.error(f"Failed to list certificates: {e}")
            raise HTTPException(status_code=500, detail=str(e))
    
    @router.get("/{cert_name}")
    async def get_certificate(
        req: Request,
        cert_name: str,
        token_hash: str = Depends(require_auth_header)
    ):
        """Get certificate details."""
        # Get async storage
        async_storage = req.app.state.async_storage if hasattr(req.app.state, 'async_storage') else None
        
        cert = await async_storage.get_certificate(cert_name)
        if not cert:
            raise HTTPException(status_code=404, detail="Certificate not found")
        
        # Check ownership
        if token_hash and cert.owner_token_hash:
            token_info = await async_storage.get_api_token(token_hash)
            if token_info and token_info.get('name') != 'ADMIN' and cert.owner_token_hash != token_hash:
                raise HTTPException(status_code=403, detail="Access denied")
        
        return cert
    
    @router.get("/{cert_name}/status")
    async def get_certificate_status(
        req: Request,
        cert_name: str,
        wait: bool = Query(default=False),
        token_hash: str = Depends(require_auth_header)
    ):
        """Get certificate generation status."""
        import asyncio
        import json
        
        # Get async storage
        async_storage = req.app.state.async_storage if hasattr(req.app.state, 'async_storage') else None
        
        # Check status with optional waiting
        max_attempts = 60 if wait else 1
        
        for attempt in range(max_attempts):
            status_data = await async_async_storage.redis_client.get(f"cert:status:{cert_name}")
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
        force: bool = Query(default=False),
        token_info: dict = Depends(require_auth)
    ):
        """Manually trigger certificate renewal."""
        # Get async storage
        async_storage = req.app.state.async_storage if hasattr(req.app.state, 'async_storage') else None
        
        cert = await async_storage.get_certificate(cert_name)
        if not cert:
            raise HTTPException(status_code=404, detail="Certificate not found")
        
        # Check ownership
        if cert.owner_token_hash and cert.owner_token_hash != token_info['hash']:
            if token_info.get('name') != 'ADMIN':
                raise HTTPException(status_code=403, detail="Access denied")
        
        # Check if renewal is needed
        if not force and cert.expires_at:
            from datetime import datetime, timedelta
            if cert.expires_at > datetime.now() + timedelta(days=30):
                return {
                    "message": "Certificate does not need renewal yet",
                    "expires_at": cert.expires_at.isoformat()
                }
        
        # Start renewal
        background_tasks.add_task(cert_manager.renew_certificate, cert_name, force)
        
        return {
            "message": f"Certificate renewal started for {cert_name}",
            "status": "pending"
        }
    
    @router.post("/{cert_name}/convert-to-production")
    async def convert_to_production(
        req: Request,
        cert_name: str,
        background_tasks: BackgroundTasks,
        token_info: dict = Depends(require_auth)
    ):
        """Convert a staging certificate to production."""
        # Get async storage
        async_storage = req.app.state.async_storage if hasattr(req.app.state, 'async_storage') else None
        
        cert = await async_storage.get_certificate(cert_name)
        if not cert:
            raise HTTPException(status_code=404, detail="Certificate not found")
        
        # Check ownership
        if cert.owner_token_hash and cert.owner_token_hash != token_info['hash']:
            if token_info.get('name') != 'ADMIN':
                raise HTTPException(status_code=403, detail="Access denied")
        
        # Check if it's actually a staging certificate
        if not cert.acme_directory_url or 'staging' not in cert.acme_directory_url.lower():
            return {
                "message": "Certificate is already a production certificate",
                "acme_url": cert.acme_directory_url
            }
        
        # Get production ACME URL
        production_url = os.getenv('ACME_DIRECTORY_URL', 'https://acme-v02.api.letsencrypt.org/directory')
        
        # Create certificate request with production URL
        from src.certmanager.models import CertificateRequest
        cert_request = CertificateRequest(
            domain=cert.domains[0] if cert.domains else "",
            domains=cert.domains,
            email=cert.email,
            acme_directory_url=production_url,
            cert_name=cert_name
        )
        
        # Mark old certificate as pending replacement
        cert.status = "replacing"
        await async_storage.store_certificate(cert_name, cert)
        # Generate new production certificate (will replace the staging one)
        from src.certmanager.async_acme import generate_certificate_async
        background_tasks.add_task(
            generate_certificate_async,
            cert_manager,
            cert_request,
            cert.owner_token_hash,
            cert.created_by
        )
        
        return {
            "message": f"Converting {cert_name} from staging to production",
            "status": "pending",
            "production_url": production_url
        }
    
    @router.delete("/{cert_name}")
    async def delete_certificate(
        req: Request,
        cert_name: str,
        token_info: dict = Depends(require_auth)
    ):
        """Delete a certificate."""
        # Get async storage and cert manager
        async_storage = req.app.state.async_storage if hasattr(req.app.state, 'async_storage') else None
        async_cert_manager = req.app.state.cert_manager if hasattr(req.app.state, 'cert_manager') else None
        
        cert = await async_storage.get_certificate(cert_name)
        if not cert:
            raise HTTPException(status_code=404, detail="Certificate not found")
        
        # Check ownership
        if cert.owner_token_hash and cert.owner_token_hash != token_info['hash']:
            if token_info.get('name') != 'ADMIN':
                raise HTTPException(status_code=403, detail="Access denied")
        
        # Delete certificate
        success = await async_storage.delete_certificate(cert_name)
        if success:
            # Update cert manager
            if async_cert_manager and hasattr(async_cert_manager, 'ssl_contexts'):
                if cert_name in async_cert_manager.ssl_contexts:
                    del async_cert_manager.ssl_contexts[cert_name]
            elif cert_name in cert_manager.ssl_contexts:
                del cert_manager.ssl_contexts[cert_name]
            
            return {"message": f"Certificate {cert_name} deleted successfully"}
        else:
            raise HTTPException(status_code=500, detail="Failed to delete certificate")
    
    return router
    
