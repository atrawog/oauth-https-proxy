"""Certificate management API endpoints."""

import logging
from typing import List, Optional
from fastapi import APIRouter, HTTPException, Depends, BackgroundTasks, Query

from ..auth import require_auth, require_auth_header

logger = logging.getLogger(__name__)


def create_router(storage, cert_manager):
    """Create certificate endpoints router."""
    router = APIRouter(prefix="/certificates", tags=["certificates"])
    
    @router.post("/")
    async def create_certificate(
        request: dict,
        background_tasks: BackgroundTasks,
        token_info: dict = Depends(require_auth)
    ):
        """Create a new certificate (async operation)."""
        from ...certmanager.models import CertificateRequest
        
        try:
            cert_request = CertificateRequest(**request)
            cert_request.cert_name = f"proxy-{cert_request.domain.replace('.', '-')}"
            
            # Store token ownership
            cert = cert_manager.get_certificate(cert_request.cert_name)
            if not cert:
                from ...certmanager.models import Certificate
                cert = Certificate(
                    cert_name=cert_request.cert_name,
                    domains=[cert_request.domain],
                    email=cert_request.email,
                    acme_directory_url=cert_request.acme_directory_url,
                    status="pending",
                    owner_token_hash=token_info['hash'],
                    created_by=token_info['name']
                )
                if not storage.store_certificate(cert_request.cert_name, cert):
                    # Storage rejected due to domain conflict
                    raise HTTPException(
                        409,
                        f"A certificate already exists for domain '{cert_request.domain}'. "
                        f"Each domain can only have one active certificate."
                    )
            
            # Start async generation
            from ...certmanager.async_acme import generate_certificate_async
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
        from ...certmanager.models import MultiDomainCertificateRequest
        
        try:
            cert_request = MultiDomainCertificateRequest(**request)
            
            # Check if certificate with this name already exists
            existing_cert = cert_manager.get_certificate(cert_request.cert_name)
            if existing_cert:
                raise HTTPException(
                    409,
                    f"Certificate '{cert_request.cert_name}' already exists"
                )
            
            # Store initial certificate record
            from ...certmanager.models import Certificate
            cert = Certificate(
                cert_name=cert_request.cert_name,
                domains=cert_request.domains,
                email=cert_request.email,
                acme_directory_url=cert_request.acme_directory_url,
                status="pending",
                owner_token_hash=token_info['hash'],
                created_by=token_info['name']
            )
            if not storage.store_certificate(cert_request.cert_name, cert):
                # Storage rejected due to domain conflict
                # Find which domain already has a certificate
                conflicting_domains = []
                for domain in cert_request.domains:
                    existing_cert_name = storage.redis_client.get(f"cert:domain:{domain}")
                    if existing_cert_name and existing_cert_name != cert_request.cert_name:
                        conflicting_domains.append(domain)
                
                raise HTTPException(
                    409,
                    f"Certificate(s) already exist for domain(s): {', '.join(conflicting_domains)}. "
                    f"Each domain can only have one active certificate."
                )
            
            # Start async generation
            background_tasks.add_task(
                cert_manager.generate_multi_domain_certificate_async,
                cert_request
            )
            
            return {
                "message": f"Multi-domain certificate generation started",
                "cert_name": cert_request.cert_name,
                "domains": cert_request.domains,
                "status": "pending"
            }
        except Exception as e:
            logger.error(f"Failed to create multi-domain certificate: {e}")
            raise HTTPException(status_code=400, detail=str(e))
    
    @router.get("/")
    async def list_certificates(
        token_hash: str = Depends(require_auth_header)
    ):
        """List all certificates."""
        try:
            # Admin token sees all
            if token_hash and storage.get_api_token(token_hash):
                token_info = storage.get_api_token(token_hash)
                if token_info and token_info.get('name') == 'ADMIN':
                    return storage.list_certificates()
            
            # Regular users see only their certificates
            all_certs = storage.list_certificates()
            if token_hash:
                user_certs = [cert for cert in all_certs if cert.owner_token_hash == token_hash]
                return user_certs
            
            return []
        except Exception as e:
            logger.error(f"Failed to list certificates: {e}")
            raise HTTPException(status_code=500, detail=str(e))
    
    @router.get("/{cert_name}")
    async def get_certificate(
        cert_name: str,
        token_hash: str = Depends(require_auth_header)
    ):
        """Get certificate details."""
        cert = storage.get_certificate(cert_name)
        if not cert:
            raise HTTPException(status_code=404, detail="Certificate not found")
        
        # Check ownership
        if token_hash and cert.owner_token_hash:
            token_info = storage.get_api_token(token_hash)
            if token_info and token_info.get('name') != 'ADMIN' and cert.owner_token_hash != token_hash:
                raise HTTPException(status_code=403, detail="Access denied")
        
        return cert
    
    @router.get("/{cert_name}/status")
    async def get_certificate_status(
        cert_name: str,
        wait: bool = Query(default=False),
        token_hash: str = Depends(require_auth_header)
    ):
        """Get certificate generation status."""
        import asyncio
        
        # Check status with optional waiting
        max_attempts = 60 if wait else 1
        
        for attempt in range(max_attempts):
            status_data = storage.redis_client.get(f"cert:status:{cert_name}")
            
            if status_data:
                import json
                status = json.loads(status_data)
                if status.get('status') in ['completed', 'failed'] or not wait:
                    return status
            
            if wait and attempt < max_attempts - 1:
                await asyncio.sleep(2)
        
        # Return current certificate status if no generation status
        cert = storage.get_certificate(cert_name)
        if cert:
            return {
                "status": cert.status,
                "message": "Certificate exists"
            }
        
        raise HTTPException(status_code=404, detail="Status not found")
    
    @router.post("/{cert_name}/renew")
    async def renew_certificate(
        cert_name: str,
        background_tasks: BackgroundTasks,
        force: bool = Query(default=False),
        token_info: dict = Depends(require_auth)
    ):
        """Manually trigger certificate renewal."""
        cert = storage.get_certificate(cert_name)
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
    
    @router.delete("/{cert_name}")
    async def delete_certificate(
        cert_name: str,
        token_info: dict = Depends(require_auth)
    ):
        """Delete a certificate."""
        cert = storage.get_certificate(cert_name)
        if not cert:
            raise HTTPException(status_code=404, detail="Certificate not found")
        
        # Check ownership
        if cert.owner_token_hash and cert.owner_token_hash != token_info['hash']:
            if token_info.get('name') != 'ADMIN':
                raise HTTPException(status_code=403, detail="Access denied")
        
        # Delete certificate
        if storage.delete_certificate(cert_name):
            # Update cert manager
            if cert_name in cert_manager.ssl_contexts:
                del cert_manager.ssl_contexts[cert_name]
            
            return {"message": f"Certificate {cert_name} deleted successfully"}
        else:
            raise HTTPException(status_code=500, detail="Failed to delete certificate")
    
    return router