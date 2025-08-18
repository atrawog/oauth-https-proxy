"""Async certificate manager with full event publishing and tracing.

This module provides certificate management with comprehensive event
publishing and trace correlation through the unified logging system.
"""

import asyncio
import logging
import os
import secrets
from typing import Dict, List, Optional, Any
from datetime import datetime, timezone, timedelta
from concurrent.futures import ThreadPoolExecutor

from .models import Certificate, CertificateRequest
from .manager import CertificateManager as SyncCertManager
from ..storage.async_redis_storage import AsyncRedisStorage
from ..shared.unified_logger import UnifiedAsyncLogger
from ..storage.redis_clients import RedisClients

logger = logging.getLogger(__name__)

# Global executor for ACME operations
max_workers = int(os.getenv('CERT_GEN_MAX_WORKERS', '5'))
executor = ThreadPoolExecutor(max_workers=max_workers)

# Track ongoing certificate generations
ongoing_generations: Dict[str, asyncio.Task] = {}
generation_results: Dict[str, Dict[str, Any]] = {}


class AsyncCertificateManager:
    """Async certificate manager with event publishing."""
    
    def __init__(self, storage: AsyncRedisStorage, redis_clients: RedisClients):
        """Initialize async certificate manager.
        
        Args:
            storage: Async Redis storage instance
            redis_clients: Redis clients for logging
        """
        self.storage = storage
        self.redis_clients = redis_clients
        
        # Initialize unified logger
        self.logger = UnifiedAsyncLogger(redis_clients)
        self.logger.set_component("certificate_manager")
        
        # Initialize sync manager for ACME operations
        # Need sync storage for sync manager
        try:
            from ..storage.redis_storage import RedisStorage
            # Build Redis URL with password
            redis_base = os.getenv('REDIS_URL', 'redis://redis:6379/0')
            redis_password = os.getenv('REDIS_PASSWORD', '')
            
            # Parse and rebuild URL with password
            if redis_password and '://' in redis_base:
                # Insert password into URL: redis://:password@host:port/db
                parts = redis_base.split('://', 1)
                if '@' not in parts[1]:  # No password in URL yet
                    host_part = parts[1]
                    redis_url = f"{parts[0]}://:{redis_password}@{host_part}"
                else:
                    redis_url = redis_base
            else:
                redis_url = redis_base
            
            logger.info(f"Initializing sync RedisStorage with URL pattern: redis://:****@{redis_url.split('@')[-1] if '@' in redis_url else redis_url.split('//')[-1]}")
            sync_storage = RedisStorage(redis_url)
            self.sync_manager = SyncCertManager(sync_storage)
            logger.info("Successfully initialized sync CertificateManager for ACME operations")
        except Exception as e:
            logger.error(f"Failed to initialize sync CertificateManager: {e}", exc_info=True)
            self.sync_manager = None
        
        # Renewal configuration
        self.renewal_check_interval = int(os.getenv('RENEWAL_CHECK_INTERVAL', '86400'))
        self.renewal_threshold_days = int(os.getenv('RENEWAL_THRESHOLD_DAYS', '30'))
        
        # Renewal task
        self.renewal_task: Optional[asyncio.Task] = None
        self.running = False
    
    async def start(self):
        """Start the certificate manager with auto-renewal."""
        if self.running:
            logger.warning("Certificate manager already running")
            return
        
        self.running = True
        self.renewal_task = asyncio.create_task(self._renewal_loop())
        
        await self.logger.info("Certificate manager started with auto-renewal")
    
    async def stop(self):
        """Stop the certificate manager."""
        self.running = False
        
        if self.renewal_task:
            self.renewal_task.cancel()
            try:
                await self.renewal_task
            except asyncio.CancelledError:
                pass
        
        # Wait for ongoing generations
        if ongoing_generations:
            await asyncio.gather(*ongoing_generations.values(), return_exceptions=True)
        
        await self.logger.info("Certificate manager stopped")
    
    async def create_certificate(self, request: CertificateRequest,
                                owner_token_hash: Optional[str] = None,
                                created_by: Optional[str] = None) -> Certificate:
        """Create a new certificate with full tracing.
        
        Args:
            request: Certificate request
            owner_token_hash: Owner token hash
            created_by: Creator identifier
            
        Returns:
            Generated certificate
        """
        cert_name = request.cert_name
        
        # Check if generation is already in progress
        if cert_name in ongoing_generations:
            await self.logger.warning(
                f"Certificate generation already in progress for {cert_name}"
            )
            
            # Wait for ongoing generation
            try:
                return await ongoing_generations[cert_name]
            except Exception as e:
                raise
        
        # Start new generation
        task = asyncio.create_task(
            self._generate_certificate_with_events(request, owner_token_hash, created_by)
        )
        ongoing_generations[cert_name] = task
        
        try:
            certificate = await task
            return certificate
        finally:
            # Clean up
            if cert_name in ongoing_generations:
                del ongoing_generations[cert_name]
    
    async def _generate_certificate_with_events(self, request: CertificateRequest,
                                               owner_token_hash: Optional[str],
                                               created_by: Optional[str]) -> Certificate:
        """Generate certificate with comprehensive event publishing.
        
        Args:
            request: Certificate request
            owner_token_hash: Owner token hash
            created_by: Creator identifier
            
        Returns:
            Generated certificate
        """
        cert_name = request.cert_name
        
        # Start trace
        is_staging = 'staging' in request.acme_directory_url.lower()
        trace_id = self.logger.start_trace(
            "certificate_generation",
            cert_name=cert_name,
            domain=request.domain,
            email=request.email,
            is_staging=is_staging
        )
        
        try:
            # Log generation start
            await self.logger.info(
                f"Starting certificate generation for {cert_name}",
                trace_id=trace_id,
                domain=request.domain,
                acme_directory=request.acme_directory_url
            )
            
            # Publish generation started event
            await self.logger.log_certificate_event(
                cert_name=cert_name,
                event_type="generation_started",
                domains=[request.domain],
                trace_id=trace_id,
                is_staging=is_staging
            )
            
            # Update generation status
            generation_results[cert_name] = {
                "status": "in_progress",
                "message": f"Generating certificate for {request.domain}",
                "started_at": asyncio.get_event_loop().time(),
                "trace_id": trace_id
            }
            
            # Run ACME operations in executor
            await self.logger.debug(
                "Starting ACME protocol operations",
                trace_id=trace_id
            )
            
            if not self.sync_manager:
                error_msg = "Sync CertificateManager not initialized - cannot generate certificates"
                logger.error(f"[CERT_GEN_ERROR] {error_msg}")
                await self.logger.error(error_msg, trace_id=trace_id)
                raise RuntimeError(error_msg)
            
            logger.info(f"[CERT_GEN] Running sync certificate generation in executor for {cert_name}")
            loop = asyncio.get_event_loop()
            certificate = await loop.run_in_executor(
                executor,
                self.sync_manager.create_certificate,
                request,
                owner_token_hash,
                created_by
            )
            logger.info(f"[CERT_GEN] Sync certificate generation completed for {cert_name}")
            
            # Add ownership info
            certificate.owner_token_hash = owner_token_hash
            certificate.created_by = created_by
            
            # Store certificate
            await self.storage.store_certificate(cert_name, certificate)
            
            await self.logger.info(
                f"Certificate generation completed for {cert_name}",
                trace_id=trace_id,
                expires_at=certificate.expires_at.isoformat() if certificate.expires_at else None
            )
            
            # Publish certificate ready event
            await self.logger.log_certificate_event(
                cert_name=cert_name,
                event_type="ready",
                domains=[request.domain],
                trace_id=trace_id,
                expires_at=certificate.expires_at.isoformat() if certificate.expires_at else None,
                is_renewal=False
            )
            
            # Update generation status
            generation_results[cert_name] = {
                "status": "completed",
                "message": f"Certificate generated successfully",
                "completed_at": asyncio.get_event_loop().time(),
                "trace_id": trace_id,
                "expires_at": certificate.expires_at.isoformat() if certificate.expires_at else None
            }
            
            # End trace successfully
            await self.logger.end_trace(trace_id, "success")
            
            return certificate
            
        except Exception as e:
            # Log failure
            await self.logger.error(
                f"Certificate generation failed for {cert_name}: {str(e)}",
                trace_id=trace_id,
                error_type=type(e).__name__
            )
            
            # Publish failure event
            await self.logger.log_certificate_event(
                cert_name=cert_name,
                event_type="generation_failed",
                domains=[request.domain],
                trace_id=trace_id,
                error=str(e)
            )
            
            # Update generation status
            generation_results[cert_name] = {
                "status": "failed",
                "message": str(e),
                "failed_at": asyncio.get_event_loop().time(),
                "trace_id": trace_id,
                "error": str(e)
            }
            
            await self.logger.end_trace(trace_id, "error", error=str(e))
            raise
    
    async def create_multi_domain_certificate(self, request,
                                             owner_token_hash: Optional[str] = None,
                                             created_by: Optional[str] = None) -> Certificate:
        """Create a multi-domain certificate with full tracing.
        
        Args:
            request: Multi-domain certificate request
            owner_token_hash: Owner token hash
            created_by: Creator identifier
            
        Returns:
            Generated certificate
        """
        cert_name = request.cert_name
        
        # Start trace
        trace_id = self.logger.start_trace(
            "multi_domain_certificate",
            cert_name=cert_name,
            domains=request.domains,
            email=request.email
        )
        
        try:
            await self.logger.info(
                f"Starting multi-domain certificate generation for {cert_name}",
                trace_id=trace_id,
                domain_count=len(request.domains)
            )
            
            # Publish event
            await self.logger.log_certificate_event(
                cert_name=cert_name,
                event_type="multi_domain_started",
                domains=request.domains,
                trace_id=trace_id
            )
            
            # Run ACME operations in executor
            loop = asyncio.get_event_loop()
            certificate = await loop.run_in_executor(
                executor,
                self.sync_manager.create_multi_domain_certificate,
                request,
                owner_token_hash,
                created_by
            )
            
            # Store certificate
            await self.storage.store_certificate(cert_name, certificate)
            
            # Publish ready event
            await self.logger.log_certificate_event(
                cert_name=cert_name,
                event_type="multi_domain_ready",
                domains=request.domains,
                trace_id=trace_id,
                expires_at=certificate.expires_at.isoformat() if certificate.expires_at else None
            )
            
            await self.logger.end_trace(trace_id, "success")
            return certificate
            
        except Exception as e:
            await self.logger.error(
                f"Multi-domain certificate generation failed: {str(e)}",
                trace_id=trace_id
            )
            
            await self.logger.log_certificate_event(
                cert_name=cert_name,
                event_type="multi_domain_failed",
                domains=request.domains,
                trace_id=trace_id,
                error=str(e)
            )
            
            await self.logger.end_trace(trace_id, "error", error=str(e))
            raise
    
    async def renew_certificate(self, cert_name: str) -> Optional[Certificate]:
        """Renew an existing certificate with event publishing.
        
        Args:
            cert_name: Name of certificate to renew
            
        Returns:
            Renewed certificate or None if renewal not needed/failed
        """
        trace_id = self.logger.start_trace(
            "certificate_renewal",
            cert_name=cert_name
        )
        
        try:
            # Get existing certificate
            existing_cert = await self.storage.get_certificate(cert_name)
            if not existing_cert:
                await self.logger.warning(
                    f"Certificate {cert_name} not found for renewal",
                    trace_id=trace_id
                )
                await self.logger.end_trace(trace_id, "not_found")
                return None
            
            # Check if renewal is needed
            if existing_cert.expires_at:
                days_until_expiry = (existing_cert.expires_at - datetime.now(timezone.utc)).days
                
                if days_until_expiry > self.renewal_threshold_days:
                    await self.logger.info(
                        f"Certificate {cert_name} does not need renewal yet ({days_until_expiry} days remaining)",
                        trace_id=trace_id
                    )
                    await self.logger.end_trace(trace_id, "not_needed")
                    return None
            
            await self.logger.info(
                f"Starting renewal for certificate {cert_name}",
                trace_id=trace_id,
                domains=existing_cert.domains
            )
            
            # Publish renewal started event
            await self.logger.log_certificate_event(
                cert_name=cert_name,
                event_type="renewal_started",
                domains=existing_cert.domains,
                trace_id=trace_id,
                days_remaining=days_until_expiry if existing_cert.expires_at else 0
            )
            
            # Run renewal in executor
            loop = asyncio.get_event_loop()
            renewed_cert = await loop.run_in_executor(
                executor,
                self.sync_manager.renew_certificate,
                cert_name
            )
            
            if renewed_cert:
                # Store renewed certificate
                await self.storage.store_certificate(cert_name, renewed_cert)
                
                await self.logger.info(
                    f"Certificate {cert_name} renewed successfully",
                    trace_id=trace_id,
                    new_expiry=renewed_cert.expires_at.isoformat() if renewed_cert.expires_at else None
                )
                
                # Publish renewal completed event
                await self.logger.log_certificate_event(
                    cert_name=cert_name,
                    event_type="renewed",
                    domains=renewed_cert.domains,
                    trace_id=trace_id,
                    expires_at=renewed_cert.expires_at.isoformat() if renewed_cert.expires_at else None,
                    is_renewal=True
                )
                
                await self.logger.end_trace(trace_id, "success")
                return renewed_cert
            else:
                await self.logger.warning(
                    f"Certificate renewal returned no certificate for {cert_name}",
                    trace_id=trace_id
                )
                await self.logger.end_trace(trace_id, "no_result")
                return None
                
        except Exception as e:
            await self.logger.error(
                f"Certificate renewal failed for {cert_name}: {str(e)}",
                trace_id=trace_id
            )
            
            # Publish renewal failed event
            await self.logger.log_certificate_event(
                cert_name=cert_name,
                event_type="renewal_failed",
                domains=existing_cert.domains if existing_cert else [],
                trace_id=trace_id,
                error=str(e)
            )
            
            await self.logger.end_trace(trace_id, "error", error=str(e))
            return None
    
    async def _renewal_loop(self):
        """Background task for automatic certificate renewal."""
        while self.running:
            try:
                # Wait for interval
                await asyncio.sleep(self.renewal_check_interval)
                
                # Check for expiring certificates
                await self._check_and_renew_certificates()
                
            except asyncio.CancelledError:
                break
            except Exception as e:
                await self.logger.error(
                    f"Error in renewal loop: {str(e)}",
                    error_type=type(e).__name__
                )
    
    async def _check_and_renew_certificates(self):
        """Check for expiring certificates and renew them."""
        trace_id = self.logger.start_trace("certificate_renewal_check")
        
        try:
            await self.logger.debug(
                "Checking for expiring certificates",
                trace_id=trace_id
            )
            
            # Get expiring certificates
            expiring_certs = await self.storage.get_expiring_certificates(
                days=self.renewal_threshold_days
            )
            
            if not expiring_certs:
                await self.logger.debug(
                    "No certificates need renewal",
                    trace_id=trace_id
                )
                await self.logger.end_trace(trace_id, "success", count=0)
                return
            
            await self.logger.info(
                f"Found {len(expiring_certs)} certificates needing renewal",
                trace_id=trace_id
            )
            
            # Renew each certificate
            renewed_count = 0
            failed_count = 0
            
            for cert_name, cert in expiring_certs:
                # Check expiry and publish warning events
                if cert.expires_at:
                    days_remaining = (cert.expires_at - datetime.now(timezone.utc)).days
                    
                    # Publish expiring event for monitoring
                    await self.logger.log_certificate_event(
                        cert_name=cert_name,
                        event_type="expiring_soon",
                        domains=cert.domains,
                        trace_id=trace_id,
                        days_remaining=days_remaining,
                        expires_at=cert.expires_at.isoformat()
                    )
                
                # Attempt renewal
                renewed_cert = await self.renew_certificate(cert_name)
                
                if renewed_cert:
                    renewed_count += 1
                else:
                    failed_count += 1
            
            await self.logger.info(
                f"Certificate renewal check completed: {renewed_count} renewed, {failed_count} failed",
                trace_id=trace_id
            )
            
            await self.logger.end_trace(
                trace_id,
                "success" if failed_count == 0 else "partial",
                renewed=renewed_count,
                failed=failed_count
            )
            
        except Exception as e:
            await self.logger.error(
                f"Certificate renewal check failed: {str(e)}",
                trace_id=trace_id
            )
            await self.logger.end_trace(trace_id, "error", error=str(e))
    
    async def get_certificate_status(self, cert_name: str) -> Dict[str, Any]:
        """Get certificate generation status.
        
        Args:
            cert_name: Certificate name
            
        Returns:
            Status dictionary
        """
        # Check ongoing generations
        if cert_name in ongoing_generations:
            return {
                "status": "in_progress",
                "message": "Certificate generation in progress"
            }
        
        # Check generation results
        if cert_name in generation_results:
            return generation_results[cert_name]
        
        # Check if certificate exists
        cert = await self.storage.get_certificate(cert_name)
        if cert:
            return {
                "status": "exists",
                "message": "Certificate exists",
                "expires_at": cert.expires_at.isoformat() if cert.expires_at else None,
                "domains": cert.domains
            }
        
        return {
            "status": "not_found",
            "message": "Certificate not found"
        }
    
    async def get_certificate(self, cert_name: str) -> Optional[Dict]:
        """Get certificate by name.
        
        Args:
            cert_name: Name of the certificate
            
        Returns:
            Certificate data or None if not found
        """
        return await self.storage.get_certificate(cert_name)
    
    async def delete_certificate(self, cert_name: str) -> bool:
        """Delete a certificate with event publishing.
        
        Args:
            cert_name: Name of certificate to delete
            
        Returns:
            True if successful
        """
        trace_id = self.logger.start_trace(
            "certificate_deletion",
            cert_name=cert_name
        )
        
        try:
            # Get certificate for logging
            cert = await self.storage.get_certificate(cert_name)
            
            # Delete certificate
            result = await self.storage.delete_certificate(cert_name)
            
            if result:
                await self.logger.info(
                    f"Certificate {cert_name} deleted successfully",
                    trace_id=trace_id
                )
                
                # Publish deletion event
                await self.logger.log_certificate_event(
                    cert_name=cert_name,
                    event_type="deleted",
                    domains=cert.domains if cert else [],
                    trace_id=trace_id
                )
                
                await self.logger.end_trace(trace_id, "success")
                return True
            else:
                await self.logger.warning(
                    f"Certificate {cert_name} deletion returned false",
                    trace_id=trace_id
                )
                await self.logger.end_trace(trace_id, "failed")
                return False
                
        except Exception as e:
            await self.logger.error(
                f"Certificate deletion failed for {cert_name}: {str(e)}",
                trace_id=trace_id
            )
            await self.logger.end_trace(trace_id, "error", error=str(e))
            return False
    
    async def list_certificates(self) -> List[Certificate]:
        """List all certificates.
        
        Returns:
            List of certificates
        """
        return await self.storage.list_certificates()
    
    async def convert_staging_to_production(self, cert_name: str) -> Optional[Certificate]:
        """Convert a staging certificate to production.
        
        Args:
            cert_name: Certificate name
            
        Returns:
            Production certificate or None
        """
        trace_id = self.logger.start_trace(
            "certificate_staging_to_production",
            cert_name=cert_name
        )
        
        try:
            # Get existing certificate
            existing_cert = await self.storage.get_certificate(cert_name)
            if not existing_cert:
                await self.logger.warning(
                    f"Certificate {cert_name} not found",
                    trace_id=trace_id
                )
                await self.logger.end_trace(trace_id, "not_found")
                return None
            
            await self.logger.info(
                f"Converting {cert_name} from staging to production",
                trace_id=trace_id,
                domains=existing_cert.domains
            )
            
            # Publish conversion started event
            await self.logger.log_certificate_event(
                cert_name=cert_name,
                event_type="production_conversion_started",
                domains=existing_cert.domains,
                trace_id=trace_id
            )
            
            # Create production request
            from .models import CertificateRequest
            production_request = CertificateRequest(
                cert_name=cert_name,
                domain=existing_cert.domains[0],
                email=existing_cert.email,
                acme_directory_url="https://acme-v02.api.letsencrypt.org/directory"  # Production
            )
            
            # Generate production certificate
            production_cert = await self.create_certificate(
                production_request,
                owner_token_hash=existing_cert.owner_token_hash,
                created_by=existing_cert.created_by
            )
            
            # Publish conversion completed event
            await self.logger.log_certificate_event(
                cert_name=cert_name,
                event_type="production_conversion_completed",
                domains=production_cert.domains,
                trace_id=trace_id
            )
            
            await self.logger.end_trace(trace_id, "success")
            return production_cert
            
        except Exception as e:
            await self.logger.error(
                f"Staging to production conversion failed: {str(e)}",
                trace_id=trace_id
            )
            
            await self.logger.log_certificate_event(
                cert_name=cert_name,
                event_type="production_conversion_failed",
                domains=existing_cert.domains if existing_cert else [],
                trace_id=trace_id,
                error=str(e)
            )
            
            await self.logger.end_trace(trace_id, "error", error=str(e))
            return None