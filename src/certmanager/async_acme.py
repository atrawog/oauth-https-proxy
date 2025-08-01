"""Async wrapper for ACME operations."""

import asyncio
import logging
import os
from typing import Dict, Any
from concurrent.futures import ThreadPoolExecutor

from .manager import CertificateManager
from .models import CertificateRequest, Certificate

logger = logging.getLogger(__name__)

# Global executor for running blocking operations
max_workers_str = os.getenv('CERT_GEN_MAX_WORKERS')
if not max_workers_str:
    raise ValueError("CERT_GEN_MAX_WORKERS not set in environment - required for certificate generation")
max_workers = int(max_workers_str)
executor = ThreadPoolExecutor(max_workers=max_workers)

# Track ongoing certificate generations
ongoing_generations: Dict[str, asyncio.Task] = {}
# Track generation results (success/failure) for status reporting
generation_results: Dict[str, Dict[str, Any]] = {}


async def generate_certificate_async(
    manager: CertificateManager,
    request: CertificateRequest,
    owner_token_hash: str = None,
    created_by: str = None
) -> Certificate:
    """Generate certificate in a thread to avoid blocking."""
    loop = asyncio.get_event_loop()
    
    # Run the blocking certificate generation in a thread
    certificate = await loop.run_in_executor(
        executor,
        manager.create_certificate,
        request,
        owner_token_hash,
        created_by
    )
    
    return certificate


async def generate_multi_domain_certificate_async(
    manager: CertificateManager,
    request,
    owner_token_hash: str = None,
    created_by: str = None
) -> Certificate:
    """Generate multi-domain certificate in a thread to avoid blocking."""
    loop = asyncio.get_event_loop()
    
    # Run the blocking certificate generation in a thread
    certificate = await loop.run_in_executor(
        executor,
        manager.create_multi_domain_certificate,
        request,
        owner_token_hash,
        created_by
    )
    
    return certificate


async def create_certificate_task(
    manager: CertificateManager,
    request: CertificateRequest,
    https_server: Any,
    owner_token_hash: str = None,
    created_by: str = None
) -> Dict[str, Any]:
    """Create certificate generation task."""
    cert_name = request.cert_name
    
    # Check if generation is already in progress
    if cert_name in ongoing_generations:
        return {
            "status": "in_progress",
            "message": f"Certificate generation already in progress for {request.domain}",
            "cert_name": cert_name
        }
    
    # Create the async task
    async def generate_and_update():
        try:
            logger.info(f"Starting async certificate generation for {cert_name}")
            
            # Update status to in_progress
            generation_results[cert_name] = {
                "status": "in_progress",
                "message": f"Generating certificate for {request.domain}",
                "started_at": asyncio.get_event_loop().time()
            }
            
            # Generate certificate
            certificate = await generate_certificate_async(manager, request)
            
            # Add ownership info
            certificate.owner_token_hash = owner_token_hash
            certificate.created_by = created_by
            
            # Store certificate with ownership info
            manager.storage.store_certificate(cert_name, certificate)
            
            logger.info(f"Certificate generation completed for {cert_name}")
            
            # Update SSL context and instance to enable HTTPS if proxy exists
            from ..dispatcher.unified_dispatcher import unified_server_instance
            if unified_server_instance:
                # Update SSL context for the new certificate
                unified_server_instance.update_ssl_context(certificate)
                
                # Certificate may be for multiple domains, update each one
                for domain in certificate.domains:
                    await unified_server_instance.update_instance_certificate(domain)
            
            # Update status to completed
            generation_results[cert_name] = {
                "status": "completed",
                "message": f"Certificate generated successfully for {request.domain}",
                "completed_at": asyncio.get_event_loop().time()
            }
            
            return certificate
        except Exception as e:
            logger.error(f"Certificate generation failed for {cert_name}: {e}")
            
            # Update status to failed
            generation_results[cert_name] = {
                "status": "failed",
                "message": f"Certificate generation failed: {str(e)}",
                "error": str(e),
                "failed_at": asyncio.get_event_loop().time()
            }
            
            raise
        finally:
            # Remove from ongoing tasks
            ongoing_generations.pop(cert_name, None)
    
    # Start the task
    task = asyncio.create_task(generate_and_update())
    ongoing_generations[cert_name] = task
    
    return {
        "status": "accepted",
        "message": f"Certificate generation started for {request.domain}",
        "cert_name": cert_name
    }


async def create_multi_domain_certificate_task(
    manager: CertificateManager,
    request,
    https_server: Any,
    owner_token_hash: str = None,
    created_by: str = None
) -> Dict[str, Any]:
    """Create multi-domain certificate generation task."""
    cert_name = request.cert_name
    
    # Check if generation is already in progress
    if cert_name in ongoing_generations:
        return {
            "status": "in_progress",
            "message": f"Certificate generation already in progress for {', '.join(request.domains)}",
            "cert_name": cert_name
        }
    
    # Create the async task
    async def generate_and_update():
        try:
            logger.info(f"Starting async multi-domain certificate generation for {cert_name}")
            
            # Update status to in_progress
            generation_results[cert_name] = {
                "status": "in_progress",
                "message": f"Generating certificate for {', '.join(request.domains)}",
                "started_at": asyncio.get_event_loop().time()
            }
            
            # Generate multi-domain certificate with ownership info
            certificate = await generate_multi_domain_certificate_async(manager, request, owner_token_hash, created_by)
            
            # Verify certificate was stored
            stored_cert = manager.storage.get_certificate(cert_name)
            if not stored_cert:
                raise Exception(f"Multi-domain certificate was generated but not stored in Redis for {cert_name}")
            
            logger.info(f"Multi-domain certificate generation completed for {cert_name}")
            
            # Update SSL context and instance to enable HTTPS if proxy exists
            from ..dispatcher.unified_dispatcher import unified_server_instance
            if unified_server_instance:
                # Update SSL context for the new certificate
                unified_server_instance.update_ssl_context(certificate)
                
                # Certificate may be for multiple domains, update each one
                for domain in certificate.domains:
                    await unified_server_instance.update_instance_certificate(domain)
            
            # Update status to completed
            generation_results[cert_name] = {
                "status": "completed",
                "message": f"Certificate generated successfully for {', '.join(request.domains)}",
                "completed_at": asyncio.get_event_loop().time()
            }
            
            return certificate
        except Exception as e:
            logger.error(f"Multi-domain certificate generation failed for {cert_name}: {e}")
            
            # Update status to failed
            generation_results[cert_name] = {
                "status": "failed",
                "message": f"Certificate generation failed: {str(e)}",
                "error": str(e),
                "failed_at": asyncio.get_event_loop().time()
            }
            
            raise
        finally:
            # Remove from ongoing tasks
            ongoing_generations.pop(cert_name, None)
    
    # Start the task
    task = asyncio.create_task(generate_and_update())
    ongoing_generations[cert_name] = task
    
    return {
        "status": "accepted",
        "message": f"Multi-domain certificate generation started for {', '.join(request.domains)}",
        "cert_name": cert_name,
        "domains": request.domains
    }


def get_generation_status(cert_name: str) -> Dict[str, Any]:
    """Get status of certificate generation."""
    # First check if there's a stored result
    if cert_name in generation_results:
        result = generation_results[cert_name].copy()
        
        # Clean up old results after 5 minutes
        if "completed_at" in result or "failed_at" in result:
            try:
                elapsed = asyncio.get_event_loop().time() - result.get("completed_at", result.get("failed_at", 0))
                retention_seconds = int(os.getenv('CERT_STATUS_RETENTION_SECONDS'))
                if elapsed > retention_seconds:
                    generation_results.pop(cert_name, None)
            except RuntimeError:
                # Handle case where there's no event loop
                pass
        
        return result
    
    # Then check ongoing generations
    if cert_name in ongoing_generations:
        task = ongoing_generations[cert_name]
        
        if task.done():
            try:
                # Try to get the result (will raise if there was an error)
                task.result()
                return {
                    "status": "completed",
                    "message": "Certificate generation completed successfully"
                }
            except Exception as e:
                return {
                    "status": "failed",
                    "message": f"Certificate generation failed: {str(e)}"
                }
        else:
            return {
                "status": "in_progress",
                "message": "Certificate generation in progress"
            }
    
    # Not found
    return {
        "status": "not_found",
        "message": "No generation found for this certificate"
    }