"""Async wrapper for ACME operations."""

import asyncio
import logging
from typing import Dict, Any
from concurrent.futures import ThreadPoolExecutor

from .manager import CertificateManager
from .models import CertificateRequest, Certificate

logger = logging.getLogger(__name__)

# Global executor for running blocking operations
executor = ThreadPoolExecutor(max_workers=5)

# Track ongoing certificate generations
ongoing_generations: Dict[str, asyncio.Task] = {}


async def generate_certificate_async(
    manager: CertificateManager,
    request: CertificateRequest
) -> Certificate:
    """Generate certificate in a thread to avoid blocking."""
    loop = asyncio.get_event_loop()
    
    # Run the blocking certificate generation in a thread
    certificate = await loop.run_in_executor(
        executor,
        manager.create_certificate,
        request
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
            
            # Generate certificate
            certificate = await generate_certificate_async(manager, request)
            
            # Add ownership info
            certificate.owner_token_hash = owner_token_hash
            certificate.created_by = created_by
            
            # Store certificate with ownership info
            manager.storage.store_certificate(cert_name, certificate)
            
            # Update SSL context
            https_server.update_ssl_context(certificate)
            
            logger.info(f"Certificate generation completed for {cert_name}")
            return certificate
        except Exception as e:
            logger.error(f"Certificate generation failed for {cert_name}: {e}")
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


def get_generation_status(cert_name: str) -> Dict[str, Any]:
    """Get status of ongoing certificate generation."""
    if cert_name not in ongoing_generations:
        return {
            "status": "not_found",
            "message": "No ongoing generation for this certificate"
        }
    
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