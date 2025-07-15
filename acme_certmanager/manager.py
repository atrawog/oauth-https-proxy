"""Certificate Manager with ACME integration and auto-renewal."""

import logging
import os
from typing import Dict, List, Optional
from datetime import datetime

from .storage import RedisStorage
from .acme_client import ACMEClient
from .models import Certificate, CertificateRequest

logger = logging.getLogger(__name__)


class CertificateManager:
    """Main certificate management class."""
    
    def __init__(self, redis_url: Optional[str] = None):
        """Initialize certificate manager."""
        # Redis URL MUST come from .env - no defaults!
        self.redis_url = redis_url or os.getenv('REDIS_URL')
        if not self.redis_url:
            raise ValueError("REDIS_URL must be set in .env")
        self.storage = RedisStorage(self.redis_url)
        self.acme_client = ACMEClient(self.storage)
        self.ssl_contexts: Dict[str, any] = {}
        
        # Initialize logging
        logging.basicConfig(
            level=os.getenv('LOG_LEVEL', 'INFO'),
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
    
    def create_certificate(self, request: CertificateRequest) -> Certificate:
        """Create new certificate from request."""
        logger.info(f"Creating certificate {request.cert_name} for {request.domain}")
        
        # Generate certificate
        certificate = self.acme_client.generate_certificate(
            domains=[request.domain],  # Can be extended to support multiple domains
            email=request.email,
            acme_directory_url=request.acme_directory_url,
            cert_name=request.cert_name
        )
        
        return certificate
    
    def get_certificate(self, cert_name: str) -> Optional[Certificate]:
        """Get certificate by name."""
        return self.storage.get_certificate(cert_name)
    
    def list_certificates(self) -> List[Dict[str, Certificate]]:
        """List all certificates."""
        return self.storage.list_certificates()
    
    def renew_certificate(self, cert_name: str) -> Optional[Certificate]:
        """Renew certificate by name."""
        return self.acme_client.renew_certificate(cert_name)
    
    def delete_certificate(self, cert_name: str) -> bool:
        """Delete certificate by name."""
        logger.info(f"Deleting certificate {cert_name}")
        return self.storage.delete_certificate(cert_name)
    
    def remove_domain_from_certificate(self, cert_name: str, domain: str) -> Optional[Certificate]:
        """Remove domain from certificate (regenerates certificate)."""
        # Get existing certificate
        cert = self.storage.get_certificate(cert_name)
        if not cert:
            return None
        
        # Remove domain
        remaining_domains = [d for d in cert.domains if d != domain]
        if not remaining_domains:
            # No domains left, delete certificate
            self.delete_certificate(cert_name)
            return None
        
        # Regenerate certificate with remaining domains
        logger.info(f"Regenerating certificate {cert_name} without {domain}")
        return self.acme_client.generate_certificate(
            domains=remaining_domains,
            email=cert.email,
            acme_directory_url=cert.acme_directory_url,
            cert_name=cert_name
        )
    
    def get_challenge_response(self, token: str) -> Optional[str]:
        """Get ACME challenge response for token."""
        return self.storage.get_challenge(token)
    
    def check_health(self) -> Dict[str, any]:
        """Check system health."""
        return {
            "redis": "healthy" if self.storage.health_check() else "unhealthy",
            "certificates_loaded": len(self.list_certificates())
        }
    
    def get_expiring_certificates(self, days: int = 30) -> List[tuple[str, Certificate]]:
        """Get certificates expiring within specified days."""
        return self.storage.get_expiring_certificates(days)
    
    def auto_renew_certificates(self, threshold_days: int = 30) -> List[str]:
        """Auto-renew certificates approaching expiry."""
        renewed = []
        expiring = self.get_expiring_certificates(threshold_days)
        
        for cert_name, cert in expiring:
            logger.info(f"Auto-renewing certificate {cert_name}")
            try:
                new_cert = self.renew_certificate(cert_name)
                if new_cert:
                    renewed.append(cert_name)
                    logger.info(f"Successfully renewed {cert_name}")
                else:
                    logger.error(f"Failed to renew {cert_name}")
            except Exception as e:
                logger.error(f"Error renewing {cert_name}: {e}")
        
        return renewed