"""Certificate Manager with ACME integration and auto-renewal."""

import logging
import os
from typing import Dict, List, Optional
from datetime import datetime

from .acme_client import ACMEClient
from .models import Certificate, CertificateRequest

logger = logging.getLogger(__name__)


class CertificateManager:
    """Main certificate management class."""
    
    def __init__(self, storage):
        """Initialize certificate manager."""
        self.storage = storage
        self.acme_client = ACMEClient(self.storage)
        self.ssl_contexts: Dict[str, any] = {}
    
    def create_certificate(self, request: CertificateRequest, owner_token_hash: str = None, created_by: str = None) -> Certificate:
        """Create new certificate from request."""
        logger.info(f"Creating certificate {request.cert_name} for {request.domain}")
        
        # Generate certificate
        certificate = self.acme_client.generate_certificate(
            domains=[request.domain],  # Can be extended to support multiple domains
            email=request.email,
            acme_directory_url=request.acme_directory_url,
            cert_name=request.cert_name,
            owner_token_hash=owner_token_hash,
            created_by=created_by
        )
        
        return certificate
    
    def create_multi_domain_certificate(self, request, owner_token_hash: str = None, created_by: str = None) -> Certificate:
        """Create multi-domain certificate from request."""
        logger.info(f"Creating multi-domain certificate {request.cert_name} for {', '.join(request.domains)}")
        
        # Generate certificate with multiple domains
        certificate = self.acme_client.generate_certificate(
            domains=request.domains,
            email=request.email,
            acme_directory_url=request.acme_directory_url,
            cert_name=request.cert_name,
            owner_token_hash=owner_token_hash,
            created_by=created_by
        )
        
        return certificate
    
    def get_certificate(self, cert_name: str) -> Optional[Certificate]:
        """Get certificate by name."""
        return self.storage.get_certificate(cert_name)
    
    def list_certificates(self) -> List[Certificate]:
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
        orphaned_count = self.count_orphaned_resources()
        return {
            "redis": "healthy" if self.storage.health_check() else "unhealthy",
            "certificates_loaded": len(self.list_certificates()),
            "orphaned_resources": orphaned_count
        }
    
    def count_orphaned_resources(self) -> int:
        """Count orphaned certificates and proxy targets."""
        try:
            # Get all valid token hashes by scanning Redis
            valid_token_hashes = set()
            cursor = 0
            while True:
                cursor, keys = self.storage.redis_client.scan(cursor, match="token:*", count=100)
                for key in keys:
                    token_data = self.storage.redis_client.hgetall(key)
                    if token_data and 'hash' in token_data:
                        valid_token_hashes.add(token_data['hash'])
                if cursor == 0:
                    break
            
            orphaned_count = 0
            
            # Check certificates
            for cert in self.list_certificates():
                if not cert.owner_token_hash or cert.owner_token_hash not in valid_token_hashes:
                    orphaned_count += 1
            
            # Check proxy targets  
            for target in self.storage.list_proxy_targets():
                if not target.owner_token_hash or target.owner_token_hash not in valid_token_hashes:
                    orphaned_count += 1
            
            return orphaned_count
        except Exception as e:
            logger.error(f"Error counting orphaned resources: {e}")
            return 0
    
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