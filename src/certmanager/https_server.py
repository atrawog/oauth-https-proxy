"""HTTPS server with dynamic certificate loading."""

import ssl
import os
import logging
import tempfile
from typing import Dict, Optional
from datetime import datetime, timedelta, timezone

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from .models import Certificate

logger = logging.getLogger(__name__)


class HTTPSServer:
    """HTTPS server with dynamic certificate loading."""
    
    def __init__(self, manager):
        """Initialize HTTPS server."""
        self.manager = manager
        self.ssl_contexts: Dict[str, ssl.SSLContext] = {}
        self.default_context: Optional[ssl.SSLContext] = None
        
    def create_ssl_context(self, certificate: Certificate) -> ssl.SSLContext:
        """Create SSL context from certificate."""
        context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        
        # Write certificate and key to temporary files
        with tempfile.NamedTemporaryFile(mode='w', suffix='.pem', delete=False) as cert_file:
            cert_file.write(certificate.fullchain_pem)
            cert_path = cert_file.name
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.key', delete=False) as key_file:
            key_file.write(certificate.private_key_pem)
            key_path = key_file.name
        
        try:
            context.load_cert_chain(cert_path, key_path)
        finally:
            # Clean up temporary files
            os.unlink(cert_path)
            os.unlink(key_path)
        
        return context
    
    def load_certificates(self):
        """Load all certificates from storage with proxy-aware prioritization."""
        certificates = self.manager.list_certificates()
        
        # First pass: Load all certificates into a temporary structure
        cert_contexts = {}  # cert_name -> (context, domains)
        for certificate in certificates:
            if certificate.fullchain_pem and certificate.private_key_pem:
                try:
                    context = self.create_ssl_context(certificate)
                    cert_contexts[certificate.cert_name] = (context, certificate.domains)
                    logger.info(f"Loaded certificate {certificate.cert_name} for domains: {certificate.domains}")
                except Exception as e:
                    logger.error(f"Failed to load certificate {certificate.cert_name}: {e}")
        
        # Second pass: Check proxy configurations to determine which certificates to use
        proxy_targets = self.manager.storage.list_proxy_targets()
        domain_to_cert = {}  # domain -> cert_name mapping based on proxy config
        
        for proxy in proxy_targets:
            if proxy.cert_name and proxy.cert_name in cert_contexts:
                domain_to_cert[proxy.proxy_hostname] = proxy.cert_name
        
        # Third pass: Apply certificates with proxy preferences taking priority
        for cert_name, (context, domains) in cert_contexts.items():
            for domain in domains:
                # If this domain has a proxy preference, only use that certificate
                if domain in domain_to_cert:
                    if domain_to_cert[domain] == cert_name:
                        self.ssl_contexts[domain] = context
                        logger.info(f"Applied certificate {cert_name} to {domain} (proxy configured)")
                else:
                    # No proxy preference, apply if not already set
                    if domain not in self.ssl_contexts:
                        self.ssl_contexts[domain] = context
                        logger.info(f"Applied certificate {cert_name} to {domain} (no proxy preference)")
        
        logger.info(f"SSL contexts loaded for domains: {list(self.ssl_contexts.keys())}")
        
        # Create default self-signed certificate if no certificates loaded
        if not self.ssl_contexts:
            self.create_self_signed_default()
    
    def reload_certificate(self, cert_name: str) -> bool:
        """Reload a specific certificate by name."""
        try:
            certificate = self.manager.storage.get_certificate(cert_name)
            if not certificate:
                logger.warning(f"Certificate {cert_name} not found for reload")
                return False
            
            if not certificate.fullchain_pem or not certificate.private_key_pem:
                logger.warning(f"Certificate {cert_name} missing PEM data")
                return False
            
            # Create new SSL context
            context = self.create_ssl_context(certificate)
            
            # Update SSL contexts for all domains in the certificate
            for domain in certificate.domains:
                self.ssl_contexts[domain] = context
                logger.info(f"Reloaded certificate {cert_name} for domain {domain}")
            
            # Notify unified dispatcher if available
            try:
                from ..dispatcher.unified_dispatcher import unified_server_instance
                if unified_server_instance:
                    unified_server_instance.update_ssl_context(certificate)
            except Exception as e:
                logger.debug(f"Could not notify unified dispatcher: {e}")
            
            return True
            
        except Exception as e:
            logger.error(f"Failed to reload certificate {cert_name}: {e}")
            return False
    
    def create_self_signed_default(self):
        """Create self-signed certificate for fallback."""
        try:
            from ..shared.config import Config
            
            # Generate key
            key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=Config.RSA_KEY_SIZE,
            )
            
            # Generate certificate
            cn = Config.SELF_SIGNED_CN
            subject = issuer = x509.Name([
                x509.NameAttribute(NameOID.COMMON_NAME, cn),
            ])
            
            cert = x509.CertificateBuilder().subject_name(
                subject
            ).issuer_name(
                issuer
            ).public_key(
                key.public_key()
            ).serial_number(
                x509.random_serial_number()
            ).not_valid_before(
                datetime.now(timezone.utc)
            ).not_valid_after(
                datetime.now(timezone.utc) + timedelta(days=Config.SELF_SIGNED_DAYS)
            ).add_extension(
                x509.SubjectAlternativeName([
                    x509.DNSName(cn),
                    x509.DNSName(Config.SERVER_HOST),
                ]),
                critical=False,
            ).sign(key, hashes.SHA256())
            
            # Convert to PEM
            cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode()
            key_pem = key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            ).decode()
            
            # Store in manager
            certificate = Certificate(
                cert_name="localhost-self-signed",
                domains=[cn],
                email="self-signed@localhost",
                status="active",
                expires_at=datetime.now(timezone.utc) + timedelta(days=Config.SELF_SIGNED_DAYS),
                fullchain_pem=cert_pem,
                private_key_pem=key_pem,
                acme_directory_url="self-signed"
            )
            
            self.manager.storage.store_certificate("localhost-self-signed", certificate)
            
            # Create context
            context = self.create_ssl_context(certificate)
            self.ssl_contexts[cn] = context
            self.default_context = context
            
            logger.info(f"Created self-signed certificate for {cn}")
            
        except Exception as e:
            logger.error(f"Failed to create self-signed certificate: {e}")
    
    def get_certificate(self, server_name: str) -> Optional[ssl.SSLContext]:
        """Get SSL context for a specific domain."""
        # Try exact match
        if server_name in self.ssl_contexts:
            return self.ssl_contexts[server_name]
        
        # Try wildcard match
        parts = server_name.split('.')
        if len(parts) > 2:
            wildcard = f"*.{'.'.join(parts[1:])}"
            if wildcard in self.ssl_contexts:
                return self.ssl_contexts[wildcard]
        
        # Return default context
        return self.default_context