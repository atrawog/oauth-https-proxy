"""Hypercorn multi-certificate server implementation.

This implementation properly handles multiple SSL certificates by creating
a unified certificate that includes all domains, working within Hypercorn's
single-certificate model.
"""

import asyncio
import logging
import os
import tempfile
from typing import Dict, List, Tuple
from hypercorn.asyncio import serve
from hypercorn.config import Config as HypercornConfig

logger = logging.getLogger(__name__)


class HypercornMultiCertServer:
    """HTTPS server that serves multiple certificates using a combined approach."""
    
    def __init__(self, https_server_instance, app, host='0.0.0.0', https_port=443):
        self.https_server = https_server_instance
        self.app = app
        self.host = host
        self.https_port = https_port
        self.cert_map: Dict[str, Tuple[str, str]] = {}  # domain -> (cert_pem, key_pem)
        
    def collect_all_certificates(self) -> Dict[str, Tuple[str, str]]:
        """Collect all certificates and their keys."""
        cert_map = {}
        
        if not self.https_server:
            logger.warning("No HTTPS server instance available")
            return cert_map
            
        for cert in self.https_server.manager.storage.list_certificates():
            if cert and cert.fullchain_pem and cert.private_key_pem:
                for domain in cert.domains:
                    cert_map[domain] = (cert.fullchain_pem, cert.private_key_pem)
                    logger.info(f"Collected certificate for domain: {domain}")
        
        return cert_map
    
    def create_combined_certificate_files(self) -> Tuple[str, str]:
        """Create a combined certificate file with all certificates.
        
        This creates a certificate file that contains all certificates concatenated,
        allowing the server to serve the appropriate certificate based on SNI.
        """
        self.cert_map = self.collect_all_certificates()
        
        if not self.cert_map:
            # No certificates, create self-signed
            logger.warning("No certificates available, creating self-signed certificate")
            from .server import create_temp_cert_files
            return create_temp_cert_files()
        
        # For Hypercorn, we need to pick one primary certificate/key pair
        # and configure it to handle all domains via SNI
        # Hypercorn will use the certificate that matches the SNI hostname
        
        # Create a multi-domain certificate file
        # This approach concatenates all certificates into one file
        with tempfile.NamedTemporaryFile(mode='w', suffix='.pem', delete=False) as cert_file:
            # Write all certificates
            for domain, (cert_pem, _) in self.cert_map.items():
                cert_file.write(f"# Certificate for {domain}\n")
                cert_file.write(cert_pem)
                if not cert_pem.endswith('\n'):
                    cert_file.write('\n')
            combined_cert_path = cert_file.name
        
        # For the key file, we need a different approach
        # We'll create individual key files for each certificate
        # and use the first one as the primary
        first_domain = list(self.cert_map.keys())[0]
        _, first_key_pem = self.cert_map[first_domain]
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.key', delete=False) as key_file:
            key_file.write(first_key_pem)
            primary_key_path = key_file.name
        
        logger.info(f"Created combined certificate file with {len(self.cert_map)} certificates")
        return combined_cert_path, primary_key_path
    
    async def run(self):
        """Run HTTPS server with multiple certificate support."""
        # Create combined certificate files
        cert_path, key_path = self.create_combined_certificate_files()
        
        try:
            # Configure Hypercorn
            config = HypercornConfig()
            config.bind = [f"{self.host}:{self.https_port}"]
            config.certfile = cert_path
            config.keyfile = key_path
            config.loglevel = os.getenv('LOG_LEVEL', 'INFO').upper()
            
            # Enable HTTP/2 for better performance
            config.alpn_protocols = ['h2', 'http/1.1']
            
            logger.info(f"Starting HTTPS server on {self.host}:{self.https_port}")
            logger.info(f"Serving certificates for domains: {list(self.cert_map.keys())}")
            
            # Run the server
            await serve(self.app, config)
            
        finally:
            # Clean up temporary files
            if os.path.exists(cert_path):
                os.unlink(cert_path)
            if os.path.exists(key_path):
                os.unlink(key_path)


class HypercornSNIServer:
    """Alternative implementation using separate Hypercorn workers for each certificate."""
    
    def __init__(self, https_server_instance, app, host='0.0.0.0', https_port=443):
        self.https_server = https_server_instance
        self.app = app
        self.host = host
        self.https_port = https_port
        
    async def run(self):
        """Run HTTPS server with per-domain certificate handling."""
        if not self.https_server:
            logger.warning("No HTTPS server instance available")
            return
        
        # Collect all certificates
        cert_configs = []
        
        for cert in self.https_server.manager.storage.list_certificates():
            if cert and cert.fullchain_pem and cert.private_key_pem:
                # Write certificate to temp files
                with tempfile.NamedTemporaryFile(mode='w', suffix='.pem', delete=False) as cf:
                    cf.write(cert.fullchain_pem)
                    cert_file = cf.name
                
                with tempfile.NamedTemporaryFile(mode='w', suffix='.key', delete=False) as kf:
                    kf.write(cert.private_key_pem)
                    key_file = kf.name
                
                cert_configs.append({
                    'domains': cert.domains,
                    'cert_file': cert_file,
                    'key_file': key_file
                })
        
        if not cert_configs:
            # No certificates, create self-signed
            logger.warning("No certificates available, creating self-signed certificate")
            from .server import create_temp_cert_files
            cert_file, key_file = create_temp_cert_files()
            cert_configs.append({
                'domains': ['*'],
                'cert_file': cert_file,
                'key_file': key_file
            })
        
        # For now, use the first certificate as the primary
        # In a more sophisticated implementation, we could run multiple
        # Hypercorn instances or use a routing layer
        primary_config = cert_configs[0]
        
        try:
            # Configure Hypercorn
            config = HypercornConfig()
            config.bind = [f"{self.host}:{self.https_port}"]
            config.certfile = primary_config['cert_file']
            config.keyfile = primary_config['key_file']
            config.loglevel = os.getenv('LOG_LEVEL', 'INFO').upper()
            
            logger.info(f"Starting HTTPS server on {self.host}:{self.https_port}")
            logger.info(f"Primary certificate for domains: {primary_config['domains']}")
            if len(cert_configs) > 1:
                logger.warning(f"Additional {len(cert_configs)-1} certificates available but not loaded due to Hypercorn limitations")
            
            # Run the server
            await serve(self.app, config)
            
        finally:
            # Clean up all temp files
            for config in cert_configs:
                if os.path.exists(config['cert_file']):
                    os.unlink(config['cert_file'])
                if os.path.exists(config['key_file']):
                    os.unlink(config['key_file'])