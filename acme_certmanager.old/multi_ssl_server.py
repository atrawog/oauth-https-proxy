"""Multi-certificate SSL server implementation."""

import asyncio
import ssl
import socket
import logging
from typing import Dict, Optional, Tuple
import tempfile
import os

logger = logging.getLogger(__name__)


class MultiCertSSLServer:
    """SSL server that properly handles multiple certificates via SNI."""
    
    def __init__(self, https_server_instance, host='0.0.0.0', https_port=443):
        self.https_server = https_server_instance
        self.host = host
        self.https_port = https_port
        self.cert_files: Dict[str, Tuple[str, str]] = {}  # domain -> (cert_file, key_file)
        
    def prepare_certificates(self):
        """Write all certificates to temporary files for SSL contexts."""
        # Clean up any existing temp files
        for cert_file, key_file in self.cert_files.values():
            try:
                os.unlink(cert_file)
                os.unlink(key_file)
            except:
                pass
        self.cert_files.clear()
        
        # Write each certificate to temp files
        if self.https_server:
            for cert in self.https_server.manager.storage.list_certificates():
                if cert and cert.fullchain_pem and cert.private_key_pem:
                    # Write cert and key to temp files
                    with tempfile.NamedTemporaryFile(mode='w', suffix='.pem', delete=False) as cf:
                        cf.write(cert.fullchain_pem)
                        cert_file = cf.name
                    
                    with tempfile.NamedTemporaryFile(mode='w', suffix='.key', delete=False) as kf:
                        kf.write(cert.private_key_pem)
                        key_file = kf.name
                    
                    # Store for each domain
                    for domain in cert.domains:
                        self.cert_files[domain] = (cert_file, key_file)
                        logger.info(f"Prepared certificate for domain: {domain}")
    
    def create_ssl_context(self, server_hostname: Optional[str] = None) -> ssl.SSLContext:
        """Create SSL context for a specific hostname."""
        context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        
        # Find certificate for this hostname
        cert_file, key_file = None, None
        
        if server_hostname and server_hostname in self.cert_files:
            cert_file, key_file = self.cert_files[server_hostname]
            logger.info(f"Using certificate for: {server_hostname}")
        else:
            # Check wildcard
            if server_hostname:
                parts = server_hostname.split('.')
                if len(parts) > 2:
                    wildcard = f"*.{'.'.join(parts[1:])}"
                    if wildcard in self.cert_files:
                        cert_file, key_file = self.cert_files[wildcard]
                        logger.info(f"Using wildcard certificate for: {server_hostname}")
        
        # Load certificate or use default
        if cert_file and key_file:
            context.load_cert_chain(cert_file, key_file)
        else:
            # Create self-signed as fallback
            logger.warning(f"No certificate found for: {server_hostname}, using self-signed")
            from .server import create_temp_cert_files
            cert_file, key_file = create_temp_cert_files()
            context.load_cert_chain(cert_file, key_file)
            os.unlink(cert_file)
            os.unlink(key_file)
        
        return context
    
    def sni_callback(self, ssl_socket, server_name, original_context):
        """SNI callback to select the right certificate."""
        if not server_name:
            return None
            
        logger.debug(f"SNI callback for: {server_name}")
        
        # Create new context for this hostname
        try:
            new_context = self.create_ssl_context(server_name)
            # This is the key - we return the new context
            return new_context
        except Exception as e:
            logger.error(f"Error creating SSL context for {server_name}: {e}")
            return None
    
    async def run_https_server(self, app, backend_port):
        """Run HTTPS server with multi-certificate support."""
        # Prepare all certificates
        self.prepare_certificates()
        
        # Create base SSL context with SNI callback
        base_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        
        # Load a default certificate (required)
        if self.cert_files:
            # Use first available certificate as default
            first_domain = list(self.cert_files.keys())[0]
            cert_file, key_file = self.cert_files[first_domain]
            base_context.load_cert_chain(cert_file, key_file)
            logger.info(f"Default certificate loaded for: {first_domain}")
        else:
            # No certificates, create self-signed
            from .server import create_temp_cert_files
            cert_file, key_file = create_temp_cert_files()
            base_context.load_cert_chain(cert_file, key_file)
            os.unlink(cert_file)
            os.unlink(key_file)
            logger.info("Using self-signed certificate as default")
        
        # Set SNI callback
        base_context.sni_callback = self.sni_callback
        
        # Import and run with Hypercorn
        from hypercorn.asyncio import serve
        from hypercorn.config import Config as HypercornConfig
        
        # Configure Hypercorn for HTTPS only
        config = HypercornConfig()
        config.bind = [f"{self.host}:{self.https_port}"]
        config.loglevel = os.getenv('LOG_LEVEL', 'INFO').upper()
        
        # Override create_ssl_context to return our base context
        config.create_ssl_context = lambda: base_context
        
        logger.info(f"Starting HTTPS server on {self.host}:{self.https_port} with {len(self.cert_files)} certificates")
        
        try:
            await serve(app, config)
        finally:
            # Clean up temp files
            for cert_file, key_file in self.cert_files.values():
                try:
                    os.unlink(cert_file)
                    os.unlink(key_file)
                except:
                    pass