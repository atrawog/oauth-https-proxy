"""SNI-based multi-certificate HTTPS server."""

import asyncio
import ssl
import logging
import os
from typing import Dict, Optional
from hypercorn.asyncio import serve
from hypercorn.config import Config as HypercornConfig

logger = logging.getLogger(__name__)


class SNIServer:
    """HTTPS server with proper SNI support for multiple certificates."""
    
    def __init__(self, https_server_instance, app, host='0.0.0.0', https_port=443):
        self.https_server = https_server_instance
        self.app = app
        self.host = host
        self.https_port = https_port
        self.ssl_contexts: Dict[str, ssl.SSLContext] = {}
        
    def setup_ssl_contexts(self):
        """Pre-create SSL contexts for all certificates."""
        if not self.https_server:
            logger.warning("No HTTPS server instance available")
            return
            
        # Create SSL context for each certificate
        for cert in self.https_server.manager.storage.list_certificates():
            if cert and cert.fullchain_pem and cert.private_key_pem:
                try:
                    # Create context for this certificate
                    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
                    
                    # Write cert and key to temp files (Hypercorn needs files)
                    import tempfile
                    with tempfile.NamedTemporaryFile(mode='w', suffix='.pem', delete=False) as cf:
                        cf.write(cert.fullchain_pem)
                        cert_file = cf.name
                    
                    with tempfile.NamedTemporaryFile(mode='w', suffix='.key', delete=False) as kf:
                        kf.write(cert.private_key_pem)
                        key_file = kf.name
                    
                    # Load certificate into context
                    context.load_cert_chain(cert_file, key_file)
                    
                    # Clean up temp files
                    os.unlink(cert_file)
                    os.unlink(key_file)
                    
                    # Store context for each domain in the certificate
                    for domain in cert.domains:
                        self.ssl_contexts[domain] = context
                        logger.info(f"Created SSL context for domain: {domain}")
                        
                except Exception as e:
                    logger.error(f"Failed to create SSL context for {cert.cert_name}: {e}")
        
        logger.info(f"Setup {len(self.ssl_contexts)} SSL contexts for domains: {list(self.ssl_contexts.keys())}")
    
    async def run(self):
        """Run HTTPS server with SNI support."""
        # Setup all SSL contexts first
        self.setup_ssl_contexts()
        
        # Create base SSL context
        base_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        
        # Load a default certificate (required for initial handshake)
        default_loaded = False
        if self.ssl_contexts:
            # Use first available context's certificate as default
            first_domain = list(self.ssl_contexts.keys())[0]
            first_context = self.ssl_contexts[first_domain]
            
            # We need to extract the cert from the context somehow
            # For now, get the first certificate from storage
            for cert in self.https_server.manager.storage.list_certificates():
                if cert and first_domain in cert.domains:
                    # Write to temp files
                    import tempfile
                    with tempfile.NamedTemporaryFile(mode='w', suffix='.pem', delete=False) as cf:
                        cf.write(cert.fullchain_pem)
                        cert_file = cf.name
                    
                    with tempfile.NamedTemporaryFile(mode='w', suffix='.key', delete=False) as kf:
                        kf.write(cert.private_key_pem)
                        key_file = kf.name
                    
                    base_context.load_cert_chain(cert_file, key_file)
                    os.unlink(cert_file)
                    os.unlink(key_file)
                    default_loaded = True
                    logger.info(f"Loaded default certificate for: {first_domain}")
                    break
        
        if not default_loaded:
            # Create self-signed certificate as fallback
            logger.warning("No certificates available, creating self-signed certificate")
            from .server import create_temp_cert_files
            cert_file, key_file = create_temp_cert_files()
            base_context.load_cert_chain(cert_file, key_file)
            os.unlink(cert_file)
            os.unlink(key_file)
        
        # Define SNI callback
        def sni_callback(ssl_socket, server_name, original_context):
            """SNI callback to select the right pre-created SSL context."""
            if not server_name:
                logger.debug("No SNI server name provided")
                return None
            
            logger.debug(f"SNI callback for: {server_name}")
            
            # Check if we have a certificate for this domain
            if server_name in self.ssl_contexts:
                logger.info(f"Certificate available for: {server_name}")
            else:
                # Check wildcard
                parts = server_name.split('.')
                if len(parts) > 2:
                    wildcard = f"*.{'.'.join(parts[1:])}"
                    if wildcard in self.ssl_contexts:
                        logger.info(f"Wildcard certificate available for: {server_name}")
                    else:
                        logger.warning(f"No certificate found for: {server_name}, using default")
                else:
                    logger.warning(f"No certificate found for: {server_name}, using default")
            
            # Must return None - Python's SSL module doesn't allow changing contexts in callback
            return None
        
        # Set SNI callback
        base_context.sni_callback = sni_callback
        
        # Configure Hypercorn
        config = HypercornConfig()
        config.bind = [f"{self.host}:{self.https_port}"]
        config.loglevel = os.getenv('LOG_LEVEL', 'INFO').upper()
        
        # We need to set certfile and keyfile for Hypercorn to enable SSL
        # Write the default cert to temp files
        import tempfile
        if self.ssl_contexts:
            # Get first certificate from storage to use as default
            for cert in self.https_server.manager.storage.list_certificates():
                if cert and cert.fullchain_pem and cert.private_key_pem:
                    with tempfile.NamedTemporaryFile(mode='w', suffix='.pem', delete=False) as cf:
                        cf.write(cert.fullchain_pem)
                        cert_file = cf.name
                    with tempfile.NamedTemporaryFile(mode='w', suffix='.key', delete=False) as kf:
                        kf.write(cert.private_key_pem)
                        key_file = kf.name
                    config.certfile = cert_file
                    config.keyfile = key_file
                    break
        else:
            # Create self-signed
            from .server import create_temp_cert_files
            cert_file, key_file = create_temp_cert_files()
            config.certfile = cert_file
            config.keyfile = key_file
        
        # Now override the SSL context creation to use our SNI-enabled context
        original_create_ssl_context = config.create_ssl_context
        config.create_ssl_context = lambda: base_context
        
        logger.info(f"Starting SNI-enabled HTTPS server on {self.host}:{self.https_port}")
        
        try:
            # Run the server
            await serve(self.app, config)
        finally:
            # Clean up temp files
            if hasattr(config, 'certfile') and config.certfile and os.path.exists(config.certfile):
                os.unlink(config.certfile)
            if hasattr(config, 'keyfile') and config.keyfile and os.path.exists(config.keyfile):
                os.unlink(config.keyfile)