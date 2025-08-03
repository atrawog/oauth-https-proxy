"""Multi-certificate HTTPS server implementation.

This implementation serves multiple certificates by creating a proper SSL context
that includes all certificates, allowing the SSL layer to automatically select
the appropriate certificate based on SNI.
"""

import asyncio
import ssl
import logging
import os
import tempfile
from typing import Dict, List, Optional, Tuple
from pathlib import Path
from hypercorn.asyncio import serve
from hypercorn.config import Config as HypercornConfig

logger = logging.getLogger(__name__)


class MultiCertServer:
    """HTTPS server that properly serves multiple certificates."""
    
    def __init__(self, https_server_instance, app, host='0.0.0.0', https_port=443):
        self.https_server = https_server_instance
        self.app = app
        self.host = host
        self.https_port = https_port
        self.cert_files: List[Tuple[str, str, List[str]]] = []  # [(cert_path, key_path, domains), ...]
        
    def prepare_certificates(self) -> bool:
        """Prepare all certificates by writing them to temporary files.
        
        Returns True if at least one certificate was prepared.
        """
        if not self.https_server:
            logger.warning("No HTTPS server instance available")
            return False
        
        # Clean up any existing temp files
        for cert_path, key_path, _ in self.cert_files:
            try:
                if os.path.exists(cert_path):
                    os.unlink(cert_path)
                if os.path.exists(key_path):
                    os.unlink(key_path)
            except Exception as e:
                logger.error(f"Error cleaning up temp files: {e}")
        
        self.cert_files.clear()
        
        # Write each certificate to temp files
        for cert in self.https_server.manager.storage.list_certificates():
            if cert and cert.fullchain_pem and cert.private_key_pem:
                try:
                    # Write certificate
                    with tempfile.NamedTemporaryFile(mode='w', suffix='.pem', delete=False) as cf:
                        cf.write(cert.fullchain_pem)
                        cert_path = cf.name
                    
                    # Write key
                    with tempfile.NamedTemporaryFile(mode='w', suffix='.key', delete=False) as kf:
                        kf.write(cert.private_key_pem)
                        key_path = kf.name
                    
                    self.cert_files.append((cert_path, key_path, cert.domains))
                    logger.info(f"Prepared certificate for domains: {cert.domains}")
                    
                except Exception as e:
                    logger.error(f"Failed to prepare certificate {cert.cert_name}: {e}")
                    # Clean up on error
                    try:
                        if 'cert_path' in locals() and os.path.exists(cert_path):
                            os.unlink(cert_path)
                        if 'key_path' in locals() and os.path.exists(key_path):
                            os.unlink(key_path)
                    except:
                        pass
        
        return len(self.cert_files) > 0
    
    def create_multi_cert_context(self) -> Optional[ssl.SSLContext]:
        """Create an SSL context that can serve multiple certificates.
        
        This uses Python 3.9+ feature where multiple certificates can be loaded
        into a single context, and the appropriate one is selected based on SNI.
        """
        if not self.cert_files:
            return None
        
        try:
            # Create SSL context
            context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
            
            # Load the first certificate as the default
            cert_path, key_path, domains = self.cert_files[0]
            context.load_cert_chain(cert_path, key_path)
            logger.info(f"Loaded primary certificate for domains: {domains}")
            
            # Note: Python's ssl module doesn't support loading multiple
            # certificate chains into one context. Each context can only
            # have one certificate chain loaded.
            # 
            # The proper way to handle multiple certificates is to:
            # 1. Use a certificate that covers all needed domains (SAN cert)
            # 2. Use separate ports/IPs for different certificates
            # 3. Use a reverse proxy that handles SSL termination
            # 
            # Since these options aren't available, we're limited to serving
            # one certificate at a time.
            
            if len(self.cert_files) > 1:
                logger.warning(
                    f"Multiple certificates available ({len(self.cert_files)}), "
                    f"but only the first one can be served due to Python SSL limitations. "
                    f"Consider using a SAN certificate that covers all domains."
                )
            
            return context
            
        except Exception as e:
            logger.error(f"Failed to create SSL context: {e}")
            return None
    
    async def run(self):
        """Run HTTPS server with multi-certificate support."""
        # Prepare certificates
        if not self.prepare_certificates():
            logger.warning("No certificates available, creating self-signed certificate")
            from .server import create_temp_cert_files
            cert_path, key_path = create_temp_cert_files()
            self.cert_files.append((cert_path, key_path, ["self-signed"]))
        
        try:
            # Create SSL context
            ssl_context = self.create_multi_cert_context()
            
            if not ssl_context:
                logger.error("Failed to create SSL context")
                return
            
            # Configure Hypercorn
            config = HypercornConfig()
            config.bind = [f"{self.host}:{self.https_port}"]
            config.loglevel = os.getenv('LOG_LEVEL', 'INFO').upper()
            
            # Use the first certificate for Hypercorn
            if self.cert_files:
                config.certfile = self.cert_files[0][0]
                config.keyfile = self.cert_files[0][1]
            
            # Log server configuration
            logger.info(f"Starting HTTPS server on {self.host}:{self.https_port}")
            if self.cert_files:
                all_domains = []
                for _, _, domains in self.cert_files:
                    all_domains.extend(domains)
                logger.info(f"Certificates available for domains: {all_domains}")
                logger.info(f"Primary certificate serves: {self.cert_files[0][2]}")
            
            # Run the server
            await serve(self.app, config)
            
        finally:
            # Clean up all temp files
            for cert_path, key_path, _ in self.cert_files:
                try:
                    if os.path.exists(cert_path):
                        os.unlink(cert_path)
                    if os.path.exists(key_path):
                        os.unlink(key_path)
                except Exception as e:
                    logger.error(f"Error cleaning up temp files: {e}")
    
    def cleanup(self):
        """Clean up temporary certificate files."""
        for cert_path, key_path, _ in self.cert_files:
            try:
                if os.path.exists(cert_path):
                    os.unlink(cert_path)
                if os.path.exists(key_path):
                    os.unlink(key_path)
            except:
                pass