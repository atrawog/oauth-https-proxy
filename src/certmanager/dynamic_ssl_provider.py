"""Dynamic SSL Context Provider using SNI callbacks.

This module provides dynamic SSL certificate loading without requiring
service restarts. It uses Python's SNI (Server Name Indication) callback
mechanism to select the appropriate certificate at connection time.
"""

import ssl
import tempfile
import os
from typing import Dict, Optional, Any
from datetime import datetime, timezone
from ..shared.logger import log_debug, log_info, log_warning, log_error, log_trace

from .models import Certificate


class DynamicSSLContextProvider:
    """Provides SSL contexts dynamically based on SNI."""
    
    def __init__(self, cert_manager):
        """Initialize with a certificate manager.
        
        Args:
            cert_manager: CertificateManager instance for certificate retrieval
        """
        self.cert_manager = cert_manager
        self.context_cache: Dict[str, ssl.SSLContext] = {}
        self.cert_versions: Dict[str, str] = {}  # Track certificate versions
        self.default_context: Optional[ssl.SSLContext] = None
        self._temp_files: Dict[str, tuple] = {}  # Track temp files for cleanup
        
        # Initialize default context
        self._create_default_context()
        
        log_info("DynamicSSLContextProvider initialized", component="ssl_provider")
    
    def _create_default_context(self) -> None:
        """Create a default SSL context with a self-signed certificate."""
        try:
            # Check if we have a stored self-signed certificate
            default_cert = self.cert_manager.get_certificate("localhost-self-signed")
            
            if default_cert and default_cert.fullchain_pem and default_cert.private_key_pem:
                self.default_context = self._create_context_from_cert(default_cert)
                log_info("Default SSL context created from stored self-signed certificate", component="ssl_provider")
            else:
                # Create a new self-signed certificate
                from .https_server import HTTPSServer
                # Use the existing logic from HTTPSServer
                https_server = HTTPSServer(self.cert_manager)
                https_server.create_self_signed_default()
                
                # Now retrieve the created certificate
                default_cert = self.cert_manager.get_certificate("localhost-self-signed")
                if default_cert:
                    self.default_context = self._create_context_from_cert(default_cert)
                    log_info("Default SSL context created with new self-signed certificate", component="ssl_provider")
                else:
                    log_error("Failed to create default SSL context", component="ssl_provider")
        except Exception as e:
            log_error(f"Error creating default SSL context: {e}", component="ssl_provider")
            # Create a minimal context as fallback
            self.default_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    
    def _create_context_from_cert(self, certificate: Certificate) -> ssl.SSLContext:
        """Create SSL context from a certificate object.
        
        Args:
            certificate: Certificate object with PEM data
            
        Returns:
            Configured SSL context
        """
        context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        
        # Write certificate and key to temporary files
        cert_file = tempfile.NamedTemporaryFile(mode='w', suffix='.pem', delete=False)
        key_file = tempfile.NamedTemporaryFile(mode='w', suffix='.key', delete=False)
        
        try:
            cert_file.write(certificate.fullchain_pem)
            cert_file.flush()
            
            key_file.write(certificate.private_key_pem)
            key_file.flush()
            
            # Load certificate chain
            context.load_cert_chain(cert_file.name, key_file.name)
            
            # Store temp file paths for cleanup
            cert_key = f"{certificate.cert_name}_{id(context)}"
            self._temp_files[cert_key] = (cert_file.name, key_file.name)
            
            return context
            
        finally:
            cert_file.close()
            key_file.close()
    
    def _cleanup_temp_files(self, cert_key: str) -> None:
        """Clean up temporary certificate files.
        
        Args:
            cert_key: Key identifying the certificate files
        """
        if cert_key in self._temp_files:
            cert_path, key_path = self._temp_files[cert_key]
            try:
                if os.path.exists(cert_path):
                    os.unlink(cert_path)
                if os.path.exists(key_path):
                    os.unlink(key_path)
                del self._temp_files[cert_key]
            except Exception as e:
                log_warning(f"Error cleaning up temp files: {e}", component="ssl_provider")
    
    def get_sni_callback(self):
        """Returns SNI callback for SSL context selection.
        
        This callback is called by the SSL layer when a client
        connects and provides the server name via SNI.
        """
        def sni_callback(ssl_socket, server_name: Optional[str], ssl_context):
            """SNI callback to select appropriate SSL context."""
            if not server_name:
                log_debug("No SNI provided, using default context", component="ssl_provider")
                return
            
            log_debug(f"SNI callback for domain: {server_name}", component="ssl_provider")
            
            try:
                # Check if we need to refresh the cached context
                if self._should_refresh_context(server_name):
                    self._refresh_context(server_name)
                
                # Get context from cache or create new one
                if server_name in self.context_cache:
                    ssl_socket.context = self.context_cache[server_name]
                    log_trace(f"Using cached SSL context for {server_name}", component="ssl_provider")
                else:
                    # Try to load certificate
                    cert = self._get_certificate_for_domain(server_name)
                    
                    if cert and cert.fullchain_pem and cert.private_key_pem:
                        # Create and cache new context
                        context = self._create_context_from_cert(cert)
                        self.context_cache[server_name] = context
                        self.cert_versions[server_name] = self._get_cert_version(cert)
                        ssl_socket.context = context
                        log_info(f"Created new SSL context for {server_name}", component="ssl_provider")
                    else:
                        # Use default context
                        ssl_socket.context = self.default_context
                        log_info(f"No certificate found for {server_name}, using default", component="ssl_provider")
                        
            except Exception as e:
                log_error(f"Error in SNI callback for {server_name}: {e}", component="ssl_provider")
                # Fall back to default context on error
                ssl_socket.context = self.default_context
        
        return sni_callback
    
    def _get_certificate_for_domain(self, domain: str) -> Optional[Certificate]:
        """Get certificate for a specific domain.
        
        Args:
            domain: Domain name to get certificate for
            
        Returns:
            Certificate object or None
        """
        # First, check if there's a proxy target for this domain
        proxy_target = self.cert_manager.storage.get_proxy_target(domain)
        
        if proxy_target and proxy_target.cert_name:
            # Get certificate by name
            cert = self.cert_manager.get_certificate(proxy_target.cert_name)
            if cert:
                return cert
        
        # If no proxy-specific certificate, check for any certificate containing this domain
        all_certs = self.cert_manager.list_certificates()
        for cert in all_certs:
            if domain in cert.domains:
                return cert
            # Check for wildcard match
            if any(d.startswith('*.') and domain.endswith(d[2:]) for d in cert.domains):
                return cert
        
        return None
    
    def _should_refresh_context(self, domain: str) -> bool:
        """Check if SSL context should be refreshed for a domain.
        
        Args:
            domain: Domain to check
            
        Returns:
            True if context should be refreshed
        """
        if domain not in self.context_cache:
            return False
        
        # Get current certificate
        cert = self._get_certificate_for_domain(domain)
        if not cert:
            return False
        
        # Check if certificate version changed
        current_version = self._get_cert_version(cert)
        cached_version = self.cert_versions.get(domain)
        
        return current_version != cached_version
    
    def _get_cert_version(self, cert: Certificate) -> str:
        """Get a version identifier for a certificate.
        
        Args:
            cert: Certificate object
            
        Returns:
            Version string
        """
        # Use fingerprint if available, otherwise use expiry date
        if hasattr(cert, 'fingerprint') and cert.fingerprint:
            return cert.fingerprint
        return str(cert.expires_at)
    
    def _refresh_context(self, domain: str) -> None:
        """Refresh SSL context for a domain.
        
        Args:
            domain: Domain to refresh
        """
        log_info(f"Refreshing SSL context for {domain}", component="ssl_provider")
        
        # Remove old context
        if domain in self.context_cache:
            # Clean up old temp files
            old_context = self.context_cache[domain]
            cert_key = f"{domain}_{id(old_context)}"
            self._cleanup_temp_files(cert_key)
            
            del self.context_cache[domain]
            
        if domain in self.cert_versions:
            del self.cert_versions[domain]
    
    def invalidate_cache(self, domain: str) -> None:
        """Invalidate cached SSL context for a domain.
        
        This should be called when a certificate is updated.
        
        Args:
            domain: Domain to invalidate
        """
        log_info(f"Invalidating SSL context cache for {domain}", component="ssl_provider")
        self._refresh_context(domain)
    
    def invalidate_certificate(self, cert_name: str) -> None:
        """Invalidate all domains associated with a certificate.
        
        Args:
            cert_name: Certificate name
        """
        cert = self.cert_manager.get_certificate(cert_name)
        if cert:
            for domain in cert.domains:
                self.invalidate_cache(domain)
            log_info(f"Invalidated SSL contexts for certificate {cert_name} domains: {cert.domains}", component="ssl_provider")
    
    def get_cached_domains(self) -> list:
        """Get list of domains with cached SSL contexts.
        
        Returns:
            List of domain names
        """
        return list(self.context_cache.keys())
    
    def cleanup(self) -> None:
        """Clean up all temporary files and resources."""
        log_info("Cleaning up DynamicSSLContextProvider resources", component="ssl_provider")
        
        # Clean up all temp files
        for cert_key in list(self._temp_files.keys()):
            self._cleanup_temp_files(cert_key)
        
        # Clear caches
        self.context_cache.clear()
        self.cert_versions.clear()