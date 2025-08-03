"""Unified HTTPS server with dynamic certificate loading.

This module provides a single HTTPS server instance that can dynamically
load and serve certificates for multiple domains without requiring restarts.
"""

import asyncio
import ssl
import logging
from typing import Optional, Dict, Any

from hypercorn.asyncio import serve
from hypercorn.config import Config as HypercornConfig

from ..certmanager.dynamic_ssl_provider import DynamicSSLContextProvider
from ..shared.config import Config, get_config

logger = logging.getLogger(__name__)


class UnifiedHTTPSServer:
    """Single HTTPS server instance with dynamic certificate loading."""
    
    def __init__(self, cert_manager, app, host: str = "0.0.0.0", port: int = 443):
        """Initialize unified HTTPS server.
        
        Args:
            cert_manager: Certificate manager instance
            app: ASGI application to serve
            host: Host to bind to
            port: Port to bind to
        """
        self.cert_manager = cert_manager
        self.app = app
        self.host = host
        self.port = port
        self.ssl_provider = DynamicSSLContextProvider(cert_manager)
        self.server_task: Optional[asyncio.Task] = None
        self.is_running = False
        
        logger.info(f"UnifiedHTTPSServer initialized for {host}:{port}")
    
    async def start(self) -> None:
        """Start the unified HTTPS server."""
        if self.is_running:
            logger.warning("UnifiedHTTPSServer already running")
            return
        
        try:
            # Create base SSL context with SNI callback
            ssl_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
            ssl_context.sni_callback = self.ssl_provider.get_sni_callback()
            
            # Configure Hypercorn
            config = HypercornConfig()
            config.bind = [f"{self.host}:{self.port}"]
            
            # Set the SSL context
            config.ssl = ssl_context
            
            # Use configured log level
            app_config = get_config()
            config.loglevel = app_config.LOG_LEVEL.upper()
            
            # Additional Hypercorn settings
            config.h11_max_incomplete_size = 16384
            config.h2_max_inbound_frame_size = 16384
            
            logger.info(f"Starting UnifiedHTTPSServer on {self.host}:{self.port}")
            
            # Start server
            self.server_task = asyncio.create_task(serve(self.app, config))
            self.is_running = True
            
            logger.info("UnifiedHTTPSServer started successfully")
            
        except Exception as e:
            logger.error(f"Failed to start UnifiedHTTPSServer: {e}")
            self.is_running = False
            raise
    
    async def stop(self) -> None:
        """Stop the unified HTTPS server."""
        if not self.is_running:
            logger.warning("UnifiedHTTPSServer not running")
            return
        
        logger.info("Stopping UnifiedHTTPSServer")
        
        if self.server_task and not self.server_task.done():
            self.server_task.cancel()
            try:
                await self.server_task
            except asyncio.CancelledError:
                pass
        
        # Cleanup SSL provider resources
        self.ssl_provider.cleanup()
        
        self.is_running = False
        logger.info("UnifiedHTTPSServer stopped")
    
    def update_certificate(self, cert_name: str) -> None:
        """Update certificate in the SSL provider.
        
        This invalidates the cached SSL context for all domains
        associated with the certificate, causing it to be reloaded
        on the next connection.
        
        Args:
            cert_name: Name of the certificate that was updated
        """
        logger.info(f"Updating certificate {cert_name} in UnifiedHTTPSServer")
        self.ssl_provider.invalidate_certificate(cert_name)
    
    def get_cached_domains(self) -> list:
        """Get list of domains with cached SSL contexts.
        
        Returns:
            List of domain names
        """
        return self.ssl_provider.get_cached_domains()
    
    async def wait_for_shutdown(self) -> None:
        """Wait for the server to shut down."""
        if self.server_task:
            await self.server_task


class UnifiedHTTPSDispatcher:
    """Dispatcher that routes HTTPS traffic through the unified server."""
    
    def __init__(self, cert_manager, proxy_handler, host: str = "0.0.0.0"):
        """Initialize HTTPS dispatcher.
        
        Args:
            cert_manager: Certificate manager instance
            proxy_handler: Proxy handler for routing requests
            host: Host to bind to
        """
        self.cert_manager = cert_manager
        self.proxy_handler = proxy_handler
        self.host = host
        self.https_server: Optional[UnifiedHTTPSServer] = None
        
        # Create the main routing app that handles all domains dynamically
        from ..proxy.app import create_proxy_app
        # Pass empty list - the app will dynamically route based on Host header
        self.app = create_proxy_app(cert_manager.storage, [])
        
        logger.info("UnifiedHTTPSDispatcher initialized")
    
    async def start(self) -> None:
        """Start the HTTPS dispatcher."""
        # Create and start unified HTTPS server
        app_config = get_config()
        self.https_server = UnifiedHTTPSServer(
            self.cert_manager,
            self.app,
            self.host,
            app_config.HTTPS_PORT
        )
        
        await self.https_server.start()
        logger.info("UnifiedHTTPSDispatcher started")
    
    async def stop(self) -> None:
        """Stop the HTTPS dispatcher."""
        if self.https_server:
            await self.https_server.stop()
        logger.info("UnifiedHTTPSDispatcher stopped")
    
    def update_certificate(self, cert_name: str) -> None:
        """Update certificate in the HTTPS server.
        
        Args:
            cert_name: Name of the certificate that was updated
        """
        if self.https_server:
            self.https_server.update_certificate(cert_name)
    
    async def on_certificate_ready(self, cert_name: str, certificate: Any) -> None:
        """Handle certificate ready event.
        
        This is called when a new certificate is generated or renewed.
        
        Args:
            cert_name: Name of the certificate
            certificate: Certificate object
        """
        logger.info(f"Certificate {cert_name} ready, updating HTTPS server")
        
        # The certificate is already stored in Redis by the certificate manager
        # Just invalidate the SSL context cache
        self.update_certificate(cert_name)
        
        logger.info(f"Certificate {cert_name} is now available for domains: {certificate.domains}")