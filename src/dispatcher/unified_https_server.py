"""Unified HTTPS server with dynamic certificate loading.

This module provides a single HTTPS server instance that can dynamically
load and serve certificates for multiple domains without requiring restarts.
"""

import asyncio
import ssl
from typing import Optional, Dict, Any

from hypercorn.asyncio import serve
from hypercorn.config import Config as HypercornConfig

from ..certmanager.dynamic_ssl_provider import DynamicSSLContextProvider
from ..shared.config import Config, get_config
from ..shared.logger import log_debug, log_info, log_warning, log_error, log_trace


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
        
        log_info(f"UnifiedHTTPSServer initialized for {host}:{port}", component="https_server")
    
    async def start(self) -> None:
        """Start the unified HTTPS server."""
        if self.is_running:
            log_warning("UnifiedHTTPSServer already running", component="https_server")
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
            
            # OPTIMIZED: Larger frame sizes for better throughput
            config.h11_max_incomplete_size = 65536  # 64KB for HTTP/1.1
            config.h2_max_inbound_frame_size = 65536  # 64KB for HTTP/2
            config.h2_max_concurrent_streams = 200  # More concurrent streams
            
            log_info(f"Starting UnifiedHTTPSServer on {self.host}:{self.port}", component="https_server")
            
            # Start server
            self.server_task = asyncio.create_task(serve(self.app, config))
            self.is_running = True
            
            log_info("UnifiedHTTPSServer started successfully", component="https_server")
            
        except Exception as e:
            log_error(f"Failed to start UnifiedHTTPSServer: {e}", component="https_server", error=e)
            self.is_running = False
            raise
    
    async def stop(self) -> None:
        """Stop the unified HTTPS server."""
        if not self.is_running:
            log_warning("UnifiedHTTPSServer not running", component="https_server")
            return
        
        log_info("Stopping UnifiedHTTPSServer", component="https_server")
        
        if self.server_task and not self.server_task.done():
            self.server_task.cancel()
            try:
                await self.server_task
            except asyncio.CancelledError:
                pass
        
        # Cleanup SSL provider resources
        self.ssl_provider.cleanup()
        
        self.is_running = False
        log_info("UnifiedHTTPSServer stopped", component="https_server")
    
    def update_certificate(self, cert_name: str) -> None:
        """Update certificate in the SSL provider.
        
        This invalidates the cached SSL context for all domains
        associated with the certificate, causing it to be reloaded
        on the next connection.
        
        Args:
            cert_name: Name of the certificate that was updated
        """
        log_info(f"Updating certificate {cert_name} in UnifiedHTTPSServer", component="https_server")
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
        
        log_info("UnifiedHTTPSDispatcher initialized", component="https_dispatcher")
    
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
        log_info("UnifiedHTTPSDispatcher started", component="https_dispatcher")
    
    async def stop(self) -> None:
        """Stop the HTTPS dispatcher."""
        if self.https_server:
            await self.https_server.stop()
        log_info("UnifiedHTTPSDispatcher stopped", component="https_dispatcher")
    
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
        log_info(f"Certificate {cert_name} ready, updating HTTPS server", component="https_dispatcher")
        
        # The certificate is already stored in Redis by the certificate manager
        # Just invalidate the SSL context cache
        self.update_certificate(cert_name)
        
        log_info(f"Certificate {cert_name} is now available for domains: {certificate.domains}", component="https_dispatcher")