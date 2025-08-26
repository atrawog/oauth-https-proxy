"""Unified dispatcher for both HTTP and HTTPS traffic.

This implementation creates dedicated Hypercorn instances for each domain
and uses dispatchers on both port 80 and 443 to route traffic.
"""

import asyncio
import ssl
import os
import sys
import tempfile
import struct
import json
import time
import traceback
import h11
from typing import Dict, Optional, List, Tuple, Set, Union
from datetime import datetime, timezone

from hypercorn.asyncio import serve
from hypercorn.config import Config as HypercornConfig
from ..middleware.proxy_protocol_handler import create_proxy_protocol_server

from ..proxy.models import ProxyTarget
from ..proxy.app import create_proxy_app
from .models import DomainService
from ..shared.logger import log_info, log_warning, log_error, log_debug, log_trace
from ..shared.dual_logger import create_dual_logger, set_redis_logger_for_component
from ..shared.config import Config
from ..shared.unified_logger import UnifiedAsyncLogger
from ..ports.manager import PortManager
from ..shared.dns_resolver import get_dns_resolver

# Create dual logger for dispatcher
dual_logger = create_dual_logger('dispatcher')

# Removed correlation ID generator - using IP as primary identifier

# Global instance for dynamic management
unified_server_instance = None


# DEPRECATED: Replaced by EnhancedProxyInstance
# This class is kept temporarily for reference but is no longer used
class HypercornInstance:
    """Hypercorn instance serving proxy domains with SSL termination.
    
    This is the correct architecture where:
    - Hypercorn handles SSL termination (it has the application context)
    - PROXY protocol preserves client IPs
    - UnifiedProxyHandler does complete OAuth validation with scopes
    """
    
    def __init__(self, app, domains: List[str], http_port: int, https_port: int, 
                 cert=None, proxy_configs: Dict = None, storage=None, async_components=None):
        self.domains = domains
        self.http_port = http_port  # Port with PROXY protocol enabled
        self.https_port = https_port  # Port with PROXY protocol enabled
        self.cert = cert
        self.proxy_configs = proxy_configs or {}
        self.storage = storage
        self.async_components = async_components
        # Get async Redis client if available
        self.async_redis = async_components.redis_clients.async_redis if async_components and hasattr(async_components, 'redis_clients') else None
        self.http_process = None
        self.https_process = None
        self.cert_file = None
        self.key_file = None
        self.proxy_handler = None
        self.proxy_handler_https = None
        
        # Create a proxy app for this instance
        from ..proxy.app import create_proxy_app
        # Pass async_storage if available for better performance
        if storage and async_components and hasattr(async_components, 'async_storage'):
            self.app = create_proxy_app(storage, domains, async_storage=async_components.async_storage)
        else:
            self.app = create_proxy_app(storage, domains) if storage else app
        
    async def start(self):
        """Start HTTP and/or HTTPS instances based on proxy configuration."""
        # Check which protocols are enabled for these domains
        http_enabled = False
        https_enabled = False
        
        # Check proxy configs for all domains
        for domain in self.domains:
            if domain in self.proxy_configs:
                config = self.proxy_configs[domain]
                if config.enable_http:
                    http_enabled = True
                if config.enable_https:
                    https_enabled = True
        
        # Start HTTP instance if any domain has HTTP enabled
        if http_enabled:
            await self.start_http()
        else:
            dual_logger.info(f"HTTP disabled for domains {self.domains}")
        
        # Start HTTPS instance if enabled and certificate available
        if https_enabled:
            if self.cert and self.cert.fullchain_pem and self.cert.private_key_pem:
                await self.start_https()
            else:
                dual_logger.warning(f"HTTPS enabled but no certificate available for domains {self.domains}")
        else:
            dual_logger.info(f"HTTPS disabled for domains {self.domains}")
    
    async def start_http(self):
        """Start HTTP instance with PROXY protocol enabled."""
        try:
            log_level = os.getenv('LOG_LEVEL')
            if not log_level:
                raise ValueError("LOG_LEVEL not set in environment - required for server configuration")
            
            # Start Hypercorn on a slightly different port for PROXY protocol handling
            # Use port + 10000 to avoid conflicts (12000 -> 22000)
            internal_port = self.http_port + 10000
            config = HypercornConfig()
            config.bind = [f"127.0.0.1:{internal_port}"]
            config.loglevel = log_level.upper()
            # Set reasonable timeouts to prevent hanging
            config.keep_alive_timeout = 60  # Keep-alive timeout in seconds
            config.shutdown_timeout = 2  # Max time to wait for graceful shutdown
            config.ssl_handshake_timeout = 5  # SSL handshake timeout
            
            dual_logger.info(f"Starting internal HTTP instance on port {internal_port} for domains: {self.domains}")
            
            # Start internal server
            self.http_process = asyncio.create_task(serve(self.app, config))
            
            # Start PROXY protocol handler that receives from dispatcher
            dual_logger.info(f"Starting PROXY protocol receiver on port {self.http_port} -> {internal_port}")
            proxy_server = await create_proxy_protocol_server(
                backend_host="127.0.0.1",
                backend_port=internal_port,
                listen_host="127.0.0.1",
                listen_port=self.http_port,
                redis_client=self.async_redis if self.async_redis else (self.storage.redis_client if self.storage else None)
            )
            self.proxy_handler = asyncio.create_task(proxy_server.serve_forever())
            
        except Exception as e:
            dual_logger.error(f"Failed to start HTTP server: {e}", error=e)
            raise
    
    async def start_https(self):
        """Start HTTPS instance with PROXY protocol enabled."""
        try:
            # Write certificate to temp files
            with tempfile.NamedTemporaryFile(mode='w', suffix='.pem', delete=False) as cf:
                cf.write(self.cert.fullchain_pem)
                self.cert_file = cf.name
            
            with tempfile.NamedTemporaryFile(mode='w', suffix='.key', delete=False) as kf:
                kf.write(self.cert.private_key_pem)
                self.key_file = kf.name
            
            log_level = os.getenv('LOG_LEVEL')
            if not log_level:
                raise ValueError("LOG_LEVEL not set in environment - required for server configuration")
            
            # Start Hypercorn on a slightly different port for PROXY protocol handling
            # Use port + 10000 to avoid conflicts (13000 -> 23000)
            internal_port = self.https_port + 10000
            config = HypercornConfig()
            config.bind = [f"127.0.0.1:{internal_port}"]
            config.certfile = self.cert_file
            config.keyfile = self.key_file
            config.loglevel = log_level.upper()
            # Set reasonable timeouts to prevent SSL shutdown hanging
            config.keep_alive_timeout = 60  # Keep-alive timeout in seconds
            config.shutdown_timeout = 2  # Max time to wait for graceful shutdown
            config.ssl_handshake_timeout = 5  # SSL handshake timeout
            
            dual_logger.info(f"Starting internal HTTPS instance on port {internal_port} for domains: {self.domains}")
            
            # Start internal server (Hypercorn handles SSL termination)
            self.https_process = asyncio.create_task(serve(self.app, config))
            
            # Start PROXY protocol handler that receives from dispatcher
            # Note: PROXY handler is just a TCP forwarder, no SSL needed here
            dual_logger.info(f"Starting PROXY protocol receiver on port {self.https_port} -> {internal_port}")
            proxy_server = await create_proxy_protocol_server(
                backend_host="127.0.0.1",
                backend_port=internal_port,
                listen_host="127.0.0.1",
                listen_port=self.https_port,
                redis_client=self.async_redis if self.async_redis else (self.storage.redis_client if self.storage else None)
            )
            self.proxy_handler_https = asyncio.create_task(proxy_server.serve_forever())
            
        except Exception as e:
            dual_logger.error(f"Failed to start HTTPS server: {e}", error=e)
            self.cleanup()
            raise
    
    async def stop(self):
        """Stop all HTTP and HTTPS instances."""
        # Stop instances
        if self.http_process:
            self.http_process.cancel()
            try:
                await self.http_process
            except asyncio.CancelledError:
                pass
                
        if self.https_process:
            self.https_process.cancel()
            try:
                await self.https_process
            except asyncio.CancelledError:
                pass
                
        self.cleanup()
        
        dual_logger.info(f"Stopped instance for domains: {self.domains}")
    
    def cleanup(self):
        """Clean up temporary files."""
        try:
            if self.cert_file and os.path.exists(self.cert_file):
                os.unlink(self.cert_file)
            if self.key_file and os.path.exists(self.key_file):
                os.unlink(self.key_file)
        except Exception as e:
            dual_logger.error(f"Error cleaning up temp files: {e}", error=e)


class UnifiedDispatcher:
    """Dispatcher that routes both HTTP and HTTPS traffic to domain instances."""
    
    def __init__(self, host='0.0.0.0', storage=None, async_components=None):
        self.host = host
        self.storage = storage
        self.async_components = async_components
        self.async_storage = async_components.async_storage if async_components else None
        
        # Create dispatcher-specific logger (required)
        if async_components and hasattr(async_components, 'redis_clients'):
            self.unified_logger = UnifiedAsyncLogger(async_components.redis_clients, component="dispatcher")
            dual_logger.info("Unified dispatcher initialized with component-specific logger")
        else:
            # Unified logger is required for proper operation
            self.unified_logger = None
            dual_logger.warning("No unified logger available - some features may be limited")
        self.hostname_to_http_port: Dict[str, int] = {}
        self.hostname_to_https_port: Dict[str, int] = {}
        self.http_server = None
        self.https_server = None
        # Named instances for routing targets
        # Named services removed - using URL-only routing
        # Initialize DNS resolver for reverse lookups
        self.dns_resolver = get_dns_resolver()
        
    async def _get_proxy_target(self, proxy_hostname: str):
        """Get proxy target using async storage if available."""
        if self.async_storage:
            return await self.async_storage.get_proxy_target(proxy_hostname)
        return self.storage.get_proxy_target(proxy_hostname) if self.storage else None
    
    async def _list_routes(self):
        """List routes using async storage if available."""
        if self.async_storage:
            return await self.async_storage.list_routes()
        return self.storage.list_routes() if self.storage else []
    
    def register_domain(self, domains: List[str], http_port: int, https_port: int, 
                          enable_http: bool = True, enable_https: bool = True):
        """Register a domain instance for specific domains and protocols."""
        dual_logger.debug(
            "register_domain called",
            domains=str(domains),
            http_port=http_port,
            https_port=https_port,
            enable_http=enable_http,
            enable_https=enable_https
        )
        
        for domain in domains:
            if enable_http:
                # Register port for dispatcher connections (all have PROXY protocol)
                self.hostname_to_http_port[domain] = http_port
                dual_logger.info(
                    f"Registered domain for HTTP",
                    domain=domain,
                    http_port=http_port,
                    protocol="HTTP"
                )
            if enable_https:
                # Register port for dispatcher connections (all have PROXY protocol)
                self.hostname_to_https_port[domain] = https_port
                dual_logger.info(
                    f"Registered domain for HTTPS",
                    domain=domain,
                    https_port=https_port,
                    protocol="HTTPS"
                )
            if not enable_http and not enable_https:
                dual_logger.warning(f"Domain {domain} has no protocols enabled!")
    
    # Removed register_named_service - using URL-only routing
    
    async def load_routes_from_storage(self):
        """Load routes from Redis storage."""
        if not self.storage:
            dual_logger.warning("No storage available for loading routes")
            return
        
        try:
            # Initialize default routes if needed
            await self.storage.initialize_default_routes()
            
            # Initialize default proxies if needed
            await self.storage.initialize_default_proxies()
            
        except Exception as e:
            dual_logger.error(f"Failed to load routes from storage: {e}", error=e)
    
    def get_request_info(self, data: bytes) -> Tuple[Optional[str], Optional[str]]:
        """Extract request method and path from HTTP request."""
        try:
            request_str = data.decode('utf-8', errors='ignore')
            lines = request_str.split('\r\n')
            if lines:
                # First line should be like: GET /path HTTP/1.1
                parts = lines[0].split(' ')
                if len(parts) >= 2:
                    return parts[0].upper(), parts[1]
            return None, None
        except Exception as e:
            dual_logger.debug(f"Error parsing HTTP request: {e}")
            return None, None
    
    def extract_hostname_with_h11(self, data: bytes) -> tuple[Optional[str], bytes]:
        """
        Extract hostname from HTTP request using h11 for safety.
        Returns (hostname, complete_request_data).
        
        We use h11 ONLY to safely parse the Host header, then forward
        the ORIGINAL data unchanged to avoid any corruption.
        """
        conn = h11.Connection(h11.SERVER)
        conn.receive_data(data)
        
        hostname = None
        dual_logger.debug(f"h11: Processing request data, length={len(data)}")
        
        # Parse just enough to get the Host header
        while True:
            event = conn.next_event()
            dual_logger.debug(f"h11 event: {type(event).__name__}")
            
            if event is h11.NEED_DATA:
                # We only have initial data, can't get more here
                # Return what we have
                break
                
            elif isinstance(event, h11.Request):
                # Headers are part of the Request event in h11
                dual_logger.debug(f"h11 Request: {event.method} {event.target}")
                # Extract Host header from request headers
                for name, value in event.headers:
                    dual_logger.debug(f"h11 header: {name}={value}")
                    if name.lower() == b'host':
                        hostname = value.decode('utf-8')
                        # Remove port if present
                        if ':' in hostname:
                            hostname = hostname.split(':')[0]
                        break
                # Stop after processing request
                break
                
            elif event in (h11.Data, h11.EndOfMessage):
                # We got past headers, stop
                break
        
        # Return hostname and ORIGINAL data (not h11's version)
        return hostname, data
    
    async def read_complete_headers(self, reader: asyncio.StreamReader) -> bytes:
        """Read until we have complete HTTP headers."""
        data = b''
        max_header_size = 16384  # 16KB max for headers
        
        while len(data) < max_header_size:
            chunk = await reader.read(4096)
            if not chunk:
                break
            data += chunk
            
            # Check if we have complete headers (empty line)
            if b'\r\n\r\n' in data:
                break
        
        return data
    
    def get_sni_hostname(self, data: bytes) -> Optional[str]:
        """Extract SNI hostname from TLS Client Hello."""
        try:
            # Check if this is a TLS handshake
            if len(data) < 5 or data[0] != 0x16:  # Not a handshake
                return None
            
            # Skip TLS record header (5 bytes)
            pos = 5
            
            # Check handshake type (Client Hello = 0x01)
            if pos >= len(data) or data[pos] != 0x01:
                return None
            
            # Skip to extensions following the same logic as before
            # ... (same SNI parsing logic as in multi_instance_server.py)
            # Skip handshake type (1 byte) and length (3 bytes)
            pos += 4
            
            # Skip client version (2 bytes) and random (32 bytes)
            pos += 34
            
            # Skip session ID
            if pos >= len(data):
                return None
            session_id_len = data[pos]
            pos += 1 + session_id_len
            
            # Skip cipher suites
            if pos + 2 > len(data):
                return None
            cipher_suites_len = struct.unpack('>H', data[pos:pos+2])[0]
            pos += 2 + cipher_suites_len
            
            # Skip compression methods
            if pos >= len(data):
                return None
            compression_methods_len = data[pos]
            pos += 1 + compression_methods_len
            
            # Check for extensions
            if pos + 2 > len(data):
                return None
            extensions_len = struct.unpack('>H', data[pos:pos+2])[0]
            pos += 2
            
            # Parse extensions
            extensions_end = pos + extensions_len
            while pos + 4 <= extensions_end and pos + 4 <= len(data):
                ext_type = struct.unpack('>H', data[pos:pos+2])[0]
                ext_len = struct.unpack('>H', data[pos+2:pos+4])[0]
                pos += 4
                
                if ext_type == 0x00:  # SNI extension
                    # Skip SNI list length (2 bytes) and type (1 byte)
                    pos += 3
                    # Get hostname length
                    if pos + 2 > len(data):
                        return None
                    hostname_len = struct.unpack('>H', data[pos:pos+2])[0]
                    pos += 2
                    # Extract hostname
                    if pos + hostname_len > len(data):
                        return None
                    proxy_hostname = data[pos:pos+hostname_len].decode('ascii', errors='ignore')
                    return proxy_hostname
                else:
                    pos += ext_len
            
            return None
            
        except Exception as e:
            dual_logger.debug(f"Error parsing SNI: {e}")
            return None
    
    def _extract_http_headers(self, data: bytes) -> Dict[str, str]:
        """Extract headers from HTTP request data."""
        headers = {}
        try:
            request_str = data.decode('utf-8', errors='ignore')
            lines = request_str.split('\r\n')
            
            for line in lines[1:]:  # Skip request line
                if line == '':  # End of headers
                    break
                if ':' in line:
                    key, value = line.split(':', 1)
                    headers[key.strip().lower()] = value.strip()
        except Exception as e:
            dual_logger.debug(f"Error extracting headers: {e}")
        
        return headers
    
    def _extract_query_params(self, data: bytes) -> Optional[str]:
        """Extract query parameters from request."""
        try:
            request_str = data.decode('utf-8', errors='ignore')
            first_line = request_str.split('\r\n')[0]
            parts = first_line.split(' ')
            if len(parts) >= 2 and '?' in parts[1]:
                return parts[1].split('?', 1)[1]
        except Exception:
            pass
        return None
    
    def _inject_http_header(self, data: bytes, header_name: str, header_value: str) -> bytes:
        """Inject a header into HTTP request data.
        
        Args:
            data: Raw HTTP request data
            header_name: Name of header to inject
            header_value: Value of header to inject
            
        Returns:
            Modified HTTP request data with injected header
        """
        try:
            request_str = data.decode('utf-8', errors='ignore')
            lines = request_str.split('\r\n')
            
            # Find the end of headers (empty line)
            header_end_idx = -1
            for i, line in enumerate(lines):
                if line == '':  # Empty line marks end of headers
                    header_end_idx = i
                    break
            
            # Insert the new header before the empty line
            if header_end_idx > 0:
                # Check if header already exists (case-insensitive)
                header_exists = False
                header_lower = header_name.lower()
                for i in range(1, header_end_idx):
                    if ':' in lines[i]:
                        existing_key = lines[i].split(':', 1)[0].strip().lower()
                        if existing_key == header_lower:
                            # Replace existing header
                            lines[i] = f"{header_name}: {header_value}"
                            header_exists = True
                            break
                
                # Add header if it doesn't exist
                if not header_exists:
                    lines.insert(header_end_idx, f"{header_name}: {header_value}")
                
                # Reconstruct the request
                modified_request = '\r\n'.join(lines)
                return modified_request.encode('utf-8')
            
            return data  # Return original if we couldn't parse
            
        except Exception as e:
            dual_logger.debug(f"Error injecting header: {e}")
            return data  # Return original on error
    
    async def handle_http_connection(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        """Handle incoming HTTP connection - extract hostname and forward."""
        client_addr = writer.get_extra_info('peername')
        client_ip = client_addr[0] if client_addr else 'unknown'
        client_port = client_addr[1] if client_addr and len(client_addr) > 1 else 0
        
        try:
            # Read complete headers first
            data = await self.read_complete_headers(reader)
            if not data:
                return
            
            # Use h11 to safely extract hostname
            try:
                proxy_hostname, complete_data = self.extract_hostname_with_h11(data)
            except Exception as e:
                dual_logger.error(f"Failed to parse HTTP request with h11: {e}", error=e)
                dual_logger.debug(f"Request data (first 200 bytes): {data[:200]}")
                # Send 400 Bad Request
                error_response = b"HTTP/1.1 400 Bad Request\r\nContent-Length: 17\r\n\r\nMalformed request"
                writer.write(error_response)
                await writer.drain()
                return
            
            if not proxy_hostname:
                # Send 400 Bad Request - no Host header
                error_response = b"HTTP/1.1 400 Bad Request\r\nContent-Length: 19\r\n\r\nNo Host header found"
                writer.write(error_response)
                await writer.drain()
                return
            
            dual_logger.info(
                f"Forwarding HTTP connection for {proxy_hostname}",
                client_ip=client_ip,
                client_port=client_port,
                proxy_hostname=proxy_hostname,
                protocol="HTTP"
            )
            
            # Find proxy instance port for hostname  
            target_port = self.hostname_to_http_port.get(proxy_hostname)
            if not target_port:
                # Send 404 Not Found
                error_msg = f"No proxy for {proxy_hostname}".encode()
                error_response = b"HTTP/1.1 404 Not Found\r\nContent-Length: %d\r\n\r\n%b" % (len(error_msg), error_msg)
                writer.write(error_response)
                await writer.drain()
                return
            
            # Forward to proxy instance with PROXY protocol
            # Use complete_data to ensure we forward the EXACT bytes received
            await self._forward_connection(
                reader, writer, complete_data, '127.0.0.1', target_port,
                client_ip=client_ip, client_port=client_port,
                use_proxy_protocol=True, proxy_hostname=proxy_hostname
            )
            
        except Exception as e:
            dual_logger.error(f"Error handling HTTP connection: {e}", error=e)
        finally:
            writer.close()
            await writer.wait_closed()
    
    async def handle_https_connection(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        """Handle incoming HTTPS connection and forward to appropriate instance."""
        client_addr = writer.get_extra_info('peername')
        client_ip = client_addr[0] if client_addr else 'unknown'
        client_port = client_addr[1] if client_addr and len(client_addr) > 1 else 0
        
        # No need to store IP mappings - PROXY protocol handles this
        
        dual_logger.debug(
            "New HTTPS connection",
            client_ip=client_ip,
            client_port=client_port,
            protocol="HTTPS"
        )
        
        try:
            # Peek at the data to get SNI hostname
            data = await reader.read(4096)
            if not data:
                log_warning(
                    "No data received in HTTPS connection",
                    client_ip=client_ip
                )
                return
            
            log_debug(
                "HTTPS data received",
                client_ip=client_ip,
                data_len=len(data)
            )
            
            # Extract SNI hostname
            proxy_hostname = self.get_sni_hostname(data)
            dual_logger.debug(f" SNI hostname extracted: {proxy_hostname}")
            if not proxy_hostname:
                dual_logger.warning(f"Python logging: No SNI hostname found from {client_ip}")
                log_warning(
                    "No SNI hostname found in connection",
                    client_ip=client_ip
                )
                writer.close()
                await writer.wait_closed()
                return
            
            # Log TLS details with unified logger if available
            if self.unified_logger:
                # Generate trace ID for this request
                trace_id = self.unified_logger.start_trace(
                    "https_request",
                    proxy=proxy_hostname,
                    client_ip=client_ip
                )
                
                # Resolve client hostname
                client_hostname = await self.dns_resolver.resolve_ptr(client_ip)
            
            # Get proxy config for ALL domains including localhost
            proxy_config = None
            if (self.storage or self.async_storage):
                try:
                    proxy_config = await self._get_proxy_target(proxy_hostname)
                    if proxy_config is None:
                        if proxy_hostname == 'localhost':
                            dual_logger.error(f"CRITICAL: localhost proxy MUST exist but was not found")
                            raise RuntimeError("localhost proxy configuration is missing - database corrupted?")
                        dual_logger.debug(f"Proxy config not found for {proxy_hostname} (may have been deleted)")
                except Exception as e:
                    dual_logger.error(f"Error getting proxy config for {proxy_hostname}: {str(e)}")
                    if proxy_hostname == 'localhost':
                        raise RuntimeError(f"CRITICAL: Cannot get localhost proxy config: {e}")
                    raise
            
            # For HTTPS, we cannot parse HTTP request info from TLS handshake data
            # Route matching must be handled by the proxy instances after TLS termination
            # The proxy app will handle route matching at the application level
            
            # Find the appropriate port for hostname-based routing
            target_port = self.hostname_to_https_port.get(proxy_hostname)
            dual_logger.debug(f" Target port for {proxy_hostname}: {target_port}")
            dual_logger.debug(f" Available HTTPS mappings: {list(self.hostname_to_https_port.keys())}")
            if not target_port:
                # Try wildcard match
                parts = proxy_hostname.split('.')
                if len(parts) > 2:
                    wildcard = f"*.{'.'.join(parts[1:])}"
                    target_port = self.hostname_to_https_port.get(wildcard)
            
            # No special handling for localhost - treat it like any other proxy
            
            if not target_port:
                # This should NEVER happen if instances are created properly
                available_https_hosts = list(self.hostname_to_https_port.keys())
                dual_logger.error(f"CRITICAL: No HTTPS port mapping for {proxy_hostname}")
                dual_logger.error(f"Available HTTPS mappings: {available_https_hosts}")
                dual_logger.error(f"Total HTTPS mappings: {len(self.hostname_to_https_port)}")
                
                # Special error for localhost
                if proxy_hostname == 'localhost':
                    error_msg = f"CRITICAL: localhost has no HTTPS port mapping - UnifiedMultiInstanceServer not properly initialized?"
                else:
                    error_msg = f"CRITICAL: No HTTPS port mapping for {proxy_hostname} - instance not created? This is a BUG!"
                
                dual_logger.error(error_msg)
                
                # Close connection - can't send HTTP error over TLS handshake
                writer.close()
                await writer.wait_closed()
                
                # Raise to ensure it's logged
                raise RuntimeError(error_msg)
            
            # Determine if this is a named instance or proxy target
            service_name = None
            dual_logger.debug(f" Checking named_services for port {target_port}")
            dual_logger.debug(f" named_services = {self.named_services if hasattr(self, 'named_services') else 'NOT SET'}")
            if hasattr(self, 'named_services'):
                for name, port in self.named_services.items():
                    if port == target_port:
                        service_name = name
                        break
            dual_logger.debug(f" service_name = {service_name}")
            
            
            # Forward to the target instance with PROXY protocol enabled for HTTPS
            dual_logger.info(
                f"Forwarding HTTPS connection for {proxy_hostname}",
                client_ip=client_ip,
                client_port=client_port,
                proxy_hostname=proxy_hostname,
                protocol="HTTPS",
                target_port=target_port
            )
            await self._forward_connection(
                reader, writer, data, '127.0.0.1', target_port, 
                client_ip=client_ip, client_port=client_port, use_proxy_protocol=True, proxy_hostname=proxy_hostname, service_name=service_name
            )
            dual_logger.debug(f" HTTPS forwarding completed for {proxy_hostname}")
            
        except ConnectionResetError as e:
            # Connection reset by peer is common with HTTPS/MCP - handle gracefully
            dual_logger.debug(f"Connection reset by peer from {client_ip}:{client_port} - likely normal client disconnect")
        except Exception as e:
            dual_logger.error(f"Error handling HTTPS connection: {e}")
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except ConnectionResetError:
                # Ignore connection reset during cleanup
                pass
            except Exception as e:
                dual_logger.debug(f"Error during connection cleanup: {e}")
    

    async def _send_proxy_protocol_header(self, writer: asyncio.StreamWriter, client_ip: str, client_port: int, server_port: int):
        """Send PROXY protocol v1 header to preserve client IP for HTTPS connections.
        
        Format: PROXY TCP4 <client_ip> <proxy_ip> <client_port> <proxy_port>\r\n
        Example: PROXY TCP4 192.168.1.100 127.0.0.1 56789 443\r\n
        """
        try:
            # Determine protocol version based on IP format
            protocol = "TCP4" if "." in client_ip else "TCP6"
            
            # Build PROXY protocol v1 header
            proxy_header = f"PROXY {protocol} {client_ip} 127.0.0.1 {client_port} {server_port}\r\n"
            
            
            # Send the header
            writer.write(proxy_header.encode('ascii'))
            await writer.drain()
            
        except Exception as e:
            dual_logger.error(f"Error sending PROXY protocol header: {e}")
            # Continue without PROXY protocol on error

    async def _forward_connection(self, client_reader, client_writer, initial_data, 
                                  target_host, target_port, client_ip=None, 
                                  client_port=None, use_proxy_protocol=False, 
                                  proxy_hostname=None, service_name=None, trace_id=None):
        """
        Forward connection to target with optional PROXY protocol.
        This is a PURE TCP forwarder - no HTTP parsing or modification.
        """
        dual_logger.debug(
            f"Forwarding connection",
            target_host=target_host,
            target_port=target_port,
            use_proxy_protocol=use_proxy_protocol,
            client_ip=client_ip,
            proxy_hostname=proxy_hostname
        )
        
        target_reader = None
        target_writer = None
        
        try:
            # Connect to target
            target_reader, target_writer = await asyncio.open_connection(target_host, target_port)
            
            # Send PROXY protocol header if needed
            if use_proxy_protocol and client_ip and client_port:
                proxy_header = f"PROXY TCP4 {client_ip} {target_host} {client_port} {target_port}\r\n"
                target_writer.write(proxy_header.encode())
                dual_logger.debug(f"Sent PROXY header: {proxy_header.strip()}")
            
            # Send initial data (the complete HTTP request)
            target_writer.write(initial_data)
            await target_writer.drain()
            
            # Bidirectional forwarding - pure TCP bytes
            async def forward(src_reader, dst_writer, direction):
                """Forward bytes from src to dst without any parsing."""
                try:
                    while True:
                        # Use larger buffer for efficiency
                        data = await src_reader.read(65536)
                        if not data:
                            break
                        dst_writer.write(data)
                        await dst_writer.drain()
                except asyncio.CancelledError:
                    raise
                except Exception as e:
                    dual_logger.debug(f"Forward {direction} ended: {e}")
                finally:
                    try:
                        if not dst_writer.is_closing():
                            dst_writer.write_eof()
                    except:
                        pass
            
            # Forward both directions concurrently
            await asyncio.gather(
                forward(client_reader, target_writer, "client->target"),
                forward(target_reader, client_writer, "target->client"),
                return_exceptions=True
            )
            
        except Exception as e:
            dual_logger.error(f"Python logging: Error forwarding connection: {e}")
            dual_logger.error(f"Error forwarding connection: {e}", error=e)
        finally:
            # Clean up connections
            for writer in [client_writer, target_writer]:
                if writer and not writer.is_closing():
                    writer.close()
                    try:
                        await writer.wait_closed()
                    except:
                        pass
    
    async def start(self):
        """Start both HTTP and HTTPS dispatchers without blocking."""
        dual_logger.info("UnifiedDispatcher.start() called - starting HTTP and HTTPS servers")
        
        # Start HTTP dispatcher on port 80
        http_port_str = os.getenv('HTTP_PORT')
        if not http_port_str:
            raise ValueError("HTTP_PORT not set in environment - required for server configuration")
        http_port = int(http_port_str)
        dual_logger.info(f"Creating HTTP server on {self.host}:{http_port}")
        try:
            self.http_server = await asyncio.start_server(
                self.handle_http_connection,
                self.host,
                http_port
            )
            dual_logger.info(f"HTTP Dispatcher listening on {self.host}:{http_port}")
        except Exception as e:
            dual_logger.error(f"Failed to create HTTP server: {e}", error=e)
            raise
        
        # Start HTTPS dispatcher on port 443
        https_port_str = os.getenv('HTTPS_PORT')
        if not https_port_str:
            raise ValueError("HTTPS_PORT not set in environment - required for server configuration")
        https_port = int(https_port_str)
        dual_logger.info(f"Creating HTTPS server on {self.host}:{https_port}")
        try:
            self.https_server = await asyncio.start_server(
                self.handle_https_connection,
                self.host,
                https_port
            )
            dual_logger.info(f"HTTPS Dispatcher listening on {self.host}:{https_port}")
        except Exception as e:
            dual_logger.error(f"Failed to create HTTPS server: {e}", error=e)
            raise
        
        # Create tasks for the servers but don't await them
        # This allows the dispatcher to start without blocking
        dual_logger.trace("Creating server tasks")
        self.server_tasks = [
            asyncio.create_task(self.http_server.serve_forever()),
            asyncio.create_task(self.https_server.serve_forever())
        ]
        dual_logger.info("Dispatcher servers started in background")
    
    async def wait_forever(self):
        """Wait for servers to complete (they run forever)."""
        if hasattr(self, 'server_tasks'):
            await asyncio.gather(*self.server_tasks)
    
    async def stop(self):
        """Stop both dispatchers."""
        if self.http_server:
            self.http_server.close()
            await self.http_server.wait_closed()
            
        if self.https_server:
            self.https_server.close()
            await self.https_server.wait_closed()


class UnifiedMultiInstanceServer:
    """Main server that manages domain instances with unified dispatching."""
    
    def __init__(self, https_server_instance, app=None, host='0.0.0.0', async_components=None, storage=None):
        dual_logger.debug(f"UnifiedMultiInstanceServer.__init__ called with https_server={https_server_instance is not None}")
        self.https_server = https_server_instance
        self.app = app  # Not used anymore - each instance creates its own proxy app
        self.host = host
        self.async_components = async_components
        self.storage = storage  # Store storage reference
        
        # UNIFIED ARCHITECTURE: Single source of truth
        self.instances = {}  # {proxy_hostname: HypercornInstance} - Changed to dict for easier lookup
        self.instance_states = {}  # {proxy_hostname: "running"|"pending"|"failed"}
        
        # Single consumer for ALL events
        self.stream_consumer = None
        self.consumer_task = None
        self.reconciliation_task = None
        
        # Single publisher for events
        from ..storage.redis_stream_publisher import RedisStreamPublisher
        redis_url = os.getenv('REDIS_URL', 'redis://:test@redis:6379/0')
        self.publisher = RedisStreamPublisher(redis_url=redis_url)
        
        # Pass storage and async components to dispatcher for route management
        self.dispatcher = UnifiedDispatcher(host, storage, async_components)
        
        # Initialize PortManager for Redis-based port allocation
        self.port_manager = PortManager(storage)
        
        # Redis client for port mappings
        self.redis = storage.redis_client if storage else None
        
    async def create_instance_for_proxy(self, proxy_hostname: str):
        """Dynamically create and start an instance for a proxy target."""
        dual_logger.info(f"[PROXY_CREATE] Method called for {proxy_hostname}")
        
        dual_logger.info(f"[PROXY_CREATE] Starting instance creation for {proxy_hostname}")
        
        # Check if instance already exists by looking at actual running instances
        # Don't rely on dispatcher maps as they may have stale entries
        instance_exists = False
        for instance in self.instances:
            if proxy_hostname in instance.domains:
                dual_logger.info(f"[PROXY_CREATE] Found existing instance for {proxy_hostname}")
                dual_logger.info(f"[PROXY_CREATE] Instance already exists for {proxy_hostname} (found in instances list)")
                instance_exists = True
                break
        
        if instance_exists:
            return
        
        # Clean up any stale entries in dispatcher maps
        if proxy_hostname in self.dispatcher.hostname_to_https_port:
            dual_logger.info(f"[PROXY_CREATE] Removing stale HTTPS map entry for {proxy_hostname}")
            del self.dispatcher.hostname_to_https_port[proxy_hostname]
        if proxy_hostname in self.dispatcher.hostname_to_http_port:
            dual_logger.info(f"[PROXY_CREATE] Removing stale HTTP map entry for {proxy_hostname}")
            del self.dispatcher.hostname_to_http_port[proxy_hostname]
        
        dual_logger.info(f"[PROXY_CREATE] No existing instance found for {proxy_hostname}, proceeding with creation")
        
        # Get proxy configuration using async storage via dispatcher
        proxy_target = await self.dispatcher._get_proxy_target(proxy_hostname)
        if not proxy_target:
            dual_logger.error(f"[PROXY_CREATE] No proxy target found for {proxy_hostname} in Redis storage")
            return
        
        dual_logger.info(f"[PROXY_CREATE] Found proxy target for {proxy_hostname}: target_url={proxy_target.target_url}, enable_http={proxy_target.enable_http}, enable_https={proxy_target.enable_https}")
        
        # Get certificate if HTTPS is enabled - but don't block if not available
        cert = None
        https_ready = False
        if proxy_target.enable_https:
            dual_logger.info(f"[PROXY_CREATE] HTTPS is enabled for {proxy_hostname}, checking certificate availability")
            cert_name = proxy_target.cert_name
            if cert_name:
                dual_logger.info(f"[PROXY_CREATE] Certificate name is {cert_name}, attempting to retrieve")
                # Use async cert manager if available
                if self.async_components and self.async_components.cert_manager:
                    cert = await self.async_components.cert_manager.get_certificate(cert_name)
                else:
                    dual_logger.warning(f"[PROXY_CREATE] No cert manager available")
                    cert = None
                
                if cert:
                    https_ready = True
                    dual_logger.info(f"[PROXY_CREATE] Certificate {cert_name} is available and ready for {proxy_hostname}")
                else:
                    dual_logger.warning(f"[PROXY_CREATE] Certificate {cert_name} not yet available for {proxy_hostname}, will enable HTTPS when ready")
            else:
                dual_logger.info(f"[PROXY_CREATE] No certificate name set for {proxy_hostname}, HTTPS will be enabled when certificate is assigned")
        else:
            dual_logger.info(f"[PROXY_CREATE] HTTPS is disabled for {proxy_hostname}")
        
        # Check Redis for existing port mapping first
        http_port = None
        https_port = None
        
        if self.redis:
            mapping_data = await self.redis.hget("proxy:ports:mappings", proxy_hostname)
            if mapping_data:
                mapping = json.loads(mapping_data)
                http_port = mapping.get("http")
                https_port = mapping.get("https")
                dual_logger.info(f"[PROXY_CREATE] Found existing port mapping for {proxy_hostname}: HTTP:{http_port}, HTTPS:{https_port}")
        
        # Allocate ports if not found in Redis
        if not http_port:
            # Use hash-based preferred port for deterministic allocation
            preferred_http = 12000 + (hash(proxy_hostname) % 1000)
            http_port = await self.port_manager.allocate_port(
                purpose="proxy_http",
                preferred=preferred_http,
                bind_address="127.0.0.1"
            )
            if not http_port:
                dual_logger.error(f"[PROXY_CREATE] No HTTP ports available for {proxy_hostname}")
                return
            dual_logger.info(f"[PROXY_CREATE] Allocated HTTP port {http_port} for {proxy_hostname}")
        
        if not https_port and proxy_target.enable_https:
            preferred_https = 13000 + (hash(proxy_hostname) % 1000)
            https_port = await self.port_manager.allocate_port(
                purpose="proxy_https",
                preferred=preferred_https,
                bind_address="127.0.0.1"
            )
            if not https_port:
                # Release HTTP port if HTTPS allocation fails
                await self.port_manager.release_port(http_port)
                dual_logger.error(f"[PROXY_CREATE] No HTTPS ports available for {proxy_hostname}")
                return
            dual_logger.info(f"[PROXY_CREATE] Allocated HTTPS port {https_port} for {proxy_hostname}")
        elif not proxy_target.enable_https:
            https_port = 13000  # Default for instances without HTTPS
        
        # Store port mapping in Redis for persistence
        if self.redis:
            mapping = {
                "http": http_port,
                "https": https_port,
                "created_at": datetime.now(timezone.utc).isoformat()
            }
            await self.redis.hset("proxy:ports:mappings", proxy_hostname, json.dumps(mapping))
            dual_logger.debug(f"[PROXY_CREATE] Stored port mapping for {proxy_hostname} in Redis")
        
        # Create instance - this is a proxy-only instance
        dual_logger.info(f"[PROXY_CREATE] Creating HypercornInstance for {proxy_hostname} on ports HTTP:{http_port}, HTTPS:{https_port}")
        instance = HypercornInstance(
            app=None,  # Will create its own proxy app
            domains=[proxy_hostname],
            http_port=http_port,
            https_port=https_port,
            cert=cert,
            proxy_configs={proxy_hostname: proxy_target},
            storage=self.storage,  # Use the storage passed to UnifiedMultiInstanceServer
            async_components=self.async_components
        )
        
        dual_logger.info(f"[PROXY_CREATE] Starting instance for {proxy_hostname}")
        # Start the instance
        await instance.start()
        dual_logger.info(f"[PROXY_CREATE] Instance started successfully for {proxy_hostname}")
        
        self.instances.append(instance)
        dual_logger.info(f"[PROXY_CREATE] Instance added to instances list for {proxy_hostname} (total instances: {len(self.instances)})")
        
        # Register with dispatcher - enable HTTPS only if certificate is actually available
        dual_logger.info(f"[PROXY_CREATE] Registering {proxy_hostname} with dispatcher - HTTP:{proxy_target.enable_http}, HTTPS:{https_ready}")
        self.dispatcher.register_domain(
            [proxy_hostname], 
            http_port, 
            https_port,
            enable_http=proxy_target.enable_http,
            enable_https=https_ready  # Only enable HTTPS routing if cert is available
        )
        dual_logger.info(f"[PROXY_CREATE] Domain {proxy_hostname} registered with dispatcher")
        
        log_info(
            f"[PROXY_CREATE] ✅ Successfully created proxy instance for {proxy_hostname} - "
            f"HTTP:{proxy_target.enable_http} (port {instance.http_port}), "
            f"HTTPS:{https_ready} (port {instance.https_port}), "
            f"HTTPS_pending:{proxy_target.enable_https and not https_ready}, "
            f"target_url:{proxy_target.target_url}, "
            f"cert_name:{proxy_target.cert_name if proxy_target.cert_name else 'none'}"
        )
    
    async def remove_instance_for_proxy(self, proxy_hostname: str):
        """Remove instance for a proxy target."""
        # Find instance serving this hostname
        instance_to_remove = None
        for instance in self.instances:
            if proxy_hostname in instance.domains:
                instance_to_remove = instance
                break
        
        if not instance_to_remove:
            dual_logger.warning(f"No instance found for {proxy_hostname}")
            return
        
        # Stop the instance
        await instance_to_remove.stop()
        self.instances.remove(instance_to_remove)
        
        # Unregister from dispatcher
        if proxy_hostname in self.dispatcher.hostname_to_http_port:
            del self.dispatcher.hostname_to_http_port[proxy_hostname]
        if proxy_hostname in self.dispatcher.hostname_to_https_port:
            del self.dispatcher.hostname_to_https_port[proxy_hostname]
        
        dual_logger.info(f"Removed instance for {proxy_hostname}")
    
    # =================== UNIFIED ARCHITECTURE METHODS ===================
    
    async def _start_unified_consumer(self):
        """Start the ONE consumer to rule them all."""
        from .redis_stream_consumer import RedisStreamConsumer
        
        try:
            redis_url = os.getenv('REDIS_URL', 'redis://:test@redis:6379/0')
            
            # Create consumer with NEW unified group
            self.stream_consumer = RedisStreamConsumer(
                redis_url=redis_url,
                group_name="unified-dispatcher"  # NEW UNIFIED GROUP
            )
            
            # Initialize consumer
            await self.stream_consumer.initialize()
            
            # Start consuming events - NON-BLOCKING
            self.consumer_task = asyncio.create_task(
                self.stream_consumer.consume_events(self.handle_unified_event)
            )
            
            # Start pending message handler
            asyncio.create_task(
                self.stream_consumer.claim_pending_messages()
            )
            
            dual_logger.info("[UNIFIED] Consumer started with group 'unified-dispatcher'")
            
        except Exception as e:
            dual_logger.error(f"[UNIFIED] Failed to start consumer: {e}", error=e)
    
    async def handle_unified_event(self, event: dict):
        """ONE handler for ALL events - simple and direct."""
        
        event_type = event.get('event_type') or event.get('type')
        proxy_hostname = event.get('proxy_hostname')
        
        dual_logger.debug(f" Processing event {event_type} for {proxy_hostname}")
        
        # Special handling for certificate_ready - it has domains instead of proxy_hostname
        if event_type == 'certificate_ready':
            cert_name = event.get('cert_name')
            domains = event.get('domains', [])
            
            dual_logger.info(f"[UNIFIED] Processing certificate_ready for {cert_name} with domains: {domains}")
            
            # Enable HTTPS for each domain that has a proxy
            for domain in domains:
                await self._enable_https(domain, cert_name)
            return
        
        if not proxy_hostname:
            dual_logger.debug(f"[UNIFIED] Event missing proxy_hostname: {event}")
            return
        
        dual_logger.info(f"[UNIFIED] Processing {event_type} for {proxy_hostname}")
        
        try:
            # Just 3 event types - that's it!
            if event_type in ['proxy_created', 'proxy_creation_requested']:
                # Both events do the same thing - ensure instance exists
                await self._ensure_instance_exists(proxy_hostname)
                
            elif event_type == 'proxy_deleted':
                await self._remove_instance(proxy_hostname)
                
            else:
                dual_logger.debug(f"[UNIFIED] Ignoring event type: {event_type}")
                
        except Exception as e:
            dual_logger.error(f"[UNIFIED] Failed to handle {event_type} for {proxy_hostname}: {e}", error=e)
    
    async def _ensure_instance_exists(self, proxy_hostname: str):
        """Create instance if it doesn't exist - FAIL LOUDLY if anything goes wrong."""
        # Skip if already exists
        if proxy_hostname in self.instances:
            dual_logger.debug(f"[UNIFIED] Instance already exists for {proxy_hostname}")
            return
        
        # Get proxy configuration - MUST exist
        proxy_target = await self.dispatcher._get_proxy_target(proxy_hostname)
        if not proxy_target:
            dual_logger.error(f"CRITICAL: No proxy config for {proxy_hostname} - cannot create instance")
            raise RuntimeError(f"Cannot create instance for {proxy_hostname} - proxy configuration not found in database")
        
        dual_logger.info(f"[UNIFIED] Creating instance for {proxy_hostname}")
        
        # Check for certificate if HTTPS is enabled
        cert = None
        https_ready = False
        if proxy_target.enable_https and proxy_target.cert_name:
            if self.async_components and self.async_components.cert_manager:
                cert = await self.async_components.cert_manager.get_certificate(proxy_target.cert_name)
                if cert:
                    https_ready = True
                    dual_logger.info(f"[UNIFIED] Certificate ready for {proxy_hostname}")
        
        # Check Redis for existing port mapping first
        http_port = None
        https_port = None
        
        if self.redis:
            mapping_data = await self.redis.hget("proxy:ports:mappings", proxy_hostname)
            if mapping_data:
                mapping = json.loads(mapping_data)
                http_port = mapping.get("http")
                https_port = mapping.get("https")
                dual_logger.info(f"[UNIFIED] Found existing port mapping for {proxy_hostname}: HTTP:{http_port}, HTTPS:{https_port}")
        
        # Allocate ports if not found in Redis
        if not http_port:
            # Use hash-based preferred port for deterministic allocation
            preferred_http = 12000 + (hash(proxy_hostname) % 1000)
            http_port = await self.port_manager.allocate_port(
                purpose="proxy_http",
                preferred=preferred_http,
                bind_address="127.0.0.1"
            )
            if not http_port:
                raise RuntimeError(f"No HTTP ports available for {proxy_hostname}")
            dual_logger.info(f"[UNIFIED] Allocated HTTP port {http_port} for {proxy_hostname}")
        
        if not https_port and proxy_target.enable_https:
            preferred_https = 13000 + (hash(proxy_hostname) % 1000)
            https_port = await self.port_manager.allocate_port(
                purpose="proxy_https",
                preferred=preferred_https,
                bind_address="127.0.0.1"
            )
            if not https_port:
                # Release HTTP port if HTTPS allocation fails
                await self.port_manager.release_port(http_port)
                raise RuntimeError(f"No HTTPS ports available for {proxy_hostname}")
            dual_logger.info(f"[UNIFIED] Allocated HTTPS port {https_port} for {proxy_hostname}")
        elif not proxy_target.enable_https:
            https_port = 13000  # Default for instances without HTTPS
        
        # Store port mapping in Redis for persistence
        if self.redis:
            mapping = {
                "http": http_port,
                "https": https_port,
                "created_at": datetime.now(timezone.utc).isoformat()
            }
            await self.redis.hset("proxy:ports:mappings", proxy_hostname, json.dumps(mapping))
            dual_logger.debug(f"[UNIFIED] Stored port mapping for {proxy_hostname} in Redis")
        
        # Create Hypercorn instance - MUST succeed
        try:
            # HypercornInstance is in this same file
            # Create the instance with the allocated ports
            instance = HypercornInstance(
                app=None,  # Will be created by HypercornInstance
                domains=[proxy_hostname],
                http_port=http_port,
                https_port=https_port,
                cert=cert if https_ready else None,
                proxy_configs={proxy_hostname: proxy_target},
                storage=self.storage,
                async_components=self.async_components
            )
            
            # Start it - MUST succeed
            await instance.start()
            
            # Track it
            self.instances[proxy_hostname] = instance
            self.instance_states[proxy_hostname] = "running"
            
            # Register routes - MUST succeed
            self.dispatcher.register_domain(
                [proxy_hostname],
                http_port,
                https_port,
                enable_http=proxy_target.enable_http,
                enable_https=https_ready
            )
            
            dual_logger.info(f"✅ [UNIFIED] Instance created for {proxy_hostname} - HTTP:{proxy_target.enable_http}, HTTPS:{https_ready}")
                    
        except Exception as e:
            dual_logger.error(f"CRITICAL: Instance creation failed for {proxy_hostname}: {e}")
            dual_logger.error(f"Traceback: {traceback.format_exc()}")
            raise RuntimeError(f"Cannot create instance for {proxy_hostname}: {e}")
    
    async def _remove_instance(self, proxy_hostname: str):
        """Remove instance for a proxy."""
        if proxy_hostname not in self.instances:
            dual_logger.debug(f"[UNIFIED] No instance to remove for {proxy_hostname}")
            return
        
        instance = self.instances[proxy_hostname]
        
        # Get port mapping from Redis to release ports
        if self.redis:
            mapping_data = await self.redis.hget("proxy:ports:mappings", proxy_hostname)
            if mapping_data:
                mapping = json.loads(mapping_data)
                http_port = mapping.get("http")
                https_port = mapping.get("https")
                
                # Release ports back to the pool
                if http_port:
                    await self.port_manager.release_port(http_port)
                    dual_logger.debug(f"[UNIFIED] Released HTTP port {http_port} for {proxy_hostname}")
                if https_port and https_port != 13000:  # Don't release default HTTPS port
                    await self.port_manager.release_port(https_port)
                    dual_logger.debug(f"[UNIFIED] Released HTTPS port {https_port} for {proxy_hostname}")
                
                # Remove mapping from Redis
                await self.redis.hdel("proxy:ports:mappings", proxy_hostname)
                dual_logger.debug(f"[UNIFIED] Removed port mapping for {proxy_hostname} from Redis")
        
        # Stop the instance
        await instance.stop()
        
        # Remove from tracking
        del self.instances[proxy_hostname]
        if proxy_hostname in self.instance_states:
            del self.instance_states[proxy_hostname]
        
        # Unregister from dispatcher
        if proxy_hostname in self.dispatcher.hostname_to_http_port:
            del self.dispatcher.hostname_to_http_port[proxy_hostname]
        if proxy_hostname in self.dispatcher.hostname_to_https_port:
            del self.dispatcher.hostname_to_https_port[proxy_hostname]
        
        dual_logger.info(f"✅ [UNIFIED] Instance removed for {proxy_hostname}")
    
    async def _enable_https(self, proxy_hostname: str, cert_name: str):
        """Enable HTTPS for an existing instance when certificate is ready."""
        if proxy_hostname not in self.instances:
            # No instance yet, create it with HTTPS
            await self._ensure_instance_exists(proxy_hostname)
            return
        
        instance = self.instances[proxy_hostname]
        
        # Get certificate
        if self.async_components and self.async_components.cert_manager:
            cert = await self.async_components.cert_manager.get_certificate(cert_name)
            if cert:
                instance.cert = cert
                await instance.start_https()
                
                # Update routing to enable HTTPS
                proxy_target = await self.dispatcher._get_proxy_target(proxy_hostname)
                if proxy_target:
                    self.dispatcher.register_domain(
                        [proxy_hostname],
                        instance.http_port,
                        instance.https_port,
                        enable_http=proxy_target.enable_http,
                        enable_https=True
                    )
                    dual_logger.info(f"✅ [UNIFIED] HTTPS enabled for {proxy_hostname}")
    
    async def _reconcile_all_proxies(self):
        """Reconcile ALL proxies - FAIL if any proxy can't be created."""
        dual_logger.info("Python logging: _reconcile_all_proxies() started")
        
        try:
            dual_logger.info("=" * 60)
            dual_logger.info("[UNIFIED] Starting proxy reconciliation")
            dual_logger.info("=" * 60)
            
            # Get all proxy targets
            all_proxies = []
            if self.dispatcher.async_storage:
                all_proxies = await self.dispatcher.async_storage.list_proxy_targets()
            elif self.storage:
                all_proxies = self.storage.list_proxy_targets()
            else:
                raise RuntimeError("CRITICAL: No storage available for proxy reconciliation")
            
            dual_logger.info(f"[UNIFIED] Found {len(all_proxies)} proxies to reconcile")
            dual_logger.debug(f" Found {len(all_proxies)} proxies to reconcile")
            
            created = 0
            skipped = 0
            failed = []
            
            for proxy in all_proxies:
                proxy_hostname = proxy.proxy_hostname if hasattr(proxy, 'proxy_hostname') else proxy.get('proxy_hostname')
                dual_logger.debug(f" Processing proxy {proxy_hostname}")
                
                try:
                    # Ensure instance exists
                    if proxy_hostname not in self.instances:
                        dual_logger.info(f"[UNIFIED] Creating instance for {proxy_hostname}...")
                        dual_logger.debug(f" Creating instance for {proxy_hostname}")
                        await self._ensure_instance_exists(proxy_hostname)
                        created += 1
                        dual_logger.info(f"✅ [UNIFIED] Created instance for {proxy_hostname}")
                    else:
                        skipped += 1
                        dual_logger.debug(f"[UNIFIED] Instance already exists for {proxy_hostname}")
                    
                    # Rate limit to avoid overwhelming
                    await asyncio.sleep(0.1)
                    
                except Exception as e:
                    dual_logger.error(f"CRITICAL: Failed to create instance for {proxy_hostname}: {e}")
                    dual_logger.error(f"Traceback: {traceback.format_exc()}")
                    failed.append((proxy_hostname, str(e)))
            
            if failed:
                dual_logger.error(f"CRITICAL: Reconciliation failed for {len(failed)} proxies")
                for hostname, error in failed:
                    dual_logger.error(f"  - {hostname}: {error}")
                raise RuntimeError(f"System cannot start - failed to create instances for: {[h for h,_ in failed]}")
            
            dual_logger.info(f"✅ [UNIFIED] Reconciliation complete: {created} created, {skipped} already existed")
            
        except Exception as e:
            dual_logger.error(f"CRITICAL: Reconciliation failed completely: {e}")
            dual_logger.error(f"Traceback: {traceback.format_exc()}")
            raise RuntimeError(f"System cannot start - reconciliation failed: {e}")
    
    # =================== END UNIFIED ARCHITECTURE METHODS ===================
    
    async def start_stream_consumer(self):
        """Start Redis Stream consumer for dynamic proxy management."""
        from .redis_stream_consumer import RedisStreamConsumer
        
        try:
            # Get Redis connection details
            redis_url = os.getenv('REDIS_URL', 'redis://:test@redis:6379/0')
            
            # Create stream consumer
            self.stream_consumer = RedisStreamConsumer(
                redis_url=redis_url,
                group_name="dispatcher-group"
            )
            
            # Initialize consumer
            await self.stream_consumer.initialize()
            dual_logger.info("[STREAM_CONSUMER] Redis Stream consumer initialized")
            
            # Start consuming events
            asyncio.create_task(
                self.stream_consumer.consume_events(self.handle_proxy_event)
            )
            
            # Start pending message handler
            asyncio.create_task(
                self.stream_consumer.claim_pending_messages()
            )
            
            dual_logger.info("[STREAM_CONSUMER] Started Redis Stream consumer for proxy events")
            
        except Exception as e:
            dual_logger.error(f"[STREAM_CONSUMER] Failed to start stream consumer: {e}", exc_info=True)
    
    async def handle_proxy_event(self, event: dict):
        """Handle events from Redis Stream."""
        event_type = event.get('type')
        proxy_hostname = event.get("proxy_hostname")
        
        dual_logger.info(f"[STREAM_EVENT] Processing {event_type} for {proxy_hostname}")
        
        try:
            if event_type == 'proxy_created':
                # Create instance for new proxy
                dual_logger.info(f"[STREAM_EVENT] Creating instance for {proxy_hostname}")
                await self.create_instance_for_proxy(proxy_hostname)
                dual_logger.info(f"[STREAM_EVENT] Instance created for {proxy_hostname}")
            
            elif event_type == 'proxy_deleted':
                # Remove instance for deleted proxy
                dual_logger.info(f"[STREAM_EVENT] Removing instance for {proxy_hostname}")
                await self.remove_instance_for_proxy(proxy_hostname)
                dual_logger.info(f"[STREAM_EVENT] Instance removed for {proxy_hostname}")
                
            elif event_type == 'certificate_ready':
                # Update instance when certificate becomes available
                dual_logger.info(f"[STREAM_EVENT] Certificate ready for {proxy_hostname}")
                await self.update_instance_certificate(proxy_hostname)
                dual_logger.info(f"[STREAM_EVENT] Certificate applied for {proxy_hostname}")
            
            elif event_type == 'create_http_instance':
                # The workflow orchestrator wants us to create an HTTP instance
                dual_logger.info(f"[STREAM_EVENT] Creating HTTP instance for {proxy_hostname}")
                await self.create_instance_for_proxy(proxy_hostname)
                
                # Get the allocated port from Redis mapping
                port = None
                if self.redis:
                    mapping_data = await self.redis.hget("proxy:ports:mappings", proxy_hostname)
                    if mapping_data:
                        mapping = json.loads(mapping_data)
                        port = mapping.get("http")
                
                # Publish confirmation event
                from ..storage.redis_stream_publisher import RedisStreamPublisher
                redis_url = os.getenv('REDIS_URL', 'redis://:test@redis:6379/0')
                publisher = RedisStreamPublisher(redis_url=redis_url)
                await publisher.publish_event("http_instance_started", {
                    "proxy_hostname": proxy_hostname,
                    "port": port if port else 0
                })
                await publisher.close()
                dual_logger.info(f"[STREAM_EVENT] HTTP instance created for {proxy_hostname}")
                    
            elif event_type == 'create_https_instance':
                # The workflow orchestrator wants us to create an HTTPS instance
                # This typically happens when a certificate becomes ready
                dual_logger.info(f"[STREAM_EVENT] Creating HTTPS instance for {proxy_hostname}")
                
                # Find existing instance and update it with HTTPS
                for instance in self.instances:
                    if proxy_hostname in instance.domains:
                        # Get certificate
                        proxy_target = await self.dispatcher._get_proxy_target(proxy_hostname)
                        if proxy_target and proxy_target.cert_name:
                            # Use async cert manager if available
                            if self.async_components and self.async_components.cert_manager:
                                cert = await self.async_components.cert_manager.get_certificate(proxy_target.cert_name)
                            else:
                                cert = None
                            if cert:
                                instance.cert = cert
                                await instance.start_https()
                                
                                # Update dispatcher registration
                                self.dispatcher.register_domain(
                                    [proxy_hostname],
                                    instance.http_port,
                                    instance.https_port,
                                    enable_http=proxy_target.enable_http,
                                    enable_https=True
                                )
                                dual_logger.info(f"[STREAM_EVENT] HTTPS instance created for {proxy_hostname}")
                        break
                
            elif event_type == 'proxy_updated':
                # Handle proxy updates
                dual_logger.info(f"[STREAM_EVENT] Processing proxy_updated event for {proxy_hostname}")
                # Recreate the instance with new configuration
                await self.remove_instance_for_proxy(proxy_hostname)
                await self.create_instance_for_proxy(proxy_hostname)
                dual_logger.info(f"[STREAM_EVENT] Instance recreated for {proxy_hostname}")
                
            elif event_type in ['http_instance_started', 'https_instance_started', 'http_route_registered', 'https_route_registered']:
                # These are confirmation events from the workflow orchestrator - no action needed
                dual_logger.debug(f"[STREAM_EVENT] Acknowledged {event_type} for {proxy_hostname}")
                
            else:
                dual_logger.warning(f"[STREAM_EVENT] Unknown event type: {event_type}")
                
        except Exception as e:
            dual_logger.error(f"[STREAM_EVENT] Error processing event {event_type} for {proxy_hostname}: {e}", exc_info=True)
    
    async def update_instance_certificate(self, proxy_hostname: str):
        """Update instance when certificate becomes available."""
        dual_logger.info(f"update_instance_certificate called for hostname {proxy_hostname}")
        
        # Get proxy configuration
        proxy_target = await self.dispatcher._get_proxy_target(proxy_hostname)
        if not proxy_target:
            dual_logger.warning(f"No proxy target found for {proxy_hostname}")
            return
        if not proxy_target.enable_https:
            dual_logger.info(f"HTTPS not enabled for {proxy_hostname}, skipping certificate update")
            return
        
        dual_logger.info(f"Proxy target found for {proxy_hostname}, cert_name: {proxy_target.cert_name}")
        
        # Get certificate
        if self.async_components and self.async_components.cert_manager:
            cert = await self.async_components.cert_manager.get_certificate(proxy_target.cert_name)
        else:
            cert = None
        if not cert:
            dual_logger.warning(f"Certificate {proxy_target.cert_name} still not available for {proxy_hostname}")
            return
        
        dual_logger.info(f"Certificate {proxy_target.cert_name} found for {proxy_hostname}")
        
        # Find the instance
        instance = None
        dual_logger.info(f"Looking for instance with hostname {proxy_hostname} in {len(self.instances)} instances")
        for inst in self.instances:
            dual_logger.debug(f"Checking instance with domains {inst.domains}")
            if proxy_hostname in inst.domains:
                instance = inst
                dual_logger.info(f"Found instance for {proxy_hostname} with domains {inst.domains}")
                break
        
        if not instance:
            dual_logger.error(f"No instance found for {proxy_hostname}")
            return
        
        # Check if HTTPS process is actually running
        if instance.https_process and not instance.https_process.done():
            dual_logger.info(f"HTTPS already running for {proxy_hostname}")
            return
        
        # Update instance with certificate
        instance.cert = cert
        
        # Start HTTPS instance
        dual_logger.info(f"Starting HTTPS instance for {proxy_hostname} with newly available certificate")
        await instance.start_https()
        
        # Update dispatcher registration to enable HTTPS
        self.dispatcher.register_domain(
            [proxy_hostname], 
            instance.http_port, 
            instance.https_port,
            enable_http=proxy_target.enable_http,
            enable_https=True
        )
        
        dual_logger.info(f"HTTPS enabled for {proxy_hostname} after certificate became available")
    
    def update_ssl_context(self, certificate):
        """Update SSL context when a new certificate is created or renewed."""
        if not certificate or not certificate.domains:
            dual_logger.warning("Invalid certificate passed to update_ssl_context")
            return
            
        dual_logger.info(f"update_ssl_context called for certificate {certificate.cert_name} domains: {certificate.domains}")
        dual_logger.info(f"Current instances: {[inst.domains for inst in self.instances]}")
        
        # For each domain in the certificate, update the instance if it exists OR create one if it doesn't
        for domain in certificate.domains:
            # Check if we have a proxy target for this domain
            # Use sync storage for this sync function
            proxy_target = self.storage.get_proxy_target(domain) if self.storage else None
            if not proxy_target:
                dual_logger.debug(f"No proxy target found for domain {domain}, skipping")
                continue
            
            # Find the instance handling this domain
            instance_found = False
            for instance in self.instances:
                if domain in instance.domains:
                    instance_found = True
                    dual_logger.info(f"Found existing instance for domain {domain}")
                    
                    # Update the certificate for this instance
                    instance.cert = certificate
                    dual_logger.info(f"Certificate updated on instance for domain {domain}")
                    
                    # If HTTPS is already running, we need to restart it
                    if instance.https_process and not instance.https_process.done():
                        dual_logger.info(f"HTTPS process is running for {domain}, restarting to use new certificate")
                        # Cancel the current HTTPS process
                        instance.https_process.cancel()
                        # Clean up old temp files
                        if instance.cert_file and os.path.exists(instance.cert_file):
                            os.unlink(instance.cert_file)
                        if instance.key_file and os.path.exists(instance.key_file):
                            os.unlink(instance.key_file)
                        # Start HTTPS with new certificate
                        asyncio.create_task(instance.start_https())
                        dual_logger.info(f"HTTPS restart initiated for {domain}")
                    else:
                        # HTTPS not running yet, start it now
                        dual_logger.info(f"Starting HTTPS for {domain} since certificate is now available")
                        asyncio.create_task(instance.start_https())
                        
                        # Update dispatcher to enable HTTPS
                        if proxy_target.enable_https:
                            self.dispatcher.register_domain(
                                [domain], 
                                instance.http_port, 
                                instance.https_port,
                                enable_http=proxy_target.enable_http,
                                enable_https=True
                            )
                            dual_logger.info(f"HTTPS routing enabled for {domain}")
                    break
            
            if not instance_found:
                # No instance exists - create one now that we have the certificate
                dual_logger.info(f"No instance found for domain {domain}, creating new instance with certificate")
                asyncio.create_task(self.create_instance_for_proxy(domain))
    
    async def run(self):
        """Run the unified dispatcher with non-blocking architecture."""
        dual_logger.info("UnifiedMultiInstanceServer.run() started")
        
        dual_logger.info("=" * 60)
        dual_logger.info("UNIFIED DISPATCHER STARTING")
        dual_logger.info("=" * 60)
        
        # Set global instance for dynamic management
        global unified_server_instance
        unified_server_instance = self
        
        if not self.https_server:
            dual_logger.error("Python logging: NO HTTPS SERVER INSTANCE - CANNOT START")
            dual_logger.error("NO HTTPS SERVER INSTANCE - CANNOT START")
            return
        
        # 1. Start unified consumer FIRST (non-blocking)
        dual_logger.info("Python logging: Starting unified consumer")
        await self._start_unified_consumer()
        dual_logger.info("✅ Unified consumer started")
        dual_logger.info("Python logging: Unified consumer started")
        
        # 2. Load routes from storage
        dual_logger.info("Python logging: Loading routes from storage")
        await self.dispatcher.load_routes_from_storage()
        
        # 3. Named services removed - using URL-only routing
        dual_logger.info("Python logging: URL-only routing enabled (no named services)")
        
        # 4. Load existing port mappings from Redis
        dual_logger.info("Python logging: Loading existing port mappings from Redis")
        dual_logger.info("Loading existing proxy port mappings from Redis...")
        
        if self.redis:
            mappings = await self.redis.hgetall("proxy:ports:mappings")
            if mappings:
                dual_logger.info(f"Found {len(mappings)} existing port mappings in Redis")
                for hostname_bytes, mapping_bytes in mappings.items():
                    hostname = hostname_bytes.decode() if isinstance(hostname_bytes, bytes) else hostname_bytes
                    mapping = json.loads(mapping_bytes)
                    http_port = mapping.get("http")
                    https_port = mapping.get("https")
                    
                    # Register with dispatcher
                    self.dispatcher.register_domain(
                        [hostname],
                        http_port,
                        https_port,
                        enable_http=True,
                        enable_https=(https_port is not None and https_port != 13000)
                    )
                    dual_logger.debug(f"Registered existing mapping for {hostname}: HTTP:{http_port}, HTTPS:{https_port}")
            else:
                dual_logger.info("No existing port mappings found in Redis")
        
        # 5. Reconcile ALL proxies SYNCHRONOUSLY before starting dispatcher
        dual_logger.info("Python logging: Reconciling all proxies before starting dispatcher")
        dual_logger.info("Reconciling all proxy instances before starting dispatcher...")
        await self._reconcile_all_proxies()
        dual_logger.info("Python logging: Reconciliation complete")
        
        # 6. NOW start dispatcher with all instances ready
        dual_logger.info("Python logging: Starting dispatcher")
        await self.dispatcher.start()
        dual_logger.info("✅ Dispatcher started")
        dual_logger.info("Python logging: Dispatcher started")
        
        dual_logger.info("=" * 60)
        dual_logger.info("UNIFIED DISPATCHER READY - Processing events in real-time")
        dual_logger.info("=" * 60)
        
        # The dispatcher is now running in background
        # unified_server_instance is available for dynamic management
        dual_logger.info("UnifiedMultiInstanceServer fully initialized in WORKFLOW MODE")
        
        # Note: Instances will be created by the workflow orchestrator for existing proxies
        # This is expected behavior - the orchestrator publishes events for all existing proxies at startup
        # So we don't check for zero instances here anymore
        dual_logger.info(f"Currently {len(self.instances)} instances running (created by workflow orchestrator)")
        
        # Wait forever (this is where we block)
        try:
            await self.dispatcher.wait_forever()
        finally:
            # Clean up instances
            for instance in self.instances:
                await instance.stop()