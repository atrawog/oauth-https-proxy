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
import httpx
from typing import Dict, Optional, List, Tuple, Set, Union
from datetime import datetime, timezone

from hypercorn.asyncio import serve
from hypercorn.config import Config as HypercornConfig
from ..middleware.proxy_protocol_handler import create_proxy_protocol_server

from ..proxy.models import ProxyTarget
from ..proxy.routes import Route, RouteTargetType, RouteScope
from ..proxy.app import create_proxy_app
from .models import DomainService
from ..shared.logger import log_info, log_warning, log_error, log_debug, log_trace
from ..shared.config import Config
from ..shared.unified_logger import UnifiedAsyncLogger
from ..shared.dns_resolver import get_dns_resolver

# Removed correlation ID generator - using IP as primary identifier

# Global instance for dynamic management
unified_server_instance = None


class HypercornInstance:
    """Represents a Hypercorn instance serving a specific set of domains."""
    
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
            log_info(f"HTTP disabled for domains {self.domains}", component="dispatcher")
        
        # Start HTTPS instance if enabled and certificate available
        if https_enabled:
            if self.cert and self.cert.fullchain_pem and self.cert.private_key_pem:
                await self.start_https()
            else:
                log_warning(f"HTTPS enabled but no certificate available for domains {self.domains}", component="dispatcher")
        else:
            log_info(f"HTTPS disabled for domains {self.domains}", component="dispatcher")
    
    async def start_http(self):
        """Start HTTP instance with PROXY protocol enabled."""
        try:
            log_level = os.getenv('LOG_LEVEL')
            if not log_level:
                raise ValueError("LOG_LEVEL not set in environment - required for server configuration")
            
            # Start internal Hypercorn on a different port
            internal_port = self.http_port + 2000  # e.g., 10002 -> 12002
            config = HypercornConfig()
            config.bind = [f"127.0.0.1:{internal_port}"]
            config.loglevel = log_level.upper()
            
            log_info(f"Starting internal HTTP instance on port {internal_port} for domains: {self.domains}", component="dispatcher")
            
            # Start internal server
            self.http_process = asyncio.create_task(serve(self.app, config))
            
            # Start PROXY protocol handler
            log_info(f"Starting PROXY protocol handler on port {self.http_port} -> {internal_port}", component="dispatcher")
            proxy_server = await create_proxy_protocol_server(
                backend_host="127.0.0.1",
                backend_port=internal_port,
                listen_host="127.0.0.1",
                listen_port=self.http_port,
                redis_client=self.async_redis if self.async_redis else (self.storage.redis_client if self.storage else None)
            )
            self.proxy_handler = asyncio.create_task(proxy_server.serve_forever())
            
        except Exception as e:
            log_error(f"Failed to start HTTP server: {e}", component="dispatcher", error=e)
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
            
            # Start internal Hypercorn on a different port 
            internal_port = self.https_port + 2000  # e.g., 11000 -> 13000
            config = HypercornConfig()
            config.bind = [f"127.0.0.1:{internal_port}"]
            config.certfile = self.cert_file
            config.keyfile = self.key_file
            config.loglevel = log_level.upper()
            
            log_info(f"Starting internal HTTPS instance on port {internal_port} for domains: {self.domains}", component="dispatcher")
            
            # Start internal server
            self.https_process = asyncio.create_task(serve(self.app, config))
            
            # Start PROXY protocol handler
            log_info(f"Starting PROXY protocol handler on port {self.https_port} -> {internal_port}", component="dispatcher")
            proxy_server = await create_proxy_protocol_server(
                backend_host="127.0.0.1",
                backend_port=internal_port,
                listen_host="127.0.0.1",
                listen_port=self.https_port,
                redis_client=self.async_redis if self.async_redis else (self.storage.redis_client if self.storage else None)
            )
            self.proxy_handler_https = asyncio.create_task(proxy_server.serve_forever())
            
        except Exception as e:
            log_error(f"Failed to start HTTPS server: {e}", component="dispatcher", error=e)
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
        
        log_info(f"Stopped instance for domains: {self.domains}", component="dispatcher")
    
    def cleanup(self):
        """Clean up temporary files."""
        try:
            if self.cert_file and os.path.exists(self.cert_file):
                os.unlink(self.cert_file)
            if self.key_file and os.path.exists(self.key_file):
                os.unlink(self.key_file)
        except Exception as e:
            log_error(f"Error cleaning up temp files: {e}", component="dispatcher", error=e)


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
            log_info("Unified dispatcher initialized with component-specific logger", component="dispatcher")
        else:
            # Unified logger is required for proper operation
            self.unified_logger = None
            log_warning("No unified logger available - some features may be limited", component="dispatcher")
        self.hostname_to_http_port: Dict[str, int] = {}
        self.hostname_to_https_port: Dict[str, int] = {}
        self.http_server = None
        self.https_server = None
        # Generic routing rules sorted by priority (highest first)
        self.routes: List[Route] = []
        # Named instances for routing targets
        self.named_services: Dict[str, int] = {}  # name -> port
        # Initialize DNS resolver for reverse lookups
        self.dns_resolver = get_dns_resolver()
        
        # HTTP client for URL route forwarding
        self.http_client = httpx.AsyncClient(
            timeout=httpx.Timeout(connect=30.0, read=120.0, write=30.0, pool=30.0),
            follow_redirects=False,
            verify=False  # Since we're forwarding internal requests
        )
        
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
    
    def get_applicable_routes(self, proxy_config: Optional[ProxyTarget]) -> List[Route]:
        """Get routes applicable to a specific proxy based on its configuration and scope."""
        if not proxy_config:
            # No proxy config means use all global routes (backwards compatibility)
            return [r for r in self.routes if r.scope == RouteScope.GLOBAL]
        
        # Filter routes by scope first
        applicable_routes = []
        for route in self.routes:
            if route.scope == RouteScope.GLOBAL:
                # Global routes apply to all proxies
                applicable_routes.append(route)
            elif route.scope == RouteScope.PROXY and proxy_config.proxy_hostname in route.proxy_hostnames:
                # Proxy-specific routes only apply to listed proxies
                applicable_routes.append(route)
        
        # Sort by priority (higher first) - proxy-specific routes can override global ones
        applicable_routes.sort(key=lambda r: r.priority, reverse=True)
        
        # Apply existing route filtering based on route_mode
        if proxy_config.route_mode == "none":
            # No routes apply
            return []
        elif proxy_config.route_mode == "selective":
            # Only enabled routes apply
            return [r for r in applicable_routes if r.route_id in proxy_config.enabled_routes]
        else:  # route_mode == "all" (default)
            # All routes except disabled ones
            return [r for r in applicable_routes if r.route_id not in proxy_config.disabled_routes]
    
    def register_domain(self, domains: List[str], http_port: int, https_port: int, 
                          enable_http: bool = True, enable_https: bool = True):
        """Register a domain instance for specific domains and protocols."""
        for domain in domains:
            if enable_http:
                # Register port for dispatcher connections (all have PROXY protocol)
                self.hostname_to_http_port[domain] = http_port
                log_info(f"Registered {domain} -> HTTP:{http_port}", component="dispatcher")
            if enable_https:
                # Register port for dispatcher connections (all have PROXY protocol)
                self.hostname_to_https_port[domain] = https_port
                log_info(f"Registered {domain} -> HTTPS:{https_port}", component="dispatcher")
            if not enable_http and not enable_https:
                log_warning(f"Domain {domain} has no protocols enabled!", component="dispatcher")
    
    def register_named_service(self, name: str, port: int, service_url: Optional[str] = None):
        """Register a named service for routing targets.
        
        Args:
            name: Service name (e.g., 'api')
            port: Port number for localhost access
            service_url: Full URL for Docker service access (e.g., 'http://api:9000')
        """
        self.named_services[name] = port
        log_info(f"Registered named service: {name} -> port {port}", component="dispatcher")
        
        # Store in Redis so proxies can access it
        if self.storage:
            try:
                # Store service URL
                if service_url:
                    self.storage.redis_client.set(f"service:url:{name}", service_url)
                    log_info(f"Stored service {name} URL in Redis: {service_url}", component="dispatcher")
                elif name == "api":
                    # Special case for API service - use Docker service name
                    self.storage.redis_client.set(f"service:url:{name}", "http://api:9000")
                    log_info(f"Stored API service URL in Redis: http://api:9000", component="dispatcher")
                
                log_debug(f"Stored service {name} in Redis", component="dispatcher")
            except Exception as e:
                log_error(f"Failed to store service in Redis: {e}", component="dispatcher", error=e)
    
    async def load_routes_from_storage(self):
        """Load routes from Redis storage."""
        if not self.storage:
            log_warning("No storage available for loading routes", component="dispatcher")
            return
        
        try:
            # Initialize default routes if needed
            self.storage.initialize_default_routes()
            
            # Initialize default proxies if needed
            self.storage.initialize_default_proxies()
            
            # Load all routes from storage
            self.routes = await self._list_routes()
            
            # Filter only enabled routes
            self.routes = [r for r in self.routes if r.enabled]
            
            log_info(f"Loaded {len(self.routes)} routes from storage", component="dispatcher")
            for route in self.routes:
                log_info(f"  {route.priority}: {route.path_pattern} -> {route.target_type.value}:{route.target_value} - {route.description}", component="dispatcher")
        except Exception as e:
            log_error(f"Failed to load routes from storage: {e}", component="dispatcher", error=e)
    
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
            log_debug(f"Error parsing HTTP request: {e}", component="dispatcher")
            return None, None
    
    def resolve_route_target(self, route: Route) -> Optional[Union[int, str]]:
        """Resolve a route to a target port or URL."""
        if route.target_type == RouteTargetType.PORT:
            return route.target_value if isinstance(route.target_value, int) else int(route.target_value)
        elif route.target_type == RouteTargetType.SERVICE:
            return self.named_services.get(route.target_value)
        elif route.target_type == RouteTargetType.HOSTNAME:
            # hostname_to_http_port contains ports with PROXY protocol enabled
            return self.hostname_to_http_port.get(route.target_value)
        elif route.target_type == RouteTargetType.URL:
            return route.target_value  # Return URL as-is
        return None
    
    async def _forward_http_request(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter, 
                                     request_data: bytes, target_url: str, path: str, method: str):
        """Forward an HTTP request to a URL target and stream the response back."""
        try:
            # Parse the HTTP request
            request_str = request_data.decode('utf-8', errors='ignore')
            lines = request_str.split('\r\n')
            
            # Extract headers from the request
            headers = {}
            body_start = -1
            for i, line in enumerate(lines[1:], 1):  # Skip request line
                if line == '':  # Empty line marks end of headers
                    body_start = i + 1
                    break
                if ':' in line:
                    key, value = line.split(':', 1)
                    headers[key.strip()] = value.strip()
            
            # Get request body if present
            body = None
            if body_start > 0 and body_start < len(lines):
                body = '\r\n'.join(lines[body_start:]).encode('utf-8')
            
            # Construct target URL
            if not target_url.endswith('/'):
                full_url = target_url + path
            else:
                full_url = target_url.rstrip('/') + path
            
            log_info(f"Forwarding {method} {path} to {full_url}", component="dispatcher")
            
            # Make the HTTP request
            response = await self.http_client.request(
                method=method,
                url=full_url,
                headers=headers,
                content=body
            )
            
            # Build response to send back
            response_lines = [f"HTTP/1.1 {response.status_code} {response.reason_phrase}"]
            
            # Add response headers
            for name, value in response.headers.items():
                # Skip some headers that might cause issues
                if name.lower() not in ['connection', 'transfer-encoding']:
                    response_lines.append(f"{name}: {value}")
            
            # Add content length if not present
            if 'content-length' not in response.headers:
                response_lines.append(f"Content-Length: {len(response.content)}")
            
            response_lines.append("")  # Empty line between headers and body
            
            # Send response headers
            response_header = '\r\n'.join(response_lines) + '\r\n'
            writer.write(response_header.encode('utf-8'))
            
            # Send response body
            if response.content:
                writer.write(response.content)
            
            await writer.drain()
            
        except Exception as e:
            log_error(f"Error forwarding HTTP request to {target_url}: {e}", component="dispatcher", error=e)
            # Send error response
            error_response = b"HTTP/1.1 502 Bad Gateway\r\nContent-Type: text/plain\r\nContent-Length: 30\r\n\r\nError forwarding HTTP request"
            writer.write(error_response)
            await writer.drain()
        finally:
            writer.close()
            await writer.wait_closed()
    
    def get_hostname_from_http_request(self, data: bytes) -> Optional[str]:
        """Extract hostname from HTTP request headers."""
        try:
            # Convert bytes to string
            request_str = data.decode('utf-8', errors='ignore')
            lines = request_str.split('\r\n')
            
            # Look for Host header
            for line in lines[1:]:  # Skip first line (request line)
                if line.lower().startswith('host:'):
                    proxy_hostname = line.split(':', 1)[1].strip()
                    # Remove port if present
                    if ':' in proxy_hostname:
                        proxy_hostname=proxy_hostname.split(':')[0]
                    return proxy_hostname
                elif line == '':  # End of headers
                    break
            
            return None
            
        except Exception as e:
            log_debug(f"Error parsing HTTP hostname: {e}", component="dispatcher")
            return None
    
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
            log_debug(f"Error parsing SNI: {e}", component="dispatcher")
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
            log_debug(f"Error extracting headers: {e}", component="dispatcher")
        
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
            log_debug(f"Error injecting header: {e}", component="dispatcher")
            return data  # Return original on error
    
    async def handle_http_connection(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        """Handle incoming HTTP connection and forward to appropriate instance."""
        log_trace("handle_http_connection called", component="api_server")
        client_addr = writer.get_extra_info('peername')
        client_ip = client_addr[0] if client_addr else 'unknown'
        client_port = client_addr[1] if client_addr and len(client_addr) > 1 else 0
        
        log_trace(f"HTTP connection from {client_ip}:{client_port}", component="api_server")
        # No need to store IP mappings - PROXY protocol handles this
        
        log_debug(
            "New HTTP connection",
            ip=client_ip
        )
        
        try:
            # Peek at the data to get hostname
            log_trace("Reading data from HTTP connection", component="api_server")
            data = await reader.read(4096)
            log_trace(f"Data received: {len(data) if data else 0} bytes", component="api_server")
            if not data:
                log_trace("No data received, returning", component="api_server")
                return
            
            # Extract hostname from HTTP Host header FIRST
            proxy_hostname = self.get_hostname_from_http_request(data)
            log_trace(f"Extracted hostname: {proxy_hostname}", component="api_server")
            if not proxy_hostname:
                log_trace("No hostname found in request", component="api_server")
                log_warning(
                    "No hostname found in HTTP request",
                    ip=client_ip
                )
                writer.close()
                await writer.wait_closed()
                return
            
            log_trace(
                "HTTP hostname extracted",
                ip=client_ip, proxy_hostname=proxy_hostname
            )
            
            # Get proxy configuration to determine route filtering  
            proxy_config = None
            if self.async_storage:
                try:
                    proxy_json = await self.async_storage.redis_client.get(f"proxy:{proxy_hostname}")
                    if proxy_json:
                        proxy_data = json.loads(proxy_json)
                        proxy_config = ProxyTarget(**proxy_data)
                    else:
                        log_debug(f"Proxy config not found for {proxy_hostname} (may have been deleted)", component="dispatcher")
                except Exception as e:
                    log_debug(f"Error loading proxy config for {proxy_hostname}: {str(e)}", component="dispatcher")
            elif self.storage:
                # Fallback to sync storage
                try:
                    proxy_json = self.storage.redis_client.get(f"proxy:{proxy_hostname}")
                    if proxy_json:
                        proxy_data = json.loads(proxy_json)
                        proxy_config = ProxyTarget(**proxy_data)
                    else:
                        log_debug(f"Proxy config not found for {proxy_hostname} (may have been deleted)", component="dispatcher")
                except Exception as e:
                    log_debug(f"Error loading proxy config for {proxy_hostname}: {str(e)}", component="dispatcher")
            
            # Apply route filtering based on proxy configuration
            applicable_routes = self.get_applicable_routes(proxy_config)
            
            # Check generic routes with filtering
            method, request_path = self.get_request_info(data)
            
            # Log detailed request with unified logger if available
            if self.unified_logger:
                # First, gather all metadata
                # Resolve client hostname
                client_hostname = await self.dns_resolver.resolve_ptr(client_ip)
                
                # Extract headers and query params
                headers = self._extract_http_headers(data)
                query_params = self._extract_query_params(data)
                body_sample = data[:1024] if data else None  # First 1KB for logging
                
                # Generate trace ID with COMPLETE metadata for Redis storage
                trace_id = self.unified_logger.start_trace(
                    "http_request",
                    proxy_hostname=proxy_hostname,  # The proxy being accessed
                    method=method or "",
                    path=request_path or "",
                    client_ip=client_ip,
                    client_port=client_port,
                    client_hostname=client_hostname,  # Resolved hostname
                    user_agent=headers.get('user-agent', '') if headers else '',
                    referer=headers.get('referer', '') if headers else '',
                    query=self._extract_query_params(data) if data else ''
                )
                
                # Log detailed request
                await self.unified_logger.log_request(
                    method=method or "",
                    path=request_path or "",
                    client_ip=client_ip,
                    proxy_hostname=proxy_hostname,  # The proxy being accessed
                    trace_id=trace_id,
                    headers=headers,
                    body=body_sample,
                    query_params=query_params,
                    client_hostname=client_hostname,  # Reverse DNS of client
                    log_source="dispatcher",
                    event_type="http_request" if method else "connection_lifecycle"
                )
            else:
                # Fallback to old logging
                log_debug(
                    "HTTP request details",
                    ip=client_ip, proxy_hostname=proxy_hostname,
                    method=method,
                    path=request_path
                )
            if request_path and applicable_routes:
                for route in applicable_routes:
                    if route.matches(request_path, method):
                        target = self.resolve_route_target(route)
                        if target:
                            if route.target_type == RouteTargetType.URL:
                                # For URL routes, forward the HTTP request
                                await self._forward_http_request(reader, writer, data, str(target), request_path, method)
                                return
                            else:
                                # Regular port-based forwarding
                                service_name = route.target_value if route.target_type == RouteTargetType.SERVICE else None
                                log_info(f"Request {method} {request_path} matched route '{route.description or route.path_pattern}' -> port {target}", component="dispatcher")
                                await self._forward_connection(
                                    reader, writer, data, '127.0.0.1', target, 
                                    client_ip=client_ip, client_port=client_port, use_proxy_protocol=True, proxy_hostname=proxy_hostname, service_name=service_name
                                )
                                return
                        else:
                            log_warning(f"Route matched but target not found: {route.target_type.value}:{route.target_value}", component="dispatcher")
            
            # Find the appropriate port for hostname-based routing
            target_port = self.hostname_to_http_port.get(proxy_hostname)
            if not target_port:
                # Log available instances for debugging
                available_http_hosts = list(self.hostname_to_http_port.keys())[:10]  # First 10
                log_debug(
                    "No HTTP instance found for hostname (may still be initializing)", proxy_hostname=proxy_hostname,
                    available_http_hosts=available_http_hosts,
                    total_http_hosts=len(self.hostname_to_http_port),
                    named_services=list(self.named_services.keys())[:10]
                )
                # Send 404 response
                response = b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n"
                writer.write(response)
                await writer.drain()
                writer.close()
                await writer.wait_closed()
                return
            
            
            # Inject X-Trace-Id header into the HTTP request if we have a trace_id
            if self.unified_logger and 'trace_id' in locals():
                # Inject the trace_id into the HTTP request
                data = self._inject_http_header(data, 'X-Trace-Id', trace_id)
                log_trace(f"Injected X-Trace-Id header: {trace_id}", component="dispatcher")
            
            # Determine if this is a named instance or proxy target
            service_name = None
            for name, port in self.named_services.items():
                if port == target_port:
                    service_name = name
                    break
            
            # Forward to the target instance with PROXY protocol enabled
            await self._forward_connection(
                reader, writer, data, '127.0.0.1', target_port, 
                client_ip=client_ip, client_port=client_port, use_proxy_protocol=True, proxy_hostname=proxy_hostname, service_name=service_name, 
                trace_id=trace_id if 'trace_id' in locals() else None
            )
            
        except Exception as e:
            log_error(f"Error handling HTTP connection: {e}", component="api_server", error=e)
            import traceback
            traceback.print_exc()
        finally:
            log_trace("Closing HTTP connection", component="api_server")
            writer.close()
            await writer.wait_closed()
    
    async def handle_https_connection(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        """Handle incoming HTTPS connection and forward to appropriate instance."""
        client_addr = writer.get_extra_info('peername')
        client_ip = client_addr[0] if client_addr else 'unknown'
        client_port = client_addr[1] if client_addr and len(client_addr) > 1 else 0
        
        # No need to store IP mappings - PROXY protocol handles this
        
        log_debug(
            "New HTTPS connection",
            ip=client_ip
        )
        
        try:
            # Peek at the data to get SNI hostname
            data = await reader.read(4096)
            if not data:
                log_warning(
                    "No data received in HTTPS connection",
                    ip=client_ip
                )
                return
            
            log_debug(
                "HTTPS data received",
                ip=client_ip,
                data_len=len(data)
            )
            
            # Extract SNI hostname
            proxy_hostname = self.get_sni_hostname(data)
            if not proxy_hostname:
                log_warning(
                    "No SNI hostname found in connection",
                    ip=client_ip
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
            
            # Get proxy config if this is a proxy domain
            proxy_config = None
            if (self.storage or self.async_storage) and proxy_hostname not in ['localhost', '127.0.0.1']:
                try:
                    proxy_config = await self._get_proxy_target(proxy_hostname)
                    if proxy_config is None:
                        log_debug(f"Proxy config not found for {proxy_hostname} (may have been deleted)", component="dispatcher")
                except Exception as e:
                    log_debug(f"Error getting proxy config for {proxy_hostname}: {str(e)}", component="dispatcher")
            
            # For HTTPS, we cannot parse HTTP request info from TLS handshake data
            # Route matching must be handled by the proxy instances after TLS termination
            # The proxy app will handle route matching at the application level
            
            # Find the appropriate port for hostname-based routing
            target_port = self.hostname_to_https_port.get(proxy_hostname)
            if not target_port:
                # Try wildcard match
                parts = proxy_hostname.split('.')
                if len(parts) > 2:
                    wildcard = f"*.{'.'.join(parts[1:])}"
                    target_port = self.hostname_to_https_port.get(wildcard)
            
            # Special handling for localhost - route to API instance
            if not target_port and proxy_hostname in ['localhost', '127.0.0.1']:
                # Route localhost to the API instance via named instance (HTTPS not available, use HTTP)
                log_debug(f"HTTPS requested for localhost, but API doesn't have HTTPS configured", component="dispatcher")
                writer.close()
                await writer.wait_closed()
                return
            
            if not target_port:
                # Log available instances for debugging
                available_https_hosts = list(self.hostname_to_https_port.keys())[:10]  # First 10
                log_debug(
                    "No HTTPS instance found for hostname (may still be initializing)", proxy_hostname=proxy_hostname,
                    available_https_hosts=available_https_hosts,
                    total_https_hosts=len(self.hostname_to_https_port),
                    named_services=list(self.named_services.keys())[:10]
                )
                writer.close()
                await writer.wait_closed()
                return
            
            # Determine if this is a named instance or proxy target
            service_name = None
            for name, port in self.named_services.items():
                if port == target_port:
                    service_name = name
                    break
            
            
            # Forward to the target instance with PROXY protocol enabled for HTTPS
            await self._forward_connection(
                reader, writer, data, '127.0.0.1', target_port, 
                client_ip=client_ip, client_port=client_port, use_proxy_protocol=True, proxy_hostname=proxy_hostname, service_name=service_name
            )
            
        except ConnectionResetError as e:
            # Connection reset by peer is common with HTTPS/MCP - handle gracefully
            log_debug(f"Connection reset by peer from {client_ip}:{client_port} - likely normal client disconnect", component="dispatcher")
        except Exception as e:
            log_error(f"Error handling HTTPS connection: {e}", component="dispatcher")
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except ConnectionResetError:
                # Ignore connection reset during cleanup
                pass
            except Exception as e:
                log_debug(f"Error during connection cleanup: {e}", component="dispatcher")
    

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
            log_error(f"Error sending PROXY protocol header: {e}", component="dispatcher")
            # Continue without PROXY protocol on error

    async def _forward_connection(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter,
                                  initial_data: bytes, target_host: str, target_port: int, 
                                  client_ip: str = None, client_port: int = None, use_proxy_protocol: bool = False,
                                  proxy_hostname: str = None, service_name: str = None, trace_id: str = None):
        """Forward a connection to target host:port with optional PROXY protocol support."""
        try:
            # Connect to the target
            target_reader, target_writer = await asyncio.open_connection(target_host, target_port)
            
            # Get the local port of our connection to backend (for Redis key)
            backend_local_addr = target_writer.get_extra_info('sockname')
            backend_local_port = backend_local_addr[1] if backend_local_addr else 0
            
            # Send PROXY protocol header to preserve real client IP
            if use_proxy_protocol:
                # Use defaults if not provided
                if not client_ip or client_ip == 'unknown':
                    client_ip = '127.0.0.1'
                if not client_port:
                    client_port = 0
                
                # Store trace_id and metadata in Redis BEFORE sending PROXY protocol
                # This allows the proxy handler to retrieve it
                if trace_id and (self.storage or self.async_storage):
                    try:
                        # Use same key format as ProxyProtocolHandler expects
                        key = f"proxy:client:{target_port}:{backend_local_port}"
                        
                        # Resolve client hostname if not already done
                        client_hostname = await self.dns_resolver.resolve_ptr(client_ip)
                        
                        # Store comprehensive metadata
                        value = {
                            "client_ip": client_ip,
                            "client_port": client_port,
                            "client_hostname": client_hostname,
                            "proxy_hostname": proxy_hostname or "",
                            "trace_id": trace_id,
                            "service_name": service_name or "",
                            "timestamp": time.time()
                        }
                        
                        if self.async_storage and self.async_storage.redis_client:
                            await self.async_storage.redis_client.setex(key, 60, json.dumps(value))
                        elif self.storage:
                            await self.storage.set(key, json.dumps(value), ex=60)
                        else:
                            log_debug("No storage available for trace metadata", component="dispatcher")
                        
                        log_trace(f"Stored trace metadata in Redis: {key} -> trace_id={trace_id}", component="dispatcher")
                    except Exception as e:
                        # Don't log as error - this is non-critical
                        log_debug(f"Could not store trace metadata: {str(e)}", component="dispatcher")
                
                # Enhanced logging with hostname and instance
                service_info = f" (service: {service_name})" if service_name else ""
                log_debug(
                    f"Forwarding connection - Client: {client_ip}:{client_port} -> "
                    f"Hostname: {proxy_hostname or 'unknown'} -> "
                    f"Target: {target_host}:{target_port}{service_info} "
                    f"[PROXY protocol: {'enabled' if use_proxy_protocol else 'disabled'}]"
                )
                await self._send_proxy_protocol_header(target_writer, client_ip, client_port, target_port)
            
            # No header injection - using PROXY protocol instead
            
            # Send the initial data we already read
            target_writer.write(initial_data)
            await target_writer.drain()
            
            # Forward data bidirectionally
            async def forward(src_reader, dst_writer, direction):
                try:
                    while True:
                        data = await src_reader.read(4096)
                        if not data:
                            break
                        dst_writer.write(data)
                        await dst_writer.drain()
                except Exception as e:
                    log_debug(f"Forward {direction} error: {e}", component="dispatcher")
                finally:
                    try:
                        dst_writer.close()
                        await dst_writer.wait_closed()
                    except:
                        pass
            
            # Create forwarding tasks
            await asyncio.gather(
                forward(reader, target_writer, "client->server"),
                forward(target_reader, writer, "server->client"),
                return_exceptions=True
            )
            
        except Exception as e:
            log_error(f"Error forwarding connection: {e}", component="dispatcher")
    
    async def start(self):
        """Start both HTTP and HTTPS dispatchers without blocking."""
        log_info("UnifiedDispatcher.start() called - starting HTTP and HTTPS servers", component="dispatcher")
        
        # Start HTTP dispatcher on port 80
        http_port_str = os.getenv('HTTP_PORT')
        if not http_port_str:
            raise ValueError("HTTP_PORT not set in environment - required for server configuration")
        http_port = int(http_port_str)
        log_info(f"Creating HTTP server on {self.host}:{http_port}", component="dispatcher")
        try:
            self.http_server = await asyncio.start_server(
                self.handle_http_connection,
                self.host,
                http_port
            )
            log_info(f"HTTP Dispatcher listening on {self.host}:{http_port}", component="dispatcher")
        except Exception as e:
            log_error(f"Failed to create HTTP server: {e}", component="dispatcher", error=e)
            raise
        
        # Start HTTPS dispatcher on port 443
        https_port_str = os.getenv('HTTPS_PORT')
        if not https_port_str:
            raise ValueError("HTTPS_PORT not set in environment - required for server configuration")
        https_port = int(https_port_str)
        log_info(f"Creating HTTPS server on {self.host}:{https_port}", component="dispatcher")
        try:
            self.https_server = await asyncio.start_server(
                self.handle_https_connection,
                self.host,
                https_port
            )
            log_info(f"HTTPS Dispatcher listening on {self.host}:{https_port}", component="dispatcher")
        except Exception as e:
            log_error(f"Failed to create HTTPS server: {e}", component="dispatcher", error=e)
            raise
        
        # Create tasks for the servers but don't await them
        # This allows the dispatcher to start without blocking
        log_trace("Creating server tasks", component="dispatcher")
        self.server_tasks = [
            asyncio.create_task(self.http_server.serve_forever()),
            asyncio.create_task(self.https_server.serve_forever())
        ]
        log_info("Dispatcher servers started in background", component="dispatcher")
    
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
        log_debug(f"UnifiedMultiInstanceServer.__init__ called with https_server={https_server_instance is not None}", component="dispatcher")
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
        self.next_http_port = 10002   # Starting port for HTTP instances (10001 reserved for API)
        self.next_https_port = 11000  # Starting port for HTTPS instances
        
    async def create_instance_for_proxy(self, proxy_hostname: str):
        """Dynamically create and start an instance for a proxy target."""
        import logging
        logger = logging.getLogger(__name__)
        logger.info(f"[PROXY_CREATE] Method called for {proxy_hostname}")
        
        log_info(f"[PROXY_CREATE] Starting instance creation for {proxy_hostname}", component="dispatcher")
        
        # Check if instance already exists by looking at actual running instances
        # Don't rely on dispatcher maps as they may have stale entries
        instance_exists = False
        for instance in self.instances:
            if proxy_hostname in instance.domains:
                logger.info(f"[PROXY_CREATE] Found existing instance for {proxy_hostname}")
                log_info(f"[PROXY_CREATE] Instance already exists for {proxy_hostname} (found in instances list)", component="dispatcher")
                instance_exists = True
                break
        
        if instance_exists:
            return
        
        # Clean up any stale entries in dispatcher maps
        if proxy_hostname in self.dispatcher.hostname_to_https_port:
            logger.info(f"[PROXY_CREATE] Removing stale HTTPS map entry for {proxy_hostname}")
            del self.dispatcher.hostname_to_https_port[proxy_hostname]
        if proxy_hostname in self.dispatcher.hostname_to_http_port:
            logger.info(f"[PROXY_CREATE] Removing stale HTTP map entry for {proxy_hostname}")
            del self.dispatcher.hostname_to_http_port[proxy_hostname]
        
        log_info(f"[PROXY_CREATE] No existing instance found for {proxy_hostname}, proceeding with creation", component="dispatcher")
        
        # Get proxy configuration using async storage via dispatcher
        proxy_target = await self.dispatcher._get_proxy_target(proxy_hostname)
        if not proxy_target:
            log_error(f"[PROXY_CREATE] No proxy target found for {proxy_hostname} in Redis storage", component="dispatcher")
            return
        
        log_info(f"[PROXY_CREATE] Found proxy target for {proxy_hostname}: target_url={proxy_target.target_url}, enable_http={proxy_target.enable_http}, enable_https={proxy_target.enable_https}", component="dispatcher")
        
        # Get certificate if HTTPS is enabled - but don't block if not available
        cert = None
        https_ready = False
        if proxy_target.enable_https:
            log_info(f"[PROXY_CREATE] HTTPS is enabled for {proxy_hostname}, checking certificate availability", component="dispatcher")
            cert_name = proxy_target.cert_name
            if cert_name:
                log_info(f"[PROXY_CREATE] Certificate name is {cert_name}, attempting to retrieve", component="dispatcher")
                # Use async cert manager if available
                if self.async_components and self.async_components.cert_manager:
                    cert = await self.async_components.cert_manager.get_certificate(cert_name)
                else:
                    log_warning(f"[PROXY_CREATE] No cert manager available", component="dispatcher")
                    cert = None
                
                if cert:
                    https_ready = True
                    log_info(f"[PROXY_CREATE] Certificate {cert_name} is available and ready for {proxy_hostname}", component="dispatcher")
                else:
                    log_warning(f"[PROXY_CREATE] Certificate {cert_name} not yet available for {proxy_hostname}, will enable HTTPS when ready", component="dispatcher")
            else:
                log_info(f"[PROXY_CREATE] No certificate name set for {proxy_hostname}, HTTPS will be enabled when certificate is assigned", component="dispatcher")
        else:
            log_info(f"[PROXY_CREATE] HTTPS is disabled for {proxy_hostname}", component="dispatcher")
        
        # Create instance - this is a proxy-only instance
        log_info(f"[PROXY_CREATE] Creating HypercornInstance for {proxy_hostname} on ports HTTP:{self.next_http_port}, HTTPS:{self.next_https_port}", component="dispatcher")
        instance = HypercornInstance(
            app=None,  # Will create its own proxy app
            domains=[proxy_hostname],
            http_port=self.next_http_port,
            https_port=self.next_https_port,
            cert=cert,
            proxy_configs={proxy_hostname: proxy_target},
            storage=self.storage,  # Use the storage passed to UnifiedMultiInstanceServer
            async_components=self.async_components
        )
        
        log_info(f"[PROXY_CREATE] Starting instance for {proxy_hostname}", component="dispatcher")
        # Start the instance
        await instance.start()
        log_info(f"[PROXY_CREATE] Instance started successfully for {proxy_hostname}", component="dispatcher")
        
        self.instances.append(instance)
        log_info(f"[PROXY_CREATE] Instance added to instances list for {proxy_hostname} (total instances: {len(self.instances)})", component="dispatcher")
        
        # Register with dispatcher - enable HTTPS only if certificate is actually available
        log_info(f"[PROXY_CREATE] Registering {proxy_hostname} with dispatcher - HTTP:{proxy_target.enable_http}, HTTPS:{https_ready}", component="dispatcher")
        self.dispatcher.register_domain(
            [proxy_hostname], 
            self.next_http_port, 
            self.next_https_port,
            enable_http=proxy_target.enable_http,
            enable_https=https_ready  # Only enable HTTPS routing if cert is available
        )
        log_info(f"[PROXY_CREATE] Domain {proxy_hostname} registered with dispatcher", component="dispatcher")
        
        self.next_http_port += 1
        self.next_https_port += 1
        
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
            log_warning(f"No instance found for {proxy_hostname}", component="dispatcher")
            return
        
        # Stop the instance
        await instance_to_remove.stop()
        self.instances.remove(instance_to_remove)
        
        # Unregister from dispatcher
        if proxy_hostname in self.dispatcher.hostname_to_http_port:
            del self.dispatcher.hostname_to_http_port[proxy_hostname]
        if proxy_hostname in self.dispatcher.hostname_to_https_port:
            del self.dispatcher.hostname_to_https_port[proxy_hostname]
        
        log_info(f"Removed instance for {proxy_hostname}", component="dispatcher")
    
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
            
            log_info("[UNIFIED] Consumer started with group 'unified-dispatcher'", component="dispatcher")
            
        except Exception as e:
            log_error(f"[UNIFIED] Failed to start consumer: {e}", component="dispatcher", error=e)
    
    async def handle_unified_event(self, event: dict):
        """ONE handler for ALL events - simple and direct."""
        event_type = event.get('event_type') or event.get('type')
        proxy_hostname = event.get('proxy_hostname')
        
        # Special handling for certificate_ready - it has domains instead of proxy_hostname
        if event_type == 'certificate_ready':
            cert_name = event.get('cert_name')
            domains = event.get('domains', [])
            
            log_info(f"[UNIFIED] Processing certificate_ready for {cert_name} with domains: {domains}", 
                    component="dispatcher")
            
            # Enable HTTPS for each domain that has a proxy
            for domain in domains:
                await self._enable_https(domain, cert_name)
            return
        
        if not proxy_hostname:
            log_debug(f"[UNIFIED] Event missing proxy_hostname: {event}", component="dispatcher")
            return
        
        log_info(f"[UNIFIED] Processing {event_type} for {proxy_hostname}", component="dispatcher")
        
        try:
            # Just 3 event types - that's it!
            if event_type in ['proxy_created', 'proxy_creation_requested']:
                # Both events do the same thing - ensure instance exists
                await self._ensure_instance_exists(proxy_hostname)
                
            elif event_type == 'proxy_deleted':
                await self._remove_instance(proxy_hostname)
                
            else:
                log_debug(f"[UNIFIED] Ignoring event type: {event_type}", component="dispatcher")
                
        except Exception as e:
            log_error(f"[UNIFIED] Failed to handle {event_type} for {proxy_hostname}: {e}", 
                     component="dispatcher", error=e)
    
    async def _ensure_instance_exists(self, proxy_hostname: str):
        """Create instance if it doesn't exist - idempotent."""
        # Skip if already exists
        if proxy_hostname in self.instances:
            log_debug(f"[UNIFIED] Instance already exists for {proxy_hostname}", component="dispatcher")
            return
        
        # Get proxy configuration
        proxy_target = await self.dispatcher._get_proxy_target(proxy_hostname)
        if not proxy_target:
            log_warning(f"[UNIFIED] No proxy config for {proxy_hostname}", component="dispatcher")
            return
        
        log_info(f"[UNIFIED] Creating instance for {proxy_hostname}", component="dispatcher")
        
        # Check for certificate if HTTPS is enabled
        cert = None
        https_ready = False
        if proxy_target.enable_https and proxy_target.cert_name:
            if self.async_components and self.async_components.cert_manager:
                cert = await self.async_components.cert_manager.get_certificate(proxy_target.cert_name)
                if cert:
                    https_ready = True
                    log_info(f"[UNIFIED] Certificate ready for {proxy_hostname}", component="dispatcher")
        
        # Create instance
        instance = HypercornInstance(
            app=None,  # Will create its own proxy app
            domains=[proxy_hostname],
            http_port=self.next_http_port,
            https_port=self.next_https_port,
            cert=cert,
            proxy_configs={proxy_hostname: proxy_target},
            storage=self.storage,
            async_components=self.async_components
        )
        
        # Start it
        await instance.start()
        
        # Track it
        self.instances[proxy_hostname] = instance
        self.instance_states[proxy_hostname] = "running"
        
        # Register routes
        self.dispatcher.register_domain(
            [proxy_hostname],
            self.next_http_port,
            self.next_https_port,
            enable_http=proxy_target.enable_http,
            enable_https=https_ready
        )
        
        self.next_http_port += 1
        self.next_https_port += 1
        
        log_info(f"✅ [UNIFIED] Instance created for {proxy_hostname} - HTTP:{proxy_target.enable_http}, HTTPS:{https_ready}", 
                component="dispatcher")
    
    async def _remove_instance(self, proxy_hostname: str):
        """Remove instance for a proxy."""
        if proxy_hostname not in self.instances:
            log_debug(f"[UNIFIED] No instance to remove for {proxy_hostname}", component="dispatcher")
            return
        
        instance = self.instances[proxy_hostname]
        
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
        
        log_info(f"✅ [UNIFIED] Instance removed for {proxy_hostname}", component="dispatcher")
    
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
                    log_info(f"✅ [UNIFIED] HTTPS enabled for {proxy_hostname}", component="dispatcher")
    
    async def _ensure_localhost_proxy(self):
        """Ensure localhost proxy exists with OAuth configuration if not manually configured."""
        try:
            localhost = None
            
            # Get existing localhost proxy
            if self.dispatcher.async_storage:
                localhost = await self.dispatcher.async_storage.get_proxy_target("localhost")
            elif self.storage:
                localhost = self.storage.get_proxy_target("localhost")
            
            needs_update = False
            
            if not localhost:
                # Create new localhost proxy
                log_info("Creating localhost proxy with OAuth configuration", component="dispatcher")
                localhost = ProxyTarget(
                    proxy_hostname="localhost",
                    target_url="http://127.0.0.1:9000",
                    cert_name=None,  # No certificate for localhost
                    owner_token_hash="system",
                    created_by="system",
                    created_at=datetime.now(timezone.utc),
                    enabled=True,
                    enable_http=True,
                    enable_https=False,  # No HTTPS for localhost
                    preserve_host_header=True,
                    custom_headers=None,
                    custom_response_headers=None,
                    
                    # OAuth will be configured below
                    auth_enabled=True,
                    auth_proxy="localhost",  # Self-referential for OAuth
                    auth_mode="redirect",  # Redirect to OAuth for auth
                    auth_required_users=None,
                    auth_required_emails=None,
                    auth_required_groups=None,
                    auth_allowed_scopes=None,
                    auth_allowed_audiences=None,
                    auth_pass_headers=True,
                    auth_cookie_name="oauth_token",
                    auth_header_prefix="X-Auth-",
                    auth_excluded_paths=[
                        "/health",
                        "/device/code",     # Must be accessible for Device Flow
                        "/device/token",    # Must be accessible for Device Flow
                    ],
                    
                    # Route control
                    route_mode="all",
                    enabled_routes=[],
                    disabled_routes=[],
                )
                needs_update = True
            
            # Only update OAuth users if ALL are None/empty
            if (localhost.oauth_admin_users is None and 
                localhost.oauth_user_users is None and 
                localhost.oauth_mcp_users is None):
                
                # Get from environment
                admin_users_env = os.getenv("OAUTH_LOCALHOST_ADMIN_USERS", "")
                user_users_env = os.getenv("OAUTH_LOCALHOST_USER_USERS", "*")
                mcp_users_env = os.getenv("OAUTH_LOCALHOST_MCP_USERS", "")
                
                admin_users = [u.strip() for u in admin_users_env.split(",") if u.strip()]
                user_users = [u.strip() for u in user_users_env.split(",") if u.strip()]
                mcp_users = [u.strip() for u in mcp_users_env.split(",") if u.strip()]
                
                localhost.oauth_admin_users = admin_users if admin_users else None
                localhost.oauth_user_users = user_users if user_users else None
                localhost.oauth_mcp_users = mcp_users if mcp_users else None
                
                # Also ensure auth is enabled if we're setting users
                if not localhost.auth_enabled:
                    localhost.auth_enabled = True
                    localhost.auth_proxy = "localhost"  # Self-referential
                    localhost.auth_mode = "redirect"
                    localhost.auth_excluded_paths = [
                        "/health",
                        "/device/code",     # Must be accessible for Device Flow
                        "/device/token",    # Must be accessible for Device Flow
                    ]
                
                needs_update = True
                log_info(
                    "Configured localhost proxy OAuth users from environment",
                    component="dispatcher",
                    admin_users=admin_users,
                    user_users=user_users,
                    mcp_users=mcp_users
                )
            
            if needs_update:
                # Store the proxy
                if self.dispatcher.async_storage:
                    await self.dispatcher.async_storage.store_proxy_target("localhost", localhost)
                    log_info("Stored localhost proxy configuration", component="dispatcher")
                elif self.storage:
                    self.storage.store_proxy_target("localhost", localhost)
                    log_info("Stored localhost proxy configuration", component="dispatcher")
                    
        except Exception as e:
            log_error(f"Error ensuring localhost proxy: {e}", component="dispatcher")
    
    async def _reconcile_all_proxies(self):
        """Reconcile ALL proxies in background without blocking."""
        try:
            # Wait for system to stabilize
            await asyncio.sleep(2)
            
            log_info("[UNIFIED] Starting background reconciliation", component="dispatcher")
            
            # Ensure localhost proxy exists with OAuth configuration
            await self._ensure_localhost_proxy()
            
            # Get all proxy targets
            all_proxies = []
            if self.dispatcher.async_storage:
                all_proxies = await self.dispatcher.async_storage.list_proxy_targets()
            elif self.storage:
                all_proxies = self.storage.list_proxy_targets()
            
            created = 0
            skipped = 0
            
            for proxy in all_proxies:
                try:
                    proxy_hostname = proxy.proxy_hostname if hasattr(proxy, 'proxy_hostname') else proxy.get('proxy_hostname')
                    
                    # Ensure instance exists
                    if proxy_hostname not in self.instances:
                        await self._ensure_instance_exists(proxy_hostname)
                        created += 1
                    else:
                        skipped += 1
                    
                    # Rate limit to avoid overwhelming
                    await asyncio.sleep(0.1)
                    
                except Exception as e:
                    log_error(f"[UNIFIED] Failed to reconcile {proxy_hostname}: {e}", 
                             component="dispatcher", error=e)
            
            log_info(f"✅ [UNIFIED] Reconciliation complete: {created} created, {skipped} already existed", 
                    component="dispatcher")
            
        except Exception as e:
            log_error(f"[UNIFIED] Reconciliation failed: {e}", component="dispatcher", error=e)
    
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
            log_info("[STREAM_CONSUMER] Redis Stream consumer initialized", component="dispatcher")
            
            # Start consuming events
            asyncio.create_task(
                self.stream_consumer.consume_events(self.handle_proxy_event)
            )
            
            # Start pending message handler
            asyncio.create_task(
                self.stream_consumer.claim_pending_messages()
            )
            
            log_info("[STREAM_CONSUMER] Started Redis Stream consumer for proxy events", component="dispatcher")
            
        except Exception as e:
            log_error(f"[STREAM_CONSUMER] Failed to start stream consumer: {e}", exc_info=True, component="dispatcher")
    
    async def handle_proxy_event(self, event: dict):
        """Handle events from Redis Stream."""
        event_type = event.get('type')
        proxy_hostname = event.get("proxy_hostname")
        
        log_info(f"[STREAM_EVENT] Processing {event_type} for {proxy_hostname}", component="dispatcher")
        
        try:
            if event_type == 'proxy_created':
                # Create instance for new proxy
                log_info(f"[STREAM_EVENT] Creating instance for {proxy_hostname}", component="dispatcher")
                await self.create_instance_for_proxy(proxy_hostname)
                log_info(f"[STREAM_EVENT] Instance created for {proxy_hostname}", component="dispatcher")
            
            elif event_type == 'proxy_deleted':
                # Remove instance for deleted proxy
                log_info(f"[STREAM_EVENT] Removing instance for {proxy_hostname}", component="dispatcher")
                await self.remove_instance_for_proxy(proxy_hostname)
                log_info(f"[STREAM_EVENT] Instance removed for {proxy_hostname}", component="dispatcher")
                
            elif event_type == 'certificate_ready':
                # Update instance when certificate becomes available
                log_info(f"[STREAM_EVENT] Certificate ready for {proxy_hostname}", component="dispatcher")
                await self.update_instance_certificate(proxy_hostname)
                log_info(f"[STREAM_EVENT] Certificate applied for {proxy_hostname}", component="dispatcher")
            
            elif event_type == 'create_http_instance':
                # The workflow orchestrator wants us to create an HTTP instance
                log_info(f"[STREAM_EVENT] Creating HTTP instance for {proxy_hostname}", component="dispatcher")
                await self.create_instance_for_proxy(proxy_hostname)
                
                # Publish confirmation event
                from ..storage.redis_stream_publisher import RedisStreamPublisher
                redis_url = os.getenv('REDIS_URL', 'redis://:test@redis:6379/0')
                publisher = RedisStreamPublisher(redis_url=redis_url)
                await publisher.publish_event("http_instance_started", {
                    "proxy_hostname": proxy_hostname,
                    "port": self.next_http_port - 1  # Last allocated port
                })
                await publisher.close()
                log_info(f"[STREAM_EVENT] HTTP instance created for {proxy_hostname}", component="dispatcher")
                    
            elif event_type == 'create_https_instance':
                # The workflow orchestrator wants us to create an HTTPS instance
                # This typically happens when a certificate becomes ready
                log_info(f"[STREAM_EVENT] Creating HTTPS instance for {proxy_hostname}", component="dispatcher")
                
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
                                log_info(f"[STREAM_EVENT] HTTPS instance created for {proxy_hostname}", component="dispatcher")
                        break
                
            elif event_type == 'proxy_updated':
                # Handle proxy updates
                log_info(f"[STREAM_EVENT] Processing proxy_updated event for {proxy_hostname}", component="dispatcher")
                # Recreate the instance with new configuration
                await self.remove_instance_for_proxy(proxy_hostname)
                await self.create_instance_for_proxy(proxy_hostname)
                log_info(f"[STREAM_EVENT] Instance recreated for {proxy_hostname}", component="dispatcher")
                
            elif event_type in ['http_instance_started', 'https_instance_started', 'http_route_registered', 'https_route_registered']:
                # These are confirmation events from the workflow orchestrator - no action needed
                log_debug(f"[STREAM_EVENT] Acknowledged {event_type} for {proxy_hostname}", component="dispatcher")
                
            else:
                log_warning(f"[STREAM_EVENT] Unknown event type: {event_type}", component="dispatcher")
                
        except Exception as e:
            log_error(f"[STREAM_EVENT] Error processing event {event_type} for {proxy_hostname}: {e}", exc_info=True, component="dispatcher")
    
    async def update_instance_certificate(self, proxy_hostname: str):
        """Update instance when certificate becomes available."""
        log_info(f"update_instance_certificate called for hostname {proxy_hostname}", component="dispatcher")
        
        # Get proxy configuration
        proxy_target = await self.dispatcher._get_proxy_target(proxy_hostname)
        if not proxy_target:
            log_warning(f"No proxy target found for {proxy_hostname}", component="dispatcher")
            return
        if not proxy_target.enable_https:
            log_info(f"HTTPS not enabled for {proxy_hostname}, skipping certificate update", component="dispatcher")
            return
        
        log_info(f"Proxy target found for {proxy_hostname}, cert_name: {proxy_target.cert_name}", component="dispatcher")
        
        # Get certificate
        if self.async_components and self.async_components.cert_manager:
            cert = await self.async_components.cert_manager.get_certificate(proxy_target.cert_name)
        else:
            cert = None
        if not cert:
            log_warning(f"Certificate {proxy_target.cert_name} still not available for {proxy_hostname}", component="dispatcher")
            return
        
        log_info(f"Certificate {proxy_target.cert_name} found for {proxy_hostname}", component="dispatcher")
        
        # Find the instance
        instance = None
        log_info(f"Looking for instance with hostname {proxy_hostname} in {len(self.instances)} instances", component="dispatcher")
        for inst in self.instances:
            log_debug(f"Checking instance with domains {inst.domains}", component="dispatcher")
            if proxy_hostname in inst.domains:
                instance = inst
                log_info(f"Found instance for {proxy_hostname} with domains {inst.domains}", component="dispatcher")
                break
        
        if not instance:
            log_error(f"No instance found for {proxy_hostname}", component="dispatcher")
            return
        
        # Check if HTTPS process is actually running
        if instance.https_process and not instance.https_process.done():
            log_info(f"HTTPS already running for {proxy_hostname}", component="dispatcher")
            return
        
        # Update instance with certificate
        instance.cert = cert
        
        # Start HTTPS instance
        log_info(f"Starting HTTPS instance for {proxy_hostname} with newly available certificate", component="dispatcher")
        await instance.start_https()
        
        # Update dispatcher registration to enable HTTPS
        self.dispatcher.register_domain(
            [proxy_hostname], 
            instance.http_port, 
            instance.https_port,
            enable_http=proxy_target.enable_http,
            enable_https=True
        )
        
        log_info(f"HTTPS enabled for {proxy_hostname} after certificate became available", component="dispatcher")
    
    def update_ssl_context(self, certificate):
        """Update SSL context when a new certificate is created or renewed."""
        if not certificate or not certificate.domains:
            log_warning("Invalid certificate passed to update_ssl_context", component="dispatcher")
            return
            
        log_info(f"update_ssl_context called for certificate {certificate.cert_name} domains: {certificate.domains}", component="dispatcher")
        log_info(f"Current instances: {[inst.domains for inst in self.instances]}", component="dispatcher")
        
        # For each domain in the certificate, update the instance if it exists OR create one if it doesn't
        for domain in certificate.domains:
            # Check if we have a proxy target for this domain
            # Use sync storage for this sync function
            proxy_target = self.storage.get_proxy_target(domain) if self.storage else None
            if not proxy_target:
                log_debug(f"No proxy target found for domain {domain}, skipping", component="dispatcher")
                continue
            
            # Find the instance handling this domain
            instance_found = False
            for instance in self.instances:
                if domain in instance.domains:
                    instance_found = True
                    log_info(f"Found existing instance for domain {domain}", component="dispatcher")
                    
                    # Update the certificate for this instance
                    instance.cert = certificate
                    log_info(f"Certificate updated on instance for domain {domain}", component="dispatcher")
                    
                    # If HTTPS is already running, we need to restart it
                    if instance.https_process and not instance.https_process.done():
                        log_info(f"HTTPS process is running for {domain}, restarting to use new certificate", component="dispatcher")
                        # Cancel the current HTTPS process
                        instance.https_process.cancel()
                        # Clean up old temp files
                        if instance.cert_file and os.path.exists(instance.cert_file):
                            os.unlink(instance.cert_file)
                        if instance.key_file and os.path.exists(instance.key_file):
                            os.unlink(instance.key_file)
                        # Start HTTPS with new certificate
                        asyncio.create_task(instance.start_https())
                        log_info(f"HTTPS restart initiated for {domain}", component="dispatcher")
                    else:
                        # HTTPS not running yet, start it now
                        log_info(f"Starting HTTPS for {domain} since certificate is now available", component="dispatcher")
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
                            log_info(f"HTTPS routing enabled for {domain}", component="dispatcher")
                    break
            
            if not instance_found:
                # No instance exists - create one now that we have the certificate
                log_info(f"No instance found for domain {domain}, creating new instance with certificate", component="dispatcher")
                asyncio.create_task(self.create_instance_for_proxy(domain))
    
    async def run(self):
        """Run the unified dispatcher with non-blocking architecture."""
        log_info("=" * 60, component="dispatcher")
        log_info("UNIFIED DISPATCHER STARTING", component="dispatcher")
        log_info("=" * 60, component="dispatcher")
        
        # Set global instance for dynamic management
        global unified_server_instance
        unified_server_instance = self
        
        if not self.https_server:
            log_error("NO HTTPS SERVER INSTANCE - CANNOT START", component="dispatcher")
            return
        
        # 1. Start unified consumer FIRST (non-blocking)
        await self._start_unified_consumer()
        log_info("✅ Unified consumer started", component="dispatcher")
        
        # 2. Load routes from storage
        await self.dispatcher.load_routes_from_storage()
        
        # 3. Register API service
        self.dispatcher.register_named_service('api', 10001, 'http://api:9000')
        # Note: localhost will get its own proxy instance during reconciliation
        
        # 4. Start dispatcher
        await self.dispatcher.start()
        log_info("✅ Dispatcher started", component="dispatcher")
        
        # 5. Reconcile existing proxies in BACKGROUND - NON-BLOCKING!
        self.reconciliation_task = asyncio.create_task(self._reconcile_all_proxies())
        
        log_info("=" * 60, component="dispatcher")
        log_info("UNIFIED DISPATCHER READY - Processing events in real-time", component="dispatcher")
        log_info("=" * 60, component="dispatcher")
        
        # The dispatcher is now running in background
        # unified_server_instance is available for dynamic management
        log_info("UnifiedMultiInstanceServer fully initialized in WORKFLOW MODE", component="dispatcher")
        
        # Note: Instances will be created by the workflow orchestrator for existing proxies
        # This is expected behavior - the orchestrator publishes events for all existing proxies at startup
        # So we don't check for zero instances here anymore
        log_info(f"Currently {len(self.instances)} instances running (created by workflow orchestrator)", component="dispatcher")
        
        # Wait forever (this is where we block)
        try:
            await self.dispatcher.wait_forever()
        finally:
            # Clean up instances
            for instance in self.instances:
                await instance.stop()