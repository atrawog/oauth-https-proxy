"""Unified dispatcher for both HTTP and HTTPS traffic.

This implementation creates dedicated Hypercorn instances for each domain
and uses dispatchers on both port 80 and 443 to route traffic.
"""

import asyncio
import ssl
import logging
import os
import tempfile
import struct
import json
import httpx
from typing import Dict, Optional, List, Tuple, Set, Union
from datetime import datetime

from hypercorn.asyncio import serve
from hypercorn.config import Config as HypercornConfig
from ..middleware.proxy_protocol_handler import create_proxy_protocol_server

from ..proxy.models import ProxyTarget
from ..proxy.routes import Route, RouteTargetType
from ..proxy.app import create_proxy_app
from .models import DomainInstance
from ..shared.logging import get_logger, configure_logging
from ..shared.config import Config

logger = get_logger(__name__)

# Removed correlation ID generator - using IP as primary identifier

# Global instance for dynamic management
unified_server_instance = None


class DomainInstance:
    """Represents a Hypercorn instance serving a specific set of domains."""
    
    def __init__(self, app, domains: List[str], http_port: int, https_port: int, 
                 cert=None, proxy_configs: Dict = None, storage=None):
        self.domains = domains
        self.http_port = http_port  # Port with PROXY protocol enabled
        self.https_port = https_port  # Port with PROXY protocol enabled
        self.cert = cert
        self.proxy_configs = proxy_configs or {}
        self.storage = storage
        self.http_process = None
        self.https_process = None
        self.cert_file = None
        self.key_file = None
        self.proxy_handler = None
        self.proxy_handler_https = None
        
        # Create a proxy app for this instance
        from ..proxy.app import create_proxy_app
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
            logger.info(f"HTTP disabled for domains {self.domains}")
        
        # Start HTTPS instance if enabled and certificate available
        if https_enabled:
            if self.cert and self.cert.fullchain_pem and self.cert.private_key_pem:
                await self.start_https()
            else:
                logger.warning(f"HTTPS enabled but no certificate available for domains {self.domains}")
        else:
            logger.info(f"HTTPS disabled for domains {self.domains}")
    
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
            
            logger.info(f"Starting internal HTTP instance on port {internal_port} for domains: {self.domains}")
            
            # Start internal server
            self.http_process = asyncio.create_task(serve(self.app, config))
            
            # Start PROXY protocol handler
            logger.info(f"Starting PROXY protocol handler on port {self.http_port} -> {internal_port}")
            proxy_server = await create_proxy_protocol_server(
                backend_host="127.0.0.1",
                backend_port=internal_port,
                listen_host="127.0.0.1",
                listen_port=self.http_port,
                redis_client=self.storage.redis_client if self.storage else None
            )
            self.proxy_handler = asyncio.create_task(proxy_server.serve_forever())
            
        except Exception as e:
            logger.error(f"Failed to start HTTP instance: {e}")
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
            
            logger.info(f"Starting internal HTTPS instance on port {internal_port} for domains: {self.domains}")
            
            # Start internal server
            self.https_process = asyncio.create_task(serve(self.app, config))
            
            # Start PROXY protocol handler
            logger.info(f"Starting PROXY protocol handler on port {self.https_port} -> {internal_port}")
            proxy_server = await create_proxy_protocol_server(
                backend_host="127.0.0.1",
                backend_port=internal_port,
                listen_host="127.0.0.1",
                listen_port=self.https_port,
                redis_client=self.storage.redis_client if self.storage else None
            )
            self.proxy_handler_https = asyncio.create_task(proxy_server.serve_forever())
            
        except Exception as e:
            logger.error(f"Failed to start HTTPS instance: {e}")
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
        
        logger.info(f"Stopped instance for domains: {self.domains}")
    
    def cleanup(self):
        """Clean up temporary files."""
        try:
            if self.cert_file and os.path.exists(self.cert_file):
                os.unlink(self.cert_file)
            if self.key_file and os.path.exists(self.key_file):
                os.unlink(self.key_file)
        except Exception as e:
            logger.error(f"Error cleaning up temp files: {e}")


class UnifiedDispatcher:
    """Dispatcher that routes both HTTP and HTTPS traffic to domain instances."""
    
    def __init__(self, host='0.0.0.0', storage=None):
        self.host = host
        self.storage = storage
        
        # Configure Redis logging if storage is available
        if storage and storage.redis_client:
            from ..shared.logging import configure_logging
            configure_logging(storage.redis_client)
        self.hostname_to_http_port: Dict[str, int] = {}
        self.hostname_to_https_port: Dict[str, int] = {}
        self.http_server = None
        self.https_server = None
        # Generic routing rules sorted by priority (highest first)
        self.routes: List[Route] = []
        # Named instances for routing targets
        self.named_instances: Dict[str, int] = {}  # name -> port
        # HTTP client for URL route forwarding
        self.http_client = httpx.AsyncClient(
            timeout=httpx.Timeout(connect=30.0, read=120.0, write=30.0, pool=30.0),
            follow_redirects=False,
            verify=False  # Since we're forwarding internal requests
        )
        
    def get_applicable_routes(self, proxy_config: Optional[ProxyTarget]) -> List[Route]:
        """Get routes applicable to a specific proxy based on its configuration."""
        if not proxy_config:
            # No proxy config means use all enabled routes (backwards compatibility)
            return self.routes
        
        # Apply route filtering based on route_mode
        if proxy_config.route_mode == "none":
            # No routes apply
            return []
        elif proxy_config.route_mode == "selective":
            # Only enabled routes apply
            return [r for r in self.routes if r.route_id in proxy_config.enabled_routes]
        else:  # route_mode == "all" (default)
            # All routes except disabled ones
            return [r for r in self.routes if r.route_id not in proxy_config.disabled_routes]
    
    def register_instance(self, domains: List[str], http_port: int, https_port: int, 
                          enable_http: bool = True, enable_https: bool = True):
        """Register a domain instance for specific domains and protocols."""
        for domain in domains:
            if enable_http:
                # Register port for dispatcher connections (all have PROXY protocol)
                self.hostname_to_http_port[domain] = http_port
                logger.info(f"Registered {domain} -> HTTP:{http_port}")
            if enable_https:
                # Register port for dispatcher connections (all have PROXY protocol)
                self.hostname_to_https_port[domain] = https_port
                logger.info(f"Registered {domain} -> HTTPS:{https_port}")
            if not enable_http and not enable_https:
                logger.warning(f"Domain {domain} has no protocols enabled!")
    
    def register_named_instance(self, name: str, port: int):
        """Register a named instance for routing targets."""
        self.named_instances[name] = port
        logger.info(f"Registered named instance: {name} -> port {port}")
        
        # Store in Redis so proxies can access it
        if self.storage:
            try:
                self.storage.redis_client.set(f"instance:{name}", str(port))
                logger.debug(f"Stored instance {name} in Redis")
            except Exception as e:
                logger.error(f"Failed to store instance in Redis: {e}")
    
    def load_routes_from_storage(self):
        """Load routes from Redis storage."""
        if not self.storage:
            logger.warning("No storage available for loading routes")
            return
        
        try:
            # Initialize default routes if needed
            self.storage.initialize_default_routes()
            
            # Initialize default proxies if needed
            self.storage.initialize_default_proxies()
            
            # Load all routes from storage
            self.routes = self.storage.list_routes()
            
            # Filter only enabled routes
            self.routes = [r for r in self.routes if r.enabled]
            
            logger.info(f"Loaded {len(self.routes)} routes from storage")
            for route in self.routes:
                logger.info(f"  {route.priority}: {route.path_pattern} -> {route.target_type.value}:{route.target_value} - {route.description}")
        except Exception as e:
            logger.error(f"Failed to load routes from storage: {e}")
    
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
            logger.debug(f"Error parsing HTTP request: {e}")
            return None, None
    
    def resolve_route_target(self, route: Route) -> Optional[Union[int, str]]:
        """Resolve a route to a target port or URL."""
        if route.target_type == RouteTargetType.PORT:
            return route.target_value if isinstance(route.target_value, int) else int(route.target_value)
        elif route.target_type == RouteTargetType.INSTANCE:
            return self.named_instances.get(route.target_value)
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
            
            logger.info(f"Forwarding {method} {path} to {full_url}")
            
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
            logger.error(f"Error forwarding HTTP request to {target_url}: {e}")
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
                    hostname = line.split(':', 1)[1].strip()
                    # Remove port if present
                    if ':' in hostname:
                        hostname = hostname.split(':')[0]
                    return hostname
                elif line == '':  # End of headers
                    break
            
            return None
            
        except Exception as e:
            logger.debug(f"Error parsing HTTP hostname: {e}")
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
                    hostname = data[pos:pos+hostname_len].decode('ascii', errors='ignore')
                    return hostname
                else:
                    pos += ext_len
            
            return None
            
        except Exception as e:
            logger.debug(f"Error parsing SNI: {e}")
            return None
    
    async def handle_http_connection(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        """Handle incoming HTTP connection and forward to appropriate instance."""
        client_addr = writer.get_extra_info('peername')
        client_ip = client_addr[0] if client_addr else 'unknown'
        client_port = client_addr[1] if client_addr and len(client_addr) > 1 else 0
        
        # No need to store IP mappings - PROXY protocol handles this
        
        logger.debug(
            "New HTTP connection",
            ip=client_ip
        )
        
        try:
            # Peek at the data to get hostname
            data = await reader.read(4096)
            if not data:
                return
            
            # Extract hostname from HTTP Host header FIRST
            hostname = self.get_hostname_from_http_request(data)
            if not hostname:
                logger.warning(
                    "No hostname found in HTTP request",
                    ip=client_ip,
                    correlation_id=correlation_id                )
                writer.close()
                await writer.wait_closed()
                return
            
            logger.debug(
                "HTTP hostname extracted",
                ip=client_ip,
                hostname=hostname,
                correlation_id=correlation_id            )
            
            # Get proxy configuration to determine route filtering
            proxy_config = None
            if self.storage:
                try:
                    proxy_json = self.storage.redis_client.get(f"proxy:{hostname}")
                    if proxy_json:
                        proxy_data = json.loads(proxy_json)
                        proxy_config = ProxyTarget(**proxy_data)
                except Exception as e:
                    logger.debug(f"Could not load proxy config for {hostname}: {e}")
            
            # Apply route filtering based on proxy configuration
            applicable_routes = self.get_applicable_routes(proxy_config)
            
            # Check generic routes with filtering
            method, request_path = self.get_request_info(data)
            logger.debug(
                "HTTP request details",
                ip=client_ip,
                hostname=hostname,
                method=method,
                path=request_path,
                correlation_id=correlation_id
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
                                instance_name = route.target_value if route.target_type == RouteTargetType.INSTANCE else None
                                logger.info(f"Request {method} {request_path} matched route '{route.description or route.path_pattern}' -> port {target}")
                                await self._forward_connection(
                                    reader, writer, data, '127.0.0.1', target, 
                                    client_ip=client_ip, client_port=client_port, use_proxy_protocol=True,
                                    hostname=hostname, instance_name=instance_name
                                )
                                return
                        else:
                            logger.warning(f"Route matched but target not found: {route.target_type.value}:{route.target_value}")
            
            # Find the appropriate port for hostname-based routing
            target_port = self.hostname_to_http_port.get(hostname)
            if not target_port:
                logger.warning(f"No HTTP instance found for hostname: {hostname}")
                # Send 404 response
                response = b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n"
                writer.write(response)
                await writer.drain()
                writer.close()
                await writer.wait_closed()
                return
            
            
            # Determine if this is a named instance or proxy target
            instance_name = None
            for name, port in self.named_instances.items():
                if port == target_port:
                    instance_name = name
                    break
            
            # Forward to the target instance with PROXY protocol enabled
            await self._forward_connection(
                reader, writer, data, '127.0.0.1', target_port, 
                client_ip=client_ip, client_port=client_port, use_proxy_protocol=True,
                hostname=hostname, instance_name=instance_name
            )
            
        except Exception as e:
            logger.error(f"Error handling HTTP connection: {e}")
        finally:
            writer.close()
            await writer.wait_closed()
    
    async def handle_https_connection(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        """Handle incoming HTTPS connection and forward to appropriate instance."""
        client_addr = writer.get_extra_info('peername')
        client_ip = client_addr[0] if client_addr else 'unknown'
        client_port = client_addr[1] if client_addr and len(client_addr) > 1 else 0
        
        # No need to store IP mappings - PROXY protocol handles this
        
        logger.debug(
            "New HTTPS connection",
            ip=client_ip
        )
        
        try:
            # Peek at the data to get SNI hostname
            data = await reader.read(4096)
            if not data:
                logger.warning(
                    "No data received in HTTPS connection",
                    ip=client_ip,
                    correlation_id=correlation_id
                )
                return
            
            logger.debug(
                "HTTPS data received",
                ip=client_ip,
                data_len=len(data),
                correlation_id=correlation_id
            )
            
            # Extract SNI hostname
            hostname = self.get_sni_hostname(data)
            if not hostname:
                logger.warning(
                    "No SNI hostname found in connection",
                    ip=client_ip,
                    correlation_id=correlation_id                )
                writer.close()
                await writer.wait_closed()
                return
            
            logger.debug(
                "SNI hostname extracted",
                ip=client_ip,
                hostname=hostname,
                correlation_id=correlation_id            )
            
            # Get proxy config if this is a proxy domain
            proxy_config = None
            if self.storage and hostname not in ['localhost', '127.0.0.1']:
                try:
                    proxy_config = self.storage.get_proxy_target(hostname)
                except Exception as e:
                    logger.debug(f"Could not get proxy config for {hostname}: {e}")
            
            # For HTTPS, we cannot parse HTTP request info from TLS handshake data
            # Route matching must be handled by the proxy instances after TLS termination
            # The proxy app will handle route matching at the application level
            
            # Find the appropriate port for hostname-based routing
            target_port = self.hostname_to_https_port.get(hostname)
            if not target_port:
                # Try wildcard match
                parts = hostname.split('.')
                if len(parts) > 2:
                    wildcard = f"*.{'.'.join(parts[1:])}"
                    target_port = self.hostname_to_https_port.get(wildcard)
            
            # Special handling for localhost - route to API instance
            if not target_port and hostname in ['localhost', '127.0.0.1']:
                # Route localhost to the API instance via named instance (HTTPS not available, use HTTP)
                logger.warning(f"HTTPS requested for localhost, but API doesn't have HTTPS configured")
                writer.close()
                await writer.wait_closed()
                return
            
            if not target_port:
                logger.warning(f"No HTTPS instance found for hostname: {hostname}")
                logger.warning(f"Available HTTPS ports: {list(self.hostname_to_https_port.keys())}")
                writer.close()
                await writer.wait_closed()
                return
            
            # Determine if this is a named instance or proxy target
            instance_name = None
            for name, port in self.named_instances.items():
                if port == target_port:
                    instance_name = name
                    break
            
            
            # Forward to the target instance with PROXY protocol enabled for HTTPS
            await self._forward_connection(
                reader, writer, data, '127.0.0.1', target_port, 
                client_ip=client_ip, client_port=client_port, use_proxy_protocol=True,
                hostname=hostname, instance_name=instance_name
            )
            
        except Exception as e:
            logger.error(f"Error handling HTTPS connection: {e}")
        finally:
            writer.close()
            await writer.wait_closed()
    

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
            logger.error(f"Error sending PROXY protocol header: {e}")
            # Continue without PROXY protocol on error

    async def _forward_connection(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter,
                                  initial_data: bytes, target_host: str, target_port: int, 
                                  client_ip: str = None, client_port: int = None, use_proxy_protocol: bool = False,
                                  hostname: str = None, instance_name: str = None):
        """Forward a connection to target host:port with optional PROXY protocol support."""
        try:
            # Connect to the target
            target_reader, target_writer = await asyncio.open_connection(target_host, target_port)
            
            # Send PROXY protocol header to preserve real client IP
            if use_proxy_protocol:
                # Use defaults if not provided
                if not client_ip or client_ip == 'unknown':
                    client_ip = '127.0.0.1'
                if not client_port:
                    client_port = 0
                
                # Enhanced logging with hostname and instance
                instance_info = f" (instance: {instance_name})" if instance_name else ""
                logger.info(
                    f"Forwarding connection - Client: {client_ip}:{client_port} -> "
                    f"Hostname: {hostname or 'unknown'} -> "
                    f"Target: {target_host}:{target_port}{instance_info} "
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
                    logger.debug(f"Forward {direction} error: {e}")
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
            logger.error(f"Error forwarding connection: {e}")
    
    async def start(self):
        """Start both HTTP and HTTPS dispatchers without blocking."""
        # Start HTTP dispatcher on port 80
        http_port_str = os.getenv('HTTP_PORT')
        if not http_port_str:
            raise ValueError("HTTP_PORT not set in environment - required for server configuration")
        http_port = int(http_port_str)
        self.http_server = await asyncio.start_server(
            self.handle_http_connection,
            self.host,
            http_port
        )
        logger.info(f"HTTP Dispatcher listening on {self.host}:{http_port}")
        
        # Start HTTPS dispatcher on port 443
        https_port_str = os.getenv('HTTPS_PORT')
        if not https_port_str:
            raise ValueError("HTTPS_PORT not set in environment - required for server configuration")
        https_port = int(https_port_str)
        self.https_server = await asyncio.start_server(
            self.handle_https_connection,
            self.host,
            https_port
        )
        logger.info(f"HTTPS Dispatcher listening on {self.host}:{https_port}")
        
        # Create tasks for the servers but don't await them
        # This allows the dispatcher to start without blocking
        self.server_tasks = [
            asyncio.create_task(self.http_server.serve_forever()),
            asyncio.create_task(self.https_server.serve_forever())
        ]
        logger.info("Dispatcher servers started in background")
    
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
    
    def __init__(self, https_server_instance, app=None, host='0.0.0.0'):
        self.https_server = https_server_instance
        self.app = app  # Not used anymore - each instance creates its own proxy app
        self.host = host
        self.instances: List[DomainInstance] = []
        # Pass storage to dispatcher for route management
        storage = https_server_instance.manager.storage if https_server_instance else None
        self.dispatcher = UnifiedDispatcher(host, storage)
        self.next_http_port = 10002   # Starting port for HTTP instances (10001 reserved for API)
        self.next_https_port = 11000  # Starting port for HTTPS instances
        
    async def create_instance_for_proxy(self, hostname: str):
        """Dynamically create and start an instance for a proxy target."""
        # Check if instance already exists
        if hostname in self.dispatcher.hostname_to_https_port:
            logger.info(f"Instance already exists for {hostname}")
            return
        
        # Get proxy configuration
        proxy_target = self.https_server.manager.storage.get_proxy_target(hostname)
        if not proxy_target:
            logger.error(f"No proxy target found for {hostname}")
            return
        
        # Get certificate if HTTPS is enabled
        cert = None
        if proxy_target.enable_https:
            cert_name = proxy_target.cert_name
            cert = self.https_server.manager.get_certificate(cert_name)
            if not cert:
                logger.warning(f"Certificate not yet available for {hostname}, creating HTTP-only instance")
        
        # Create instance - this is a proxy-only instance
        instance = DomainInstance(
            app=None,  # Will create its own proxy app
            domains=[hostname],
            http_port=self.next_http_port,
            https_port=self.next_https_port,
            cert=cert,
            proxy_configs={hostname: proxy_target},
            storage=self.https_server.manager.storage
        )
        
        # Start the instance
        await instance.start()
        self.instances.append(instance)
        
        # Register with dispatcher
        self.dispatcher.register_instance(
            [hostname], 
            self.next_http_port, 
            self.next_https_port,
            enable_http=proxy_target.enable_http,
            enable_https=proxy_target.enable_https and cert is not None
        )
        
        self.next_http_port += 1
        self.next_https_port += 1
        
        logger.info(f"Created instance for {hostname} (HTTP:{proxy_target.enable_http}, HTTPS:{proxy_target.enable_https and cert is not None})")
    
    async def remove_instance_for_proxy(self, hostname: str):
        """Remove instance for a proxy target."""
        # Find instance serving this hostname
        instance_to_remove = None
        for instance in self.instances:
            if hostname in instance.domains:
                instance_to_remove = instance
                break
        
        if not instance_to_remove:
            logger.warning(f"No instance found for {hostname}")
            return
        
        # Stop the instance
        await instance_to_remove.stop()
        self.instances.remove(instance_to_remove)
        
        # Unregister from dispatcher
        if hostname in self.dispatcher.hostname_to_http_port:
            del self.dispatcher.hostname_to_http_port[hostname]
        if hostname in self.dispatcher.hostname_to_https_port:
            del self.dispatcher.hostname_to_https_port[hostname]
        
        logger.info(f"Removed instance for {hostname}")
    
    async def update_instance_certificate(self, hostname: str):
        """Update instance when certificate becomes available."""
        # Get proxy configuration
        proxy_target = self.https_server.manager.storage.get_proxy_target(hostname)
        if not proxy_target or not proxy_target.enable_https:
            return
        
        # Get certificate
        cert = self.https_server.manager.get_certificate(proxy_target.cert_name)
        if not cert:
            logger.warning(f"Certificate still not available for {hostname}")
            return
        
        # Find the instance
        instance = None
        for inst in self.instances:
            if hostname in inst.domains:
                instance = inst
                break
        
        if not instance:
            logger.error(f"No instance found for {hostname}")
            return
        
        # Check if HTTPS process is actually running
        if instance.https_process and not instance.https_process.done():
            logger.info(f"HTTPS already running for {hostname}")
            return
        
        # Update instance with certificate
        instance.cert = cert
        
        # Start HTTPS instance
        logger.info(f"Starting HTTPS instance for {hostname} with newly available certificate")
        await instance.start_https()
        
        # Update dispatcher registration to enable HTTPS
        self.dispatcher.register_instance(
            [hostname], 
            instance.http_port, 
            instance.https_port,
            enable_http=proxy_target.enable_http,
            enable_https=True
        )
        
        logger.info(f"HTTPS enabled for {hostname} after certificate became available")
    
    def update_ssl_context(self, certificate):
        """Update SSL context when a new certificate is created or renewed."""
        if not certificate or not certificate.domains:
            logger.warning("Invalid certificate passed to update_ssl_context")
            return
            
        logger.info(f"Updating SSL context for certificate {certificate.cert_name} domains: {certificate.domains}")
        
        # For each domain in the certificate, update the instance if it exists
        for domain in certificate.domains:
            # Find the instance handling this domain
            for instance in self.instances:
                if domain in instance.domains:
                    # Update the certificate for this instance
                    instance.cert = certificate
                    
                    # If HTTPS is already running, we need to restart it
                    if instance.https_process and not instance.https_process.done():
                        logger.info(f"Restarting HTTPS for {domain} to use new certificate")
                        # Cancel the current HTTPS process
                        instance.https_process.cancel()
                        # Clean up old temp files
                        if instance.cert_file and os.path.exists(instance.cert_file):
                            os.unlink(instance.cert_file)
                        if instance.key_file and os.path.exists(instance.key_file):
                            os.unlink(instance.key_file)
                        # Start HTTPS with new certificate
                        asyncio.create_task(instance.start_https())
                    else:
                        # HTTPS not running yet, just update the cert
                        logger.info(f"Certificate updated for {domain}, HTTPS will use it when started")
                    
                    break  # Found the instance, move to next domain
    
    async def run(self):
        """Run the unified multi-instance server architecture."""
        logger.info("UnifiedMultiInstanceServer.run() started")
        
        # Set global instance for dynamic management
        global unified_server_instance
        unified_server_instance = self
        
        if not self.https_server:
            logger.warning("No HTTPS server instance available")
            return
        
        logger.info("HTTPS server available, listing proxy targets")
        
        # Get proxy configurations first
        proxy_targets = self.https_server.manager.storage.list_proxy_targets()
        domain_to_proxy = {pt.hostname: pt for pt in proxy_targets if pt.enabled}
        
        logger.info(f"Found {len(proxy_targets)} proxy targets, {len(domain_to_proxy)} enabled")
        logger.info(f"Enabled proxy targets: {list(domain_to_proxy.keys())}")
        
        # Group domains by the certificate they're configured to use (from proxy config)
        cert_to_domains: Dict[str, List[str]] = {}
        domain_to_cert = {}
        
        # Load all available certificates for lookup
        all_certs = {cert.cert_name: cert for cert in self.https_server.manager.storage.list_certificates()
                     if cert and cert.fullchain_pem and cert.private_key_pem}
        
        # Group domains based on proxy configuration
        for hostname, proxy_target in domain_to_proxy.items():
            # Skip localhost - it's handled by the API directly
            if hostname in ['localhost', '127.0.0.1']:
                logger.info(f"Skipping instance creation for {hostname} - handled by API")
                continue
                
            cert_name = proxy_target.cert_name
            
            if cert_name and cert_name in all_certs:
                # Domain has a certificate assigned
                cert = all_certs[cert_name]
                domain_to_cert[hostname] = cert
                
                if cert_name not in cert_to_domains:
                    cert_to_domains[cert_name] = []
                cert_to_domains[cert_name].append(hostname)
            else:
                # Domain has no certificate or certificate doesn't exist
                if 'no-cert' not in cert_to_domains:
                    cert_to_domains['no-cert'] = []
                cert_to_domains['no-cert'].append(hostname)
        
        # Load routes from Redis storage
        self.dispatcher.load_routes_from_storage()
        
        # Register the API service as a named instance
        # The API runs on port 10001 with PROXY protocol
        self.dispatcher.register_named_instance('api', 10001)
        
        # Register localhost to route to the API instance
        self.dispatcher.register_instance(['localhost', '127.0.0.1'], 10001, 10001, enable_http=True, enable_https=False)
        
        if not cert_to_domains and not domain_to_proxy:
            logger.info("No additional certificates or proxy configurations available")
        
        # Create instances for each group of domains
        for cert_name, domains in cert_to_domains.items():
            # Get certificate if available
            cert = None
            if cert_name != 'no-cert':
                cert = all_certs.get(cert_name)
            
            # Get proxy configs for these domains
            proxy_configs = {d: domain_to_proxy[d] for d in domains if d in domain_to_proxy}
            
            # Create instance - these are proxy domains
            instance = DomainInstance(
                app=None,  # Will create its own proxy app
                domains=domains,
                http_port=self.next_http_port,
                https_port=self.next_https_port,
                cert=cert,
                proxy_configs=proxy_configs,
                storage=self.https_server.manager.storage
            )
            
            self.instances.append(instance)
            
            logger.info(f"Starting instance for domains: {domains}, cert: {cert_name}")
            
            # Start the instance
            await instance.start()
            
            # Determine which protocols are enabled for registration
            http_enabled = False
            https_enabled = False
            for domain in domains:
                if domain in proxy_configs:
                    config = proxy_configs[domain]
                    if config.enable_http:
                        http_enabled = True
                    if config.enable_https:
                        https_enabled = True
            
            # Default to both enabled if no proxy config exists
            if not proxy_configs:
                http_enabled = True
                https_enabled = True
            
            # Register with dispatcher for enabled protocols
            self.dispatcher.register_instance(
                domains, 
                self.next_http_port, 
                self.next_https_port,
                enable_http=http_enabled,
                enable_https=https_enabled
            )
            
            self.next_http_port += 1
            self.next_https_port += 1
        
        logger.info(f"Started {len(self.instances)} domain instances")
        for instance in self.instances:
            logger.info(f"Instance domains: {instance.domains}, HTTP port: {instance.http_port}, HTTPS port: {instance.https_port}")
        
        # Start the dispatcher (non-blocking now!)
        await self.dispatcher.start()
        
        # The dispatcher is now running in background
        # unified_server_instance is available for dynamic management
        logger.info("UnifiedMultiInstanceServer fully initialized and ready for dynamic instance management")
        
        # Wait forever (this is where we block)
        try:
            await self.dispatcher.wait_forever()
        finally:
            # Clean up instances
            for instance in self.instances:
                await instance.stop()