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
from typing import Dict, Optional, List, Tuple, Set
from datetime import datetime

from hypercorn.asyncio import serve
from hypercorn.config import Config as HypercornConfig

from .routes import Route, RouteTargetType
from .proxy_app import create_proxy_app

logger = logging.getLogger(__name__)

# Global instance for dynamic management
unified_server_instance = None


class DomainInstance:
    """Represents a Hypercorn instance serving a specific set of domains."""
    
    def __init__(self, app, domains: List[str], http_port: int, https_port: int, 
                 cert=None, proxy_configs: Dict = None, is_api_instance: bool = False,
                 storage=None):
        self.app = app
        self.domains = domains
        self.http_port = http_port
        self.https_port = https_port
        self.cert = cert
        self.proxy_configs = proxy_configs or {}
        self.is_api_instance = is_api_instance
        self.storage = storage
        self.http_process = None
        self.https_process = None
        self.cert_file = None
        self.key_file = None
        
        # For proxy-only instances, create a dedicated app
        if not is_api_instance and storage:
            self.app = create_proxy_app(storage)
        
    async def start(self):
        """Start HTTP and/or HTTPS instances based on proxy configuration."""
        # Check which protocols are enabled for these domains
        http_enabled = False
        https_enabled = False
        
        # Special case for localhost - always enable HTTP for API access
        if 'localhost' in self.domains or '127.0.0.1' in self.domains:
            http_enabled = True
            # No HTTPS for localhost API
        else:
            # For other domains, check proxy configs
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
        """Start HTTP instance."""
        try:
            # Configure Hypercorn for HTTP
            config = HypercornConfig()
            config.bind = [f"127.0.0.1:{self.http_port}"]
            config.loglevel = os.getenv('LOG_LEVEL', 'INFO').upper()
            
            logger.info(f"Starting HTTP instance on port {self.http_port} for domains: {self.domains}")
            
            # Start the server in a background task
            self.http_process = asyncio.create_task(serve(self.app, config))
            
        except Exception as e:
            logger.error(f"Failed to start HTTP instance: {e}")
            raise
    
    async def start_https(self):
        """Start HTTPS instance with certificate."""
        try:
            # Write certificate to temp files
            with tempfile.NamedTemporaryFile(mode='w', suffix='.pem', delete=False) as cf:
                cf.write(self.cert.fullchain_pem)
                self.cert_file = cf.name
            
            with tempfile.NamedTemporaryFile(mode='w', suffix='.key', delete=False) as kf:
                kf.write(self.cert.private_key_pem)
                self.key_file = kf.name
            
            # Configure Hypercorn for HTTPS
            config = HypercornConfig()
            config.bind = [f"127.0.0.1:{self.https_port}"]
            config.certfile = self.cert_file
            config.keyfile = self.key_file
            config.loglevel = os.getenv('LOG_LEVEL', 'INFO').upper()
            
            logger.info(f"Starting HTTPS instance on port {self.https_port} for domains: {self.domains}")
            
            # Start the server in a background task
            self.https_process = asyncio.create_task(serve(self.app, config))
            
        except Exception as e:
            logger.error(f"Failed to start HTTPS instance: {e}")
            self.cleanup()
            raise
    
    async def stop(self):
        """Stop both HTTP and HTTPS instances."""
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
        
        # Log appropriately based on instance type
        if self.is_api_instance:
            logger.info(f"Stopped API instance for domains: {self.domains}")
        else:
            logger.info(f"Stopped proxy instance for domains: {self.domains}")
    
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
        self.hostname_to_http_port: Dict[str, int] = {}
        self.hostname_to_https_port: Dict[str, int] = {}
        self.http_server = None
        self.https_server = None
        # Generic routing rules sorted by priority (highest first)
        self.routes: List[Route] = []
        # Named instances for routing targets
        self.named_instances: Dict[str, int] = {}  # name -> port
        
    def register_instance(self, domains: List[str], http_port: int, https_port: int, 
                          enable_http: bool = True, enable_https: bool = True):
        """Register a domain instance for specific domains and protocols."""
        for domain in domains:
            if enable_http:
                self.hostname_to_http_port[domain] = http_port
                logger.info(f"Registered {domain} -> HTTP:{http_port}")
            if enable_https:
                self.hostname_to_https_port[domain] = https_port
                logger.info(f"Registered {domain} -> HTTPS:{https_port}")
            if not enable_http and not enable_https:
                logger.warning(f"Domain {domain} has no protocols enabled!")
    
    def register_named_instance(self, name: str, port: int):
        """Register a named instance for routing targets."""
        self.named_instances[name] = port
        logger.info(f"Registered named instance: {name} -> port {port}")
    
    def load_routes_from_storage(self):
        """Load routes from Redis storage."""
        if not self.storage:
            logger.warning("No storage available for loading routes")
            return
        
        try:
            # Initialize default routes if needed
            self.storage.initialize_default_routes()
            
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
    
    def resolve_route_target(self, route: Route) -> Optional[int]:
        """Resolve a route to a target port."""
        if route.target_type == RouteTargetType.PORT:
            return route.target_value if isinstance(route.target_value, int) else int(route.target_value)
        elif route.target_type == RouteTargetType.INSTANCE:
            return self.named_instances.get(route.target_value)
        elif route.target_type == RouteTargetType.HOSTNAME:
            return self.hostname_to_http_port.get(route.target_value)
        return None
    
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
        logger.debug(f"New HTTP connection from {client_addr}")
        
        try:
            # Peek at the data to get hostname
            data = await reader.read(4096)
            if not data:
                return
            
            # First check generic routes
            method, request_path = self.get_request_info(data)
            if request_path:
                for route in self.routes:
                    if route.matches(request_path, method):
                        target_port = self.resolve_route_target(route)
                        if target_port:
                            logger.info(f"Request {method} {request_path} matched route '{route.description or route.path_pattern}' -> port {target_port}")
                            await self._forward_connection(reader, writer, data, '127.0.0.1', target_port)
                            return
                        else:
                            logger.warning(f"Route matched but target not found: {route.target_type.value}:{route.target_value}")
            
            # Extract hostname from HTTP Host header
            hostname = self.get_hostname_from_http_request(data)
            if not hostname:
                logger.warning(f"No hostname found in HTTP request from {client_addr}")
                writer.close()
                await writer.wait_closed()
                return
            
            logger.debug(f"HTTP hostname: {hostname}")
            
            # Find the appropriate port
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
            
            logger.debug(f"Forwarding HTTP {hostname} to localhost:{target_port}")
            
            # Forward to the target instance
            await self._forward_connection(reader, writer, data, '127.0.0.1', target_port)
            
        except Exception as e:
            logger.error(f"Error handling HTTP connection: {e}")
        finally:
            writer.close()
            await writer.wait_closed()
    
    async def handle_https_connection(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        """Handle incoming HTTPS connection and forward to appropriate instance."""
        client_addr = writer.get_extra_info('peername')
        logger.debug(f"New HTTPS connection from {client_addr}")
        
        try:
            # Peek at the data to get SNI hostname
            data = await reader.read(4096)
            if not data:
                return
            
            # Extract SNI hostname
            hostname = self.get_sni_hostname(data)
            if not hostname:
                logger.warning(f"No SNI hostname found in connection from {client_addr}")
                writer.close()
                await writer.wait_closed()
                return
            
            logger.debug(f"SNI hostname: {hostname}")
            
            # Find the appropriate port
            target_port = self.hostname_to_https_port.get(hostname)
            if not target_port:
                # Try wildcard match
                parts = hostname.split('.')
                if len(parts) > 2:
                    wildcard = f"*.{'.'.join(parts[1:])}"
                    target_port = self.hostname_to_https_port.get(wildcard)
            
            if not target_port:
                logger.warning(f"No HTTPS instance found for hostname: {hostname}")
                writer.close()
                await writer.wait_closed()
                return
            
            logger.debug(f"Forwarding HTTPS {hostname} to localhost:{target_port}")
            
            # Forward to the target instance
            await self._forward_connection(reader, writer, data, '127.0.0.1', target_port)
            
        except Exception as e:
            logger.error(f"Error handling HTTPS connection: {e}")
        finally:
            writer.close()
            await writer.wait_closed()
    
    async def _forward_connection(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter,
                                  initial_data: bytes, target_host: str, target_port: int):
        """Forward a connection to target host:port."""
        try:
            # Connect to the target
            target_reader, target_writer = await asyncio.open_connection(target_host, target_port)
            
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
        http_port = int(os.getenv('HTTP_PORT', '80'))
        self.http_server = await asyncio.start_server(
            self.handle_http_connection,
            self.host,
            http_port
        )
        logger.info(f"HTTP Dispatcher listening on {self.host}:{http_port}")
        
        # Start HTTPS dispatcher on port 443
        https_port = int(os.getenv('HTTPS_PORT', '443'))
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
    
    def __init__(self, https_server_instance, app, host='0.0.0.0'):
        self.https_server = https_server_instance
        self.app = app
        self.host = host
        self.instances: List[DomainInstance] = []
        # Pass storage to dispatcher for route management
        storage = https_server_instance.manager.storage if https_server_instance else None
        self.dispatcher = UnifiedDispatcher(host, storage)
        self.next_http_port = 9000   # Starting port for HTTP instances
        self.next_https_port = 10000 # Starting port for HTTPS instances
        
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
            app=self.app,
            domains=[hostname],
            http_port=self.next_http_port,
            https_port=self.next_https_port,
            cert=cert,
            proxy_configs={hostname: proxy_target},
            is_api_instance=False,
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
    
    async def run(self):
        """Run the unified multi-instance server architecture."""
        # Set global instance for dynamic management
        global unified_server_instance
        unified_server_instance = self
        
        if not self.https_server:
            logger.warning("No HTTPS server instance available")
            return
        
        # Group domains by certificate
        cert_to_domains: Dict[str, List[str]] = {}
        domain_to_cert = {}
        
        # Also get proxy configurations
        proxy_targets = self.https_server.manager.storage.list_proxy_targets()
        domain_to_proxy = {pt.hostname: pt for pt in proxy_targets if pt.enabled}
        
        # Collect all domains and their certificates
        for cert in self.https_server.manager.storage.list_certificates():
            if cert and cert.fullchain_pem and cert.private_key_pem:
                for domain in cert.domains:
                    domain_to_cert[domain] = cert
                    if cert.cert_name not in cert_to_domains:
                        cert_to_domains[cert.cert_name] = []
                    cert_to_domains[cert.cert_name].append(domain)
        
        # Also include domains that have proxy configs but no certificates yet
        for hostname, proxy_target in domain_to_proxy.items():
            if hostname not in domain_to_cert:
                # Domain has proxy config but no certificate
                if 'no-cert' not in cert_to_domains:
                    cert_to_domains['no-cert'] = []
                cert_to_domains['no-cert'].append(hostname)
        
        # ALWAYS create a localhost instance for API access
        localhost_domains = ['localhost', '127.0.0.1']
        localhost_instance = DomainInstance(
            app=self.app,
            domains=localhost_domains,
            http_port=self.next_http_port,
            https_port=self.next_https_port,
            cert=None,  # Will use self-signed
            proxy_configs={},  # No proxy config for localhost
            is_api_instance=True,  # This is the API server!
            storage=self.https_server.manager.storage
        )
        
        self.instances.append(localhost_instance)
        await localhost_instance.start()
        
        # Register localhost with dispatcher - HTTP only for API access
        self.dispatcher.register_instance(
            localhost_domains, 
            self.next_http_port, 
            self.next_https_port,
            enable_http=True,    # Enable HTTP for API access
            enable_https=False   # No HTTPS needed for localhost API
        )
        
        # Register localhost as a named instance for routing
        self.dispatcher.register_named_instance('localhost', self.next_http_port)
        self.dispatcher.register_named_instance('api', self.next_http_port)  # Alias for API access
        
        # Load routes from Redis storage
        self.dispatcher.load_routes_from_storage()
        
        self.next_http_port += 1
        self.next_https_port += 1
        
        logger.info("Created localhost instance for API access")
        
        if not cert_to_domains and not domain_to_proxy:
            logger.info("No additional certificates or proxy configurations available")
        
        # Create instances for each group of domains
        for cert_name, domains in cert_to_domains.items():
            # Get certificate if available
            cert = None
            if cert_name != 'no-cert' and domains:
                cert = domain_to_cert.get(domains[0])
            
            # Get proxy configs for these domains
            proxy_configs = {d: domain_to_proxy[d] for d in domains if d in domain_to_proxy}
            
            # Create instance - these are proxy domains
            instance = DomainInstance(
                app=self.app,
                domains=domains,
                http_port=self.next_http_port,
                https_port=self.next_https_port,
                cert=cert,
                proxy_configs=proxy_configs,
                is_api_instance=False,  # These are proxy instances
                storage=self.https_server.manager.storage
            )
            
            self.instances.append(instance)
            
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