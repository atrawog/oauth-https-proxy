"""Multi-instance Hypercorn server architecture.

This implementation creates a dedicated Hypercorn instance for each proxy
configuration, ensuring each host is served by its own dedicated SSL context.
"""

import asyncio
import ssl
import logging
import os
import tempfile
from typing import Dict, Optional, List, Tuple
from datetime import datetime
import socket
import struct

from hypercorn.asyncio import serve
from hypercorn.config import Config as HypercornConfig

logger = logging.getLogger(__name__)


class HypercornInstance:
    """Represents a single Hypercorn instance with its own certificate."""
    
    def __init__(self, app, cert, port: int):
        self.app = app
        self.cert = cert
        self.port = port
        self.domains = cert.domains
        self.process = None
        self.cert_file = None
        self.key_file = None
        
    async def start(self):
        """Start this Hypercorn instance."""
        try:
            # Write certificate to temp files
            with tempfile.NamedTemporaryFile(mode='w', suffix='.pem', delete=False) as cf:
                cf.write(self.cert.fullchain_pem)
                self.cert_file = cf.name
            
            with tempfile.NamedTemporaryFile(mode='w', suffix='.key', delete=False) as kf:
                kf.write(self.cert.private_key_pem)
                self.key_file = kf.name
            
            # Configure Hypercorn for this instance
            config = HypercornConfig()
            config.bind = [f"127.0.0.1:{self.port}"]  # Bind to localhost only
            config.certfile = self.cert_file
            config.keyfile = self.key_file
            config.loglevel = os.getenv('LOG_LEVEL', 'INFO').upper()
            
            logger.info(f"Starting Hypercorn instance on port {self.port} for domains: {self.domains}")
            
            # Start the server in a background task
            self.process = asyncio.create_task(serve(self.app, config))
            
        except Exception as e:
            logger.error(f"Failed to start Hypercorn instance: {e}")
            self.cleanup()
            raise
    
    async def stop(self):
        """Stop this Hypercorn instance."""
        if self.process:
            self.process.cancel()
            try:
                await self.process
            except asyncio.CancelledError:
                pass
        self.cleanup()
    
    def cleanup(self):
        """Clean up temporary files."""
        try:
            if self.cert_file and os.path.exists(self.cert_file):
                os.unlink(self.cert_file)
            if self.key_file and os.path.exists(self.key_file):
                os.unlink(self.key_file)
        except Exception as e:
            logger.error(f"Error cleaning up temp files: {e}")


class SNIDispatcher:
    """Dispatcher that forwards connections based on SNI hostname."""
    
    def __init__(self, host='0.0.0.0', port=443):
        self.host = host
        self.port = port
        self.hostname_to_port: Dict[str, int] = {}
        self.server = None
        
    def register_instance(self, domains: List[str], port: int):
        """Register a Hypercorn instance for specific domains."""
        for domain in domains:
            self.hostname_to_port[domain] = port
            logger.info(f"Registered {domain} -> localhost:{port}")
    
    def get_sni_hostname(self, data: bytes) -> Optional[str]:
        """Extract SNI hostname from TLS Client Hello.
        
        This parses the raw TLS handshake to extract the SNI hostname
        before establishing the SSL connection.
        """
        try:
            # Check if this is a TLS handshake
            if len(data) < 5 or data[0] != 0x16:  # Not a handshake
                return None
            
            # Skip TLS record header (5 bytes)
            pos = 5
            
            # Check handshake type (Client Hello = 0x01)
            if pos >= len(data) or data[pos] != 0x01:
                return None
            
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
                    # Skip SNI list length (2 bytes)
                    pos += 2
                    # Skip SNI type (1 byte)
                    pos += 1
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
    
    async def handle_connection(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        """Handle incoming connection and forward to appropriate instance."""
        client_addr = writer.get_extra_info('peername')
        logger.debug(f"New connection from {client_addr}")
        
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
            
            logger.info(f"SNI hostname: {hostname}")
            
            # Find the appropriate port
            target_port = self.hostname_to_port.get(hostname)
            if not target_port:
                # Try wildcard match
                parts = hostname.split('.')
                if len(parts) > 2:
                    wildcard = f"*.{'.'.join(parts[1:])}"
                    target_port = self.hostname_to_port.get(wildcard)
            
            if not target_port:
                logger.warning(f"No instance found for hostname: {hostname}")
                writer.close()
                await writer.wait_closed()
                return
            
            logger.info(f"Forwarding {hostname} to localhost:{target_port}")
            
            # Connect to the target Hypercorn instance
            try:
                target_reader, target_writer = await asyncio.open_connection('127.0.0.1', target_port)
            except Exception as e:
                logger.error(f"Failed to connect to instance on port {target_port}: {e}")
                writer.close()
                await writer.wait_closed()
                return
            
            # Send the initial data we read
            target_writer.write(data)
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
            logger.error(f"Error handling connection: {e}")
        finally:
            writer.close()
            await writer.wait_closed()
    
    async def start(self):
        """Start the SNI dispatcher."""
        self.server = await asyncio.start_server(
            self.handle_connection,
            self.host,
            self.port
        )
        
        logger.info(f"SNI Dispatcher listening on {self.host}:{self.port}")
        
        async with self.server:
            await self.server.serve_forever()
    
    async def stop(self):
        """Stop the dispatcher."""
        if self.server:
            self.server.close()
            await self.server.wait_closed()


class MultiInstanceServer:
    """Main server that manages multiple Hypercorn instances."""
    
    def __init__(self, https_server_instance, app, host='0.0.0.0', https_port=443):
        self.https_server = https_server_instance
        self.app = app
        self.host = host
        self.https_port = https_port
        self.instances: List[HypercornInstance] = []
        self.dispatcher = SNIDispatcher(host, https_port)
        self.next_port = 9000  # Starting port for instances
        
    async def run(self):
        """Run the multi-instance server architecture."""
        if not self.https_server:
            logger.warning("No HTTPS server instance available")
            return
        
        # Create instances for each certificate
        certificates = self.https_server.manager.storage.list_certificates()
        
        if not certificates:
            logger.warning("No certificates available")
            # Create a self-signed certificate instance
            from .server import create_temp_cert_files
            # This would need to be adapted to create a proper cert object
            return
        
        # Start an instance for each certificate
        for cert in certificates:
            if cert and cert.fullchain_pem and cert.private_key_pem:
                instance = HypercornInstance(self.app, cert, self.next_port)
                self.instances.append(instance)
                
                # Start the instance
                await instance.start()
                
                # Register with dispatcher
                self.dispatcher.register_instance(cert.domains, self.next_port)
                
                self.next_port += 1
        
        logger.info(f"Started {len(self.instances)} Hypercorn instances")
        
        # Start the dispatcher
        try:
            await self.dispatcher.start()
        finally:
            # Clean up instances
            for instance in self.instances:
                await instance.stop()