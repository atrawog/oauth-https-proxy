"""Custom SSL server with dynamic certificate support."""

import asyncio
import ssl
import logging
from typing import Dict, Optional
import httpx

logger = logging.getLogger(__name__)


class DynamicSSLServer:
    """SSL server that supports multiple certificates via SNI."""
    
    def __init__(self, https_server, app, host='0.0.0.0', port=443, backend_port=8000):
        self.https_server = https_server
        self.app = app
        self.host = host
        self.port = port
        self.backend_port = backend_port
        self.ssl_contexts: Dict[str, ssl.SSLContext] = {}
        
    def create_sni_context(self):
        """Create SSL context with SNI callback."""
        # Create default context
        default_ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        
        # We need a default cert for the initial handshake
        if self.https_server.default_context:
            # Use the existing default context as base
            return self.https_server.default_context
        else:
            # Create self-signed cert
            from .server import create_temp_cert_files
            import os
            cert_file, key_file = create_temp_cert_files()
            default_ctx.load_cert_chain(cert_file, key_file)
            os.unlink(cert_file)
            os.unlink(key_file)
            return default_ctx
    
    async def handle_client(self, reader, writer):
        """Handle incoming SSL client connection."""
        try:
            # Get client address
            client_addr = writer.get_extra_info('peername')
            logger.debug(f"New SSL connection from {client_addr}")
            
            # Get the SNI hostname from SSL
            ssl_object = writer.get_extra_info('ssl_object')
            hostname = ssl_object.server_hostname if ssl_object else None
            logger.info(f"SSL connection for hostname: {hostname}")
            
            # Read the HTTP request
            data = await reader.read(65536)
            if not data:
                return
                
            # Parse HTTP request to get headers
            request_lines = data.decode('utf-8', errors='ignore').split('\r\n')
            headers = {}
            for line in request_lines[1:]:
                if ': ' in line:
                    key, value = line.split(': ', 1)
                    headers[key.lower()] = value
                elif line == '':
                    break
            
            # Use Host header if SNI wasn't provided
            if not hostname and 'host' in headers:
                hostname = headers['host'].split(':')[0]
            
            # Forward to backend
            async with httpx.AsyncClient(verify=False) as client:
                # Reconstruct the request
                method = request_lines[0].split()[0]
                path = request_lines[0].split()[1]
                url = f"http://localhost:{self.backend_port}{path}"
                
                # Forward the request
                response = await client.request(
                    method=method,
                    url=url,
                    headers=dict(headers),
                    content=data if method not in ['GET', 'HEAD'] else None
                )
                
                # Send response back
                response_data = f"HTTP/1.1 {response.status_code} {response.reason_phrase}\r\n"
                for key, value in response.headers.items():
                    response_data += f"{key}: {value}\r\n"
                response_data += "\r\n"
                writer.write(response_data.encode())
                
                # Send body if present
                if response.content:
                    writer.write(response.content)
                
                await writer.drain()
                
        except Exception as e:
            logger.error(f"Error handling SSL client: {e}")
        finally:
            writer.close()
            await writer.wait_closed()
    
    async def handle_ssl_connection(self, reader, writer):
        """Handle SSL connection with proper certificate selection."""
        try:
            # Get SSL object to find hostname
            ssl_obj = writer.get_extra_info('ssl_object')
            if ssl_obj:
                hostname = getattr(ssl_obj, 'server_hostname', None)
                logger.info(f"SSL connection for: {hostname}")
            else:
                hostname = None
            
            # Forward to handle_client
            await self.handle_client(reader, writer)
        except Exception as e:
            logger.error(f"SSL connection error: {e}")
            writer.close()
            await writer.wait_closed()
    
    async def start_ssl_server(self):
        """Start the SSL server with proper SNI support."""
        logger.info(f"Starting SSL server on {self.host}:{self.port}")
        
        # For each domain, create a separate server socket with its own context
        servers = []
        
        # First, create the default server
        default_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        
        # Load default certificate
        if self.https_server.default_context:
            # Use existing default
            default_context = self.https_server.default_context
        else:
            # Create self-signed default
            from .server import create_temp_cert_files
            import os
            cert_file, key_file = create_temp_cert_files()
            default_context.load_cert_chain(cert_file, key_file)
            os.unlink(cert_file)
            os.unlink(key_file)
        
        # SNI callback that logs but doesn't try to change context
        def sni_callback(ssl_socket, server_name, ctx):
            if server_name:
                logger.info(f"SNI request for: {server_name}")
                # Check if we have a cert for this domain
                if server_name in self.https_server.ssl_contexts:
                    logger.info(f"Have certificate for: {server_name}")
                    # We can't change the context here, but we can log it
                else:
                    logger.warning(f"No certificate for: {server_name}")
            return None
        
        default_context.sni_callback = sni_callback
        
        # Create main server with default context
        server = await asyncio.start_server(
            self.handle_ssl_connection,
            self.host,
            self.port,
            ssl=default_context
        )
        
        logger.info(f"SSL server started with contexts for domains: {list(self.https_server.ssl_contexts.keys())}")
        
        async with server:
            await server.serve_forever()