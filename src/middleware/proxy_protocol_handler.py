"""
Simple PROXY protocol handler that forwards to Hypercorn.

This creates a TCP server that:
1. Accepts connections with PROXY protocol headers
2. Parses and strips the PROXY protocol header
3. Forwards the clean connection to Hypercorn
4. Stores client info in Redis for unified HTTP/HTTPS handling
"""
import asyncio
import logging
import json
import ipaddress
from typing import Optional, Tuple
import redis.asyncio as redis
from ..shared.dns_resolver import get_dns_resolver

logger = logging.getLogger(__name__)

# PROXY protocol v1 constants
PROXY_V1_MAX_LENGTH = 107  # Maximum header length per spec


class ProxyProtocolHandler:
    """Handles PROXY protocol and forwards to backend."""
    
    def __init__(self, backend_host: str, backend_port: int, redis_client: Optional[redis.Redis] = None):
        self.backend_host = backend_host
        self.backend_port = backend_port
        self.redis_client = redis_client
        self.dns_resolver = get_dns_resolver()
        
    async def handle_connection(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        """Handle incoming connection with PROXY protocol."""
        client_addr = writer.get_extra_info('peername')
        
        try:
            # Read up to max header size for PROXY v1 (spec limit)
            header_data = await asyncio.wait_for(reader.read(PROXY_V1_MAX_LENGTH), timeout=5.0)
            
            # Default to connection info
            real_client_ip = client_addr[0] if client_addr else '127.0.0.1'
            real_client_port = client_addr[1] if client_addr else 0
            
            # Initialize first_data
            first_data = None
            
            # Look for CRLF in the data we read
            crlf_pos = header_data.find(b'\r\n')
            if crlf_pos != -1:
                # Found CRLF, extract the line
                first_line = header_data[:crlf_pos]
                remaining_data = header_data[crlf_pos + 2:]
            else:
                # No CRLF found in first 107 bytes, not a valid PROXY header
                first_line = b''
                remaining_data = header_data
            
            # Check if it's a PROXY protocol header
            if first_line.startswith(b'PROXY '):
                # Parse PROXY protocol v1
                try:
                    # Decode as ASCII (spec requirement)
                    line_str = first_line.decode('ascii').strip()
                    parts = line_str.split()
                    
                    # Validate field count first
                    if len(parts) != 6:
                        raise ValueError(f"Invalid field count: expected 6, got {len(parts)}")
                    
                    # Validate protocol
                    if parts[1] not in ('TCP4', 'TCP6'):
                        raise ValueError(f"Invalid protocol: {parts[1]}")
                    
                    # Now we know we have exactly 6 fields and valid protocol
                    # Validate IP addresses based on protocol
                    if parts[1] == 'TCP4':
                        # Validate IPv4 addresses
                        ipaddress.IPv4Address(parts[2])  # Source IP
                        ipaddress.IPv4Address(parts[3])  # Dest IP
                    else:  # TCP6
                        # Validate IPv6 addresses
                        ipaddress.IPv6Address(parts[2])  # Source IP
                        ipaddress.IPv6Address(parts[3])  # Dest IP
                    
                    # Validate ports
                    src_port = int(parts[4])
                    dst_port = int(parts[5])
                    
                    # Check port range (0-65535)
                    if not (0 <= src_port <= 65535):
                        raise ValueError(f"Source port out of range: {src_port}")
                    if not (0 <= dst_port <= 65535):
                        raise ValueError(f"Destination port out of range: {dst_port}")
                    
                    # Check for leading zeros (except "0" itself)
                    if parts[4] != '0' and parts[4].startswith('0'):
                        raise ValueError(f"Source port has leading zeros: {parts[4]}")
                    if parts[5] != '0' and parts[5].startswith('0'):
                        raise ValueError(f"Destination port has leading zeros: {parts[5]}")
                    
                    real_client_ip = parts[2]
                    real_client_port = src_port
                    
                    # Resolve client hostname
                    client_hostname = await self.dns_resolver.resolve_ptr(real_client_ip)
                    
                    logger.info(f"PROXY protocol: {real_client_ip}:{real_client_port} ({client_hostname})")
                    
                    # Use remaining data after PROXY header
                    first_data = remaining_data
                    # If no remaining data, read some
                    if not first_data:
                        first_data = await asyncio.wait_for(reader.read(1024), timeout=5.0)
                except UnicodeDecodeError as e:
                    logger.error(f"Invalid PROXY protocol header - non-ASCII characters: {e}")
                    writer.close()
                    await writer.wait_closed()
                    return
                except (ValueError, ipaddress.AddressValueError) as e:
                    logger.error(f"Invalid PROXY protocol header: {e}")
                    writer.close()
                    await writer.wait_closed()
                    return
                except Exception as e:
                    logger.error(f"Unexpected error parsing PROXY protocol: {e}")
                    writer.close()
                    await writer.wait_closed()
                    return
            else:
                # Not PROXY protocol, use all the data we read
                first_data = header_data
            
            # Connect to backend
            backend_reader, backend_writer = await asyncio.open_connection(
                self.backend_host, self.backend_port
            )
            
            # Get the local port of our connection to backend (unique identifier)
            backend_local_addr = backend_writer.get_extra_info('sockname')
            if backend_local_addr:
                backend_local_port = backend_local_addr[1]
                # Store client info in Redis with 60 second TTL
                # Key format: client_info:backend_port:local_port
                await self._store_client_info(self.backend_port, backend_local_port, real_client_ip, real_client_port)
            
            # Process first_data
            if first_data:
                # Check if it looks like TLS/SSL handshake (starts with 0x16 for TLS handshake)
                if first_data[0] == 0x16:
                    # This is TLS/SSL, just forward it
                    backend_writer.write(first_data)
                    await backend_writer.drain()
                else:
                    # Might be HTTP, check if it has a complete line
                    if b'\r\n' in first_data:
                        # Extract first line
                        line_end = first_data.index(b'\r\n')
                        first_line = first_data[:line_end + 2]
                        remaining_data = first_data[line_end + 2:]
                        
                        # Check if it's an HTTP request
                        inject_headers = False
                        http_methods = [b'GET ', b'POST ', b'PUT ', b'DELETE ', b'HEAD ', b'OPTIONS ', b'PATCH ', b'CONNECT ']
                        for method in http_methods:
                            if first_line.startswith(method):
                                inject_headers = True
                                break
                        
                        if inject_headers:
                            # It's an HTTP request, collect headers and inject X-Forwarded-For
                            headers = [first_line]
                            
                            # Process remaining data for more headers
                            data_to_process = remaining_data
                            while True:
                                if b'\r\n' in data_to_process:
                                    line_end = data_to_process.index(b'\r\n')
                                    line = data_to_process[:line_end + 2]
                                    data_to_process = data_to_process[line_end + 2:]
                                    
                                    if line == b'\r\n':
                                        # End of headers
                                        headers.append(f'X-Real-IP: {real_client_ip}\r\n'.encode())
                                        headers.append(f'X-Forwarded-For: {real_client_ip}\r\n'.encode())
                                        headers.append(line)
                                        # Send headers
                                        for header in headers:
                                            backend_writer.write(header)
                                        # Send any remaining data
                                        if data_to_process:
                                            backend_writer.write(data_to_process)
                                        await backend_writer.drain()
                                        break
                                    else:
                                        headers.append(line)
                                else:
                                    # Need more data
                                    more_data = await asyncio.wait_for(reader.read(1024), timeout=5.0)
                                    data_to_process += more_data
                        else:
                            # Not HTTP, just forward all data
                            backend_writer.write(first_data)
                            await backend_writer.drain()
                    else:
                        # No complete line, just forward
                        backend_writer.write(first_data)
                        await backend_writer.drain()
            
            # Now forward bidirectionally
            await asyncio.gather(
                self._forward_data(reader, backend_writer, "client->backend"),
                self._forward_data(backend_reader, writer, "backend->client"),
                return_exceptions=True
            )
            
        except asyncio.TimeoutError:
            logger.error("Timeout reading from client")
        except Exception as e:
            logger.error(f"Error handling connection: {e}")
        finally:
            writer.close()
            await writer.wait_closed()
            
    async def _store_client_info(self, backend_port: int, local_port: int, client_ip: str, client_port: int):
        """Store client info in Redis for the ASGI app to retrieve."""
        if not self.redis_client:
            return
            
        try:
            # Key includes backend port and local port for uniqueness
            key = f"proxy:client:{backend_port}:{local_port}"
            value = json.dumps({
                "client_ip": client_ip,
                "client_port": client_port
            })
            # Set with 60 second TTL - connections shouldn't last longer
            # The redis client should be async (redis.asyncio.Redis)
            await self.redis_client.setex(key, 60, value)
            logger.debug(f"Stored client info in Redis: {key} -> {client_ip}:{client_port}")
        except Exception as e:
            logger.error(f"Failed to store client info in Redis: {e}")
            
    async def _forward_data(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter, direction: str):
        """Forward data between connections."""
        try:
            while True:
                data = await reader.read(8192)
                if not data:
                    break
                writer.write(data)
                await writer.drain()
        except Exception as e:
            logger.debug(f"Forward {direction} ended: {e}")
        finally:
            writer.close()
            await writer.wait_closed()


async def create_proxy_protocol_server(
    backend_host: str,
    backend_port: int, 
    listen_host: str,
    listen_port: int,
    redis_client: Optional[redis.Redis] = None
) -> asyncio.Server:
    """Create a server that handles PROXY protocol and forwards to backend."""
    handler = ProxyProtocolHandler(backend_host, backend_port, redis_client)
    
    server = await asyncio.start_server(
        handler.handle_connection,
        listen_host,
        listen_port
    )
    
    logger.info(f"PROXY protocol server listening on {listen_host}:{listen_port}, forwarding to {backend_host}:{backend_port}")
    return server