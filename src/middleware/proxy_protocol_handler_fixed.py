"""
HAProxy PROXY protocol v1 handler - Spec-compliant implementation.

Implements PROXY protocol v1 according to:
https://www.haproxy.org/download/1.8/doc/proxy-protocol.txt

Key compliance points:
- Maximum header size: 107 bytes
- Supports TCP4, TCP6, and UNKNOWN protocols
- Strict IP address and port validation
- Immediate connection abort on invalid headers
"""
import asyncio
import logging
import json
import ipaddress
from typing import Optional, Tuple
import redis

logger = logging.getLogger(__name__)

# PROXY protocol v1 constants
PROXY_V1_MAX_LENGTH = 107  # Maximum header length
PROXY_V1_PREFIX = b'PROXY '
PROXY_TIMEOUT = 5.0  # Spec recommends at least 3 seconds


class ProxyProtocolHandler:
    """HAProxy PROXY protocol v1 compliant handler."""
    
    def __init__(self, backend_host: str, backend_port: int, redis_client: Optional[redis.Redis] = None):
        self.backend_host = backend_host
        self.backend_port = backend_port
        self.redis_client = redis_client
        
    async def handle_connection(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        """Handle incoming connection with PROXY protocol v1."""
        client_addr = writer.get_extra_info('peername')
        
        try:
            # Read up to max header size (107 bytes for PROXY v1)
            header_data = await asyncio.wait_for(
                reader.read(PROXY_V1_MAX_LENGTH), 
                timeout=PROXY_TIMEOUT
            )
            
            # Default to actual connection info
            real_client_ip = client_addr[0] if client_addr else '127.0.0.1'
            real_client_port = client_addr[1] if client_addr else 0
            
            # Look for CRLF in the data
            crlf_pos = header_data.find(b'\r\n')
            if crlf_pos == -1:
                # No CRLF found, might not be PROXY protocol
                remaining_data = header_data
            else:
                # Extract the line up to CRLF
                proxy_line = header_data[:crlf_pos]
                remaining_data = header_data[crlf_pos + 2:]
                
                # Check if it's a PROXY protocol header
                if proxy_line.startswith(PROXY_V1_PREFIX):
                    try:
                        # Parse PROXY protocol v1
                        real_client_ip, real_client_port = await self._parse_proxy_v1(proxy_line)
                        logger.info(f"PROXY protocol: {real_client_ip}:{real_client_port}")
                    except Exception as e:
                        # Invalid PROXY header - abort connection per spec
                        logger.error(f"Invalid PROXY protocol header: {e}")
                        writer.close()
                        await writer.wait_closed()
                        return
                else:
                    # Not PROXY protocol, include the line in remaining data
                    remaining_data = header_data
            
            # Connect to backend
            try:
                backend_reader, backend_writer = await asyncio.open_connection(
                    self.backend_host, self.backend_port
                )
            except Exception as e:
                logger.error(f"Failed to connect to backend: {e}")
                writer.close()
                await writer.wait_closed()
                return
            
            # Store client info in Redis
            backend_local_addr = backend_writer.get_extra_info('sockname')
            if backend_local_addr and self.redis_client:
                backend_local_port = backend_local_addr[1]
                await self._store_client_info(
                    self.backend_port, backend_local_port, 
                    real_client_ip, real_client_port
                )
            
            # Forward any remaining data
            if remaining_data:
                backend_writer.write(remaining_data)
                await backend_writer.drain()
            
            # Bidirectional forwarding
            await asyncio.gather(
                self._forward_data(reader, backend_writer, "client->backend"),
                self._forward_data(backend_reader, writer, "backend->client"),
                return_exceptions=True
            )
            
        except asyncio.TimeoutError:
            logger.error("Timeout waiting for PROXY protocol header")
        except Exception as e:
            logger.error(f"Error handling connection: {e}")
        finally:
            writer.close()
            await writer.wait_closed()
    
    async def _parse_proxy_v1(self, proxy_line: bytes) -> Tuple[str, int]:
        """
        Parse PROXY protocol v1 header line.
        
        Format: PROXY <protocol> <src_ip> <dst_ip> <src_port> <dst_port>
        Protocol: TCP4, TCP6, or UNKNOWN
        
        Returns: (client_ip, client_port)
        Raises: ValueError on invalid format
        """
        try:
            # Decode and split the line
            parts = proxy_line.decode('ascii').strip().split()
            
            if len(parts) < 2:
                raise ValueError("Too few fields")
            
            protocol = parts[1]
            
            # Handle UNKNOWN protocol (no address info)
            if protocol == 'UNKNOWN':
                # For UNKNOWN, use the actual connection info
                return '0.0.0.0', 0
            
            # TCP4 or TCP6 require exactly 6 fields
            if len(parts) != 6:
                raise ValueError(f"Invalid field count for {protocol}: {len(parts)}")
            
            if protocol not in ('TCP4', 'TCP6'):
                raise ValueError(f"Invalid protocol: {protocol}")
            
            src_ip = parts[2]
            dst_ip = parts[3]
            src_port_str = parts[4]
            dst_port_str = parts[5]
            
            # Validate IP addresses match protocol
            if protocol == 'TCP4':
                # Validate IPv4 addresses
                ipaddress.IPv4Address(src_ip)
                ipaddress.IPv4Address(dst_ip)
            else:  # TCP6
                # Validate IPv6 addresses
                ipaddress.IPv6Address(src_ip)
                ipaddress.IPv6Address(dst_ip)
            
            # Validate ports (0-65535, no leading zeros except "0")
            src_port = int(src_port_str)
            dst_port = int(dst_port_str)
            
            if not (0 <= src_port <= 65535):
                raise ValueError(f"Source port out of range: {src_port}")
            if not (0 <= dst_port <= 65535):
                raise ValueError(f"Destination port out of range: {dst_port}")
            
            # Check for leading zeros (except "0" itself)
            if (src_port_str != '0' and src_port_str.startswith('0')):
                raise ValueError(f"Source port has leading zeros: {src_port_str}")
            if (dst_port_str != '0' and dst_port_str.startswith('0')):
                raise ValueError(f"Destination port has leading zeros: {dst_port_str}")
            
            return src_ip, src_port
            
        except UnicodeDecodeError:
            raise ValueError("Non-ASCII characters in PROXY header")
    
    async def _store_client_info(self, backend_port: int, local_port: int, 
                                client_ip: str, client_port: int):
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
            self.redis_client.setex(key, 60, value)
            logger.debug(f"Stored client info in Redis: {key} -> {client_ip}:{client_port}")
        except Exception as e:
            logger.error(f"Failed to store client info in Redis: {e}")
    
    async def _forward_data(self, reader: asyncio.StreamReader, 
                           writer: asyncio.StreamWriter, direction: str):
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
    
    logger.info(
        f"PROXY protocol server listening on {listen_host}:{listen_port}, "
        f"forwarding to {backend_host}:{backend_port}"
    )
    return server