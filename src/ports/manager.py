"""Port allocation and management system."""

import asyncio
import logging
import json
from typing import Dict, List, Optional, Set, Tuple
from datetime import datetime, timezone
import hashlib

from ..storage import RedisStorage
from .models import ServicePort, PortAccessToken, PortAllocation

logger = logging.getLogger(__name__)


class PortManager:
    """Manages port allocation and access control."""
    
    # Port ranges for different purposes
    INTERNAL_HTTP_START = 9000
    INTERNAL_HTTP_END = 9999
    INTERNAL_HTTPS_START = 10000
    INTERNAL_HTTPS_END = 10999
    EXPOSED_PORT_START = 11000
    EXPOSED_PORT_END = 65535
    
    # Restricted ports that should not be allocated
    RESTRICTED_PORTS = {
        22,    # SSH
        25,    # SMTP
        53,    # DNS
        80,    # HTTP (reserved for proxy)
        443,   # HTTPS (reserved for proxy)
        3306,  # MySQL
        5432,  # PostgreSQL
        6379,  # Redis
        27017, # MongoDB
    }
    
    def __init__(self, storage: RedisStorage):
        """Initialize the port manager."""
        self.storage = storage
        self.redis = storage.redis_client
        self._allocation_lock = asyncio.Lock()
    
    async def allocate_port(self, purpose: str = "exposed", 
                           preferred: Optional[int] = None,
                           bind_address: str = "127.0.0.1") -> Optional[int]:
        """Allocate a port for use.
        
        Args:
            purpose: Purpose of the port ("internal_http", "internal_https", "exposed")
            preferred: Preferred port number if available
            bind_address: Bind address for the port
            
        Returns:
            Allocated port number or None if no ports available
        """
        async with self._allocation_lock:
            # Check if preferred port is available
            if preferred and await self.is_port_available(preferred, bind_address):
                await self._mark_port_allocated(preferred, purpose, bind_address)
                return preferred
            
            # Determine port range based on purpose
            if purpose == "internal_http":
                start, end = self.INTERNAL_HTTP_START, self.INTERNAL_HTTP_END
            elif purpose == "internal_https":
                start, end = self.INTERNAL_HTTPS_START, self.INTERNAL_HTTPS_END
            else:  # exposed
                start, end = self.EXPOSED_PORT_START, self.EXPOSED_PORT_END
            
            # Find next available port
            for port in range(start, end + 1):
                if port in self.RESTRICTED_PORTS:
                    continue
                if await self.is_port_available(port, bind_address):
                    await self._mark_port_allocated(port, purpose, bind_address)
                    return port
            
            logger.error(f"No available ports in range {start}-{end} for {purpose}")
            return None
    
    async def is_port_available(self, port: int, bind_address: str = "0.0.0.0") -> bool:
        """Check if a port is available for allocation.
        
        Args:
            port: Port number to check
            bind_address: Bind address to check (0.0.0.0 checks all interfaces)
            
        Returns:
            True if port is available, False otherwise
        """
        if port in self.RESTRICTED_PORTS:
            return False
        
        # Check if port is already allocated
        port_key = f"port:{port}"
        allocation_data = self.redis.get(port_key)
        if allocation_data:
            allocation = json.loads(allocation_data)
            # If allocated to a different address and not checking all interfaces
            if bind_address != "0.0.0.0" and allocation.get("bind_address") != bind_address:
                return True
            return False
        
        # Check all allocated ports if checking all interfaces
        if bind_address == "0.0.0.0":
            cursor = 0
            while True:
                cursor, keys = self.redis.scan(cursor, match="port:*", count=100)
                for key in keys:
                    try:
                        port_num = int(key.decode().split(":")[-1])
                        if port_num == port:
                            return False
                    except (ValueError, IndexError):
                        continue
                if cursor == 0:
                    break
        
        return True
    
    async def _mark_port_allocated(self, port: int, purpose: str, bind_address: str):
        """Mark a port as allocated."""
        allocation = {
            "port": port,
            "purpose": purpose,
            "bind_address": bind_address,
            "allocated_at": datetime.now(timezone.utc).isoformat()
        }
        self.redis.set(f"port:{port}", json.dumps(allocation))
        
        # Add to appropriate set
        if purpose.startswith("internal"):
            self.redis.sadd("ports:internal", str(port))
        else:
            self.redis.sadd("ports:exposed", str(port))
        
        self.redis.sadd("ports:allocated", str(port))
    
    async def release_port(self, port: int):
        """Release an allocated port."""
        port_key = f"port:{port}"
        allocation_data = self.redis.get(port_key)
        
        if allocation_data:
            allocation = json.loads(allocation_data)
            purpose = allocation.get("purpose", "exposed")
            
            # Remove from sets
            self.redis.srem("ports:allocated", str(port))
            if purpose.startswith("internal"):
                self.redis.srem("ports:internal", str(port))
            else:
                self.redis.srem("ports:exposed", str(port))
            
            # Delete the allocation record
            self.redis.delete(port_key)
            
            logger.info(f"Released port {port}")
    
    async def add_service_port(self, service_port: ServicePort) -> bool:
        """Add a port configuration for a service.
        
        Args:
            service_port: ServicePort configuration
            
        Returns:
            True if successful, False otherwise
        """
        try:
            # Store port configuration
            port_data = service_port.model_dump_json()
            
            # Store by service and port
            self.redis.hset(
                f"service:ports:{service_port.service_name}",
                service_port.port_name,
                port_data
            )
            
            # Store port to service mapping
            port_mapping = {
                "service_name": service_port.service_name,
                "port_name": service_port.port_name,
                "container_port": service_port.container_port,
                "bind_address": service_port.bind_address,
                "source_token_hash": service_port.source_token_hash,
                "require_token": service_port.require_token
            }
            self.redis.set(
                f"port:{service_port.host_port}",
                json.dumps(port_mapping)
            )
            
            # Track in allocated ports
            await self._mark_port_allocated(
                service_port.host_port, 
                "exposed", 
                service_port.bind_address
            )
            
            logger.info(f"Added port {service_port.port_name} ({service_port.host_port}) for service {service_port.service_name}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to add service port: {e}")
            return False
    
    async def remove_service_port(self, service_name: str, port_name: str) -> bool:
        """Remove a port configuration from a service.
        
        Args:
            service_name: Name of the service
            port_name: Name of the port to remove
            
        Returns:
            True if successful, False otherwise
        """
        try:
            # Get port configuration
            port_data = self.redis.hget(f"service:ports:{service_name}", port_name)
            if not port_data:
                logger.warning(f"Port {port_name} not found for service {service_name}")
                return False
            
            port_config = ServicePort.model_validate_json(port_data)
            
            # Remove from service ports
            self.redis.hdel(f"service:ports:{service_name}", port_name)
            
            # Release the port
            await self.release_port(port_config.host_port)
            
            logger.info(f"Removed port {port_name} ({port_config.host_port}) from service {service_name}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to remove service port: {e}")
            return False
    
    async def get_service_ports(self, service_name: str) -> List[ServicePort]:
        """Get all ports for a service.
        
        Args:
            service_name: Name of the service
            
        Returns:
            List of ServicePort configurations
        """
        ports = []
        port_data = self.redis.hgetall(f"service:ports:{service_name}")
        
        for port_name, port_json in port_data.items():
            try:
                port = ServicePort.model_validate_json(port_json)
                ports.append(port)
            except Exception as e:
                logger.error(f"Failed to parse port {port_name}: {e}")
        
        return sorted(ports, key=lambda p: p.host_port)
    
    async def remove_all_service_ports(self, service_name: str):
        """Remove all ports for a service."""
        ports = await self.get_service_ports(service_name)
        for port in ports:
            await self.remove_service_port(service_name, port.port_name)
    
    async def get_allocated_ports(self) -> Dict[int, Dict]:
        """Get all allocated ports with their details.
        
        Returns:
            Dictionary mapping port numbers to allocation details
        """
        allocated = {}
        cursor = 0
        
        while True:
            cursor, keys = self.redis.scan(cursor, match="port:*", count=100)
            for key in keys:
                try:
                    port_num = int(key.decode().split(":")[-1])
                    data = self.redis.get(key)
                    if data:
                        allocated[port_num] = json.loads(data)
                except (ValueError, IndexError):
                    continue
            if cursor == 0:
                break
        
        return allocated
    
    async def get_available_port_ranges(self) -> List[Tuple[int, int]]:
        """Get ranges of available ports.
        
        Returns:
            List of tuples (start, end) representing available port ranges
        """
        allocated = await self.get_allocated_ports()
        allocated_set = set(allocated.keys()) | self.RESTRICTED_PORTS
        
        ranges = []
        start = None
        
        for port in range(1024, 65536):
            if port not in allocated_set:
                if start is None:
                    start = port
            else:
                if start is not None:
                    ranges.append((start, port - 1))
                    start = None
        
        if start is not None:
            ranges.append((start, 65535))
        
        return ranges
    
    # Token management methods
    
    async def create_port_access_token(self, token: PortAccessToken) -> str:
        """Create a new port access token.
        
        Args:
            token: PortAccessToken configuration
            
        Returns:
            The generated token value
        """
        # Generate random token
        import secrets
        token_value = f"pat_{secrets.token_urlsafe(32)}"
        token.token_hash = hashlib.sha256(token_value.encode()).hexdigest()
        
        # Store token
        self.redis.set(
            f"port:token:{token.token_hash}",
            token.model_dump_json()
        )
        
        # Index by name
        self.redis.set(
            f"port:token:name:{token.token_name}",
            token.token_hash
        )
        
        logger.info(f"Created port access token: {token.token_name}")
        return token_value
    
    async def validate_port_access(self, port: int, token_value: Optional[str]) -> bool:
        """Validate access to a port using a token.
        
        Args:
            port: Port number to access
            token_value: Token value provided for access
            
        Returns:
            True if access is allowed, False otherwise
        """
        # Get port configuration
        port_data = self.redis.get(f"port:{port}")
        if not port_data:
            logger.warning(f"Port {port} not found")
            return False
        
        port_config = json.loads(port_data)
        
        # Check if token is required
        if not port_config.get("require_token", False):
            return True
        
        if not token_value:
            logger.warning(f"Token required for port {port} but none provided")
            return False
        
        # Validate token
        token_hash = hashlib.sha256(token_value.encode()).hexdigest()
        
        # Check if it matches the port's source token
        if token_hash == port_config.get("source_token_hash"):
            return True
        
        # Check if it's a valid port access token
        token_data = self.redis.get(f"port:token:{token_hash}")
        if not token_data:
            logger.warning(f"Invalid token for port {port}")
            return False
        
        try:
            token = PortAccessToken.model_validate_json(token_data)
            
            # Check if token is expired
            if token.is_expired():
                logger.warning(f"Token {token.token_name} is expired")
                return False
            
            # Check service access
            service_name = port_config.get("service_name")
            if service_name and not token.can_access_service(service_name):
                logger.warning(f"Token {token.token_name} not allowed for service {service_name}")
                return False
            
            # Check port access
            if not token.can_access_port(port):
                logger.warning(f"Token {token.token_name} not allowed for port {port}")
                return False
            
            # Update usage stats
            token.last_used = datetime.now(timezone.utc)
            token.use_count += 1
            self.redis.set(
                f"port:token:{token_hash}",
                token.model_dump_json()
            )
            
            return True
            
        except Exception as e:
            logger.error(f"Failed to validate token: {e}")
            return False
    
    async def revoke_port_access_token(self, token_name: str) -> bool:
        """Revoke a port access token.
        
        Args:
            token_name: Name of the token to revoke
            
        Returns:
            True if revoked, False if not found
        """
        # Get token hash by name
        token_hash = self.redis.get(f"port:token:name:{token_name}")
        if not token_hash:
            return False
        
        # Delete token records
        self.redis.delete(f"port:token:{token_hash}")
        self.redis.delete(f"port:token:name:{token_name}")
        
        logger.info(f"Revoked port access token: {token_name}")
        return True
    
    async def list_port_access_tokens(self) -> List[PortAccessToken]:
        """List all port access tokens.
        
        Returns:
            List of PortAccessToken objects
        """
        tokens = []
        cursor = 0
        
        while True:
            cursor, keys = self.redis.scan(cursor, match="port:token:*", count=100)
            for key in keys:
                # Skip name index keys
                if b":name:" in key:
                    continue
                    
                token_data = self.redis.get(key)
                if token_data:
                    try:
                        token = PortAccessToken.model_validate_json(token_data)
                        tokens.append(token)
                    except Exception as e:
                        logger.error(f"Failed to parse token: {e}")
            
            if cursor == 0:
                break
        
        return sorted(tokens, key=lambda t: t.created_at, reverse=True)