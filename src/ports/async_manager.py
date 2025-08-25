"""Async port allocation and management system.

This module provides a fully async port manager that doesn't block
the event loop with synchronous Redis operations.
"""

import asyncio
import logging
import json
from typing import Dict, List, Optional, Set, Tuple
from datetime import datetime, timezone
import hashlib

from ..storage import UnifiedStorage
from .models import ServicePort, PortAllocation

logger = logging.getLogger(__name__)


class AsyncPortManager:
    """Async port allocation and access control manager."""
    
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
    
    def __init__(self, storage: UnifiedStorage):
        """Initialize the async port manager."""
        self.storage = storage
        self.redis = storage.redis_client  # Will be async Redis client
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
        allocation_data = await self.redis.get(port_key)
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
                cursor, keys = await self.redis.scan(cursor, match="port:*", count=100)
                for key in keys:
                    try:
                        # Handle both bytes and string keys
                        key_str = key.decode() if isinstance(key, bytes) else key
                        port_num = int(key_str.split(":")[-1])
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
        await self.redis.set(f"port:{port}", json.dumps(allocation))
        
        # Add to appropriate set
        if purpose.startswith("internal"):
            await self.redis.sadd("ports:internal", str(port))
        else:
            await self.redis.sadd("ports:exposed", str(port))
        
        await self.redis.sadd("ports:allocated", str(port))
    
    async def release_port(self, port: int):
        """Release an allocated port."""
        port_key = f"port:{port}"
        allocation_data = await self.redis.get(port_key)
        
        if allocation_data:
            allocation = json.loads(allocation_data)
            purpose = allocation.get("purpose", "exposed")
            
            # Remove from sets
            await self.redis.srem("ports:allocated", str(port))
            if purpose.startswith("internal"):
                await self.redis.srem("ports:internal", str(port))
            else:
                await self.redis.srem("ports:exposed", str(port))
            
            # Delete the allocation record
            await self.redis.delete(port_key)
            
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
            await self.redis.hset(
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
            await self.redis.set(
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
            port_data = await self.redis.hget(f"service:ports:{service_name}", port_name)
            if not port_data:
                logger.warning(f"Port {port_name} not found for service {service_name}")
                return False
            
            port_config = ServicePort.model_validate_json(port_data)
            
            # Remove from service ports
            await self.redis.hdel(f"service:ports:{service_name}", port_name)
            
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
        port_data = await self.redis.hgetall(f"service:ports:{service_name}")
        
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
            cursor, keys = await self.redis.scan(cursor, match="port:*", count=100)
            for key in keys:
                try:
                    # Handle both bytes and string keys
                    key_str = key.decode() if isinstance(key, bytes) else key
                    # Skip port:token keys
                    if "token" in key_str:
                        continue
                    port_num = int(key_str.split(":")[-1])
                    data = await self.redis.get(key)
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
    
    # Port access validation
    
    async def validate_port_access(self, port: int, token_value: Optional[str]) -> bool:
        """Validate access to a port using a token.
        
        This simplified version only checks if the provided token matches
        the port's configured source_token.
        
        Args:
            port: Port number to access
            token_value: Token value provided for access
            
        Returns:
            True if access is allowed, False otherwise
        """
        # Get port configuration
        port_data = await self.redis.get(f"port:{port}")
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
        
        # Validate token matches the port's source token
        token_hash = hashlib.sha256(token_value.encode()).hexdigest()
        
        if token_hash == port_config.get("source_token_hash"):
            return True
        
        logger.warning(f"Invalid token for port {port}")
        return False