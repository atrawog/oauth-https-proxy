"""Port management using Redis Streams for coordination.

This module provides a robust port allocation system using Redis Streams
to ensure atomic allocation, prevent conflicts, and enable proper cleanup.
"""

import asyncio
import json
import time
from typing import Optional, Dict, List, Tuple
from datetime import datetime, timezone

from ..storage.redis_stream_publisher import RedisStreamPublisher
from ..dispatcher.redis_stream_consumer import RedisStreamConsumer
from ..shared.logger import log_info, log_warning, log_error, log_debug, log_trace


class StreamBasedPortManager:
    """Manages port allocation using Redis Streams for coordination."""
    
    # Port ranges
    HTTP_START = 10000
    HTTP_END = 10999
    HTTPS_START = 11000
    HTTPS_END = 11999
    INTERNAL_OFFSET = 2000  # Internal ports are base + offset
    
    def __init__(self, redis_url: str, consumer_name: str = "port-manager"):
        """Initialize the port manager.
        
        Args:
            redis_url: Redis connection URL
            consumer_name: Name for this consumer instance
        """
        self.redis_url = redis_url
        self.consumer_name = consumer_name
        
        # Redis Streams components
        self.publisher = RedisStreamPublisher(redis_url=redis_url)
        self.consumer = RedisStreamConsumer(
            redis_url=redis_url,
            group_name="port-management",
            stream_key="port:events:stream"
        )
        
        # Initialize Redis connection for direct operations
        import redis
        self.redis = redis.from_url(redis_url)
        
        # Track active allocations in this instance (for cleanup)
        self.active_allocations: Dict[str, List[int]] = {}
        
    async def initialize(self):
        """Initialize the port manager and set up Redis structures."""
        log_info("[PORT_MANAGER] Initializing port management system", component="port_manager")
        
        # Initialize available port ranges if not exists
        await self._initialize_port_ranges()
        
        # Start consumer for port events
        await self.consumer.initialize()
        
        # Start event processing
        self.consumer_task = asyncio.create_task(
            self.consumer.consume_events(self.handle_port_event)
        )
        
        # Start health check task
        self.health_task = asyncio.create_task(self._health_check_loop())
        
        log_info("[PORT_MANAGER] Port management system initialized", component="port_manager")
    
    async def _initialize_port_ranges(self):
        """Initialize available port ranges in Redis sorted sets."""
        # Check if ranges already initialized
        http_exists = self.redis.exists("port:range:http")
        https_exists = self.redis.exists("port:range:https")
        
        if not http_exists:
            log_info(f"[PORT_MANAGER] Initializing HTTP port range {self.HTTP_START}-{self.HTTP_END}", component="port_manager")
            pipe = self.redis.pipeline()
            for port in range(self.HTTP_START, self.HTTP_END + 1):
                pipe.zadd("port:range:http", {str(port): port})
            pipe.execute()
        
        if not https_exists:
            log_info(f"[PORT_MANAGER] Initializing HTTPS port range {self.HTTPS_START}-{self.HTTPS_END}", component="port_manager")
            pipe = self.redis.pipeline()
            for port in range(self.HTTPS_START, self.HTTPS_END + 1):
                pipe.zadd("port:range:https", {str(port): port})
            pipe.execute()
    
    async def request_ports(self, proxy_hostname: str, enable_http: bool = True, enable_https: bool = True) -> Dict[str, int]:
        """Request port allocation for a hostname.
        
        Args:
            hostname: Hostname requesting ports
            enable_http: Whether to allocate HTTP port
            enable_https: Whether to allocate HTTPS port
            
        Returns:
            Dict with allocated ports or empty dict on failure
        """
        log_info(f"[PORT_MANAGER] Requesting ports for {proxy_hostname}: HTTP={enable_http}, HTTPS={enable_https}", component="port_manager")
        
        # Publish port request event
        request_id = f"{proxy_hostname}:{time.time()}"
        await self.publisher.publish_event("port_requested", {
            "request_id": request_id,
            "proxy_hostname": proxy_hostname,
            "enable_http": enable_http,
            "enable_https": enable_https,
            "requested_by": self.consumer_name,
            "timestamp": datetime.now(timezone.utc).isoformat()
        }, stream_key="port:events:stream")
        
        # Wait for allocation result (with timeout)
        result_key = f"port:result:{request_id}"
        for _ in range(30):  # 3 second timeout
            result = self.redis.get(result_key)
            if result:
                self.redis.delete(result_key)
                ports = json.loads(result)
                log_info(f"[PORT_MANAGER] Allocated ports for {proxy_hostname}: {ports}", component="port_manager")
                return ports
            await asyncio.sleep(0.1)
        
        log_error(f"[PORT_MANAGER] Timeout waiting for port allocation for {proxy_hostname}", component="port_manager")
        return {}
    
    async def handle_port_event(self, event: Dict):
        """Handle port management events."""
        event_type = event.get('event_type')
        
        try:
            if event_type == 'port_requested':
                await self._handle_port_request(event)
            elif event_type == 'port_released':
                await self._handle_port_release(event)
            elif event_type == 'port_health_check':
                await self._handle_health_check(event)
        except Exception as e:
            log_error(f"[PORT_MANAGER] Error handling {event_type}: {e}", component="port_manager", error=e)
    
    async def _handle_port_request(self, event: Dict):
        """Handle port allocation request."""
        request_id = event.get('request_id')
        proxy_hostname = event.get("proxy_hostname")
        enable_http = event.get('enable_http', True)
        enable_https = event.get('enable_https', True)
        
        log_info(f"[PORT_MANAGER] Processing port request {request_id} for {proxy_hostname}", component="port_manager")
        
        allocated = {}
        allocated_ports = []
        
        try:
            # Atomic allocation using Redis transactions
            with self.redis.pipeline() as pipe:
                while True:
                    try:
                        # Watch the sorted sets for changes
                        pipe.watch("port:range:http", "port:range:https")
                        
                        # Get available ports
                        if enable_http:
                            http_ports = pipe.zrange("port:range:http", 0, 0)
                            if http_ports:
                                http_port = int(http_ports[0])
                                allocated['http_port'] = http_port
                                allocated['http_internal_port'] = http_port + self.INTERNAL_OFFSET
                                allocated_ports.extend([http_port, http_port + self.INTERNAL_OFFSET])
                        
                        if enable_https:
                            https_ports = pipe.zrange("port:range:https", 0, 0)
                            if https_ports:
                                https_port = int(https_ports[0])
                                allocated['https_port'] = https_port
                                allocated['https_internal_port'] = https_port + self.INTERNAL_OFFSET
                                allocated_ports.extend([https_port, https_port + self.INTERNAL_OFFSET])
                        
                        # Start transaction
                        pipe.multi()
                        
                        # Remove allocated ports from available ranges
                        if 'http_port' in allocated:
                            pipe.zrem("port:range:http", str(allocated['http_port']))
                            # Store allocation info
                            pipe.hset(f"port:allocated:{allocated['http_port']}", mapping={
                                "proxy_hostname": proxy_hostname,
                                "type": "http",
                                "internal_port": allocated['http_internal_port'],
                                "allocated_at": datetime.now(timezone.utc).isoformat(),
                                "allocated_by": self.consumer_name
                            })
                        
                        if 'https_port' in allocated:
                            pipe.zrem("port:range:https", str(allocated['https_port']))
                            # Store allocation info
                            pipe.hset(f"port:allocated:{allocated['https_port']}", mapping={
                                "proxy_hostname": proxy_hostname,
                                "type": "https",
                                "internal_port": allocated['https_internal_port'],
                                "allocated_at": datetime.now(timezone.utc).isoformat(),
                                "allocated_by": self.consumer_name
                            })
                        
                        # Store hostname -> ports mapping
                        if allocated:
                            pipe.set(f"port:hostname:{proxy_hostname}", json.dumps(allocated))
                        
                        # Execute transaction
                        pipe.execute()
                        break
                        
                    except redis.WatchError:
                        # Retry if values changed during transaction
                        log_debug("[PORT_MANAGER] Port allocation race detected, retrying", component="port_manager")
                        continue
            
            # Store result for requester
            self.redis.setex(f"port:result:{request_id}", 5, json.dumps(allocated))
            
            # Track allocation
            self.active_allocations[hostname] = allocated_ports
            
            # Publish allocation event
            await self.publisher.publish_event("port_allocated", {
                "proxy_hostname": proxy_hostname,
                "ports": allocated,
                "allocated_by": self.consumer_name,
                "timestamp": datetime.now(timezone.utc).isoformat()
            }, stream_key="port:events:stream")
            
            log_info(f"[PORT_MANAGER] Successfully allocated ports for {proxy_hostname}: {allocated}", component="port_manager")
            
        except Exception as e:
            log_error(f"[PORT_MANAGER] Failed to allocate ports for {proxy_hostname}: {e}", component="port_manager", error=e)
            # Store error result
            self.redis.setex(f"port:result:{request_id}", 5, json.dumps({}))
    
    async def release_ports(self, proxy_hostname: str):
        """Release ports allocated to a hostname.
        
        Args:
            hostname: Hostname to release ports for
        """
        log_info(f"[PORT_MANAGER] Releasing ports for {proxy_hostname}", component="port_manager")
        
        # Get allocated ports
        port_data = self.redis.get(f"port:hostname:{proxy_hostname}")
        if not port_data:
            log_warning(f"[PORT_MANAGER] No ports found for {proxy_hostname}", component="port_manager")
            return
        
        ports = json.loads(port_data)
        
        # Return ports to available pools
        with self.redis.pipeline() as pipe:
            if 'http_port' in ports:
                pipe.zadd("port:range:http", {str(ports['http_port']): ports['http_port']})
                pipe.delete(f"port:allocated:{ports['http_port']}")
            
            if 'https_port' in ports:
                pipe.zadd("port:range:https", {str(ports['https_port']): ports['https_port']})
                pipe.delete(f"port:allocated:{ports['https_port']}")
            
            # Remove hostname mapping
            pipe.delete(f"port:hostname:{proxy_hostname}")
            pipe.execute()
        
        # Remove from active allocations
        if hostname in self.active_allocations:
            del self.active_allocations[hostname]
        
        # Publish release event
        await self.publisher.publish_event("port_released", {
            "proxy_hostname": proxy_hostname,
            "ports": ports,
            "released_by": self.consumer_name,
            "timestamp": datetime.now(timezone.utc).isoformat()
        }, stream_key="port:events:stream")
        
        log_info(f"[PORT_MANAGER] Released ports for {proxy_hostname}: {ports}", component="port_manager")
    
    async def _handle_port_release(self, event: Dict):
        """Handle port release event."""
        proxy_hostname = event.get("proxy_hostname")
        await self.release_ports(hostname)
    
    async def _health_check_loop(self):
        """Periodically check port health and cleanup orphaned allocations."""
        while True:
            try:
                await asyncio.sleep(60)  # Check every minute
                await self._check_port_health()
            except Exception as e:
                log_error(f"[PORT_MANAGER] Health check error: {e}", component="port_manager", error=e)
    
    async def _check_port_health(self):
        """Check health of allocated ports and cleanup dead ones."""
        log_debug("[PORT_MANAGER] Running port health check", component="port_manager")
        
        # Get all allocated ports
        allocated_keys = self.redis.keys("port:allocated:*")
        
        for key in allocated_keys:
            port_info = self.redis.hgetall(key)
            if not port_info:
                continue
            
            port = int(key.split(":")[-1])
            proxy_hostname = port_info.get(b'hostname', b'').decode()
            allocated_at = port_info.get(b'allocated_at', b'').decode()
            
            # Check if port is actually in use
            import socket
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex(('127.0.0.1', port))
            sock.close()
            
            if result != 0:
                # Port not in use, check age
                if allocated_at:
                    from datetime import datetime
                    alloc_time = datetime.fromisoformat(allocated_at.replace('Z', '+00:00'))
                    age = (datetime.now(timezone.utc) - alloc_time).total_seconds()
                    
                    # If allocated more than 5 minutes ago and not in use, release it
                    if age > 300:
                        log_warning(f"[PORT_MANAGER] Port {port} for {proxy_hostname} is orphaned, releasing", component="port_manager")
                        await self.release_ports(hostname)
    
    async def get_ports_for_hostname(self, proxy_hostname: str) -> Optional[Dict[str, int]]:
        """Get allocated ports for a hostname.
        
        Args:
            hostname: Hostname to get ports for
            
        Returns:
            Dict with port allocations or None
        """
        port_data = self.redis.get(f"port:hostname:{proxy_hostname}")
        if port_data:
            return json.loads(port_data)
        return None
    
    async def close(self):
        """Clean up resources."""
        log_info("[PORT_MANAGER] Shutting down port management system", component="port_manager")
        
        # Cancel tasks
        if hasattr(self, 'consumer_task'):
            self.consumer_task.cancel()
        if hasattr(self, 'health_task'):
            self.health_task.cancel()
        
        # Close Redis connection
        self.redis.close()