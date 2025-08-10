"""Redis Stream publisher for proxy events."""

import json
import logging
from datetime import datetime, timezone
from typing import Any, Dict, Optional
import redis.asyncio as redis_async

logger = logging.getLogger(__name__)


class RedisStreamPublisher:
    """Publisher for Redis Stream events."""
    
    def __init__(self, redis_client=None, redis_url: str = None):
        """Initialize with either a Redis client or URL."""
        self.redis = redis_client
        self.redis_url = redis_url
        self.stream_key = "proxy:events:stream"
        self.max_stream_length = 10000  # Keep last 10k events
        
    async def _ensure_connection(self):
        """Ensure Redis connection is available."""
        if not self.redis and self.redis_url:
            self.redis = await redis_async.from_url(
                self.redis_url,
                decode_responses=True
            )
    
    async def publish_event(self, event_type: str, data: Dict[str, Any]) -> Optional[str]:
        """
        Publish an event to the Redis Stream.
        
        Args:
            event_type: Type of event (proxy_created, certificate_ready, etc.)
            data: Event data dictionary
            
        Returns:
            Event ID from Redis or None on failure
        """
        try:
            await self._ensure_connection()
            
            if not self.redis:
                logger.error("No Redis connection available for stream publishing")
                return None
            
            # Build event with metadata
            event = {
                "type": event_type,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                **data
            }
            
            # Convert all values to strings for Redis
            # Redis Streams require string key-value pairs
            flat_event = {}
            for key, value in event.items():
                if isinstance(value, (dict, list)):
                    flat_event[key] = json.dumps(value)
                elif isinstance(value, bool):
                    flat_event[key] = "true" if value else "false"
                elif value is None:
                    flat_event[key] = "null"
                else:
                    flat_event[key] = str(value)
            
            # Add to stream with automatic trimming
            event_id = await self.redis.xadd(
                self.stream_key,
                flat_event,
                maxlen=self.max_stream_length,
                approximate=True  # Faster trimming
            )
            
            logger.info(f"[STREAM_PUBLISH] Published {event_type} event: {event_id} for {data.get('hostname', 'N/A')}")
            return event_id
            
        except Exception as e:
            logger.error(f"[STREAM_PUBLISH] Failed to publish {event_type} event: {e}", exc_info=True)
            return None
    
    async def publish_proxy_created(self, hostname: str, target_url: str, 
                                   cert_name: Optional[str] = None,
                                   enable_http: bool = True,
                                   enable_https: bool = True) -> Optional[str]:
        """Publish a proxy_created event."""
        return await self.publish_event("proxy_created", {
            "hostname": hostname,
            "target_url": target_url,
            "cert_name": cert_name or "",
            "enable_http": enable_http,
            "enable_https": enable_https
        })
    
    async def publish_proxy_deleted(self, hostname: str) -> Optional[str]:
        """Publish a proxy_deleted event."""
        return await self.publish_event("proxy_deleted", {
            "hostname": hostname
        })
    
    async def publish_certificate_ready(self, cert_name: str, domains: list,
                                       is_renewal: bool = False) -> Optional[str]:
        """Publish a certificate_ready event."""
        return await self.publish_event("certificate_ready", {
            "cert_name": cert_name,
            "domains": domains,
            "is_renewal": is_renewal
        })
    
    async def publish_proxy_updated(self, hostname: str, changes: dict) -> Optional[str]:
        """Publish a proxy_updated event."""
        return await self.publish_event("proxy_updated", {
            "hostname": hostname,
            "changes": changes
        })
    
    async def publish_http_instance_created(self, hostname: str, port: int) -> Optional[str]:
        """Publish an http_instance_created event."""
        return await self.publish_event("http_instance_created", {
            "hostname": hostname,
            "port": port
        })
    
    async def publish_https_instance_created(self, hostname: str, port: int, 
                                            cert_name: str) -> Optional[str]:
        """Publish an https_instance_created event."""
        return await self.publish_event("https_instance_created", {
            "hostname": hostname,
            "port": port,
            "cert_name": cert_name
        })
    
    async def publish_instance_failed(self, hostname: str, instance_type: str, 
                                     error: str) -> Optional[str]:
        """Publish an instance_failed event."""
        return await self.publish_event("instance_failed", {
            "hostname": hostname,
            "instance_type": instance_type,
            "error": error
        })
    
    async def publish_route_changed(self, route_id: str, action: str, 
                                   details: dict) -> Optional[str]:
        """Publish a route_changed event."""
        return await self.publish_event("route_changed", {
            "route_id": route_id,
            "action": action,  # created, updated, deleted
            "details": details
        })
    
    async def publish_service_state_changed(self, service_name: str, 
                                           state: str, details: dict = None) -> Optional[str]:
        """Publish a service_state_changed event."""
        return await self.publish_event("service_state_changed", {
            "service_name": service_name,
            "state": state,  # starting, running, stopped, failed
            "details": details or {}
        })
    
    async def publish_port_changed(self, port: int, action: str, 
                                  service: str = None) -> Optional[str]:
        """Publish a port_changed event."""
        return await self.publish_event("port_changed", {
            "port": port,
            "action": action,  # allocated, released
            "service": service
        })
    
    async def close(self):
        """Close Redis connection if we created it."""
        if self.redis and self.redis_url:
            await self.redis.close()