"""Instance state tracking in Redis."""

import json
import logging
from datetime import datetime, timezone
from typing import Dict, Optional, List
from enum import Enum
import redis.asyncio as redis_async

logger = logging.getLogger(__name__)


class InstanceState(str, Enum):
    """Instance lifecycle states."""
    PENDING = "pending"  # Waiting for resources (e.g., certificate)
    HTTP_ONLY = "http_only"  # Only HTTP is running
    HTTPS_ONLY = "https_only"  # Only HTTPS is running
    FULLY_RUNNING = "fully_running"  # Both HTTP and HTTPS are running
    FAILED = "failed"  # Instance failed to start
    STOPPING = "stopping"  # Instance is being stopped
    STOPPED = "stopped"  # Instance has been stopped


class InstanceStateTracker:
    """Track instance states in Redis."""
    
    def __init__(self, redis_url: str):
        self.redis_url = redis_url
        self.redis: Optional[redis_async.Redis] = None
        
    async def _ensure_connection(self):
        """Ensure Redis connection is available."""
        if not self.redis:
            self.redis = await redis_async.from_url(
                self.redis_url,
                decode_responses=True
            )
    
    async def set_instance_state(self, hostname: str, state: InstanceState, 
                                 details: Dict = None) -> bool:
        """
        Set the state of an instance.
        
        Args:
            hostname: The proxy hostname
            state: The instance state
            details: Additional state details
            
        Returns:
            True if successful, False otherwise
        """
        try:
            await self._ensure_connection()
            
            state_data = {
                "hostname": hostname,
                "state": state.value,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "details": details or {}
            }
            
            key = f"instance:state:{hostname}"
            await self.redis.set(key, json.dumps(state_data))
            
            # Also track in a set for quick lookups
            await self.redis.sadd(f"instances:{state.value}", hostname)
            
            # Remove from other state sets
            for other_state in InstanceState:
                if other_state != state:
                    await self.redis.srem(f"instances:{other_state.value}", hostname)
            
            logger.info(f"[STATE] Set {hostname} to {state.value}")
            return True
            
        except Exception as e:
            logger.error(f"[STATE] Failed to set state for {hostname}: {e}")
            return False
    
    async def get_instance_state(self, hostname: str) -> Optional[Dict]:
        """
        Get the current state of an instance.
        
        Args:
            hostname: The proxy hostname
            
        Returns:
            State data dictionary or None
        """
        try:
            await self._ensure_connection()
            
            key = f"instance:state:{hostname}"
            data = await self.redis.get(key)
            
            if data:
                return json.loads(data)
            return None
            
        except Exception as e:
            logger.error(f"[STATE] Failed to get state for {hostname}: {e}")
            return None
    
    async def get_instances_by_state(self, state: InstanceState) -> List[str]:
        """
        Get all instances in a specific state.
        
        Args:
            state: The state to query
            
        Returns:
            List of hostnames in that state
        """
        try:
            await self._ensure_connection()
            
            key = f"instances:{state.value}"
            return list(await self.redis.smembers(key))
            
        except Exception as e:
            logger.error(f"[STATE] Failed to get instances for state {state}: {e}")
            return []
    
    async def set_pending_operation(self, hostname: str, operation: str, 
                                   details: Dict = None) -> bool:
        """
        Track a pending operation for an instance.
        
        Args:
            hostname: The proxy hostname
            operation: The operation type (e.g., "waiting_for_certificate")
            details: Operation details
            
        Returns:
            True if successful, False otherwise
        """
        try:
            await self._ensure_connection()
            
            operation_data = {
                "hostname": hostname,
                "operation": operation,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "details": details or {}
            }
            
            key = f"instance:pending:{hostname}"
            await self.redis.set(key, json.dumps(operation_data), ex=3600)  # Expire after 1 hour
            
            logger.info(f"[STATE] Set pending operation '{operation}' for {hostname}")
            return True
            
        except Exception as e:
            logger.error(f"[STATE] Failed to set pending operation for {hostname}: {e}")
            return False
    
    async def get_pending_operation(self, hostname: str) -> Optional[Dict]:
        """
        Get pending operation for an instance.
        
        Args:
            hostname: The proxy hostname
            
        Returns:
            Operation data or None
        """
        try:
            await self._ensure_connection()
            
            key = f"instance:pending:{hostname}"
            data = await self.redis.get(key)
            
            if data:
                return json.loads(data)
            return None
            
        except Exception as e:
            logger.error(f"[STATE] Failed to get pending operation for {hostname}: {e}")
            return None
    
    async def clear_pending_operation(self, hostname: str) -> bool:
        """
        Clear pending operation for an instance.
        
        Args:
            hostname: The proxy hostname
            
        Returns:
            True if successful, False otherwise
        """
        try:
            await self._ensure_connection()
            
            key = f"instance:pending:{hostname}"
            await self.redis.delete(key)
            
            logger.info(f"[STATE] Cleared pending operation for {hostname}")
            return True
            
        except Exception as e:
            logger.error(f"[STATE] Failed to clear pending operation for {hostname}: {e}")
            return False
    
    async def close(self):
        """Close Redis connection."""
        if self.redis:
            await self.redis.close()
            self.redis = None