"""Dual Redis architecture for managing both async and sync operations.

This module provides a unified interface for Redis connections:
- Async Redis for high-frequency operations
- Stream Redis for event/log publishing
- Sync Redis for legacy operations (wrapped in executors)
"""

import logging
import os
from typing import Optional
import redis
import redis.asyncio as redis_async

logger = logging.getLogger(__name__)


class RedisClients:
    """Manages multiple Redis connections for different purposes."""
    
    def __init__(self, redis_url: str = None):
        """Initialize Redis clients manager.
        
        Args:
            redis_url: Redis connection URL (defaults to REDIS_URL env var)
        """
        self.redis_url = redis_url or os.getenv('REDIS_URL', 'redis://localhost:6379/0')
        
        # Client instances
        self._async_client: Optional[redis_async.Redis] = None
        self._stream_client: Optional[redis_async.Redis] = None
        self._sync_client: Optional[redis.Redis] = None
        
        # Connection pools for better performance
        self._async_pool: Optional[redis_async.ConnectionPool] = None
        self._stream_pool: Optional[redis_async.ConnectionPool] = None
        self._sync_pool: Optional[redis.ConnectionPool] = None
        
        logger.info(f"RedisClients initialized with URL: {self.redis_url}")
    
    async def initialize(self):
        """Initialize all Redis connections."""
        # Create connection pools
        self._async_pool = redis_async.ConnectionPool.from_url(
            self.redis_url,
            decode_responses=True,
            max_connections=50  # For high-frequency operations
        )
        
        self._stream_pool = redis_async.ConnectionPool.from_url(
            self.redis_url,
            decode_responses=True,
            max_connections=20  # For stream operations
        )
        
        # Create async clients
        self._async_client = redis_async.Redis(connection_pool=self._async_pool)
        self._stream_client = redis_async.Redis(connection_pool=self._stream_pool)
        
        # Test connections
        await self._async_client.ping()
        await self._stream_client.ping()
        
        logger.info("All async Redis connections initialized successfully")
    
    def initialize_sync(self):
        """Initialize synchronous Redis connection for legacy operations."""
        if not self._sync_client:
            self._sync_pool = redis.ConnectionPool.from_url(
                self.redis_url,
                decode_responses=True,
                max_connections=10  # Lower for sync operations
            )
            self._sync_client = redis.Redis(connection_pool=self._sync_pool)
            
            # Test connection
            self._sync_client.ping()
            logger.info("Sync Redis connection initialized")
    
    @property
    def async_redis(self) -> redis_async.Redis:
        """Get async Redis client for high-frequency operations.
        
        Returns:
            Async Redis client for storage, config, etc.
        """
        if not self._async_client:
            raise RuntimeError("Async Redis not initialized. Call initialize() first.")
        return self._async_client
    
    @property
    def stream_redis(self) -> redis_async.Redis:
        """Get async Redis client for stream operations.
        
        Returns:
            Async Redis client dedicated to streams
        """
        if not self._stream_client:
            raise RuntimeError("Stream Redis not initialized. Call initialize() first.")
        return self._stream_client
    
    @property
    def sync_redis(self) -> redis.Redis:
        """Get sync Redis client for legacy operations.
        
        Returns:
            Sync Redis client (use only in executors)
        """
        if not self._sync_client:
            self.initialize_sync()
        return self._sync_client
    
    async def close(self):
        """Close all Redis connections."""
        if self._async_client:
            await self._async_client.close()
            await self._async_pool.disconnect()
            
        if self._stream_client:
            await self._stream_client.close()
            await self._stream_pool.disconnect()
            
        if self._sync_client:
            self._sync_client.close()
            if self._sync_pool:
                self._sync_pool.disconnect()
        
        logger.info("All Redis connections closed")
    
    async def health_check(self) -> dict:
        """Check health of all Redis connections.
        
        Returns:
            Dictionary with health status of each connection
        """
        health = {
            "async_redis": False,
            "stream_redis": False,
            "sync_redis": False
        }
        
        try:
            if self._async_client:
                await self._async_client.ping()
                health["async_redis"] = True
        except Exception as e:
            logger.error(f"Async Redis health check failed: {e}")
        
        try:
            if self._stream_client:
                await self._stream_client.ping()
                health["stream_redis"] = True
        except Exception as e:
            logger.error(f"Stream Redis health check failed: {e}")
        
        try:
            if self._sync_client:
                self._sync_client.ping()
                health["sync_redis"] = True
        except Exception as e:
            logger.error(f"Sync Redis health check failed: {e}")
        
        return health
    
    async def get_info(self) -> dict:
        """Get Redis server information.
        
        Returns:
            Redis server info dictionary
        """
        if self._async_client:
            return await self._async_client.info()
        return {}
    
    async def get_memory_usage(self) -> dict:
        """Get Redis memory usage statistics.
        
        Returns:
            Memory usage statistics
        """
        if self._async_client:
            info = await self._async_client.info("memory")
            return {
                "used_memory_human": info.get("used_memory_human"),
                "used_memory_peak_human": info.get("used_memory_peak_human"),
                "mem_fragmentation_ratio": info.get("mem_fragmentation_ratio"),
                "maxmemory_human": info.get("maxmemory_human", "unlimited")
            }
        return {}


# Global instance for the application
_redis_clients: Optional[RedisClients] = None


def get_redis_clients() -> RedisClients:
    """Get the global RedisClients instance.
    
    Returns:
        Global RedisClients instance
    """
    global _redis_clients
    if not _redis_clients:
        _redis_clients = RedisClients()
    return _redis_clients


async def initialize_redis_clients():
    """Initialize the global RedisClients instance."""
    clients = get_redis_clients()
    await clients.initialize()
    return clients