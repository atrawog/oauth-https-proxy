"""Redis client management for OAuth state storage"""

from typing import Optional

import redis.asyncio as redis

from .config import Settings
from ...shared.logger import log_info


class RedisManager:
    """Manages Redis connection pool and operations"""

    def __init__(self, settings: Settings):
        self.settings = settings
        self._pool: Optional[redis.Redis] = None

    async def initialize(self):
        """Initialize Redis connection pool"""
        self._pool = redis.from_url(
            self.settings.redis_url,
            encoding="utf-8",
            decode_responses=True,
            password=self.settings.redis_password,
        )
        # Test connection
        await self._pool.ping()
        log_info("✓ Redis connection established", component="oauth_redis")

    async def close(self):
        """Close Redis connection pool"""
        if self._pool:
            await self._pool.close()

    @property
    def client(self) -> redis.Redis:
        """Get Redis client from pool"""
        if not self._pool:
            # Auto-initialize the pool if not already done
            import asyncio
            loop = asyncio.get_event_loop()
            if loop.is_running():
                # We're in an async context but can't await here
                # Create a synchronous Redis client instead
                self._pool = redis.from_url(
                    self.settings.redis_url,
                    encoding="utf-8",
                    decode_responses=True,
                    password=self.settings.redis_password,
                )
            else:
                # Initialize asynchronously
                loop.run_until_complete(self.initialize())
        return self._pool
