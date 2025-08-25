"""Async log filtering for source-level suppression and sampling.

Pure async, fire-and-forget filtering without local state.
All filtering decisions are made using Redis for distributed consistency.
"""

import asyncio
import json
import re
import random
from typing import Optional, Dict, Any, List
from hashlib import md5


class AsyncLogFilter:
    """Pure async log filter - no caching, all Redis-based."""
    
    def __init__(self, redis_client):
        """Initialize with Redis client.
        
        Args:
            redis_client: Async Redis client for filter operations
        """
        self.redis = redis_client
        
    async def should_filter(self, level: str, message: str, component: str, **kwargs) -> bool:
        """Check if a log should be filtered (suppressed).
        
        Returns True if the log should be FILTERED OUT (not logged).
        
        Args:
            level: Log level
            message: Log message
            component: Component name
            **kwargs: Additional log fields
            
        Returns:
            True if log should be filtered out, False if it should be logged
        """
        try:
            # Get filter configuration from Redis
            filter_json = await self.redis.get(f"log:filter:{component}")
            if not filter_json:
                return False  # No filters, don't filter
            
            filters = json.loads(filter_json.decode() if isinstance(filter_json, bytes) else filter_json)
            
            # Check pattern suppression
            if await self._check_suppress_patterns(message, filters.get("suppress_patterns", [])):
                # Track suppressed count
                asyncio.create_task(
                    self.redis.hincrby(f"log:stats:suppressed", component, 1)
                )
                return True
            
            # Check sampling
            if await self._check_sampling(level, component, filters.get("sample_rates", {})):
                # Track sampled out count
                asyncio.create_task(
                    self.redis.hincrby(f"log:stats:sampled", f"{component}:{level}", 1)
                )
                return True
            
            # Check rate limiting
            if await self._check_rate_limit(message, component, filters.get("rate_limits", {})):
                # Track rate limited count
                asyncio.create_task(
                    self.redis.hincrby(f"log:stats:rate_limited", component, 1)
                )
                return True
            
            return False  # Don't filter
            
        except Exception:
            # On any error, don't filter (fail open)
            return False
    
    async def _check_suppress_patterns(self, message: str, patterns: List[str]) -> bool:
        """Check if message matches any suppression patterns.
        
        Args:
            message: Log message
            patterns: List of regex patterns to suppress
            
        Returns:
            True if message should be suppressed
        """
        if not patterns:
            return False
        
        for pattern in patterns:
            try:
                if re.search(pattern, message, re.IGNORECASE):
                    return True
            except re.error:
                # Invalid regex, skip it
                continue
        
        return False
    
    async def _check_sampling(self, level: str, component: str, sample_rates: Dict[str, float]) -> bool:
        """Check if log should be sampled out.
        
        Uses consistent hash-based sampling for deterministic behavior.
        
        Args:
            level: Log level
            component: Component name
            sample_rates: Dict of level -> sample rate (0.0 to 1.0)
            
        Returns:
            True if log should be sampled out
        """
        if not sample_rates:
            return False
        
        # Get sample rate for this level
        rate = sample_rates.get(level, 1.0)
        
        if rate >= 1.0:
            return False  # No sampling
        
        if rate <= 0.0:
            return True  # Filter all
        
        # Use Redis INCR for distributed counting
        # This ensures consistent sampling across instances
        count_key = f"log:sample:counter:{component}:{level}"
        count = await self.redis.incr(count_key)
        
        # Set TTL on first count
        if count == 1:
            await self.redis.expire(count_key, 3600)  # 1 hour TTL
        
        # Use modulo for consistent sampling
        # e.g., rate=0.1 means keep 1 in 10 (10% sampling)
        sample_interval = int(1 / rate)
        return (count % sample_interval) != 1
    
    async def _check_rate_limit(self, message: str, component: str, rate_limits: Dict[str, str]) -> bool:
        """Check if log exceeds rate limits.
        
        Uses sliding window rate limiting with Redis.
        
        Args:
            message: Log message
            component: Component name
            rate_limits: Dict of pattern -> limit (e.g., "10/minute")
            
        Returns:
            True if rate limit exceeded
        """
        if not rate_limits:
            return False
        
        # Generate message hash for deduplication
        msg_hash = md5(message.encode()).hexdigest()[:8]
        
        for limit_type, limit_spec in rate_limits.items():
            if limit_type == "same_message":
                # Rate limit identical messages
                if await self._check_window_rate_limit(
                    f"log:ratelimit:{component}:msg:{msg_hash}",
                    limit_spec
                ):
                    return True
            
            elif limit_type == "same_error" and "error" in message.lower():
                # Rate limit similar errors
                if await self._check_window_rate_limit(
                    f"log:ratelimit:{component}:error:{msg_hash}",
                    limit_spec
                ):
                    return True
        
        return False
    
    async def _check_window_rate_limit(self, key: str, limit_spec: str) -> bool:
        """Check sliding window rate limit.
        
        Args:
            key: Redis key for the rate limit counter
            limit_spec: Limit specification (e.g., "10/minute")
            
        Returns:
            True if rate limit exceeded
        """
        try:
            # Parse limit spec (e.g., "10/minute")
            parts = limit_spec.split("/")
            if len(parts) != 2:
                return False
            
            max_count = int(parts[0])
            window = parts[1].lower()
            
            # Convert window to seconds
            window_seconds = {
                "second": 1,
                "minute": 60,
                "hour": 3600,
                "day": 86400
            }.get(window, 60)
            
            # Use Redis sorted set for sliding window
            now = asyncio.get_event_loop().time()
            window_start = now - window_seconds
            
            # Remove old entries outside the window
            await self.redis.zremrangebyscore(key, 0, window_start)
            
            # Count entries in current window
            count = await self.redis.zcard(key)
            
            if count >= max_count:
                return True  # Rate limit exceeded
            
            # Add current entry
            await self.redis.zadd(key, {str(now): now})
            await self.redis.expire(key, window_seconds)
            
            return False
            
        except Exception:
            # On error, don't rate limit
            return False
    
    async def set_filter(self, component: str, filter_config: Dict[str, Any]) -> None:
        """Set filter configuration for a component.
        
        Args:
            component: Component name
            filter_config: Filter configuration dict
        """
        await self.redis.set(
            f"log:filter:{component}",
            json.dumps(filter_config)
        )
    
    async def get_filter(self, component: str) -> Optional[Dict[str, Any]]:
        """Get filter configuration for a component.
        
        Args:
            component: Component name
            
        Returns:
            Filter configuration dict or None
        """
        filter_json = await self.redis.get(f"log:filter:{component}")
        if filter_json:
            return json.loads(filter_json.decode() if isinstance(filter_json, bytes) else filter_json)
        return None
    
    async def reset_filter(self, component: str) -> None:
        """Reset (remove) filter configuration for a component.
        
        Args:
            component: Component name
        """
        await self.redis.delete(f"log:filter:{component}")
    
    async def get_stats(self) -> Dict[str, Any]:
        """Get filtering statistics.
        
        Returns:
            Dict with suppressed, sampled, and rate limited counts
        """
        stats = {
            "suppressed": {},
            "sampled": {},
            "rate_limited": {}
        }
        
        # Get suppressed counts
        suppressed = await self.redis.hgetall("log:stats:suppressed")
        for comp, count in suppressed.items():
            comp_str = comp.decode() if isinstance(comp, bytes) else comp
            stats["suppressed"][comp_str] = int(count)
        
        # Get sampled counts
        sampled = await self.redis.hgetall("log:stats:sampled")
        for key, count in sampled.items():
            key_str = key.decode() if isinstance(key, bytes) else key
            stats["sampled"][key_str] = int(count)
        
        # Get rate limited counts
        rate_limited = await self.redis.hgetall("log:stats:rate_limited")
        for comp, count in rate_limited.items():
            comp_str = comp.decode() if isinstance(comp, bytes) else comp
            stats["rate_limited"][comp_str] = int(count)
        
        return stats