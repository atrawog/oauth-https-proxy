"""
HTTP Request/Response logging with efficient Redis indexing.

This module provides high-performance logging for HTTP requests and responses
using async Redis for storage and multiple indexes for efficient querying.
"""

import asyncio
import time
import json
from typing import Dict, List, Optional, Any
from datetime import datetime, timezone
import redis.asyncio as redis_async

from .config import Config
from .logging import get_logger

logger = get_logger(__name__)


class RequestLogger:
    """High-performance HTTP request logger with Redis indexing."""
    
    def __init__(self, redis_url: str):
        """Initialize with async Redis connection."""
        self.redis = redis_async.from_url(redis_url, decode_responses=True)
        self.ttl_seconds = 86400  # 24 hours
        self.max_stream_length = 100000  # Keep last 100k entries
        
    async def log_request(
        self,
        ip: str,
        hostname: str,
        method: str,
        path: str,
        query: Optional[str] = None,
        user_agent: Optional[str] = None,
        auth_user: Optional[str] = None,
        referer: Optional[str] = None,
        **extra_fields
    ) -> None:
        """Log HTTP request with multiple indexes for efficient querying."""
        timestamp = time.time()
        
        # Create request data
        request_data = {
            "timestamp": timestamp,
            "ip": ip,
            "hostname": hostname,
            "method": method,
            "path": path,
            "query": query or "",
            "user_agent": user_agent or "",
            "auth_user": auth_user or "",
            "referer": referer or "",
            "type": "request",
            **extra_fields
        }
        
        # Generate unique key using IP and timestamp
        sequence = int((timestamp * 1000) % 1000000)
        request_key = f"req:{ip}:{int(timestamp)}:{sequence}"
        await self.redis.hset(request_key, mapping=request_data)
        await self.redis.expire(request_key, self.ttl_seconds)
        
        # Create multiple indexes for querying
        # Index by IP
        await self.redis.zadd(f"idx:req:ip:{ip}", {request_key: timestamp})
        await self.redis.expire(f"idx:req:ip:{ip}", self.ttl_seconds)
        
        # Index by hostname
        await self.redis.zadd(f"idx:req:host:{hostname}", {request_key: timestamp})
        await self.redis.expire(f"idx:req:host:{hostname}", self.ttl_seconds)
        
        # Index by user if authenticated
        if auth_user:
            await self.redis.zadd(f"idx:req:user:{auth_user}", {request_key: timestamp})
            await self.redis.expire(f"idx:req:user:{auth_user}", self.ttl_seconds)
        
        # OAuth-specific indexes
        if oauth_client_id := extra_fields.get("oauth_client_id"):
            await self.redis.zadd(f"idx:req:oauth:client:{oauth_client_id}", {request_key: timestamp})
            await self.redis.expire(f"idx:req:oauth:client:{oauth_client_id}", self.ttl_seconds)
        
        if oauth_username := extra_fields.get("oauth_username"):
            await self.redis.zadd(f"idx:req:oauth:user:{oauth_username}", {request_key: timestamp})
            await self.redis.expire(f"idx:req:oauth:user:{oauth_username}", self.ttl_seconds)
        
        if oauth_token_jti := extra_fields.get("oauth_token_jti"):
            await self.redis.zadd(f"idx:req:oauth:token:{oauth_token_jti}", {request_key: timestamp})
            await self.redis.expire(f"idx:req:oauth:token:{oauth_token_jti}", self.ttl_seconds)
        
        # Global timeline index
        await self.redis.zadd("idx:req:all", {request_key: timestamp})
        
        # Path pattern index (for analyzing popular endpoints)
        path_pattern = f"{method}:{path.split('?')[0]}"
        await self.redis.zadd(f"idx:req:path:{path_pattern}", {request_key: timestamp})
        await self.redis.expire(f"idx:req:path:{path_pattern}", self.ttl_seconds)
        
        # Live stream for real-time monitoring
        await self.redis.xadd(
            "stream:requests",
            {
                "ip": ip,
                "hostname": hostname,
                "method": method,
                "path": path,
                "timestamp": str(timestamp)
            },
            maxlen=self.max_stream_length
        )
        
        # Update statistics
        date_hour = datetime.fromtimestamp(timestamp, timezone.utc).strftime("%Y%m%d:%H")
        await self.redis.hincrby(f"stats:requests:{date_hour}", hostname, 1)
        await self.redis.expire(f"stats:requests:{date_hour}", 3600 * 48)  # Keep 48 hours
        
        # Track unique IPs
        await self.redis.pfadd(f"stats:unique_ips:{date_hour}", ip)
        await self.redis.pfadd(f"stats:unique_ips:{hostname}:{date_hour}", ip)
        
        # Return the request key for linking with response
        return request_key
        
    async def log_response(
        self,
        ip: str,
        status: int,
        duration_ms: float,
        response_size: Optional[int] = None,
        error: Optional[Dict[str, Any]] = None,
        **extra_fields
    ) -> None:
        """Log HTTP response data."""
        timestamp = time.time()
        
        # Generate response key using IP and timestamp
        sequence = int((timestamp * 1000) % 1000000)
        response_key = f"resp:{ip}:{int(timestamp)}:{sequence}"
        
        # Create response data
        response_data = {
            "timestamp": timestamp,
            "ip": ip,
            "status": status,
            "duration_ms": round(duration_ms, 2),
            "response_size": response_size or 0,
            "type": "response",
            **extra_fields
        }
        
        if error:
            response_data["error_type"] = error.get("type", "unknown")
            response_data["error_message"] = error.get("message", "")
        
        # Store response data separately
        await self.redis.hset(response_key, mapping=response_data)
        await self.redis.expire(response_key, self.ttl_seconds)
        
        # Index by status code
        await self.redis.zadd(f"idx:req:status:{status}", {response_key: timestamp})
        await self.redis.expire(f"idx:req:status:{status}", self.ttl_seconds)
        
        # Index by IP for responses
        await self.redis.zadd(f"idx:resp:ip:{ip}", {response_key: timestamp})
        await self.redis.expire(f"idx:resp:ip:{ip}", self.ttl_seconds)
        
        # Index errors specially
        if status >= 400:
            await self.redis.zadd(f"idx:req:errors", {response_key: timestamp})
            
            # Track error statistics
            if hostname := extra_fields.get("hostname", "unknown"):
                
                # Track error rates
                date_hour = datetime.fromtimestamp(timestamp, timezone.utc).strftime("%Y%m%d:%H")
                await self.redis.hincrby(f"stats:errors:{date_hour}", hostname, 1)
                await self.redis.expire(f"stats:errors:{date_hour}", 3600 * 48)
                
                # Track error types
                if error:
                    error_type = error.get("type", f"http_{status}")
                    await self.redis.hincrby(f"stats:error_types:{date_hour}", error_type, 1)
                    await self.redis.expire(f"stats:error_types:{date_hour}", 3600 * 48)
        
        # Index slow requests
        if duration_ms > 1000:  # Requests over 1 second
            await self.redis.zadd(f"idx:req:slow", {response_key: duration_ms})
        
        # Update response time statistics
        if hostname := extra_fields.get("hostname", "unknown"):
            # Track p50, p95, p99 in time windows
            await self._update_response_time_stats(hostname, duration_ms)
    
    async def _update_response_time_stats(self, hostname: str, duration_ms: float):
        """Update response time statistics for monitoring."""
        # Use a sliding window for response times
        window_key = f"stats:response_times:{hostname}"
        timestamp = time.time()
        
        # Add to sorted set with timestamp as score
        await self.redis.zadd(window_key, {f"{timestamp}:{duration_ms}": timestamp})
        
        # Remove old entries (keep 5 minutes)
        await self.redis.zremrangebyscore(window_key, 0, timestamp - 300)
        await self.redis.expire(window_key, 600)
    
    async def query_by_ip(self, ip: str, hours: int = 24, limit: int = 100) -> List[Dict[str, Any]]:
        """Query requests and responses by IP address."""
        min_timestamp = time.time() - (hours * 3600)
        
        # Get request keys from index
        request_keys = await self.redis.zrangebyscore(
            f"idx:req:ip:{ip}",
            min_timestamp,
            "+inf",
            start=0,
            num=limit // 2  # Split limit between requests and responses
        )
        
        # Get response keys from index
        response_keys = await self.redis.zrangebyscore(
            f"idx:resp:ip:{ip}",
            min_timestamp,
            "+inf",
            start=0,
            num=limit // 2
        )
        
        # Batch fetch all data
        all_keys = list(request_keys) + list(response_keys)
        if not all_keys:
            return []
        
        pipeline = self.redis.pipeline()
        for key in all_keys:
            pipeline.hgetall(key)
        
        results = await pipeline.execute()
        # Sort by timestamp
        data = [r for r in results if r]
        return sorted(data, key=lambda x: float(x.get('timestamp', 0)))
    
    async def query_by_hostname(self, hostname: str, hours: int = 24, limit: int = 100) -> List[Dict[str, Any]]:
        """Query requests by hostname."""
        min_timestamp = time.time() - (hours * 3600)
        
        request_keys = await self.redis.zrangebyscore(
            f"idx:req:host:{hostname}",
            min_timestamp,
            "+inf",
            start=0,
            num=limit
        )
        
        if not request_keys:
            return []
        
        pipeline = self.redis.pipeline()
        for key in request_keys:
            pipeline.hgetall(key)
        
        requests = await pipeline.execute()
        return [r for r in requests if r]
    
    async def query_recent_errors(self, hours: int = 1, limit: int = 50) -> List[Dict[str, Any]]:
        """Query recent errors."""
        min_timestamp = time.time() - (hours * 3600)
        
        request_keys = await self.redis.zrangebyscore(
            "idx:req:errors",
            min_timestamp,
            "+inf",
            start=0,
            num=limit
        )
        
        if not request_keys:
            return []
        
        pipeline = self.redis.pipeline()
        for key in request_keys:
            pipeline.hgetall(key)
        
        requests = await pipeline.execute()
        return [r for r in requests if r]
    
    async def get_stats(self, hostname: Optional[str] = None) -> Dict[str, Any]:
        """Get current statistics."""
        current_hour = datetime.now(timezone.utc).strftime("%Y%m%d:%H")
        
        stats = {
            "current_hour": current_hour,
            "requests": {},
            "errors": {},
            "unique_ips": {}
        }
        
        # Get request counts
        request_counts = await self.redis.hgetall(f"stats:requests:{current_hour}")
        stats["requests"] = {k: int(v) for k, v in request_counts.items()}
        
        # Get error counts
        error_counts = await self.redis.hgetall(f"stats:errors:{current_hour}")
        stats["errors"] = {k: int(v) for k, v in error_counts.items()}
        
        # Get unique IP counts
        if hostname:
            unique_ips = await self.redis.pfcount(f"stats:unique_ips:{hostname}:{current_hour}")
            stats["unique_ips"][hostname] = unique_ips
        else:
            # Get total unique IPs
            total_unique = await self.redis.pfcount(f"stats:unique_ips:{current_hour}")
            stats["unique_ips"]["total"] = total_unique
        
        return stats
    
    async def close(self):
        """Close Redis connection."""
        await self.redis.close()