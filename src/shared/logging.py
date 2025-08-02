"""Centralized structured logging configuration for MCP HTTP Proxy.

This module provides:
- Structured JSON logging with structlog
- Correlation ID tracking across requests
- Sensitive data masking
- Redis-based log storage and querying
- Performance-optimized async logging
"""

import asyncio
import json
import logging
import os
import re
import secrets
import time
from contextvars import ContextVar
from datetime import datetime, timedelta
from functools import lru_cache
from typing import Any, Dict, List, Optional, Set, Union

import redis.asyncio as redis
import structlog
from structlog.processors import JSONRenderer, TimeStamper, add_log_level
from structlog.stdlib import BoundLogger

from .config import Config

# Context variable for correlation ID tracking
correlation_id_var: ContextVar[Optional[str]] = ContextVar("correlation_id", default=None)

# Sensitive data patterns to mask
SENSITIVE_PATTERNS = [
    (r"(client_secret[\"']?\s*[:=]\s*[\"']?)([^\"'\s,}]+)", r"\1***MASKED***"),
    (r"(access_token[\"']?\s*[:=]\s*[\"']?)([^\"'\s,}]+)", r"\1***MASKED***"),
    (r"(refresh_token[\"']?\s*[:=]\s*[\"']?)([^\"'\s,}]+)", r"\1***MASKED***"),
    (r"(authorization[\"']?\s*[:=]\s*[\"']?Bearer\s+)([^\"'\s,}]+)", r"\1***MASKED***"),
    (r"(password[\"']?\s*[:=]\s*[\"']?)([^\"'\s,}]+)", r"\1***MASKED***"),
    (r"(private_key[\"']?\s*[:=]\s*[\"']?)([^\"'\s,}]+)", r"\1***MASKED***"),
    (r"(token[\"']?\s*[:=]\s*[\"']?)([^\"'\s,}]{20,})", r"\1***MASKED***"),
]


class CorrelationIDGenerator:
    """Generates unique correlation IDs for request tracking."""
    
    def __init__(self):
        self._counter = 0
        self._lock = asyncio.Lock()
    
    async def generate(self, source: str = "unknown") -> str:
        """Generate a unique correlation ID.
        
        Format: {timestamp}-{source}-{random}-{sequence}
        Example: 1735689600-https-a7b3c9d2-001
        """
        async with self._lock:
            self._counter = (self._counter + 1) % 1000
            
        timestamp = int(time.time())
        random_part = secrets.token_hex(4)
        sequence = f"{self._counter:03d}"
        
        return f"{timestamp}-{source}-{random_part}-{sequence}"
    
    def extract_parent_id(self, correlation_id: str) -> str:
        """Extract parent correlation ID for sub-requests."""
        parts = correlation_id.split("-")
        if len(parts) >= 4:
            # Keep timestamp, source, and random parts
            return "-".join(parts[:3])
        return correlation_id


class SensitiveDataMasker:
    """Masks sensitive data in log entries."""
    
    def __init__(self, patterns: Optional[List[tuple]] = None):
        self.patterns = patterns or SENSITIVE_PATTERNS
    
    def mask(self, data: Any) -> Any:
        """Recursively mask sensitive data in various data types."""
        if isinstance(data, str):
            return self._mask_string(data)
        elif isinstance(data, dict):
            return {k: self.mask(v) for k, v in data.items()}
        elif isinstance(data, list):
            return [self.mask(item) for item in data]
        elif isinstance(data, tuple):
            return tuple(self.mask(item) for item in data)
        return data
    
    def _mask_string(self, text: str) -> str:
        """Apply masking patterns to a string."""
        for pattern, replacement in self.patterns:
            text = re.sub(pattern, replacement, text, flags=re.IGNORECASE)
        return text


class RedisLogStorage:
    """Stores and queries structured logs in Redis."""
    
    def __init__(self, redis_client: redis.Redis, ttl_days: int = 7):
        self.redis = redis_client
        self.ttl_seconds = ttl_days * 86400
        self.stream_key = "logs:stream"
        self.index_prefix = "logs:index:"
    
    async def store(self, log_entry: Dict[str, Any]) -> str:
        """Store a log entry in Redis with indexing."""
        # Generate log ID
        log_id = f"{log_entry['timestamp']}-{log_entry.get('correlation_id', 'unknown')}"
        
        # Store in main stream
        await self.redis.xadd(
            self.stream_key,
            {"data": json.dumps(log_entry)},
            maxlen=1000000  # Keep last 1M entries
        )
        
        # Store full entry with TTL
        log_key = f"logs:entry:{log_id}"
        await self.redis.setex(
            log_key,
            self.ttl_seconds,
            json.dumps(log_entry)
        )
        
        # Create indexes
        await self._create_indexes(log_id, log_entry)
        
        return log_id
    
    async def _create_indexes(self, log_id: str, entry: Dict[str, Any]):
        """Create indexes for efficient querying."""
        # Index by correlation ID
        if correlation_id := entry.get("correlation_id"):
            index_key = f"{self.index_prefix}correlation:{correlation_id}"
            await self.redis.zadd(index_key, {log_id: entry["timestamp"]})
            await self.redis.expire(index_key, self.ttl_seconds)
        
        # Index by IP
        if ip := entry.get("ip"):
            index_key = f"{self.index_prefix}ip:{ip}"
            await self.redis.zadd(index_key, {log_id: entry["timestamp"]})
            await self.redis.expire(index_key, self.ttl_seconds)
        
        # Index by client ID
        if client_id := entry.get("client_id"):
            index_key = f"{self.index_prefix}client:{client_id}"
            await self.redis.zadd(index_key, {log_id: entry["timestamp"]})
            await self.redis.expire(index_key, self.ttl_seconds)
        
        # Index by hostname
        if hostname := entry.get("hostname"):
            index_key = f"{self.index_prefix}host:{hostname}"
            await self.redis.zadd(index_key, {log_id: entry["timestamp"]})
            await self.redis.expire(index_key, self.ttl_seconds)
        
        # Index by error type
        if error := entry.get("error", {}).get("type"):
            index_key = f"{self.index_prefix}error:{error}"
            await self.redis.zadd(index_key, {log_id: entry["timestamp"]})
            await self.redis.expire(index_key, self.ttl_seconds)
    
    async def query_by_ip(self, ip: str, hours: int = 24) -> List[Dict[str, Any]]:
        """Query logs by IP address."""
        return await self._query_by_index(f"ip:{ip}", hours)
    
    async def query_by_client(self, client_id: str, hours: int = 24) -> List[Dict[str, Any]]:
        """Query logs by OAuth client ID."""
        return await self._query_by_index(f"client:{client_id}", hours)
    
    async def query_by_correlation(self, correlation_id: str) -> List[Dict[str, Any]]:
        """Query all logs for a correlation ID flow."""
        index_key = f"{self.index_prefix}correlation:{correlation_id}"
        log_ids = await self.redis.zrange(index_key, 0, -1)
        
        logs = []
        for log_id in log_ids:
            log_key = f"logs:entry:{log_id.decode() if isinstance(log_id, bytes) else log_id}"
            if data := await self.redis.get(log_key):
                logs.append(json.loads(data))
        
        # Also get sub-requests
        parent_pattern = f"logs:entry:{correlation_id}*"
        cursor = 0
        while True:
            cursor, keys = await self.redis.scan(
                cursor, match=parent_pattern, count=100
            )
            for key in keys:
                if data := await self.redis.get(key):
                    log_entry = json.loads(data)
                    if log_entry not in logs:
                        logs.append(log_entry)
            if cursor == 0:
                break
        
        return sorted(logs, key=lambda x: x.get("timestamp", 0))
    
    async def _query_by_index(self, index_suffix: str, hours: int) -> List[Dict[str, Any]]:
        """Query logs using an index."""
        index_key = f"{self.index_prefix}{index_suffix}"
        min_timestamp = time.time() - (hours * 3600)
        
        log_ids = await self.redis.zrangebyscore(
            index_key, min_timestamp, "+inf"
        )
        
        logs = []
        for log_id in log_ids:
            log_key = f"logs:entry:{log_id.decode() if isinstance(log_id, bytes) else log_id}"
            if data := await self.redis.get(log_key):
                logs.append(json.loads(data))
        
        return sorted(logs, key=lambda x: x.get("timestamp", 0))


class AsyncRedisLogHandler(logging.Handler):
    """Async logging handler that stores logs in Redis."""
    
    def __init__(self, storage: RedisLogStorage, masker: SensitiveDataMasker):
        super().__init__()
        self.storage = storage
        self.masker = masker
        self._queue = asyncio.Queue(maxsize=1000)
        self._task = None
    
    def emit(self, record: logging.LogRecord):
        """Queue log record for async processing."""
        try:
            # Convert to dict and mask sensitive data
            log_entry = {
                "timestamp": record.created,
                "level": record.levelname,
                "component": record.name,
                "message": record.getMessage(),
                "correlation_id": getattr(record, "correlation_id", None),
                "ip": getattr(record, "ip", None),
                "client_id": getattr(record, "client_id", None),
                "hostname": getattr(record, "hostname", None),
                "user_id": getattr(record, "user_id", None),
                "method": getattr(record, "method", None),
                "path": getattr(record, "path", None),
                "status": getattr(record, "status", None),
                "duration_ms": getattr(record, "duration_ms", None),
                "error": getattr(record, "error", None),
                "context": getattr(record, "context", {}),
            }
            
            # Remove None values
            log_entry = {k: v for k, v in log_entry.items() if v is not None}
            
            # Mask sensitive data
            log_entry = self.masker.mask(log_entry)
            
            # Queue for async storage
            if self._task and not self._task.done():
                try:
                    self._queue.put_nowait(log_entry)
                except asyncio.QueueFull:
                    pass  # Drop log if queue is full
        except Exception:
            # Silently fail to avoid logging loops
            pass
    
    async def start(self):
        """Start the async log processor."""
        self._task = asyncio.create_task(self._process_logs())
    
    async def stop(self):
        """Stop the async log processor."""
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
    
    async def _process_logs(self):
        """Process queued logs and store in Redis."""
        while True:
            try:
                # Batch process logs
                batch = []
                deadline = time.time() + 0.1  # 100ms batch window
                
                while time.time() < deadline and len(batch) < 100:
                    try:
                        timeout = max(0, deadline - time.time())
                        log_entry = await asyncio.wait_for(
                            self._queue.get(), timeout=timeout
                        )
                        batch.append(log_entry)
                    except asyncio.TimeoutError:
                        break
                
                # Store batch
                if batch:
                    for entry in batch:
                        await self.storage.store(entry)
                        
            except asyncio.CancelledError:
                # Process remaining logs before shutdown
                while not self._queue.empty():
                    log_entry = self._queue.get_nowait()
                    await self.storage.store(log_entry)
                raise
            except Exception:
                # Silently continue on errors
                await asyncio.sleep(1)


def inject_correlation_id(logger, method_name, event_dict):
    """Inject correlation ID into all log entries."""
    if correlation_id := correlation_id_var.get():
        event_dict["correlation_id"] = correlation_id
    return event_dict


def inject_request_context(logger, method_name, event_dict):
    """Inject request context into log entries."""
    # This will be called with request context set
    return event_dict


@lru_cache(maxsize=1)
def get_logger_config() -> Dict[str, Any]:
    """Get logger configuration from environment."""
    return {
        "level": getattr(logging, Config.LOG_LEVEL, logging.INFO),
        "format": os.getenv("LOG_FORMAT", "json"),
        "enable_redis": os.getenv("LOG_STORAGE", "redis") == "redis",
        "mask_sensitive": os.getenv("LOG_SENSITIVE_MASK", "true").lower() == "true",
        "log_request_body": os.getenv("LOG_REQUEST_BODY", "true").lower() == "true",
        "log_response_body": os.getenv("LOG_RESPONSE_BODY", "true").lower() == "true",
        "max_body_size": int(os.getenv("LOG_MAX_BODY_SIZE", "10240")),
        "sampling_rate": float(os.getenv("LOG_SAMPLING_RATE", "1.0")),
    }


def configure_logging(redis_client: Optional[redis.Redis] = None) -> Dict[str, Any]:
    """Configure structured logging for the application.
    
    Returns:
        Dict containing logger instances and utilities
    """
    config = get_logger_config()
    
    # Create processors
    processors = [
        structlog.stdlib.filter_by_level,
        structlog.stdlib.add_logger_name,
        structlog.stdlib.add_log_level,
        inject_correlation_id,
        inject_request_context,
        structlog.stdlib.PositionalArgumentsFormatter(),
        TimeStamper(fmt="iso"),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
    ]
    
    # Add JSON renderer for production
    if config["format"] == "json":
        processors.append(JSONRenderer())
    else:
        processors.append(structlog.dev.ConsoleRenderer())
    
    # Configure structlog
    structlog.configure(
        processors=processors,
        context_class=dict,
        logger_factory=structlog.stdlib.LoggerFactory(),
        cache_logger_on_first_use=True,
    )
    
    # Configure standard logging
    logging.basicConfig(
        format="%(message)s",
        level=config["level"],
    )
    
    # Create components
    correlation_generator = CorrelationIDGenerator()
    masker = SensitiveDataMasker() if config["mask_sensitive"] else None
    redis_handler = None
    log_storage = None
    
    if redis_client and config["enable_redis"]:
        log_storage = RedisLogStorage(redis_client)
        redis_handler = AsyncRedisLogHandler(log_storage, masker)
        
        # Check if we already have a Redis handler to avoid duplicates
        root_logger = logging.getLogger()
        has_redis_handler = any(
            isinstance(h, AsyncRedisLogHandler) for h in root_logger.handlers
        )
        
        if not has_redis_handler:
            root_logger.addHandler(redis_handler)
    
    return {
        "logger": structlog.get_logger(),
        "correlation_generator": correlation_generator,
        "masker": masker,
        "log_storage": log_storage,
        "redis_handler": redis_handler,
        "config": config,
    }


def get_logger(name: str) -> BoundLogger:
    """Get a structured logger instance."""
    return structlog.get_logger(name)


# Global request logger instance
_request_logger = None

def get_request_logger():
    """Get the global request logger instance."""
    return _request_logger

def set_request_logger(logger):
    """Set the global request logger instance."""
    global _request_logger
    _request_logger = logger

# Request logging utilities
async def log_request(
    logger: BoundLogger,
    request: Any,
    correlation_id: str,
    ip: str,
    **extra_context
) -> Dict[str, Any]:
    """Log HTTP request details."""
    config = get_logger_config()
    
    log_data = {
        "correlation_id": correlation_id,
        "ip": ip,
        "method": request.method,
        "path": str(request.url.path),
        "query": str(request.url.query) if request.url.query else None,
        "hostname": request.headers.get("host"),
        "user_agent": request.headers.get("user-agent"),
        **extra_context
    }
    
    # Log request body if enabled
    if config["log_request_body"] and hasattr(request, "body"):
        try:
            body = await request.body()
            if body and len(body) <= config["max_body_size"]:
                log_data["request_body"] = body.decode("utf-8", errors="ignore")
        except Exception:
            pass
    
    # Log to structlog for console output
    logger.info("Request received", **log_data)
    
    # Also log to RequestLogger if available
    request_logger = get_request_logger()
    if request_logger:
        try:
            await request_logger.log_request(
                correlation_id=correlation_id,
                ip=ip,
                hostname=log_data.get("hostname", ""),
                method=log_data.get("method", ""),
                path=log_data.get("path", ""),
                query=log_data.get("query", ""),
                user_agent=log_data.get("user_agent", ""),
                auth_user=extra_context.get("auth_user"),
                **{k: v for k, v in extra_context.items() if k not in ["hostname", "auth_user"]}
            )
        except Exception as e:
            logger.error(f"Failed to log request to RequestLogger: {e}")
    
    return log_data


async def log_response(
    logger: BoundLogger,
    response: Any,
    duration_ms: float,
    correlation_id: str,
    **extra_context
) -> Dict[str, Any]:
    """Log HTTP response details."""
    config = get_logger_config()
    
    log_data = {
        "correlation_id": correlation_id,
        "status": getattr(response, "status_code", None),
        "duration_ms": round(duration_ms, 2),
        **extra_context
    }
    
    # Log response body for errors
    if config["log_response_body"] and log_data.get("status", 0) >= 400:
        try:
            if hasattr(response, "body"):
                body = response.body
                if isinstance(body, bytes):
                    body = body.decode("utf-8", errors="ignore")
                if len(body) <= config["max_body_size"]:
                    log_data["response_body"] = body
        except Exception:
            pass
    
    level = "error" if log_data.get("status", 0) >= 500 else "info"
    getattr(logger, level)("Response sent", **log_data)
    
    # Also log to RequestLogger if available
    request_logger = get_request_logger()
    if request_logger:
        try:
            error = None
            if log_data.get("status", 0) >= 400:
                error = {
                    "type": f"http_{log_data.get('status', 'unknown')}",
                    "message": log_data.get("response_body", "")
                }
            
            await request_logger.log_response(
                correlation_id=correlation_id,
                status=log_data.get("status", 0),
                duration_ms=duration_ms,
                response_size=len(log_data.get("response_body", "")),
                error=error,
                **{k: v for k, v in extra_context.items() if k not in ["hostname", "status"]}
            )
        except Exception as e:
            logger.error(f"Failed to log response to RequestLogger: {e}")
    
    return log_data