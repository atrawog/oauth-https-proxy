"""Centralized structured logging configuration for MCP HTTP Proxy.

This module provides:
- Structured JSON logging with structlog
- IP-based request tracking
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
# No ContextVar needed - using IP as primary identifier
from datetime import datetime, timedelta
from functools import lru_cache
from typing import Any, Dict, List, Optional, Set, Union

import redis.asyncio as redis
import structlog
from structlog.processors import JSONRenderer, TimeStamper, add_log_level
from structlog.stdlib import BoundLogger

from .config import Config

# Using IP as primary identifier for request tracking

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


# Using IP-based tracking instead of correlation IDs


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
        log_id = f"{log_entry['timestamp']}-{log_entry.get('client_ip', 'unknown')}"
        
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
        # Index by client IP
        if client_ip := entry.get("client_ip"):
            index_key = f"{self.index_prefix}ip:{client_ip}"
            await self.redis.zadd(index_key, {log_id: entry["timestamp"]})
            await self.redis.expire(index_key, self.ttl_seconds)
        
        # Index by client ID
        if client_id := entry.get("client_id"):
            index_key = f"{self.index_prefix}client:{client_id}"
            await self.redis.zadd(index_key, {log_id: entry["timestamp"]})
            await self.redis.expire(index_key, self.ttl_seconds)
        
        # Index by proxy hostname
        if proxy_hostname := entry.get("proxy_hostname"):
            index_key = f"{self.index_prefix}host:{proxy_hostname}"
            await self.redis.zadd(index_key, {log_id: entry["timestamp"]})
            await self.redis.expire(index_key, self.ttl_seconds)
        
        # Index by error type
        if error := entry.get("error", {}).get("type"):
            index_key = f"{self.index_prefix}error:{error}"
            await self.redis.zadd(index_key, {log_id: entry["timestamp"]})
            await self.redis.expire(index_key, self.ttl_seconds)
    
    async def query_by_ip(self, client_ip: str, hours: int = 24) -> List[Dict[str, Any]]:
        """Query logs by client IP address."""
        return await self._query_by_index(f"ip:{client_ip}", hours)
    
    async def query_by_client(self, client_id: str, hours: int = 24) -> List[Dict[str, Any]]:
        """Query logs by OAuth client ID."""
        return await self._query_by_index(f"client:{client_id}", hours)
    
    # Removed query_by_correlation - using IP as primary identifier
    
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
                "client_ip": getattr(record, "client_ip", None),
                "client_id": getattr(record, "client_id", None),
                "proxy_hostname": getattr(record, "proxy_hostname", None),
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


# Using IP as primary identifier for log tracking


def inject_request_context(logger, method_name, event_dict):
    """Inject request context into log entries."""
    # This will be called with request context set
    return event_dict


class IPLogCapture:
    """Captures all logs containing IP addresses and sends them to RequestLogger."""
    
    def __init__(self, request_logger):
        self.request_logger = request_logger
        self._queue = []
        self._processing = False
    
    def __call__(self, logger, method_name, event_dict):
        """Process log entries and capture those with IP addresses."""
        # Skip if this is a RequestLogger call to avoid recursion
        if event_dict.get("logger", "").startswith("src.shared.request_logger"):
            return event_dict
            
        # Extract client IP from various possible fields
        client_ip = None
        for field in ["client_ip", "x_real_ip", "x_forwarded_for"]:
            if field in event_dict:
                client_ip = event_dict[field]
                break
        
        # Also check message for IP patterns
        if not client_ip and "event" in event_dict:
            import re
            ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
            match = re.search(ip_pattern, str(event_dict.get("event", "")))
            if match:
                client_ip = match.group()
        
        # If we found a client IP and have a request logger, queue for logging
        if client_ip and self.request_logger:
            # Extract relevant fields for RequestLogger
            proxy_hostname = event_dict.get("proxy_hostname", "")
            method = event_dict.get("method", "SYSTEM")
            path = event_dict.get("path", "/system/log")
            
            # Create log entry
            log_data = {
                "client_ip": client_ip,
                "proxy_hostname": proxy_hostname,
                "method": method,
                "path": path,
                "log_level": event_dict.get("level", "INFO"),
                "component": event_dict.get("logger", ""),
                "message": event_dict.get("event", ""),
                "timestamp": event_dict.get("timestamp", ""),
                "full_event": {k: v for k, v in event_dict.items() if k not in ["_queue", "_processing"]}
            }
            
            # Queue for later processing
            self._queue.append(log_data)
            
            # Try to process queue if not already processing
            if not self._processing:
                self._process_queue()
        
        return event_dict
    
    def _process_queue(self):
        """Process queued log entries."""
        if not self._queue or self._processing:
            return
            
        self._processing = True
        try:
            import asyncio
            try:
                loop = asyncio.get_event_loop()
                if loop.is_running():
                    # Process all queued items
                    items = self._queue[:]
                    self._queue.clear()
                    
                    # Create a single task to process all items
                    asyncio.create_task(self._log_batch_to_request_logger(items))
            except RuntimeError:
                # No event loop or not running
                self._queue.clear()
        except Exception:
            # Clear queue on any error
            self._queue.clear()
        finally:
            self._processing = False
    
    async def _log_batch_to_request_logger(self, items):
        """Asynchronously log a batch of entries to RequestLogger."""
        for log_data in items:
            try:
                # Create a dictionary with all log data
                request_data = {
                    "client_ip": log_data["client_ip"],
                    "proxy_hostname": log_data["proxy_hostname"],
                    "method": log_data["method"],
                    "path": log_data["path"],
                    "query": "",
                    "user_agent": "system-logger",
                    "auth_user": None,
                    "referer": None,
                    "log_level": log_data["log_level"],
                    "component": log_data["component"],
                    "message": log_data["message"],
                    "system_log": True,
                }
                # Add all fields from full_event
                request_data.update(log_data["full_event"])
                
                # Unpack dictionary to pass as individual parameters
                await self.request_logger.log_request(
                    ip=request_data.get("ip"),
                    hostname=request_data.get("hostname"),
                    method=request_data.get("method"),
                    path=request_data.get("path"),
                    query=request_data.get("query"),
                    user_agent=request_data.get("user_agent"),
                    auth_user=request_data.get("auth_user"),
                    referer=request_data.get("referer"),
                    **{k: v for k, v in request_data.items() 
                       if k not in ["ip", "hostname", "method", "path", "query", "user_agent", "auth_user", "referer"]}
                )
            except Exception:
                # Silently fail for individual items
                pass


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


def configure_logging(redis_client: Optional[redis.Redis] = None, request_logger=None) -> Dict[str, Any]:
    """Configure structured logging for the application.
    
    Args:
        redis_client: Redis client for log storage
        request_logger: RequestLogger instance for IP-based log capture
    
    Returns:
        Dict containing logger instances and utilities
    """
    config = get_logger_config()
    
    # Create processors
    processors = [
        structlog.stdlib.filter_by_level,
        structlog.stdlib.add_logger_name,
        structlog.stdlib.add_log_level,
        inject_request_context,
        structlog.stdlib.PositionalArgumentsFormatter(),
        TimeStamper(fmt="iso"),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
    ]
    
    # Add IP log capture processor if RequestLogger is available
    if request_logger:
        processors.insert(4, IPLogCapture(request_logger))  # Insert after inject_request_context
    
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
    
    result = {
        "logger": structlog.get_logger(),
        "masker": masker,
        "log_storage": log_storage,
        "redis_handler": redis_handler,
        "config": config,
    }
    
    # Save configuration state globally
    global _logging_config
    _logging_config = result
    
    return result


def get_logger(name: str) -> BoundLogger:
    """Get a structured logger instance."""
    return structlog.get_logger(name)


# Global request logger instance
_request_logger = None
_logging_config = None

def get_request_logger():
    """Get the global request logger instance."""
    return _request_logger

def set_request_logger(logger):
    """Set the global request logger instance and reconfigure logging."""
    global _request_logger, _logging_config
    _request_logger = logger
    
    # If logging was already configured, reconfigure with RequestLogger
    if _logging_config and logger:
        reconfigure_with_request_logger(logger)

def reconfigure_with_request_logger(request_logger):
    """Reconfigure logging to include IP log capture."""
    config = get_logger_config()
    
    # Create processors with IP capture
    processors = [
        structlog.stdlib.filter_by_level,
        structlog.stdlib.add_logger_name,
        structlog.stdlib.add_log_level,
        inject_request_context,
        IPLogCapture(request_logger),  # Add IP capture
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
    
    # Reconfigure structlog with new processors
    structlog.configure(
        processors=processors,
        context_class=dict,
        logger_factory=structlog.stdlib.LoggerFactory(),
        cache_logger_on_first_use=False,  # Don't cache to allow reconfiguration
    )

# Request logging utilities
async def log_request(
    logger: BoundLogger,
    request: Any,
    client_ip: str,
    **extra_context
) -> Dict[str, Any]:
    """Log HTTP request details with enhanced body logging for OAuth/MCP endpoints."""
    config = get_logger_config()
    
    log_data = {
        "client_ip": client_ip,
        "method": request.method,
        "path": str(request.url.path),
        "query": str(request.url.query) if request.url.query else None,
        "proxy_hostname": request.headers.get("host"),  # Domain being accessed
        "user_agent": request.headers.get("user-agent"),
        "referer": request.headers.get("referer"),
        **extra_context
    }
    
    # Enhanced request body logging for critical endpoints
    request_path = str(request.url.path)
    is_critical_endpoint = any(path in request_path for path in [
        "/token", "/mcp", "/authorize", "/verify", "/introspect", 
        "/.well-known/oauth-protected-resource", "/.well-known/oauth-authorization-server"
    ])
    
    # Log request body if enabled or if it's a critical endpoint
    if (config["log_request_body"] or is_critical_endpoint) and hasattr(request, "body"):
        try:
            body = await request.body()
            if body:
                body_text = body.decode("utf-8", errors="ignore")
                
                # For critical endpoints, always log (with size limit)
                if is_critical_endpoint:
                    max_size = config["max_body_size"] * 2  # Double the limit for critical endpoints
                    if len(body_text) <= max_size:
                        log_data["request_body"] = body_text
                        log_data["request_body_size"] = len(body_text)
                    else:
                        log_data["request_body"] = body_text[:max_size] + "... [TRUNCATED]"
                        log_data["request_body_size"] = len(body_text)
                        log_data["request_body_truncated"] = True
                    
                    # Parse form data for OAuth endpoints
                    if request.headers.get("content-type", "").startswith("application/x-www-form-urlencoded"):
                        try:
                            from urllib.parse import parse_qs
                            form_data = parse_qs(body_text)
                            # Mask sensitive fields
                            masked_form_data = {}
                            for key, values in form_data.items():
                                if key.lower() in ["client_secret", "code", "refresh_token", "code_verifier"]:
                                    masked_form_data[key] = ["***MASKED***" for _ in values]
                                else:
                                    masked_form_data[key] = values
                            log_data["request_form_data"] = masked_form_data
                        except Exception:
                            pass
                
                elif len(body_text) <= config["max_body_size"]:
                    log_data["request_body"] = body_text
                    log_data["request_body_size"] = len(body_text)
        except Exception as e:
            log_data["request_body_error"] = str(e)
    
    # Add headers for critical endpoints
    if is_critical_endpoint:
        critical_headers = {}
        for header_name in ["authorization", "content-type", "accept", "x-forwarded-host", "x-forwarded-proto"]:
            header_value = request.headers.get(header_name)
            if header_value:
                if header_name == "authorization":
                    # Mask authorization header
                    critical_headers[header_name] = header_value[:20] + "..." if len(header_value) > 20 else header_value
                else:
                    critical_headers[header_name] = header_value
        log_data["critical_headers"] = critical_headers
        log_data["is_critical_endpoint"] = True
    
    # Log to structlog for console output
    logger.info("Request received", **log_data)
    
    # Also log to RequestLogger if available
    request_logger = get_request_logger()
    request_key = None
    if request_logger:
        try:
            # Create a dictionary with all request data
            request_data = {
                "client_ip": client_ip,
                "proxy_hostname": log_data.get("proxy_hostname", ""),  # Domain being accessed
                "method": log_data.get("method", ""),
                "path": log_data.get("path", ""),
                "query": log_data.get("query", ""),
                "user_agent": log_data.get("user_agent", ""),
                "auth_user": extra_context.get("auth_user"),
                "referer": log_data.get("referer", ""),
                # Include ALL enhanced logging data for OAuth debugging
                "request_body": log_data.get("request_body", ""),
                "request_body_size": log_data.get("request_body_size", 0),
                "request_body_truncated": log_data.get("request_body_truncated", False),
                "request_form_data": log_data.get("request_form_data", {}),
                "critical_headers": log_data.get("critical_headers", {}),
                "is_critical_endpoint": log_data.get("is_critical_endpoint", False),
            }
            # Add extra context fields
            for k, v in extra_context.items():
                if k not in ["hostname", "auth_user"]:
                    request_data[k] = v
            
            # Unpack dictionary to pass as individual parameters
            request_key = await request_logger.log_request(
                ip=request_data.get("ip"),
                hostname=request_data.get("hostname"),
                method=request_data.get("method"),
                path=request_data.get("path"),
                query=request_data.get("query"),
                user_agent=request_data.get("user_agent"),
                auth_user=request_data.get("auth_user"),
                referer=request_data.get("referer"),
                **{k: v for k, v in request_data.items() 
                   if k not in ["ip", "hostname", "method", "path", "query", "user_agent", "auth_user", "referer"]}
            )
            log_data["_request_key"] = request_key  # Store for later use
        except Exception as e:
            logger.error(f"Failed to log request to RequestLogger: {e}")
    
    return log_data


async def log_response(
    logger: BoundLogger,
    response: Any,
    duration_ms: float,
    request_key: Optional[str] = None,
    **extra_context
) -> Dict[str, Any]:
    """Log HTTP response details with enhanced body logging for OAuth/MCP endpoints."""
    config = get_logger_config()
    
    log_data = {
        "status": getattr(response, "status_code", None),
        "duration_ms": round(duration_ms, 2),
        **extra_context
    }
    
    # Determine if this is a critical endpoint response
    request_path = extra_context.get("path", "")
    is_critical_endpoint = any(path in str(request_path) for path in [
        "/token", "/mcp", "/authorize", "/verify", "/introspect", 
        "/.well-known/oauth-protected-resource", "/.well-known/oauth-authorization-server"
    ]) or extra_context.get("is_critical_endpoint", False)
    
    # Enhanced response body logging
    should_log_body = (
        config["log_response_body"] or 
        is_critical_endpoint or 
        log_data.get("status", 0) >= 400  # Always log error responses
    )
    
    if should_log_body:
        try:
            body = None
            if hasattr(response, "body"):
                body = response.body
            elif hasattr(response, "content"):
                body = response.content
            
            if body:
                if isinstance(body, bytes):
                    body_text = body.decode("utf-8", errors="ignore")
                else:
                    body_text = str(body)
                
                # For critical endpoints or errors, be more generous with size limits
                max_size = config["max_body_size"]
                if is_critical_endpoint or log_data.get("status", 0) >= 400:
                    max_size *= 3  # Triple the limit for critical endpoints and errors
                
                if len(body_text) <= max_size:
                    log_data["response_body"] = body_text
                    log_data["response_body_size"] = len(body_text)
                else:
                    log_data["response_body"] = body_text[:max_size] + "... [TRUNCATED]"
                    log_data["response_body_size"] = len(body_text)
                    log_data["response_body_truncated"] = True
                
                # Try to parse JSON responses for better logging
                if body_text.strip().startswith(('{', '[')):
                    try:
                        import json
                        parsed_body = json.loads(body_text)
                        
                        # For OAuth token responses, mask sensitive data
                        if isinstance(parsed_body, dict) and "access_token" in parsed_body:
                            masked_body = parsed_body.copy()
                            for sensitive_key in ["access_token", "refresh_token", "id_token"]:
                                if sensitive_key in masked_body:
                                    token_value = masked_body[sensitive_key]
                                    if isinstance(token_value, str) and len(token_value) > 20:
                                        masked_body[sensitive_key] = token_value[:10] + "..." + token_value[-10:]
                            log_data["response_json_masked"] = masked_body
                        else:
                            log_data["response_json"] = parsed_body
                    except json.JSONDecodeError:
                        pass
        except Exception as e:
            log_data["response_body_error"] = str(e)
    
    # Add response headers for critical endpoints
    if is_critical_endpoint and hasattr(response, "headers"):
        critical_response_headers = {}
        for header_name in ["content-type", "www-authenticate", "cache-control", "location"]:
            header_value = response.headers.get(header_name)
            if header_value:
                critical_response_headers[header_name] = header_value
        log_data["critical_response_headers"] = critical_response_headers
    
    # Enhanced logging for OAuth failures
    status_code = log_data.get("status", 0)
    if status_code in [401, 403] and is_critical_endpoint:
        log_data["oauth_failure_analysis"] = {
            "status": status_code,
            "is_auth_failure": status_code == 401,
            "is_authorization_failure": status_code == 403,
            "endpoint_type": "oauth_critical",
            "failure_context": extra_context
        }
    
    # Determine log level based on status code
    if status_code >= 500:
        level = "error"
        message = "Server error response"
    elif status_code >= 400:
        level = "warning"
        message = "Client error response"
    else:
        level = "info"
        message = "Response sent"
    
    getattr(logger, level)(message, **log_data)
    
    # Log to RequestLogger if available (as response data)
    request_logger = get_request_logger()
    if request_logger:
        try:
            # Extract IP from extra_context
            ip = extra_context.get("ip", "unknown")
            
            error = None
            if log_data.get("status", 0) >= 400:
                error = {
                    "type": f"http_{log_data.get('status', 'unknown')}",
                    "message": log_data.get("response_body", "")[:200]  # Limit error message length
                }
            
            # Create a dictionary with all response data
            response_data = {
                "ip": ip,
                "status": log_data.get("status", 0),
                "duration_ms": duration_ms,
                "response_size": len(log_data.get("response_body", "")),
                "error": error,
                "request_key": request_key,  # Pass the request_key for unified entries
                # Include ALL enhanced OAuth debugging data
                "response_body": log_data.get("response_body", ""),
                "response_body_size": log_data.get("response_body_size", 0),
                "response_body_truncated": log_data.get("response_body_truncated", False),
                "response_json": log_data.get("response_json", {}),
                "response_json_masked": log_data.get("response_json_masked", {}),
                "critical_response_headers": log_data.get("critical_response_headers", {}),
                "oauth_failure_analysis": log_data.get("oauth_failure_analysis", {}),
                "is_critical_endpoint": log_data.get("is_critical_endpoint", False),
                "hostname": extra_context.get("hostname", ""),
                "path": extra_context.get("path", ""),
                "method": extra_context.get("method", ""),
                "response_type": "response",  # Mark this as response data
            }
            # Add extra context fields
            for k, v in extra_context.items():
                if k not in ["ip", "status", "hostname", "path", "method"]:
                    response_data[k] = v
            
            # Log as request data (but marked as response)
            # Unpack dictionary to pass as individual parameters
            await request_logger.log_request(
                ip=response_data.get("ip"),
                hostname=response_data.get("hostname"),
                method=response_data.get("method"),
                path=response_data.get("path"),
                query=response_data.get("query"),
                user_agent=response_data.get("user_agent"),
                auth_user=response_data.get("auth_user"),
                referer=response_data.get("referer"),
                **{k: v for k, v in response_data.items() 
                   if k not in ["ip", "hostname", "method", "path", "query", "user_agent", "auth_user", "referer"]}
            )
        except Exception as e:
            logger.error(f"Failed to log response to RequestLogger: {e}")
    
    return log_data