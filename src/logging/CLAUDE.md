# Unified Async Logging Architecture Documentation

## Overview

The logging system uses a unified async logging architecture with fire-and-forget patterns for high-performance, non-blocking logging. All components use a centralized `UnifiedAsyncLogger` that writes to Redis Streams with multiple indexes, real-time streaming, and comprehensive analytics.

## Configuration

- `LOG_LEVEL` - Application log level (TRACE, DEBUG, INFO, WARNING, ERROR, CRITICAL) - default: INFO
- **TRACE Level**: Custom level (value=5) for very verbose debugging, below DEBUG

## Architecture

### Unified Async Logger
The system uses a centralized `UnifiedAsyncLogger` with fire-and-forget patterns:
- **Fire-and-Forget Logging**: All log calls use `asyncio.create_task()` for non-blocking operation
- **Component Isolation**: Each component has immutable component name to prevent contamination
- **No Logger Instances**: Direct function calls (`log_info()`, `log_debug()`, etc.) instead of logger objects
- **Async Redis Streams**: All logs written to Redis Streams for persistence and querying
- **Unified Stream Publisher**: Single publisher instance for all log events

## Logging API

### Fire-and-Forget Functions
All logging uses non-blocking fire-and-forget patterns:

```python
from src.shared.logger import log_info, log_debug, log_warning, log_error, log_trace

# Basic logging - all are non-blocking
log_info("Server started", component="api_server")
log_debug("Processing request", component="handler", request_id="123")
log_warning("High memory usage", component="monitor", memory_mb=1024)
log_error("Connection failed", component="proxy", error=e)
log_trace("Detailed trace info", component="debug")  # TRACE level for verbose debugging

# Request/Response logging
log_request("GET", "/api/health", "192.168.1.1", "api.example.com")
log_response(200, 45.3, trace_id="req-123")

# Event logging
log_event("proxy_created", {"hostname": "example.com"}, trace_id="evt-456")
```

### Component Isolation
Each component uses an immutable component name:
```python
# Component name is passed with each call, not stored in logger instance
log_info("Message", component="my_component")
# NOT: logger = get_logger("my_component"); logger.info("Message")
```

## RequestLogger System

The RequestLogger provides efficient HTTP request/response logging with multiple indexes.

### Key Features
- Multiple indexes for efficient querying (IP, hostname, status, user, path)
- Real-time streaming for monitoring
- HyperLogLog for unique visitor tracking
- Response time statistics with sliding windows

### Redis Storage Schema

```
req:{timestamp}:{client_ip}  # Request/response data as hash
idx:req:ip:{client_ip}       # Index by client IP
idx:req:fqdn:{fqdn}          # Index by client FQDN (reverse DNS)
idx:req:host:{proxy_hostname} # Index by proxy hostname
idx:req:user:{username}      # Index by authenticated user
idx:req:status:{code}        # Index by HTTP status code
idx:req:errors               # All error responses (4xx/5xx)
idx:req:slow                 # Slow requests (>1s)
idx:req:path:{method}:{path} # Path pattern analysis
stream:requests              # Live request stream
stats:requests:{YYYYMMDD:HH} # Hourly request counts
stats:errors:{YYYYMMDD:HH}   # Hourly error counts
stats:unique_ips:{hostname}:{YYYYMMDD:HH} # Unique visitors
```

## Log Entry Schema

```json
{
  "timestamp": "2024-01-15T10:30:45.123Z",
  "client_ip": "192.168.1.100",
  "client_hostname": "client.example.com",
  "proxy_hostname": "api.example.com",
  "method": "GET",
  "path": "/users",
  "status_code": 200,
  "response_time_ms": 45,
  "user_id": "github-123",
  "user_agent": "Mozilla/5.0...",
  "referrer": "https://example.com",
  "bytes_sent": 1234,
  "error": null
}
```

## Log Query API

Access logs via the `/logs` endpoints:

### Endpoints
- `GET /logs/ip/{ip}` - Query by client IP address
- `GET /logs/host/{hostname}` - Query by client FQDN (reverse DNS)
- `GET /logs/client/{client_id}` - Query by OAuth client
- `GET /logs/search` - Search logs with filters
- `GET /logs/errors` - Recent errors
- `GET /logs/events` - Event statistics

### Query Parameters
- `hours` - How many hours back to search (default: 24)
- `event` - Filter by event type
- `level` - Filter by log level
- `hostname` - Filter by hostname
- `limit` - Maximum results (default: 100)

## Log Query Commands

```bash
just logs [hours] [event] [level] [hostname] [limit] [token]  # Show recent logs (oldest to newest)
just logs-ip <ip> [hours] [event] [level] [limit] [token]    # Query logs by client IP
just logs-proxy <hostname> [hours] [limit] [token]            # Query logs by proxy hostname
just logs-hostname <hostname> [hours] [limit] [token]         # Query logs by hostname
just logs-oauth-client <client-id> [hours] [event] [level] [limit] [token]  # Query logs by OAuth client
just logs-search [query] [hours] [event] [level] [hostname] [limit] [token]  # Search logs with filters
just logs-errors [hours] [limit] [token]                      # Show recent errors
just logs-errors-debug [hours] [include-warnings] [limit] [token]  # Detailed errors with debugging
just logs-follow [interval] [event] [level] [hostname] [token] # Follow logs in real-time with ANSI colors
just logs-oauth <ip> [hours] [limit] [token]                  # OAuth activity summary
just logs-oauth-debug <ip> [hours] [limit] [token]            # Full OAuth flow debugging
just logs-oauth-flow [client-id] [username] [hours] [token]   # Track OAuth flows
just logs-stats [hours] [token]                               # Show event statistics
just logs-test [token]                                        # Test logging system
just logs-user <user-id> [hours] [limit] [token]              # Query logs by user ID
just logs-session <session-id> [hours] [limit] [token]        # Query logs by session ID
just logs-method <method> [hours] [limit] [token]             # Query logs by HTTP method
just logs-status <code> [hours] [limit] [token]               # Query logs by status code
just logs-slow [threshold-ms] [hours] [limit] [token]         # Query slow requests
just logs-path <pattern> [hours] [limit] [token]              # Query logs by path pattern
just logs-oauth-user <username> [hours] [limit] [token]       # Query logs by OAuth username
just logs-docker [lines] [follow]                             # Docker container logs only
just logs-service [service] [lines]                           # Service-specific Docker logs
just logs-clear [token]                                       # Clear all log entries from Redis
just logs-help                                                # Show logging commands help
```

### Key Features
- **Chronological Order**: Logs displayed oldest to newest (most recent at bottom)
- **No Summary**: Clean output without summary statistics
- **ANSI Colors**: Full color support in `logs-follow` for visual distinction
- **Real-time Following**: Live log streaming with configurable interval

## Performance Optimizations

### Fire-and-Forget Pattern
All log operations are non-blocking:
```python
def log_info(message: str, component: Optional[str] = None, **kwargs):
    """Fire-and-forget info log."""
    if _logger:
        asyncio.create_task(_logger.info(message, component=component, **kwargs))
```

### Batch Processing
Logs are batched with 100ms windows:
```python
async def batch_logs(entries: List[LogEntry]):
    async with redis.pipeline() as pipe:
        for entry in entries:
            pipe.hset(f"req:{entry.timestamp}:{entry.client_ip}", mapping=entry.dict())
        await pipe.execute()
```

### Pipeline Operations
Bulk fetches use pipelining:
```python
async def fetch_logs_by_ip(ip: str, limit: int = 100):
    keys = await redis.zrevrange(f"idx:req:ip:{ip}", 0, limit-1)
    
    async with redis.pipeline() as pipe:
        for key in keys:
            pipe.hgetall(key)
        return await pipe.execute()
```

### Sliding Windows
Response time percentiles with sliding windows:
```python
async def calculate_percentiles(hostname: str, window_hours: int = 1):
    now = datetime.utcnow()
    start = now - timedelta(hours=window_hours)
    
    response_times = await redis.zrangebyscore(
        f"stats:response_times:{hostname}",
        start.timestamp(),
        now.timestamp()
    )
    
    return calculate_percentiles(response_times)
```

### HyperLogLog
Memory-efficient unique visitor counting:
```python
async def track_unique_visitor(hostname: str, ip: str):
    key = f"stats:unique_ips:{hostname}:{datetime.utcnow():%Y%m%d:%H}"
    await redis.pfadd(key, ip)
```

### Automatic Index Expiration
Indexes expire automatically to prevent unbounded growth:
```python
async def add_to_index(index_key: str, value: str, ttl: int = 86400):
    await redis.zadd(index_key, {value: time.time()})
    await redis.expire(index_key, ttl)
```

## Real-Time Streaming

### Stream Publishing
```python
async def publish_log(entry: LogEntry):
    await redis.xadd("stream:requests", {
        "data": json.dumps(entry.dict())
    })
```

### Stream Consumption
```python
async def consume_logs():
    last_id = "$"
    while True:
        entries = await redis.xread(
            {"stream:requests": last_id},
            block=1000
        )
        for entry in entries:
            yield json.loads(entry["data"])
            last_id = entry["id"]
```

## Log Aggregation

### Hourly Statistics
```python
async def update_hourly_stats(entry: LogEntry):
    hour_key = f"stats:requests:{entry.timestamp:%Y%m%d:%H}"
    
    # Increment request count
    await redis.hincrby(hour_key, "total", 1)
    
    # Track status codes
    await redis.hincrby(hour_key, f"status_{entry.status_code}", 1)
    
    # Track response times
    await redis.lpush(f"{hour_key}:response_times", entry.response_time_ms)
```

### Error Tracking
```python
async def track_error(entry: LogEntry):
    if entry.status_code >= 400:
        # Add to error index
        await redis.zadd("idx:req:errors", {
            f"req:{entry.timestamp}:{entry.client_ip}": time.time()
        })
        
        # Update error stats
        hour_key = f"stats:errors:{entry.timestamp:%Y%m%d:%H}"
        await redis.hincrby(hour_key, str(entry.status_code), 1)
```

## Log Analysis

### Path Pattern Analysis
```python
async def analyze_path_patterns(hours: int = 24):
    patterns = defaultdict(int)
    
    # Get recent logs
    logs = await get_recent_logs(hours)
    
    for log in logs:
        pattern = normalize_path(log.path)
        patterns[pattern] += 1
    
    return sorted(patterns.items(), key=lambda x: x[1], reverse=True)
```

### Slow Request Detection
```python
async def find_slow_requests(threshold_ms: int = 1000):
    return await redis.zrevrange("idx:req:slow", 0, 99, withscores=True)
```

## OAuth Activity Tracking

### OAuth-Specific Logging
```python
async def log_oauth_activity(
    event_type: str,
    client_id: str,
    user_id: str,
    details: dict
):
    entry = {
        "timestamp": datetime.utcnow().isoformat(),
        "event_type": event_type,
        "client_id": client_id,
        "user_id": user_id,
        "details": json.dumps(details)
    }
    
    # Store in OAuth-specific index
    await redis.zadd(f"idx:oauth:{event_type}", {
        json.dumps(entry): time.time()
    })
```

### OAuth Flow Tracking
```python
async def track_oauth_flow(session_id: str, step: str, data: dict):
    flow_key = f"oauth:flow:{session_id}"
    await redis.rpush(flow_key, json.dumps({
        "step": step,
        "timestamp": time.time(),
        "data": data
    }))
    await redis.expire(flow_key, 3600)  # 1 hour TTL
```

## Log Retention

### Configurable Retention
```python
LOG_RETENTION_DAYS = {
    "requests": 7,      # General request logs
    "errors": 30,       # Error logs
    "oauth": 90,        # OAuth activity
    "stats": 365        # Aggregated statistics
}
```

### Cleanup Job
```python
async def cleanup_old_logs():
    for log_type, days in LOG_RETENTION_DAYS.items():
        cutoff = datetime.utcnow() - timedelta(days=days)
        
        # Remove old entries from indexes
        await redis.zremrangebyscore(
            f"idx:{log_type}:*",
            0,
            cutoff.timestamp()
        )
```

## Monitoring and Alerts

### Alert Conditions
- Error rate exceeds threshold
- Response time degradation
- Unusual traffic patterns
- OAuth authentication failures

### Metrics Export
```python
async def export_metrics():
    return {
        "requests_per_second": await calculate_rps(),
        "error_rate": await calculate_error_rate(),
        "p50_response_time": await get_percentile(50),
        "p95_response_time": await get_percentile(95),
        "p99_response_time": await get_percentile(99),
        "unique_visitors": await count_unique_visitors()
    }
```

## Best Practices

1. **Use Indexes Wisely**: Create indexes only for frequently queried fields
2. **Batch Operations**: Group multiple log writes for performance
3. **Set TTLs**: Always set expiration on temporary data
4. **Monitor Memory**: Track Redis memory usage
5. **Compress Old Logs**: Archive old logs to reduce storage

## Troubleshooting

### Common Issues

1. **High Memory Usage**: Check index expiration settings
2. **Slow Queries**: Optimize index usage and limits
3. **Missing Logs**: Verify Redis connection and permissions
4. **Incorrect Timestamps**: Check timezone configuration

### Debug Commands

```bash
# Check log entry count
redis-cli ZCARD idx:req:ip:192.168.1.1

# View recent errors
just logs-errors 1 10

# Check unique visitor count
redis-cli PFCOUNT stats:unique_ips:api.example.com:20240115:10

# Monitor real-time logs
just logs-follow api
```

## Related Documentation

- [Storage](../storage/CLAUDE.md) - Redis storage details
- [Middleware](../middleware/CLAUDE.md) - Request interception
- [API](../api/CLAUDE.md) - Log query endpoints