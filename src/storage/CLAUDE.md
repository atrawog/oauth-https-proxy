# Redis Storage Schema Documentation

## Overview

The storage layer provides a unified async Redis interface for all system components with connection pooling, atomic operations, and stream processing.

## Async Redis Architecture

All Redis operations use async/await patterns through the AsyncRedisStorage class:
- **Connection Pooling**: Maintains efficient connection pool for high concurrency
- **Pipeline Operations**: Batch operations for improved performance
- **Atomic Operations**: Lua scripts for complex atomic operations
- **Stream Processing**: Async consumers for Redis Streams events

## Key Naming Conventions

The system uses consistent key naming patterns for organization and performance:

### Service Keys
```
service:url:{name}          # Service name to URL mapping (all service types)
service:external:{name}     # External service configuration JSON
docker_service:{name}       # Docker service configuration JSON
services:external           # Set of external service names
```

### OAuth Token Keys (JWT-based, no storage of bearer tokens)
```
# OAuth tokens are JWT-based and validated cryptographically
# No bearer tokens (`acm_*`) are stored anymore
```

### Certificate Keys
```
cert:{name}                 # Certificate data JSON
cert:domain:{domain}        # Domain to certificate name mapping
cert:status:{name}          # Certificate generation status
```

### Proxy Keys
```
proxy:{hostname}            # Proxy target configuration JSON
proxy:client:{port}:{port}  # PROXY protocol client info (60s TTL)
```

### Route Keys
```
route:{id}                  # Route configuration JSON
route:unique:{path}:{prio}  # Unique route constraint
route:priority:{prio}:{id}  # Priority-ordered route index
```

### OAuth Keys
```
oauth:client:{id}           # OAuth client data
oauth:state:{state}         # OAuth authorization state
oauth:code:{code}           # OAuth authorization code
oauth:token:{jti}           # OAuth access token data
oauth:refresh:{token}       # OAuth refresh token data
oauth:user_tokens:{user}    # Set of token JTIs for user
```

### Port Management Keys
```
port:{port}                 # Port allocation data
service:ports:{service}     # Hash of service port configurations
```

### Resource Keys (MCP)
```
resource:{uri}              # Protected resource configuration
```

### Workflow Stream Keys
```
events:workflow             # Main event stream for instance lifecycle
workflow:state:{hostname}   # Current state of workflow for each hostname
workflow:pending            # Set of pending workflow tasks
workflow:consumer:info      # Consumer group metadata
```

### Logging Keys
```
req:{timestamp}:{client_ip}  # Request/response data as hash
idx:req:ip:{client_ip}       # Index by client IP
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

## AsyncRedisStorage Class

The central storage interface providing all Redis operations:

### Core Methods

```python
async def get(key: str) -> Optional[str]
async def set(key: str, value: str, ex: Optional[int] = None) -> bool
async def delete(key: str) -> int
async def exists(key: str) -> bool
async def keys(pattern: str) -> List[str]
async def hget(key: str, field: str) -> Optional[str]
async def hset(key: str, field: str, value: str) -> int
async def hgetall(key: str) -> Dict[str, str]
async def hdel(key: str, *fields: str) -> int
```

### Pipeline Operations

```python
async def pipeline_execute(commands: List[Command]) -> List[Any]
```

### Stream Operations

```python
async def xadd(stream: str, fields: Dict, id: str = "*") -> str
async def xread(streams: Dict[str, str], block: int = None) -> Dict
async def xgroup_create(stream: str, group: str, id: str = "$") -> bool
async def xreadgroup(group: str, consumer: str, streams: Dict) -> Dict
async def xack(stream: str, group: str, *ids: str) -> int
```

### Atomic Operations

```python
async def atomic_increment(key: str) -> int
async def atomic_set_if_not_exists(key: str, value: str) -> bool
async def atomic_update_json(key: str, updates: Dict) -> bool
```

## Data Serialization

### JSON Storage
Most configuration data is stored as JSON:
```python
data = {
    "hostname": "api.example.com",
    "target_url": "http://backend:3000",
    "created_at": datetime.utcnow().isoformat()
}
await storage.set(f"proxy:{hostname}", json.dumps(data))
```

### Binary Data
Certificates and keys stored as base64-encoded strings:
```python
cert_data = {
    "fullchain_pem": base64.b64encode(cert_bytes).decode(),
    "private_key_pem": base64.b64encode(key_bytes).decode()
}
```

## Redis Streams for Events

### Event Publishing
```python
await storage.xadd("events:workflow", {
    "event_type": "proxy_created",
    "hostname": hostname,
    "data": json.dumps(proxy_data)
})
```

### Consumer Groups
```python
# Create consumer group
await storage.xgroup_create("events:workflow", "workflow-group")

# Read events
events = await storage.xreadgroup(
    "workflow-group",
    "consumer-1",
    {"events:workflow": ">"}
)
```

## Connection Management

### Connection Pool Configuration
```python
redis_pool = await aioredis.create_redis_pool(
    redis_url,
    password=redis_password,
    minsize=5,
    maxsize=20,
    encoding="utf-8"
)
```

### Connection Health
```python
async def ping() -> bool:
    """Check Redis connection health"""
    try:
        return await self.redis.ping()
    except Exception:
        return False
```

## Expiration and TTL

### Temporary Data
PROXY protocol client info with 60s TTL:
```python
await storage.set(
    f"proxy:client:{server_port}:{client_port}",
    client_info,
    ex=60  # 60 seconds TTL
)
```

### Certificate Status
Temporary status during generation:
```python
await storage.set(
    f"cert:status:{cert_name}",
    status_json,
    ex=300  # 5 minutes TTL
)
```

## Indexes and Lookups

### Dual-Key Storage
Tokens accessible by name and hash:
```python
# Store by name
await storage.set(f"token:{name}", token_data)
# Store hash mapping
await storage.set(f"token:hash:{hash}", name)
```

### Priority Indexes
Routes indexed by priority for ordered retrieval:
```python
await storage.zadd("route:priorities", {route_id: priority})
```

## Lua Scripts

For complex atomic operations:
```lua
-- Atomic check and set
local current = redis.call('GET', KEYS[1])
if current == ARGV[1] then
    redis.call('SET', KEYS[1], ARGV[2])
    return 1
else
    return 0
end
```

## Best Practices

1. **Use Pipelining**: Batch multiple operations for performance
2. **Set TTLs**: Use expiration for temporary data
3. **Atomic Operations**: Use Lua scripts for complex updates
4. **Connection Pooling**: Reuse connections efficiently
5. **Error Handling**: Always handle connection failures gracefully

## Performance Optimization

### Batch Operations
```python
async with storage.pipeline() as pipe:
    for key, value in items.items():
        pipe.set(key, value)
    await pipe.execute()
```

### Efficient Queries
Use specific patterns instead of broad wildcards:
```python
# Good: Specific pattern
keys = await storage.keys("proxy:*.example.com")

# Bad: Too broad
keys = await storage.keys("*")
```

## Monitoring

### Key Metrics
- Connection pool utilization
- Operation latency
- Memory usage
- Key count by pattern
- Slow query log

### Health Checks
```python
async def health_check():
    return {
        "connected": await storage.ping(),
        "memory": await storage.info("memory"),
        "keys": await storage.dbsize()
    }
```

## Related Documentation

- [General Guidelines](../CLAUDE.md) - Redis configuration
- [OAuth Service](../api/oauth/CLAUDE.md) - OAuth data storage
- [Certificate Manager](../certmanager/CLAUDE.md) - Certificate storage
- [Workflow Orchestration](../orchestration/CLAUDE.md) - Event streams