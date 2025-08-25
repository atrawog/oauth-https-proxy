# Unified Dispatcher Documentation

## Overview

The Unified Dispatcher is THE server - FastAPI is just another service it manages! It handles all incoming HTTP/HTTPS requests and routes them to appropriate services based on hostname and path.

## Architecture

```
Client → Dispatcher (80/443) → HypercornInstance → ProxyOnlyApp → UnifiedProxyHandler → Backend
         (Read SNI & route)     ├─ PROXY Handler (12xxx/13xxx)
                                │  • Parse PROXY header
                                │  • Store client IP in Redis
                                └─ Hypercorn (22xxx/23xxx)
                                   • Terminate SSL
                                   • Run Starlette app
                                   • OAuth validation in UnifiedProxyHandler

For localhost with Docker:
Client → Dispatcher (80) → HypercornInstance → ProxyOnlyApp → UnifiedProxyHandler → API (http://api:9000)
```

## Why HypercornInstance, Not EnhancedProxyInstance

### The Failed Experiment
We tried creating EnhancedProxyInstance to handle OAuth "at the edge" (at the TCP/SSL layer) but this failed because:

1. **OAuth validation needs application context**: The edge doesn't know routes, scopes, or backends
2. **Partial validation creates security holes**: Basic JWT validation without scope checking is dangerous
3. **The edge layer can't make routing decisions**: It doesn't know which backend to forward to

### The Working Solution
HypercornInstance + UnifiedProxyHandler provides:
- **Clean separation of concerns**: SSL at Hypercorn, OAuth at UnifiedProxyHandler
- **Complete OAuth validation with context**: Scopes, user allowlists, route-specific auth
- **No duplicate implementations**: One place for routing logic
- **Proven, working architecture**: This was already working before we broke it

## Why the Dispatcher CANNOT Terminate SSL

**Critical Insight**: The dispatcher doesn't know which certificate to use until AFTER 
it reads the SNI hostname from the TLS Client Hello. Since each proxy has its own 
certificate, the dispatcher MUST forward the raw TLS data to the correct proxy instance.

## Why We Use PROXY Protocol

When the dispatcher forwards a connection to a proxy instance, the proxy would normally 
see the connection as coming from 127.0.0.1 (the dispatcher). The PROXY protocol header 
preserves the real client IP: `PROXY TCP4 <real_ip> 127.0.0.1 <port> 443`

INTERNAL PROXY protocol flow:
- Dispatcher adds PROXY header when forwarding to proxy instances
- Preserves real client IP for logging and security
- NO external load balancers involved

## Server Configuration

- `HTTP_PORT` - HTTP server port (default: 80)
- `HTTPS_PORT` - HTTPS server port (default: 443)
- `SERVER_HOST` - Server bind address (default: 0.0.0.0)
- `SELF_SIGNED_CN` - Common name for self-signed certificates (default: localhost)
- `API_URL` - Base URL for API endpoints (default: http://localhost:9000)

### Internal Ports
- Port 9000: API (internal only, Docker service name: api)
- Port 12000-12999: HTTP proxy instances (Redis-allocated)
- Port 13000-13999: HTTPS proxy instances (Redis-allocated)

## Port Management

The dispatcher uses Redis-based PortManager for all port allocations:

- **Persistent**: Port mappings stored in Redis survive restarts
- **Atomic**: PortManager ensures no conflicts via Redis locks
- **Deterministic**: Hash-based preferred ports for consistency
- **Tracked**: All allocations visible in Redis

### Port Allocation Flow
1. Check Redis for existing mapping: `proxy:ports:mappings`
2. If missing, allocate via PortManager with preferred port
3. Store mapping in Redis for persistence
4. Register with dispatcher for routing

### Redis Keys
```
proxy:ports:mappings -> hash of hostname to port mapping
port:12001 -> allocation details for specific port
ports:allocated -> set of all allocated ports
ports:proxy:http -> set of allocated HTTP proxy ports
ports:proxy:https -> set of allocated HTTPS proxy ports
```

## Dual App Architecture

### API App (FastAPI) - localhost only
- Full FastAPI with async lifespan management
- Async API endpoints, Web GUI, certificate management
- Integrated OAuth 2.1 server functionality
- Global resources (scheduler, Redis) with async initialization
- Runs on internal port 9000
- Background tasks for certificate renewal and cleanup

### Proxy App (Minimal ASGI) - all proxy domains
- Lightweight Starlette app with async handlers
- ONLY proxy forwarding, no API
- Per-instance async httpx client (isolated)
- NO lifespan side effects
- Clean shutdown without affecting others
- Streaming response handling for large payloads

## Service Management

```python
class DomainService:
    is_api_service: bool  # True=FastAPI, False=Proxy
    internal_http_port: int  # 9000+ 
    internal_https_port: int  # 10000+
    ssl_context: Optional[SSLContext]  # Pre-loaded
```

## Request Routing

### Hostname-Based Routing
1. Extract hostname from request
2. Look up service for hostname in Redis
3. Route to appropriate app instance
4. Apply SSL context if HTTPS

### Path-Based Routing
Within each hostname, paths are routed based on:
1. Route priority (higher checked first)
2. Path pattern matching
3. HTTP method filtering
4. Scope (global vs proxy-specific)

## SSL/TLS Handling

### SNI (Server Name Indication)
The dispatcher supports SNI for serving multiple HTTPS domains:
```python
async def get_ssl_context(hostname: str) -> Optional[SSLContext]:
    """Get SSL context for hostname via SNI"""
    cert = await get_certificate(hostname)
    if cert:
        return create_ssl_context(cert)
    return None
```

### Dynamic SSL Provider
- Loads certificates from Redis on demand
- Caches SSL contexts for performance
- Automatically updates when certificates renew
- Falls back to self-signed for localhost

## Multi-Instance Management

Each proxy domain gets its own ASGI app instance with Redis-managed ports:

### Benefits
- **Persistent Ports**: Port allocations survive restarts via Redis
- **No Conflicts**: PortManager ensures atomic allocation
- **Instance Isolation**: Delete proxy without affecting others
- **Clean Resource Management**: Ports released on deletion
- **Dynamic Operations**: Add/remove without service restart
- **Deterministic**: Same proxy gets similar ports via hash
- **Debuggable**: All port mappings visible in Redis

### Instance Lifecycle
1. **Port Check**: Look for existing mapping in Redis
2. **Port Allocation**: Use PortManager if no mapping exists
3. **Instance Creation**: Create with allocated ports
4. **Registration**: Store mapping and register with dispatcher
5. **Deletion**: Release ports back to pool and remove mapping

## WebSocket and SSE Support

The dispatcher handles streaming protocols:
```python
async def handle_websocket(websocket: WebSocket):
    """Forward WebSocket connections"""
    await websocket.accept()
    # Bidirectional streaming
    await forward_websocket(websocket, backend_ws)
```

### MCP SSE Streaming
The dispatcher properly handles MCP's Server-Sent Events:
- Detects `text/event-stream` content type
- Uses `StreamingResponse` for proper SSE delivery
- Maintains persistent connections for real-time updates
- Supports both `/mcp` and `/mcp/` endpoints

## Health Monitoring

### Dispatcher Health
```python
async def health_check():
    return {
        "status": "healthy",
        "instances": len(active_instances),
        "uptime": uptime_seconds,
        "memory": process_memory_mb
    }
```

### Instance Health
Each instance monitored for:
- Request rate
- Error rate
- Response time
- Memory usage

## Performance Optimizations

### Connection Pooling
Shared connection pools for backend communication:
```python
http_client = httpx.AsyncClient(
    limits=httpx.Limits(
        max_keepalive_connections=20,
        max_connections=100
    )
)
```

### Request Streaming
Large requests/responses streamed to prevent memory issues:
```python
async def stream_response(backend_response):
    async for chunk in backend_response.aiter_bytes():
        yield chunk
```

## Error Handling

### Graceful Degradation
- Fallback to error page if backend unavailable
- Retry logic for transient failures
- Circuit breaker for persistent failures

### Error Responses
```python
async def error_response(status: int, message: str):
    return JSONResponse(
        status_code=status,
        content={"error": message}
    )
```

## Logging and Monitoring

### Request Logging
All requests logged with:
- Client IP (real IP via PROXY protocol)
- Hostname
- Path
- Method
- Status code
- Response time
- User agent

### Metrics Collection
- Requests per second
- Error rate
- P50/P95/P99 response times
- Active connections
- Backend health

## Integration Points

### PROXY Protocol (Internal Use Only)
The PROXY protocol is used INTERNALLY to preserve real client IPs between components:
```
Dispatcher (80/443) → [PROXY header] → Proxy Instance (12000+) → Parse & Store in Redis
                                                ↓
                                    Extract real client IP for logging/auth
```

**CRITICAL**: PROXY protocol is only used internally between the dispatcher and proxy instances.
There are NO external load balancers involved in this architecture.

### Redis Storage
All configuration and state in Redis:
- Service mappings
- SSL certificates
- Route configurations
- Client IP information

## Unified Event Architecture

The dispatcher now directly handles all event processing without an intermediate orchestrator:

### Simplified Event System
Only 3 event types (down from 15+):
- **proxy_created**: Create/update proxy instance
- **proxy_deleted**: Remove proxy instance
- **certificate_ready**: Enable HTTPS for domain

### Event Processing
```python
async def handle_unified_event(self, event: dict):
    """Direct event handling - simple and efficient"""
    event_type = event.get('event_type')
    
    if event_type == 'proxy_created':
        await self._ensure_instance_exists(proxy_hostname)
    elif event_type == 'proxy_deleted':
        await self._remove_instance(proxy_hostname)
    elif event_type == 'certificate_ready':
        await self._enable_https(domain, cert_name)
```

### Non-Blocking Reconciliation
Startup reconciliation uses `asyncio.create_task()` to avoid blocking:
```python
self.reconciliation_task = asyncio.create_task(
    self._reconcile_all_proxies()
)
```

### Consumer Configuration
- **Stream**: `events:all:stream`
- **Consumer Group**: `unified-dispatcher`
- **Single Consumer**: No competing consumers
- **Automatic ACK**: Events acknowledged after processing

## Best Practices

1. **Instance Isolation**: Each proxy domain isolated
2. **Resource Limits**: Set connection pool limits
3. **Streaming**: Use streaming for large payloads
4. **Health Checks**: Monitor all instances
5. **Graceful Shutdown**: Clean up resources properly

## Troubleshooting

### Port Issues

#### Check Allocated Ports
```bash
redis-cli hgetall proxy:ports:mappings
redis-cli smembers ports:allocated
redis-cli smembers ports:proxy:http
```

#### Port Already in Use
```bash
# Check what's using the port
lsof -i :12000
# Check Redis allocation
redis-cli get port:12000
# Clear stale allocation if needed
redis-cli del port:12000
```

#### Missing Port Mappings
```bash
# Check if proxy exists
redis-cli hget proxy:targets localhost
# Check port mapping
redis-cli hget proxy:ports:mappings localhost
# Restart to trigger reconciliation
just restart
```

### Common Issues

1. **SSL Certificate Not Found**: Check certificate exists for hostname
2. **Backend Unreachable**: Verify target URL and network
3. **No Available Ports**: Check port range usage and clean orphaned allocations
4. **Port Mapping Mismatch**: Delete and recreate proxy instance

### Debug Commands

```bash
# Check active instances
curl http://localhost:9000/dispatcher/instances

# View instance health
curl http://localhost:9000/dispatcher/health

# Check SSL context
curl https://hostname --resolve hostname:443:127.0.0.1
```

## SSL/TLS Architecture

### How SSL Works in the System

**For HTTPS Proxy Instances:**
1. **Hypercorn handles SSL termination** using `config.certfile` and `config.keyfile`
2. **PROXY protocol handler is just a TCP forwarder** - it does NOT handle SSL
3. **No SSL context needed for PROXY handler** - it forwards raw TCP to Hypercorn

**Flow for HTTPS:**
```
Client --[HTTPS]--> Dispatcher:443 --[TCP+PROXY header]--> ProxyHandler:13xxx --[TCP]--> Hypercorn:23xxx (SSL termination here)
```

**IMPORTANT**: 
- The PROXY protocol handler (`create_proxy_protocol_server`) does NOT accept or need an `ssl_context` parameter
- SSL is handled entirely by Hypercorn using the certificate files
- The PROXY handler is a simple TCP forwarder that preserves client IP information

### Certificate Storage
- Certificates are stored in Redis (fulfilling the "no filesystem" principle)
- Temporary files are created ONLY for Hypercorn (Python SSL limitation)
- These temp files are managed by the HypercornInstance lifecycle

## Related Documentation

- [Proxy Manager](../proxy/CLAUDE.md) - Proxy configuration
- [Certificate Manager](../certmanager/CLAUDE.md) - SSL certificates
- [Middleware](../middleware/CLAUDE.md) - PROXY protocol
- [Storage Layer](../storage/CLAUDE.md) - Redis Streams configuration