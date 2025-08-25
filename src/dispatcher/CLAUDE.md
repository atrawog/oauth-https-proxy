# Unified Dispatcher Documentation

## Overview

The Unified Dispatcher is a **PURE TCP FORWARDER** that routes incoming connections to proxy instances based solely on hostname. It does NOT parse, modify, or interpret HTTP beyond extracting the hostname.

## Architecture

```
Client → Dispatcher (80/443) → HypercornInstance → ProxyOnlyApp → UnifiedProxyHandler → Backend
         (Extract hostname)     ├─ PROXY Protocol TCP Forward
         (Forward raw TCP)      ├─ Ports 12xxx (HTTP) / 13xxx (HTTPS)
                               └─ All HTTP/OAuth/Routing logic here

For localhost with Docker:
Client → Dispatcher (80) → [PROXY + TCP] → HypercornInstance (12000) → UnifiedProxyHandler → API (http://api:9000)
```

### Key Principle: Pure TCP Forwarding

The dispatcher's ONLY responsibilities are:
1. **Extract hostname** from HTTP Host header (using h11) or TLS SNI
2. **Look up target port** in Redis hostname-to-port mapping
3. **Add PROXY protocol header** to preserve client IP
4. **Forward raw TCP bidirectionally** without modification

The dispatcher does NOT:
- Parse HTTP requests or responses
- Match routes or paths
- Modify headers
- Handle authentication
- Make routing decisions beyond hostname
- Interpret HTTP bodies or methods

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

## h11 for Safe Hostname Extraction

The dispatcher uses the h11 library (the same HTTP/1.1 parser used by httpx and uvicorn) ONLY to safely extract the hostname from HTTP requests:

```python
def extract_hostname_with_h11(self, data: bytes) -> tuple[Optional[str], bytes]:
    """Extract hostname using h11 - safe and standards-compliant"""
    conn = h11.Connection(h11.SERVER)
    conn.receive_data(data)
    
    while True:
        event = conn.next_event()
        if isinstance(event, h11.Request):
            # Headers are part of the Request event in h11
            for name, value in event.headers:
                if name.lower() == b'host':
                    hostname = value.decode('utf-8')
                    if ':' in hostname:
                        hostname = hostname.split(':')[0]
                    return hostname, data
        elif event is h11.NEED_DATA:
            break
    return None, data
```

**Why h11?**
- Standards-compliant HTTP/1.1 parsing
- Handles edge cases and malformed requests safely
- Same parser used by production Python web servers
- Avoids manual string manipulation bugs

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

## Request Forwarding (NOT Routing!)

### Pure Hostname-Based Forwarding
The dispatcher does NOT route - it only forwards based on hostname:

1. **HTTP**: Extract hostname from Host header using h11
2. **HTTPS**: Extract hostname from TLS SNI
3. **Lookup**: Get target port from Redis `proxy:ports:mappings`
4. **Forward**: Add PROXY header and forward raw TCP

### NO Path-Based Routing in Dispatcher
Path-based routing happens in UnifiedProxyHandler, NOT the dispatcher:
- The dispatcher forwards ALL requests for a hostname to ONE proxy instance
- That proxy instance handles all path matching and backend routing
- OAuth validation, scope checking, and user allowlists happen there too

**Critical**: The dispatcher is a Layer 4 (TCP) forwarder with minimal Layer 7 (HTTP) awareness - just enough to extract hostname.

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

## What Was Removed (January 2025 Refactor)

The dispatcher was simplified from an HTTP-aware proxy to a pure TCP forwarder:

### Removed Components (~150 lines)
- `_forward_http_request()` method - Was parsing and reassembling HTTP
- `resolve_route_target()` method - Route matching moved to proxy instances
- Route priority checking - Now handled by UnifiedProxyHandler
- httpx client - No HTTP client needed for TCP forwarding
- HTTP response creation - Only minimal error responses for missing Host header
- Request/response modification - Pure forwarding, no modification

### Why These Were Removed
The previous implementation was:
1. **Corrupting POST bodies** by splitting on `\r\n` and rejoining
2. **Duplicating logic** that already existed in UnifiedProxyHandler
3. **Violating separation of concerns** by doing routing at the TCP layer
4. **Creating maintenance burden** with duplicate route matching

## Performance Optimizations

### Bidirectional TCP Streaming
The dispatcher now uses efficient bidirectional streaming:
```python
async def _forward_connection(self, reader, writer, initial_data, target_host, target_port):
    """Pure TCP forwarding with PROXY protocol header"""
    # Add PROXY header for client IP preservation
    proxy_header = f"PROXY TCP4 {client_ip} {target_host} {client_port} {target_port}\r\n"
    
    # Forward initial data with PROXY header
    target_writer.write(proxy_header.encode() + initial_data)
    
    # Bidirectional streaming
    await asyncio.gather(
        self._stream_data(reader, target_writer),  # Client → Backend
        self._stream_data(target_reader, writer)   # Backend → Client
    )
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