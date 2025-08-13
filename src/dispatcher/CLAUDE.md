# Unified Dispatcher Documentation

## Overview

The Unified Dispatcher is THE server - FastAPI is just another service it manages! It handles all incoming HTTP/HTTPS requests and routes them to appropriate services based on hostname and path.

## Architecture

```
Client → Port 80/443 → UnifiedDispatcher (in api container)
                              ↓
                    Route by hostname/path
                              ↓
         ├→ localhost → FastAPI App (API/GUI/OAuth)
         ├→ proxy1.com → Proxy App (forwarding only)
         └→ proxy2.com → Proxy App (forwarding only)

For PROXY protocol support:
External LB → Port 10001 → PROXY Handler → Port 9000 → UnifiedDispatcher
```

## Server Configuration

- `HTTP_PORT` - HTTP server port (default: 80)
- `HTTPS_PORT` - HTTPS server port (default: 443)
- `SERVER_HOST` - Server bind address (default: 0.0.0.0)
- `SELF_SIGNED_CN` - Common name for self-signed certificates (default: localhost)
- `API_URL` - Base URL for API endpoints (default: http://localhost:9000)

### Internal Ports
- Port 9000: Direct API access (localhost-only)
- Port 10001: PROXY protocol endpoint (forwards to 9000)

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

Each proxy domain gets its own ASGI app instance:

### Benefits
- No port conflicts or race conditions
- Instance isolation - delete proxy without affecting others
- Clean resource management per instance
- Dynamic add/remove without side effects
- Preserves real client IPs through PROXY protocol
- Unified HTTP/HTTPS client IP handling via Redis

### Instance Lifecycle
1. **Creation**: New proxy triggers instance creation
2. **Update**: Configuration changes update instance
3. **Deletion**: Proxy removal cleanly shuts down instance
4. **No Restart**: All operations without service restart

## WebSocket and SSE Support

The dispatcher handles streaming protocols:
```python
async def handle_websocket(websocket: WebSocket):
    """Forward WebSocket connections"""
    await websocket.accept()
    # Bidirectional streaming
    await forward_websocket(websocket, backend_ws)
```

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

### PROXY Protocol
TCP-level handler preserves real client IPs:
```
External LB → Port 10001 → Parse PROXY header → Store in Redis → Forward to 9000
```

### Redis Storage
All configuration and state in Redis:
- Service mappings
- SSL certificates
- Route configurations
- Client IP information

### Workflow Orchestration
Event-driven instance management:
- Proxy events trigger instance updates
- Certificate events trigger SSL updates
- No manual intervention required

## Best Practices

1. **Instance Isolation**: Each proxy domain isolated
2. **Resource Limits**: Set connection pool limits
3. **Streaming**: Use streaming for large payloads
4. **Health Checks**: Monitor all instances
5. **Graceful Shutdown**: Clean up resources properly

## Troubleshooting

### Common Issues

1. **SSL Certificate Not Found**: Check certificate exists for hostname
2. **Backend Unreachable**: Verify target URL and network
3. **High Memory Usage**: Check for response streaming
4. **PROXY Protocol Issues**: Verify load balancer configuration

### Debug Commands

```bash
# Check active instances
curl http://localhost:9000/api/v1/dispatcher/instances

# View instance health
curl http://localhost:9000/api/v1/dispatcher/health

# Check SSL context
curl https://hostname --resolve hostname:443:127.0.0.1
```

## Related Documentation

- [Proxy Manager](../proxy/CLAUDE.md) - Proxy configuration
- [Certificate Manager](../certmanager/CLAUDE.md) - SSL certificates
- [Middleware](../middleware/CLAUDE.md) - PROXY protocol
- [Workflow Orchestration](../orchestration/CLAUDE.md) - Instance lifecycle