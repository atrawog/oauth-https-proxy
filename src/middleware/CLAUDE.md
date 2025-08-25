# Middleware Documentation

## Overview

The middleware layer provides request/response processing, including PROXY protocol support for preserving real client IPs and other cross-cutting concerns.

## PROXY Protocol Support

The system uses HAProxy PROXY protocol v1 INTERNALLY to preserve real client IPs between components. This is essential for security, logging, and rate limiting.

### Why PROXY Protocol is Essential

Without PROXY protocol, all connections to proxy instances would appear to come from 127.0.0.1 (the dispatcher). This would break:
- **Security**: Can't identify real attackers
- **Rate Limiting**: Would rate-limit the dispatcher, not clients
- **Logging**: All logs would show 127.0.0.1 as the source
- **OAuth Validation**: Can't track client sessions properly
- **Analytics**: No way to count unique visitors

### The Correct Architecture

```
INTERNAL PROXY PROTOCOL FLOW:

Client → Dispatcher (80/443) → [PROXY header] → HypercornInstance (12xxx/13xxx)
                                                 ├─ PROXY Handler
                                                 │  • Parse PROXY header
                                                 │  • Store client IP in Redis
                                                 └─ Hypercorn (22xxx/23xxx)
                                                    • Terminate SSL
                                                    • Run ProxyOnlyApp
                                                    • UnifiedProxyHandler validates OAuth

The architecture correctly separates concerns:
1. PROXY Handler: Parses PROXY header, stores client IP in Redis
2. Hypercorn: Terminates SSL, runs Starlette app
3. UnifiedProxyHandler: Complete OAuth validation with full application context
4. Clean separation: Each component does one thing well

Note: PROXY protocol is used INTERNALLY between dispatcher and proxy instances only!
There are NO external load balancers using PROXY protocol.
```

#### Why This Architecture Works
1. **PROXY protocol preserves client IPs**: Without it, all connections appear from 127.0.0.1
2. **Hypercorn terminates SSL**: It has the certificates and application context
3. **UnifiedProxyHandler validates OAuth**: It knows routes, scopes, and backends (912 lines of battle-tested logic)
4. **Clear separation of concerns**: Each layer does one thing well
5. **No "OAuth at the edge"**: OAuth needs full application context, not just TCP/SSL layer

### Ports

- Port 9000: Direct API access (internal only, Docker service)
- Port 12000+: HTTP proxy instances with PROXY protocol
- Port 13000+: HTTPS proxy instances with PROXY protocol
- Port 22000+: Internal HTTP Hypercorn (12xxx + 10000)
- Port 23000+: Internal HTTPS Hypercorn with SSL (13xxx + 10000)

**CRITICAL**: PROXY protocol is only used internally for client IP preservation between dispatcher and proxy instances

## Key Components

### proxy_protocol_handler.py
TCP-level handler that parses PROXY headers:

```python
class ProxyProtocolHandler:
    async def handle_connection(self, reader, writer):
        # Read PROXY protocol header
        header = await reader.readline()
        
        if header.startswith(b'PROXY '):
            # Parse client info
            client_ip, client_port = parse_proxy_header(header)
            
            # Store in Redis with TTL
            await store_client_info(client_ip, client_port)
            
            # Forward connection without PROXY header
            await forward_to_backend(reader, writer)
```

### proxy_client_middleware.py
ASGI middleware that injects client IPs:

```python
class ProxyClientMiddleware:
    async def __call__(self, scope, receive, send):
        if scope["type"] == "http":
            # Retrieve client info from Redis
            client_info = await get_client_info(
                scope["server"][1],  # server port
                scope["client"][1]   # client port
            )
            
            if client_info:
                # Inject headers
                scope["headers"].append(
                    (b"x-real-ip", client_info["ip"].encode())
                )
                scope["headers"].append(
                    (b"x-forwarded-for", client_info["ip"].encode())
                )
        
        await self.app(scope, receive, send)
```

### Redis Side Channel
Stores client info keyed by `proxy:client:{server_port}:{client_port}`:

```python
async def store_client_info(server_port: int, client_port: int, client_ip: str):
    key = f"proxy:client:{server_port}:{client_port}"
    await redis.set(key, json.dumps({
        "client_ip": client_ip,
        "timestamp": time.time()
    }), ex=60)  # 60 second TTL
```

## PROXY Protocol v1 Format

```
PROXY TCP4 192.168.1.100 10.0.0.1 56789 443\r\n
```

Components:
- `PROXY` - Protocol identifier
- `TCP4` - Protocol family (TCP4 or TCP6)
- `192.168.1.100` - Source IP (real client)
- `10.0.0.1` - Destination IP (proxy)
- `56789` - Source port
- `443` - Destination port

## Implementation Details

### Connection Flow

1. **Client** connects to Dispatcher on port 80 or 443
2. **Dispatcher** determines target proxy instance based on hostname
3. **Dispatcher** adds PROXY protocol header with real client IP
4. **Proxy Instance** (port 12000+) receives connection with PROXY header
5. **Proxy Instance** parses PROXY header to get real client IP
6. **Proxy Instance** validates OAuth token if auth is enabled
7. **Proxy Instance** forwards request to target with auth headers
8. **Target Application** sees real client IP and auth info

### TTL Management

Client info has 60-second TTL to:
- Prevent Redis memory bloat
- Handle connection cleanup
- Support reasonable connection durations

### Error Handling

```python
async def parse_proxy_header(header: bytes) -> Optional[ClientInfo]:
    try:
        parts = header.decode().strip().split()
        if len(parts) >= 6 and parts[0] == "PROXY":
            return ClientInfo(
                ip=parts[2],
                port=int(parts[4])
            )
    except Exception as e:
        logger.error(f"Failed to parse PROXY header: {e}")
    return None
```

## Other Middleware Components

### Request Logging Middleware
Logs all incoming requests with timing:

```python
class RequestLoggingMiddleware:
    async def __call__(self, scope, receive, send):
        start_time = time.time()
        
        await self.app(scope, receive, send)
        
        duration = time.time() - start_time
        await log_request(scope, duration)
```

### Error Handling Middleware
Catches and formats errors consistently:

```python
class ErrorHandlingMiddleware:
    async def __call__(self, scope, receive, send):
        try:
            await self.app(scope, receive, send)
        except Exception as e:
            await send_error_response(send, e)
```

## Configuration

### Environment Variables
- `PROXY_PROTOCOL_ENABLED` - Enable PROXY protocol support (default: true for proxy instances)
- `PROXY_CLIENT_TTL` - Redis TTL for client info (default: 60 seconds)

## Security Considerations

1. **Port Binding**: PROXY protocol port should only accept connections from trusted sources
2. **Header Validation**: Strict parsing to prevent injection attacks
3. **TTL Limits**: Reasonable TTLs to prevent resource exhaustion
4. **IP Spoofing**: Only trust PROXY protocol from known load balancers

## Performance Impact

- **Minimal Overhead**: < 1ms for PROXY header parsing
- **Redis Lookup**: < 0.5ms for client info retrieval
- **Connection Pooling**: Reuse Redis connections
- **Async Operations**: Non-blocking throughout

## Testing

### Test PROXY Protocol
```bash
# Send PROXY header manually
echo -e "PROXY TCP4 1.2.3.4 5.6.7.8 12345 80\r\nGET / HTTP/1.1\r\nHost: example.com\r\n\r\n" | nc localhost 10001
```

### Verify Client IP
```bash
# Check if real IP is preserved
curl -H "X-Forwarded-For: test" http://localhost:10001/debug/headers
```

## Monitoring

### Metrics
- PROXY protocol parse success/failure rate
- Client info cache hit/miss ratio
- Connection handling time
- Redis operation latency

### Debugging
```bash
# Check Redis for client info
redis-cli KEYS "proxy:client:*"

# Monitor PROXY protocol handling
tail -f logs/proxy_protocol.log
```

## Internal PROXY Protocol Usage

The PROXY protocol is used INTERNALLY only between:
- **Dispatcher** (ports 80/443): Receives client connections
- **Proxy Instances** (ports 12000+): Process requests with OAuth validation

This is NOT for external load balancers. The dispatcher acts as the entry point and routes to appropriate proxy instances using PROXY protocol to preserve the real client IP.

## Unified IP Handling

The same mechanism works for both HTTP and HTTPS:
- HTTP: Headers directly accessible
- HTTPS: Headers injected after TLS termination
- Consistent client IP across protocols

## PROXY Protocol and SSL

**CRITICAL**: The PROXY protocol handler does NOT handle SSL/TLS!

- PROXY protocol is a TCP-level protocol for preserving client IPs
- It operates BEFORE SSL termination
- SSL is handled by the backend service (Hypercorn in our case)

### Function Signature
```python
async def create_proxy_protocol_server(
    backend_host: str,
    backend_port: int, 
    listen_host: str,
    listen_port: int,
    redis_client: Optional[redis.Redis] = None
) -> asyncio.Server:
    # Note: NO ssl_context parameter!
```

The PROXY handler simply:
1. Accepts TCP connections
2. Reads the PROXY protocol header
3. Stores client info in Redis
4. Forwards the raw TCP stream to the backend
5. The backend (Hypercorn) handles SSL termination

## Best Practices

1. **Trusted Sources Only**: Only accept PROXY protocol from known LBs
2. **Monitor TTLs**: Ensure Redis doesn't accumulate stale entries
3. **Log Parsing Errors**: Track malformed PROXY headers
4. **Test Thoroughly**: Verify client IPs are preserved correctly
5. **Document Configuration**: Clear documentation for operations team

## Related Documentation

- [Dispatcher](../dispatcher/CLAUDE.md) - Request routing
- [Storage](../storage/CLAUDE.md) - Redis client info storage
- [Logging](../logging/CLAUDE.md) - Request logging with real IPs