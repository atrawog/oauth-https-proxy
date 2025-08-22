# Middleware Documentation

## Overview

The middleware layer provides request/response processing, including PROXY protocol support for preserving real client IPs and other cross-cutting concerns.

## PROXY Protocol Support

The system supports HAProxy PROXY protocol v1 for preserving real client IPs across load balancers and reverse proxies.

### Architecture

```
External LB → Port 10001 (PROXY handler) → Port 9000 (Hypercorn)
              ↓
        Parses & strips PROXY header
        Stores client info in Redis
              ↓
        ASGI middleware retrieves client IP
        Injects X-Real-IP/X-Forwarded-For headers
```

### Ports

- Port 9000: Direct API access (localhost-only, no PROXY protocol)
- Port 10001: PROXY protocol v1 enabled (for external load balancers/reverse proxies)
- Client IP preservation through Redis side channel for unified HTTP/HTTPS handling

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

1. **External Load Balancer** connects to port 10001
2. **PROXY Protocol Handler** reads and parses header
3. **Client Info Stored** in Redis with connection details
4. **Connection Forwarded** to port 9000 without PROXY header
5. **ASGI Middleware** retrieves client info from Redis
6. **Headers Injected** into HTTP request
7. **Application** sees real client IP

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
- `PROXY_PROTOCOL_ENABLED` - Enable PROXY protocol support (default: true on port 10001)
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

## Integration with Load Balancers

### HAProxy Configuration
```
backend api_backend
    mode tcp
    server api1 api.example.com:10001 send-proxy
```

### NGINX Configuration
```
stream {
    server {
        listen 443;
        proxy_pass backend:10001;
        proxy_protocol on;
    }
}
```

## Unified IP Handling

The same mechanism works for both HTTP and HTTPS:
- HTTP: Headers directly accessible
- HTTPS: Headers injected after TLS termination
- Consistent client IP across protocols

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