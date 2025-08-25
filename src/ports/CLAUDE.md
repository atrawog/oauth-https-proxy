# Port Management Architecture Documentation

## Overview

The port management system provides comprehensive control over port allocation and access with dynamic allocation, multi-port support per service, bind address control, and optional token-based access control.

## Key Features

- **Dynamic port allocation** with configurable ranges
- **Multi-port support** per service
- **Bind address control** (localhost vs all interfaces)
- **Source token authentication** for port access
- **Port ownership tracking** by service
- **Atomic port allocation** - No race conditions
- **Service isolation** - Ports owned by services
- **Access control** - Optional source_token for port access
- **Automatic cleanup** - Ports released when service deleted
- **Bind address flexibility** - Choose localhost or public access

## Port Ranges

- **Internal HTTP**: 9000-9999 (API and internal services)
- **Internal HTTPS**: 10000-10999 (internal SSL services)
- **Proxy HTTP**: 12000-12999 (HTTP proxy instances)
- **Proxy HTTPS**: 13000-13999 (HTTPS proxy instances with SSL)
- **Exposed Ports**: 14000-65535 (user-facing services)
- **Restricted Ports**: 22, 25, 53, 80, 443, 3306, 5432, 6379, 27017 (system reserved)

## Port Schema

```json
{
  "service_name": "my-app",
  "port_name": "http",
  "host_port": 3000,
  "container_port": 3000,
  "bind_address": "127.0.0.1",  // or "0.0.0.0"
  "protocol": "tcp",            // or "udp"
  "source_token_hash": "sha256:...",  // Optional access control
  "require_token": false,
  "owner_token_hash": "sha256:...",
  "description": "Main HTTP port"
}
```

## Port Configuration

Services can expose multiple ports with different access controls:

```python
port_configs = [
    {
        "name": "http",
        "host": 3000,
        "container": 3000,
        "bind": "127.0.0.1",  // localhost only
        "protocol": "tcp"
    },
    {
        "name": "api",
        "host": 3001,
        "container": 3001,
        "bind": "0.0.0.0",  // all interfaces
        "protocol": "tcp",
        "source_token": "api_access_token"  // requires token
    }
]
```

## Bind Address Options

### Localhost Only (`127.0.0.1`)
- Service only accessible from the host machine
- Ideal for internal services
- Enhanced security by default

### All Interfaces (`0.0.0.0`)
- Service accessible from external networks
- Required for public-facing services
- Use with caution and proper authentication

## Access Control

### Source Token Authentication
- Optional token requirement for port access
- Token stored as hash in Redis
- Validated on each connection attempt
- Provides simple access control without complex authentication

### Example Usage
```bash
# Create service with protected port
just service port-add my-app 3001 0.0.0.0 "secret_token"

# Access requires token in header/query
curl -H "X-Source-Token: secret_token" http://host:3001
```

## Port Purposes

The PortManager supports different purpose types for allocation:

- `internal_http`: Internal API services (9000-9999)
- `internal_https`: Internal SSL services (10000-10999)  
- `proxy_http`: HTTP proxy instances (12000-12999)
- `proxy_https`: HTTPS proxy instances (13000-13999)
- `exposed`: User-facing services (14000-65535)

## Port Allocation Process

1. **Check Redis Mapping**: Look for existing allocation
2. **Availability Check**: Verify port not in use
3. **Range Validation**: Ensure port in allowed range
4. **Atomic Allocation**: Use Redis lock to prevent conflicts
5. **Persistence**: Store mapping in Redis
3. **Atomic Allocation**: Redis atomic operation prevents races
4. **Ownership Assignment**: Port linked to service
5. **Configuration Storage**: Port config saved to Redis
6. **Docker Mapping**: Port mapped in container

## Multi-Port Services

Services can expose multiple ports for different purposes:

```bash
# Web interface on localhost
just service port-add my-app 8080 127.0.0.1

# API on all interfaces with token
just service port-add my-app 8081 0.0.0.0 "api_token"

# Admin interface on localhost
just service port-add my-app 8082 127.0.0.1
```

## Port Management Commands

```bash
# Add port to service
just service port-add <name> <port> [bind-address] [source-token] [token]

# Remove port from service
just service port-remove <name> <port-name> [token]

# List service ports
just service port-list <name> [token]

# Check port availability
just service port-check <port> [bind-address] [token]

# View all allocated ports
just service ports-global [available-only] [token]
```

## Python-on-whales Integration

The system uses python-on-whales for Docker port publishing with tuple format:
```python
ports = [("127.0.0.1", 3000), 3000]  # (host_ip:port, container_port)
```

## Port Cleanup

Ports are automatically released when:
- Service is deleted
- Port is explicitly removed
- Service configuration is updated

Manual cleanup available via:
```bash
just cleanup [token]
```

## Best Practices

1. **Use Localhost Binding**: Default to `127.0.0.1` for internal services
2. **Token Protection**: Use source tokens for public ports
3. **Port Ranges**: Stay within allocated ranges
4. **Document Ports**: Use descriptive port names
5. **Monitor Usage**: Check port allocation regularly

## Troubleshooting

### Common Issues

1. **Port Already in Use**: Check with `just service-ports-global`
2. **Bind Address Error**: Ensure network interface exists
3. **Token Validation Fails**: Verify token hash matches
4. **Port Range Violation**: Use ports within allowed ranges

### Debug Commands

```bash
# Check what's using a port
just service port-check 3000

# View all port allocations
just service ports-global

# Check available ranges
just service ports-global true
```

## Redis Storage

Port allocations stored in Redis:
```
port:{port}                 # Port allocation data
service:ports:{service}     # Hash of service port configurations
```

## Integration Points

- **Docker Services**: Automatic port mapping for containers
- **Proxy Routing**: Services accessible via port-based routes
- **Service Discovery**: Port information in service registry

## Security Considerations

1. **Default to Localhost**: Minimize attack surface
2. **Token Rotation**: Regularly update access tokens
3. **Port Scanning**: Monitor for unauthorized access attempts
4. **Firewall Rules**: Additional layer beyond bind address
5. **Audit Logging**: Track port access attempts

## Related Documentation

- [Docker Services](../docker/CLAUDE.md) - Service port configuration
- [Storage](../storage/CLAUDE.md) - Port data persistence
- [Proxy Manager](../proxy/CLAUDE.md) - Port-based routing