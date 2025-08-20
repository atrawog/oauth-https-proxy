# Docker Service Management Documentation

## Overview

The Docker service management module provides unified management for containerized services with lifecycle control, resource limits, and port management.

## Service Types

```python
class ServiceType(str, Enum):
    DOCKER = "docker"      # Docker container services
    EXTERNAL = "external"  # External URL references (registered via API)
    INTERNAL = "internal"  # Built-in services (currently only 'api')
```

## Internal Services

The system automatically registers these internal services:
- **api**: The main API service (http://api:9000) - handles all API, OAuth, and certificate operations

## Docker Configuration

- `DOCKER_GID` - Docker group GID on host (default: 999, varies by OS)
- `DOCKER_API_VERSION` - Docker API version (default: 1.41)
- `DOCKER_HOST` - Docker socket path (default: unix:///var/run/docker.sock)
- `BASE_DOMAIN` - Base domain for auto-created service proxies

## Docker Service Schema

```json
{
  "service_name": "my-app",
  "service_type": "docker",
  "image": "nginx:latest",  // OR use dockerfile_path
  "dockerfile_path": "./dockerfiles/custom.Dockerfile",
  "internal_port": 3000,  // Port inside container (auto-detected from image if not specified)
  "external_port": 3000,  // DEPRECATED - use port_configs for multi-port support
  "memory_limit": "512m",
  "cpu_limit": 1.0,
  "environment": {"KEY": "value"},
  "command": ["npm", "start"],
  "networks": ["proxy_network"],
  "labels": {"custom": "label"},
  "expose_ports": true,  // Enable port exposure
  "port_configs": [  // Multi-port configuration
    {
      "name": "http",
      "host": 3000,
      "container": 3000,
      "bind": "127.0.0.1",  // or "0.0.0.0" for all interfaces
      "protocol": "tcp",
      "source_token": "optional_access_token"  // For port access control
    }
  ],
  "bind_address": "127.0.0.1"  // Default bind address for ports
}
```

## External Service Schema

```json
{
  "service_name": "api-gateway",
  "service_type": "external",
  "target_url": "https://gateway.example.com",
  "description": "API Gateway service",
  "routing_enabled": true,
  "created_by": "admin",
  "created_at": "2024-01-15T10:00:00Z",
  "owner_token_hash": "sha256:..."
}
```

## API Endpoints

### Docker Service Endpoints
- `POST /services/` - Create new Docker service
- `GET /services/` - List all Docker services (requires trailing slash)
- `GET /services/unified` - List all services (Docker + external)
- `GET /services/{name}` - Get service details
- `PUT /services/{name}` - Update service configuration
- `DELETE /services/{name}` - Delete service
- `POST /services/{name}/start` - Start service
- `POST /services/{name}/stop` - Stop service
- `POST /services/{name}/restart` - Restart service
- `GET /services/{name}/logs` - Get service logs
- `GET /services/{name}/stats` - Get service statistics
- `POST /services/{name}/proxy` - Create proxy for service
- `POST /services/cleanup` - Clean up orphaned services

### External Service Endpoints
- `POST /services/external` - Register external service
- `GET /services/external` - List external services
- `DELETE /services/external/{name}` - Delete external service

### Port Management Endpoints
- `GET /services/{name}/ports` - List all ports for a service
- `POST /services/{name}/ports` - Add a port to existing service
- `DELETE /services/{name}/ports/{port_name}` - Remove a port from service
- `PUT /services/{name}/ports/{port_name}` - Update port configuration

### Global Port Query Endpoints
- `GET /services/ports` - List all allocated ports across all services
- `GET /services/ports/available` - Get available port ranges
- `POST /services/ports/check` - Check if port is available

## Service Commands

```bash
# Docker service management
just service-create <name> [image] [dockerfile] [port] [memory] [cpu] [auto-proxy] [token]
just service-create-exposed <name> <image> <port> [bind-address] [memory] [cpu] [token]  # Create with exposed port
just service-list [owned-only] [token]  # List Docker services
just service-show <name> [token]
just service-delete <name> [force] [delete-proxy] [token]
just service-start <name> [token]
just service-stop <name> [token]
just service-restart <name> [token]

# External service management
just service-register <name> <target-url> [description] [token]  # Register external service
just service-list-external [token]                               # List external services
just service-show-external <name> [token]                        # Show external service details
just service-update-external <name> <target-url> [description] [token]  # Update external service
just service-unregister <name> [token]                          # Delete external service
just service-register-oauth [token]                              # Register OAuth as external service

# Unified service views
just service-list-all [type] [token]                             # List all services (Docker + external)

# Service monitoring
just service-logs <name> [lines] [timestamps] [token]
just service-stats <name> [token]

# Service proxy management
just service-proxy-create <name> [hostname] [enable-https] [token]
just service-cleanup [token]

# Port management
just service-port-add <name> <port> [bind-address] [source-token] [token]
just service-port-remove <name> <port-name> [token]
just service-port-list <name> [token]
just service-port-check <port> [bind-address] [token]
just service-ports-global [available-only] [token]
```

## Container Lifecycle Management

### Service Creation
1. **Image Pull**: Docker image is pulled if not locally available
2. **Container Creation**: Container created with specified configuration
3. **Network Connection**: Container connected to proxy_network
4. **Port Allocation**: Ports allocated and mapped
5. **Health Check**: Container health verified
6. **Proxy Creation**: Optional automatic proxy creation

### Resource Limits
- **Memory**: Specified in format like "512m", "1g"
- **CPU**: Decimal value (e.g., 0.5 = 50% of one CPU core)
- **Enforced**: Limits are hard limits, container killed if exceeded

### Network Configuration
All Docker services are connected to the `proxy_network` by default, allowing:
- Service-to-service communication by container name
- Isolation from host network
- Integration with proxy routing

## Multi-Port Support

Services can expose multiple ports with different configurations:

```python
port_configs = [
    {
        "name": "http",
        "host": 8080,
        "container": 80,
        "bind": "127.0.0.1",  # localhost only
        "protocol": "tcp"
    },
    {
        "name": "admin",
        "host": 8081,
        "container": 8081,
        "bind": "0.0.0.0",  # all interfaces
        "protocol": "tcp",
        "source_token": "admin_token"  # access control
    }
]
```

## External Services

External services are references to services running outside the Docker environment:

### Use Cases
- Reference existing infrastructure
- External APIs
- Third-party services
- Services on other hosts

### Integration
External services can be:
- Referenced in routes by service name
- Used as proxy targets
- Included in service discovery

## Service Discovery

Services are discoverable by name through:
1. **Docker DNS**: Container name resolution within proxy_network
2. **Redis Registry**: Service URL mapping in Redis
3. **Route Resolution**: Service names in routing rules

## Health Monitoring

### Docker Health Checks
- Container status monitoring
- Automatic restart on failure (if configured)
- Health endpoint verification

### Service Statistics
- CPU usage
- Memory consumption
- Network I/O
- Container uptime

## Best Practices

1. **Resource Limits**: Always set memory and CPU limits
2. **Port Binding**: Use localhost binding for internal services
3. **Health Checks**: Implement health endpoints
4. **Logging**: Configure appropriate log levels
5. **Cleanup**: Remove unused containers and images

## Troubleshooting

### Common Issues

1. **Port Conflicts**: Check port availability before creation
2. **Network Issues**: Ensure proxy_network exists
3. **Resource Limits**: Monitor for OOM kills
4. **Image Pull Failures**: Check registry access

### Debug Commands

```bash
# Check service status
just service-show <name> | jq .status

# View service logs
just service-logs <name> 100 true

# Check port allocation
just service-ports-global

# Monitor resource usage
just service-stats <name>
```

## Related Documentation

- [Port Management](../ports/CLAUDE.md) - Port allocation details
- [Proxy Manager](../proxy/CLAUDE.md) - Service proxy integration
- [Storage](../storage/CLAUDE.md) - Service data storage