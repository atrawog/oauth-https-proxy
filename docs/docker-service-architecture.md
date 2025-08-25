# Docker Service Management Architecture

This document explains how the dynamic Docker service management feature works and its security implications.

## Overview

The system allows creating and managing Docker containers dynamically through the API. The proxy container runs as a non-root user but has access to the Docker socket through group permissions.

## Components

### 1. Proxy Container (Main Application)
- Runs as non-root user (`proxyuser`, UID 1000)
- Has `CAP_NET_BIND_SERVICE` capability to bind to ports 80/443
- Contains Docker CLI and python-on-whales library
- Added to docker group via GID for socket access

### 2. Python-on-whales
- Python library that wraps Docker CLI commands
- Executes `docker` commands internally
- Uses Unix socket at `/var/run/docker.sock` by default

## Security Model

### Direct Socket Access
The proxy container has direct access to the Docker socket through group permissions. This means:
- Any code running in the proxy container can control Docker
- Creating containers effectively grants root access to the host
- Security depends entirely on API-level authentication and authorization

### Security Flow

```
User API Request
    ↓
FastAPI Endpoint (/api/v1/services)
    ↓ (Authentication & Authorization)
DockerManager (Python)
    ↓
python-on-whales library
    ↓
Docker CLI command (e.g., "docker run ...")
    ↓ (uses /var/run/docker.sock)
Docker daemon executes operation
```

## Environment Variables

### Docker Configuration
```bash
DOCKER_GID=999              # Docker group GID (must match host)
DOCKER_API_VERSION=1.41     # Docker API version
# DOCKER_HOST=...           # Optional: Override Docker socket location
```

### Finding Your Docker GID
```bash
# On the host system, run:
getent group docker | cut -d: -f3

# Common values:
# - Debian/Ubuntu: 999
# - Arch Linux: 994  
# - Fedora: 989
```

## Security Considerations

⚠️ **IMPORTANT**: Docker socket access effectively grants root privileges on the host system.

1. **Direct Socket Access**: The proxy container has full Docker control via socket
2. **API Authentication**: Security relies entirely on token-based API access control
3. **Non-root User**: Application runs as `proxyuser`, but with docker group permissions
4. **Network Isolation**: Created services should be placed on isolated networks
5. **Resource Limits**: CPU and memory limits help prevent resource exhaustion
6. **Image Allowlist**: Only approved images can be deployed (application-level control)

### Security Implications

Anyone who can create Docker containers through the API can potentially:
- Mount host filesystem into containers
- Run privileged containers
- Access host network namespace
- Effectively gain root access to the host

**Recommendation**: Only grant service creation permissions to fully trusted users.

## Common Operations

### Creating a Service
```bash
# Via API
curl -X POST http://localhost/api/v1/services \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "service_name": "my-nginx",
    "image": "nginx:alpine",
    "memory_limit": "128m",
    "cpu_limit": 0.5
  }'

# Via just command
just service create my-nginx nginx:alpine
```

### How It Works Internally

1. **API validates** the request and checks permissions
2. **DockerManager** allocates a port from the range (11000-20000)
3. **python-on-whales** executes: `docker run --name my-nginx --memory 128m ...`
4. **Docker CLI** communicates with Docker daemon via Unix socket
5. **Docker daemon** creates and starts the container
6. **Service info** is stored in Redis for tracking

## Troubleshooting

### Cannot connect to Docker
- Check Docker socket is mounted: `docker exec proxy ls -la /var/run/docker.sock`
- Verify Docker GID matches host: `docker exec proxy id`
- Test connection: `docker exec proxy docker version`

### Permission denied errors
- Ensure DOCKER_GID in .env matches host docker group
- Find host docker GID: `getent group docker | cut -d: -f3`
- Restart proxy container after changing DOCKER_GID

### Services not accessible
- Ensure services are created on `proxy_network`
- Check allocated port is not blocked
- Verify proxy target is configured correctly

## Limitations

1. **No Swarm Mode**: Only standalone containers supported
2. **No Direct Exec**: Can't directly exec into containers from API (security)
3. **Build Context**: Limited to predefined directories
4. **Network Access**: Services must be on proxy_network to be accessible

## Alternative Approaches Considered

### Pure Python Docker Client
Instead of python-on-whales (which requires Docker CLI), we could use `docker-py`:
- **Pros**: No Docker CLI needed, direct HTTP API calls, smaller container
- **Cons**: Less modern API, fewer features, more complex for some operations

The current approach with python-on-whales was chosen for its better developer experience and type safety, despite requiring the Docker CLI installation.

## Future Enhancements

1. Support for Docker Compose files
2. Service templates for common applications  
3. Automatic SSL certificate generation for services
4. Service health monitoring and auto-restart
5. Resource usage quotas per token
6. Consider switching to docker-py for smaller footprint