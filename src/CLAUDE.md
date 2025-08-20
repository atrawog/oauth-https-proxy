# Source Code Structure and Implementation

This document describes the source code organization and technical implementation details. For general development guidelines, see [main CLAUDE.md](../CLAUDE.md).

## Directory Structure

```
./src/
  ├── api/         # API routers and async operations
  ├── auth/        # Flexible authentication system
  ├── certmanager/ # Certificate management with async ACME
  ├── consumers/   # Redis Streams consumers
  ├── dispatcher/  # Unified async dispatcher
  ├── docker/      # Docker service management
  ├── logging/     # Logging system
  ├── middleware/  # Middleware components including PROXY protocol handler
  ├── orchestration/# Workflow orchestrator for instance management
  ├── ports/       # Port management
  ├── proxy/       # Proxy management with async forwarding
  ├── shared/      # Shared utilities and config
  └── storage/     # Async Redis storage layer
```

## Environment Variables

### Core Configuration
- `LOG_LEVEL` - Application log level (DEBUG, INFO, WARNING, ERROR, CRITICAL) - default: INFO
- `HTTP_PORT` - HTTP server port (default: 80)
- `HTTPS_PORT` - HTTPS server port (default: 443)
- `SERVER_HOST` - Server bind address (default: 0.0.0.0)
- `SELF_SIGNED_CN` - Common name for self-signed certificates (default: localhost)
- `API_URL` - Base URL for API endpoints (default: http://localhost:9000)
- `BASE_DOMAIN` - Base domain for services and OAuth (e.g., yourdomain.com)
- `REDIS_PASSWORD` - Redis authentication password (required, 32+ random bytes recommended)
- `REDIS_URL` - Full Redis connection URL including password (format: `redis://:password@host:port/db`)

### Internal Ports
- Port 9000: Direct API access (localhost-only)
- Port 10001: PROXY protocol endpoint (forwards to 9000)

## Async Architecture Overview

The entire system has been migrated to a fully asynchronous architecture for improved performance and scalability:

### Async Components
- **AsyncRedisStorage**: Central async storage layer with connection pooling
- **Async API Routers**: All FastAPI endpoints use async handlers
- **Async Certificate Manager**: Non-blocking ACME operations
- **Async Proxy Forwarding**: Streaming request/response handling
- **Async Service Manager**: Docker operations via async python-on-whales
- **Async Consumers**: Redis Streams consumers with async processing
- **Unified Consumer**: Single consumer handles all workflow events
- **Instance Workflow**: Async orchestration of proxy instances
- **Async Initialization**: Background tasks for service startup

### Async Benefits
- **Improved Concurrency**: Handle thousands of simultaneous connections
- **Reduced Latency**: Non-blocking I/O for all operations
- **Better Resource Utilization**: Single process handles more requests
- **Streaming Support**: Efficient WebSocket and SSE handling

## Component Documentation

For detailed documentation on specific components:

- [API Documentation](api/CLAUDE.md) - API routers, endpoints, and FastAPI app
- [Authentication System](auth/CLAUDE.md) - Flexible authentication with multiple auth types
- [OAuth Service](api/oauth/CLAUDE.md) - OAuth implementation and MCP compliance
- [Certificate Manager](certmanager/CLAUDE.md) - ACME certificate management
- [Proxy Manager](proxy/CLAUDE.md) - Reverse proxy and routing
- [Docker Services](docker/CLAUDE.md) - Container management
- [Port Management](ports/CLAUDE.md) - Port allocation and control
- [Storage Layer](storage/CLAUDE.md) - Redis storage schema
- [Dispatcher](dispatcher/CLAUDE.md) - Unified dispatcher architecture
- [Workflow Orchestration](orchestration/CLAUDE.md) - Event-driven lifecycle
- [Middleware](middleware/CLAUDE.md) - PROXY protocol and middleware
- [Logging System](logging/CLAUDE.md) - Advanced logging architecture