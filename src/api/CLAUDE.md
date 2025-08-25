# API Documentation

## Overview

The API module provides the main FastAPI application, routers, and web interface for the HTTPS OAuth Proxy system.

## Architecture

### API Architecture
- Runs on a SINGLE port: 9000
- Internal access only (no external port exposure)
- Accessed via Docker service name: http://api:9000
- Binds to 0.0.0.0:9000 in Docker for container networking
- ALL requests come through proxy instances (OAuth validated)
- Full FastAPI with async lifespan management
- Background tasks for certificate renewal and cleanup

### Directory Structure
```
api/
├── __init__.py
├── async_init.py     # Async initialization
├── auth.py          # Authentication utilities
├── models.py        # Pydantic models
├── oauth/           # OAuth implementation (see oauth/CLAUDE.md)
├── routers/         # API routers organized by path
│   ├── auth/       # /auth-config/* and /auth/endpoints/*
│   ├── certificates/ # /certificates/*
│   ├── logs/       # /logs/*
│   ├── mcp/        # /mcp - Model Context Protocol server
│   ├── oauth/      # /oauth/*
│   ├── proxy/      # /proxy/targets/* - includes sub-modules:
│   │   ├── core.py     # Basic proxy CRUD operations
│   │   ├── auth.py     # Proxy authentication configuration
│   │   ├── routes.py   # Proxy route management
│   │   ├── resources.py # Protected resource metadata
│   │   ├── oauth_server.py # OAuth server metadata
│   │   └── github_oauth.py # GitHub OAuth credentials
│   ├── resources/  # /resources/*
│   ├── routes/     # /routes/*
│   ├── services/   # /services/*
│   └── tokens/     # /tokens/*
├── server.py        # FastAPI app setup
└── static/         # Web GUI assets
```

## API Structure

All API endpoints are mounted at the root level with clean URLs: `/{resource}`. This provides a simple, consistent API structure.

## OAuth-Only Authentication System

### How It Works
- **Single Auth Layer**: Proxy validates OAuth JWT tokens
- **Trust Headers**: API reads `X-Auth-User`, `X-Auth-Scopes`, `X-Auth-Email` from proxy
- **No Validation in API**: Complete trust of proxy-provided headers
- **Three Scopes**: `admin` (write), `user` (read), `mcp` (protocol)

### Header-Based Authentication in API
```python
# Every API endpoint now uses this pattern:
auth_user = request.headers.get("X-Auth-User", "system")
auth_scopes = request.headers.get("X-Auth-Scopes", "").split()
is_admin = "admin" in auth_scopes

# Check permissions for mutations
if not is_admin:
    raise HTTPException(403, "Admin scope required")
```

### OAuth Commands
- `just oauth-login` - Login via GitHub Device Flow
- `just oauth-status` - Check token status  
- `just oauth-refresh` - Refresh access token

## Route Management API

### Route Endpoints
**Note**: Collection endpoints require trailing slashes to avoid 307 redirects.
- `GET /routes/` - List all routing rules (requires trailing slash)
- `POST /routes/` - Create new routing rule
- `GET /routes/{route_id}` - Get specific route details
- `PUT /routes/{route_id}` - Update route configuration
- `DELETE /routes/{route_id}` - Delete route
- `GET /routes/formatted` - Get routes in formatted table

### Route Schema
```json
{
  "route_id": "auth-route",
  "path_pattern": "/auth/",
  "target_type": "service",  // port|service|hostname|url
  "target_value": "auth",
  "priority": 90,  // Higher = checked first
  "methods": ["GET", "POST"],
  "enabled": true,
  "scope": "global",  // global|proxy - defines route applicability
  "proxy_hostnames": [],  // List of proxies when scope=proxy
  "auth_config": {  // Optional: Override proxy auth settings
    "auth_type": "none",  // Make specific route public
    "override_proxy_auth": true
  }
}
```

## Log Query API

### Log Endpoints
- `GET /logs/ip/{ip}` - Query by IP address
- `GET /logs/client/{client_id}` - Query by OAuth client
- `GET /logs/search` - Search logs with filters
- `GET /logs/errors` - Recent errors
- `GET /logs/events` - Event statistics

## MCP (Model Context Protocol) Server

### MCP Endpoint
- `POST /mcp` - Main MCP endpoint for LLM integration
- Supports streamable HTTP transport with SSE and JSON responses
- Stateful session management with persistent context
- Protocol versions: 2024-11-05, 2025-03-26, 2025-06-18

### MCP Features
- **Direct Mounting**: MCP SDK's Starlette app mounted directly on FastAPI
- **SSE Streaming**: Proper Server-Sent Events streaming for real-time responses
- **Session Management**: Stateful sessions with task group initialization
- **Tool Integration**: 10+ tools for system management (proxies, certificates, services)
- **Claude.ai Compatible**: Fully tested with Claude.ai connection requirements

### Implementation Details
See [MCP Router Documentation](routers/mcp/CLAUDE.md) for detailed implementation.

## Web GUI

The API includes a web-based management interface accessible at the root path (`/`).

### Static Assets
- `index.html` - Main web interface
- `app.js` - Client-side JavaScript
- `styles.css` - UI styling

### GUI Features
- Token management interface
- Certificate monitoring
- Proxy configuration
- Service management
- Real-time logs viewer

## Authentication

### Simplified Authentication Architecture

The API now uses a trust-based model with OAuth validation at the proxy layer only:

#### No Authentication in API
- **Removed AuthDep**: All `AuthDep` dependencies removed from routers
- **Trust Headers**: API reads authentication info from proxy headers
- **No Token Validation**: API never validates OAuth tokens
- **90% Code Reduction**: Removed ~80KB of auth code

#### Reading Auth Headers in Routes

All API endpoints now read headers directly:

```python
# Standard pattern for all endpoints
@router.post("/proxy/targets/")
async def create_proxy(
    request: Request,
    proxy_data: ProxyCreateRequest
):
    # Get auth info from headers (set by proxy)
    auth_user = request.headers.get("X-Auth-User", "system")
    auth_scopes = request.headers.get("X-Auth-Scopes", "").split()
    is_admin = "admin" in auth_scopes
    
    # Check permissions - admin scope required for mutations
    if not is_admin:
        raise HTTPException(403, "Admin scope required")
    
    # Process request...
```

#### Headers Set by Proxy

```http
X-Auth-User: alice              # GitHub username
X-Auth-Scopes: admin user       # Space-separated scopes
X-Auth-Email: alice@example.com # GitHub email
X-Auth-Client-Id: oauth_12345   # OAuth client ID
```

#### Scope Requirements

- **admin**: Required for all POST, PUT, DELETE, PATCH operations
- **user**: Required for all GET, HEAD, OPTIONS operations  
- **mcp**: Required for /mcp endpoints
- **Public**: /health and /.well-known/* require no auth

## Error Handling

The API uses standard HTTP status codes:
- `200` - Success
- `201` - Created
- `400` - Bad Request
- `401` - Unauthorized
- `404` - Not Found
- `500` - Internal Server Error

Error responses include detailed messages:
```json
{
  "detail": "Error description"
}
```

## Related Documentation

- [OAuth Service](oauth/CLAUDE.md) - OAuth implementation details
- [MCP Server](routers/mcp/CLAUDE.md) - Model Context Protocol implementation
- [API Routers](routers/v1/CLAUDE.md) - Detailed router documentation
- [Proxy Manager](../proxy/CLAUDE.md) - Proxy endpoints
- [Certificate Manager](../certmanager/CLAUDE.md) - Certificate endpoints
- [Service Management](../docker/CLAUDE.md) - Service endpoints