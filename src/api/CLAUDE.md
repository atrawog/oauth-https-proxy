# API Documentation

## Overview

The API module provides the main FastAPI application, routers, and web interface for the HTTPS OAuth Proxy system.

## Architecture

### API App (FastAPI)
- Full FastAPI with async lifespan management
- Async API endpoints, Web GUI, certificate management
- Integrated OAuth 2.1 server functionality
- Global resources (scheduler, Redis) with async initialization
- Runs on internal port 9000
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

## OAuth Token Management

### OAuth Authentication
- All authentication via OAuth 2.1 with GitHub integration
- JWT tokens with RS256 signature
- Scopes: `admin`, `user`, `mcp`
- Token lifetime: 30 minutes (configurable)
- Refresh tokens supported

### OAuth Token Commands
Use the justfile commands for OAuth token management:
- `just oauth-login` - Login via device flow
- `just oauth-status` - Check token status
- `just oauth-refresh` - Refresh access token
- `just oauth-logout` - Clear stored tokens
- `just oauth-info` - Display detailed token info

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
  "proxy_hostnames": []  // List of proxies when scope=proxy
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

### Flexible Authentication System

The API uses a flexible authentication system that supports multiple auth types:

#### Authentication Types
- **none** - Public access, no authentication required
- **oauth** - OAuth 2.1 with GitHub integration (default for all protected endpoints)
- **admin** - Admin-only operations (OAuth token with admin scope)

#### Using AuthDep in Routes

All API endpoints use the `AuthDep` dependency for authentication:

```python
from src.auth import AuthDep, AuthResult

# Public endpoint
@router.get("/health")
async def health():
    return {"status": "ok"}

# OAuth token required (default)
@router.get("/data")
async def get_data(auth: AuthResult = Depends(AuthDep())):
    return {"user": auth.principal}

# Admin only
@router.delete("/tokens/{name}")
async def delete_token(name: str, auth: AuthResult = Depends(AuthDep(admin=True))):
    return {"deleted": name}

# OAuth with specific requirements
@router.post("/services")
async def create_service(
    auth: AuthResult = Depends(AuthDep(
        auth_type="oauth",
        required_scopes=["service:write"],
        allowed_users=["alice", "bob"]
    ))
):
    return {"created_by": auth.principal}

# OAuth with ownership check
@router.delete("/certificates/{cert_name}")
async def delete_cert(
    cert_name: str,
    auth: AuthResult = Depends(AuthDep(check_owner=True))
):
    return {"deleted": cert_name}
```

#### Request Format

For endpoints requiring authentication:
```
Authorization: Bearer <oauth_jwt_token>
```

#### Dynamic Configuration

Authentication can be configured at runtime via the API:

```bash
# Configure endpoint authentication
POST /auth/endpoints
{
  "path_pattern": "/admin/*",
  "methods": ["*"],
  "auth_type": "admin",
  "priority": 100
}

# Configure route authentication
PUT /routes/{route_id}/auth
{
  "auth_type": "oauth",
  "oauth_scopes": ["route:access"]
}
```

Tokens are validated via Redis with caching for optimal performance.

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