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
├── routers/         # API routers
│   └── v1/         # Version 1 API
├── server.py        # FastAPI app setup
└── static/         # Web GUI assets
```

## API Versioning

All API endpoints follow the versioning pattern `/api/v1/{resource}`. This allows for future API versions without breaking existing integrations.

## Token Management API

### Token Architecture
- Bearer token authentication for all write operations
- Dual-key storage: by hash (auth) and by name (management)
- Full token retrieval (not just preview)
- Ownership tracking - tokens own certificates/proxies
- Cascade deletion - deleting token removes owned resources

### Token Schema
```json
{
  "name": "admin",
  "token": "acme_7da65cc83419b3...",
  "hash": "sha256:479719852dbf16c7...",
  "cert_email": "admin@example.com",
  "created_at": "2024-01-15T10:00:00Z"
}
```

### Token Endpoints
- `GET /api/v1/tokens/` - List all tokens (requires trailing slash)
- `POST /api/v1/tokens/` - Create new token
- `POST /api/v1/tokens/generate` - Generate token for display
- `PUT /api/v1/tokens/email` - Update certificate email for current token
- `GET /api/v1/tokens/info` - Get current token information
- `GET /api/v1/tokens/{name}` - Get specific token details
- `DELETE /api/v1/tokens/{name}` - Delete a token
- `GET /api/v1/tokens/{name}/reveal` - Securely reveal token value

## Route Management API

### Route Endpoints
**Note**: Collection endpoints require trailing slashes to avoid 307 redirects.
- `GET /api/v1/routes/` - List all routing rules (requires trailing slash)
- `POST /api/v1/routes/` - Create new routing rule
- `GET /api/v1/routes/{route_id}` - Get specific route details
- `PUT /api/v1/routes/{route_id}` - Update route configuration
- `DELETE /api/v1/routes/{route_id}` - Delete route
- `GET /api/v1/routes/formatted` - Get routes in formatted table

### Route Schema
```json
{
  "route_id": "api-v1",
  "path_pattern": "/api/v1/",
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
- `GET /api/v1/logs/ip/{ip}` - Query by IP address
- `GET /api/v1/logs/client/{client_id}` - Query by OAuth client
- `GET /api/v1/logs/search` - Search logs with filters
- `GET /api/v1/logs/errors` - Recent errors
- `GET /api/v1/logs/events` - Event statistics

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
- **bearer** - API token authentication (acm_* tokens)
- **admin** - Admin-only operations (requires ADMIN_TOKEN)
- **oauth** - OAuth 2.1 with GitHub integration

#### Using AuthDep in Routes

All API endpoints use the `AuthDep` dependency for authentication:

```python
from src.auth import AuthDep, AuthResult

# Public endpoint
@router.get("/health")
async def health():
    return {"status": "ok"}

# Bearer token required (default)
@router.get("/api/v1/data")
async def get_data(auth: AuthResult = Depends(AuthDep())):
    return {"user": auth.principal}

# Admin only
@router.delete("/api/v1/tokens/{name}")
async def delete_token(name: str, auth: AuthResult = Depends(AuthDep(admin=True))):
    return {"deleted": name}

# OAuth with specific requirements
@router.post("/api/v1/services")
async def create_service(
    auth: AuthResult = Depends(AuthDep(
        auth_type="oauth",
        required_scopes=["service:write"],
        allowed_users=["alice", "bob"]
    ))
):
    return {"created_by": auth.principal}

# Bearer with ownership check
@router.delete("/api/v1/certificates/{cert_name}")
async def delete_cert(
    cert_name: str,
    auth: AuthResult = Depends(AuthDep(check_owner=True))
):
    return {"deleted": cert_name}
```

#### Request Format

For endpoints requiring authentication:
```
Authorization: Bearer acm_your_token_here
```

#### Dynamic Configuration

Authentication can be configured at runtime via the API:

```bash
# Configure endpoint authentication
POST /api/v1/auth/endpoints
{
  "path_pattern": "/api/v1/admin/*",
  "methods": ["*"],
  "auth_type": "admin",
  "priority": 100
}

# Configure route authentication
PUT /api/v1/routes/{route_id}/auth
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
- [API Routers](routers/v1/CLAUDE.md) - Detailed router documentation
- [Proxy Manager](../proxy/CLAUDE.md) - Proxy endpoints
- [Certificate Manager](../certmanager/CLAUDE.md) - Certificate endpoints
- [Service Management](../docker/CLAUDE.md) - Service endpoints