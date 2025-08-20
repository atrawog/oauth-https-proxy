# Flexible Authentication System Documentation

## Overview

The flexible authentication system provides unified authentication and authorization across all layers of the OAuth HTTPS Proxy:
- **API Endpoints** - Fine-grained control per API path
- **Routes** - Auth requirements for routing rules  
- **Proxies** - Per-proxy authentication settings

## Architecture

### Core Components

1. **FlexibleAuthService** (`service.py`) - Central authentication service
2. **Auth Models** (`models.py`) - Configuration and result models
3. **Auth Dependencies** (`dependencies.py`) - FastAPI dependency injection
4. **Auth Configs** - Stored in Redis with pattern matching

### Authentication Types

The system supports four authentication types:

#### 1. `none` - Public Access
No authentication required. Anyone can access.

#### 2. `bearer` - API Token
Requires valid `acm_*` bearer token. Options:
- `bearer_allow_admin`: Admin tokens can access (default: true)
- `bearer_check_owner`: Verify token owns the resource

#### 3. `admin` - Admin Only
Requires the admin token (`ADMIN_TOKEN` environment variable).

#### 4. `oauth` - OAuth 2.1
Requires valid OAuth token with configurable:
- `oauth_scopes`: Required scopes
- `oauth_audiences`: Required audiences
- `oauth_allowed_users`: Allowed GitHub usernames
- `oauth_allowed_emails`: Allowed email patterns
- `oauth_allowed_groups`: Allowed groups/organizations

## Usage Examples

### API Endpoint Authentication

#### Using AuthDep in Routes

```python
from src.auth import AuthDep, AuthResult

# Public endpoint (no auth)
@router.get("/health")
async def health():
    return {"status": "ok"}

# Bearer token required (uses config or default)
@router.get("/api/v1/data")
async def get_data(auth: AuthResult = Depends(AuthDep())):
    return {"user": auth.principal}

# Admin only
@router.delete("/api/v1/tokens/{name}")
async def delete_token(
    name: str,
    auth: AuthResult = Depends(AuthDep(admin=True))
):
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
    auth: AuthResult = Depends(AuthDep(
        auth_type="bearer",
        check_owner=True,
        owner_param="cert_name"
    ))
):
    return {"deleted": cert_name}
```

### Configuring Endpoint Authentication

Endpoints can be configured via the API or directly in Redis:

```python
# Configure public health endpoint
{
    "path_pattern": "/health",
    "methods": ["GET"],
    "auth_type": "none",
    "priority": 100
}

# Configure admin-only token management
{
    "path_pattern": "/api/v1/tokens/*",
    "methods": ["*"],
    "auth_type": "admin",
    "priority": 90
}

# Configure OAuth for services with specific users
{
    "path_pattern": "/api/v1/services/*",
    "methods": ["POST", "PUT", "DELETE"],
    "auth_type": "oauth",
    "oauth_scopes": ["service:write"],
    "oauth_allowed_users": ["alice", "bob", "charlie"],
    "priority": 80
}

# Configure bearer with ownership for certificates
{
    "path_pattern": "/api/v1/certificates/{cert_name}",
    "methods": ["DELETE"],
    "auth_type": "bearer",
    "bearer_check_owner": true,
    "owner_param": "cert_name",
    "priority": 85
}
```

### Route Authentication

Routes can have their own auth requirements:

```python
# Route model with auth config
route = {
    "route_id": "metrics",
    "path_pattern": "/metrics",
    "target_type": "service",
    "target_value": "prometheus",
    "auth_config": {
        "auth_type": "admin"
    },
    "override_proxy_auth": true  # Override proxy-level auth
}

# In the route handler
auth_service = request.app.state.auth_service
result = await auth_service.check_route_auth(
    request=request,
    route_id="metrics"
)
```

### Proxy Authentication

Proxies have flexible auth configuration:

```python
# OAuth-protected API proxy
proxy_config = {
    "hostname": "api.example.com",
    "target_url": "http://backend:3000",
    "auth_enabled": true,
    "auth_proxy": "auth.example.com",  # OAuth server
    "auth_mode": "enforce",  # or "redirect", "pass-through"
    "auth_required_users": ["*"],  # All GitHub users
    "auth_allowed_scopes": ["api:read", "api:write"],
    "auth_excluded_paths": ["/.well-known/", "/health"]
}

# Bearer-protected internal service
proxy_config = {
    "hostname": "internal.example.com",
    "target_url": "http://internal:8080",
    "auth_enabled": true,
    "auth_type": "bearer",
    "auth_mode": "enforce"
}
```

## Configuration API

### Endpoint Auth Configuration

```bash
# List all endpoint configs
GET /api/v1/auth/endpoints

# Create endpoint config
POST /api/v1/auth/endpoints
{
    "path_pattern": "/api/v1/admin/*",
    "auth_type": "admin",
    "priority": 100
}

# Update endpoint config
PUT /api/v1/auth/endpoints/{config_id}

# Delete endpoint config
DELETE /api/v1/auth/endpoints/{config_id}

# Test path matching
POST /api/v1/auth/endpoints/test
{
    "path": "/api/v1/tokens/mytoken",
    "method": "GET"
}
```

### Route Auth Configuration

```bash
# Get route auth config
GET /api/v1/routes/{route_id}/auth

# Set route auth config
PUT /api/v1/routes/{route_id}/auth
{
    "auth_type": "oauth",
    "oauth_scopes": ["route:access"],
    "override_proxy_auth": true
}

# Remove route auth config
DELETE /api/v1/routes/{route_id}/auth
```

### Proxy Auth Configuration (Existing)

```bash
# Configure proxy auth
POST /api/v1/proxy/targets/{hostname}/auth
{
    "auth_type": "oauth",
    "auth_proxy": "auth.example.com",
    "auth_mode": "redirect",
    "auth_required_users": ["alice", "bob"]
}
```

## Pattern Matching

Endpoint patterns support wildcards:
- `*` matches any characters
- `/api/*` matches all paths starting with `/api/`
- `/api/v1/*/config` matches `/api/v1/service/config`, `/api/v1/token/config`, etc.

Patterns are matched by priority (higher first), then by specificity.

## Caching

Auth results are cached for performance:
- Default TTL: 60 seconds
- Configurable per auth config
- Cache key includes: path, method, token
- Cache cleared on config changes

## Migration from Old System

### Backward Compatibility

The old dependencies still work:

```python
# Old style (still works)
from src.api.auth import require_auth, require_admin

@router.get("/data")
async def get_data(auth = Depends(require_auth)):
    ...

# New style (recommended)
from src.auth import AuthDep

@router.get("/data")
async def get_data(auth = Depends(AuthDep())):
    ...
```

### Default Configurations

If no endpoint config exists, defaults are applied:
- `/api/*` paths default to `bearer` auth
- `/health`, `/.well-known/*` default to `none`
- Other paths default to `none`

## Security Considerations

1. **Admin Token**: Keep `ADMIN_TOKEN` secure and rotate regularly
2. **OAuth Scopes**: Use specific scopes, not wildcards
3. **User Allowlists**: Prefer specific users over `["*"]`
4. **Cache TTL**: Balance performance vs security
5. **Ownership Checks**: Enable for resource-specific operations

## Troubleshooting

### Debug Authentication

Check auth decisions:
```python
# Enable debug logging
LOG_LEVEL=DEBUG

# Check cache status in AuthResult
if result.cached:
    print(f"Result from cache: {result.cache_key}")

# Check auth service state
auth_service.clear_cache()  # Clear cache
```

### Common Issues

1. **401 Unauthorized**: Check token format, expiry, and configuration
2. **403 Forbidden**: Token valid but lacks required permissions
3. **No Config Found**: Default config applied, may not match expectations
4. **Cache Issues**: Clear cache after config changes

## Performance

The auth system is optimized for performance:
- Pattern matching uses efficient algorithms
- Results cached to minimize lookups
- Batch config loading on startup
- Async throughout for non-blocking ops

## Future Enhancements

Planned improvements:
- WebAuthn support
- API key authentication
- Rate limiting per auth type
- Auth metrics and monitoring
- Dynamic scope mapping