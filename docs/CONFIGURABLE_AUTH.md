# Configurable Authentication System

## Overview

The OAuth HTTPS Proxy now supports **configurable per-endpoint authentication**, allowing different authentication requirements for the same API endpoint at different mount points (e.g., `/` vs `/api/v1/`). This system reuses existing authentication code from both the OAuth and bearer token systems, providing a unified interface for all authentication types.

## Key Features

1. **Path-Specific Authentication**: Different auth for `/tokens/` vs `/api/v1/tokens/`
2. **Multiple Auth Types**: Support for `none`, `bearer`, `admin`, and `oauth`
3. **Pattern Matching**: Wildcards, parameters, and recursive patterns
4. **Priority Resolution**: Overlapping patterns resolved by priority
5. **OAuth Integration**: Full OAuth support with scopes and user restrictions
6. **Owner Validation**: Resource ownership checks for bearer tokens
7. **Runtime Configuration**: Change auth without code modifications
8. **Zero Breaking Changes**: Existing hardcoded auth continues to work

## Architecture

### Components

1. **AuthConfigMiddleware** (`src/api/auth_middleware.py`)
   - Captures full request paths before routing
   - Stores path in `request.state.full_path`

2. **PathPatternMatcher** (`src/api/pattern_matcher.py`)
   - Sophisticated pattern matching engine
   - Supports wildcards, parameters, and priorities

3. **UnifiedAuthHandler** (`src/api/unified_auth.py`)
   - Reuses existing auth code from OAuth and bearer systems
   - Provides consistent interface for all auth types
   - Integrates with `AsyncResourceProtector` for OAuth

4. **Auth Config Storage** (`src/storage/async_redis_storage.py`)
   - Redis-based configuration storage
   - Efficient caching with TTL
   - Index-based listing

5. **Management API** (`src/api/routers/v1/auth_config.py`)
   - CRUD operations for auth configurations
   - Pattern testing and validation
   - Admin-only access

## Authentication Types

### 1. None (Public)
```json
{
  "path_pattern": "/health",
  "auth_type": "none",
  "description": "Public health endpoint"
}
```

### 2. Bearer Token
```json
{
  "path_pattern": "/api/v1/certificates/*",
  "auth_type": "bearer",
  "owner_validation": true,
  "owner_param": "cert_name"
}
```

### 3. Admin Token
```json
{
  "path_pattern": "/tokens/*",
  "auth_type": "admin",
  "description": "Admin-only token management"
}
```

### 4. OAuth
```json
{
  "path_pattern": "/api/v1/mcp/*",
  "auth_type": "oauth",
  "oauth_scopes": ["mcp:read", "mcp:write"],
  "oauth_allowed_users": ["user1", "user2"],
  "oauth_resource": "https://mcp.example.com"
}
```

## Pattern Matching

### Supported Patterns

1. **Exact Match**: `/api/v1/tokens/`
2. **Single Wildcard**: `/api/v1/tokens/*` (one segment)
3. **Recursive Wildcard**: `/api/v1/**` (any depth)
4. **Parameters**: `/api/v1/tokens/{name}`

### Priority Resolution

When multiple patterns match, the highest priority wins:

```json
[
  {"pattern": "/api/v1/health", "priority": 100},  // Wins
  {"pattern": "/api/v1/*", "priority": 70},
  {"pattern": "/api/**", "priority": 50}
]
```

## API Endpoints

### Configuration Management

```bash
# List all configurations
GET /api/v1/auth-config/

# Create configuration
POST /api/v1/auth-config/
{
  "path_pattern": "/api/v1/protected/*",
  "method": "POST",
  "auth_type": "bearer",
  "priority": 75
}

# Update configuration
PUT /api/v1/auth-config/{config_id}

# Delete configuration
DELETE /api/v1/auth-config/{config_id}

# Test pattern matching
POST /api/v1/auth-config/test
{
  "path": "/api/v1/tokens/admin",
  "method": "GET"
}

# Get effective auth for path
GET /api/v1/auth-config/effective/api/v1/tokens/?method=POST

# Apply default configurations
POST /api/v1/auth-config/apply-defaults

# Clear cache
DELETE /api/v1/auth-config/cache/clear
```

## Usage Examples

### Example 1: Different Auth for Same Endpoint

Configure `/tokens/` as admin-only but `/api/v1/tokens/` GET as bearer:

```bash
# Root path - admin only
curl -X POST http://localhost:9000/api/v1/auth-config/ \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "path_pattern": "/tokens/*",
    "method": "*",
    "auth_type": "admin",
    "priority": 90,
    "description": "Root tokens - admin only"
  }'

# API path - bearer for GET
curl -X POST http://localhost:9000/api/v1/auth-config/ \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "path_pattern": "/api/v1/tokens/",
    "method": "GET",
    "auth_type": "bearer",
    "priority": 80,
    "description": "List tokens - any authenticated"
  }'
```

### Example 2: OAuth for MCP Endpoints

```bash
curl -X POST http://localhost:9000/api/v1/auth-config/ \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "path_pattern": "/api/v1/mcp/*",
    "method": "*",
    "auth_type": "oauth",
    "oauth_scopes": ["mcp:read", "mcp:write"],
    "oauth_allowed_users": ["github_user1", "github_user2"],
    "priority": 75,
    "description": "MCP endpoints - OAuth only"
  }'
```

### Example 3: Public Health Endpoints

```bash
curl -X POST http://localhost:9000/api/v1/auth-config/ \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "path_pattern": "/health",
    "method": "GET",
    "auth_type": "none",
    "priority": 100,
    "description": "Public health check"
  }'
```

## Testing Configuration

### Test Pattern Matching

```bash
curl -X POST http://localhost:9000/api/v1/auth-config/test \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "path": "/api/v1/tokens/admin",
    "method": "DELETE"
  }'
```

Response shows all matching patterns and the effective configuration:
```json
{
  "matched": true,
  "matched_configs": [...],
  "effective_config": {
    "path_pattern": "/api/v1/tokens/*",
    "auth_type": "admin",
    "priority": 80
  },
  "explanation": "Found 2 matching configuration(s)..."
}
```

### Check Effective Auth

```bash
curl -X GET "http://localhost:9000/api/v1/auth-config/effective/api/v1/tokens/?method=POST" \
  -H "Authorization: Bearer $ADMIN_TOKEN"
```

## Integration with Existing Code

The system **reuses existing authentication code**:

1. **Bearer/Admin Auth**: Uses functions from `src/api/auth.py`
   - `get_current_token_info()`
   - `is_admin_token()`
   - Token validation logic

2. **OAuth Auth**: Uses `AsyncResourceProtector` from `src/api/oauth/`
   - JWT token validation
   - Audience checking
   - Scope validation

3. **Unified Interface**: `UnifiedAuthContext` provides consistent data:
   ```python
   auth = UnifiedAuthContext(
       authenticated=True,
       auth_type="oauth",
       oauth_user="github_username",
       oauth_scopes=["mcp:read"],
       request_path="/api/v1/mcp/tools",
       matched_pattern="/api/v1/mcp/*"
   )
   ```

## Using in Endpoints

### Option 1: Unified Auth Dependency

```python
from src.api.unified_auth import get_unified_auth, UnifiedAuthContext

@router.get("/some/endpoint")
async def my_endpoint(
    auth: UnifiedAuthContext = Depends(get_unified_auth)
):
    if not auth.authenticated:
        raise HTTPException(401, "Authentication required")
    
    if auth.auth_type == "oauth":
        # Handle OAuth user
        user = auth.oauth_user
    elif auth.auth_type == "bearer":
        # Handle bearer token
        token_name = auth.token_name
```

### Option 2: Existing Dependencies (Backward Compatible)

Existing endpoints continue to work without changes:

```python
from src.api.auth import require_admin

@router.delete("/api/v1/tokens/{name}")
async def delete_token(
    name: str,
    _: dict = Depends(require_admin)  # Still works!
):
    ...
```

## Default Configurations

Apply sensible defaults with one command:

```bash
curl -X POST http://localhost:9000/api/v1/auth-config/apply-defaults \
  -H "Authorization: Bearer $ADMIN_TOKEN"
```

This creates:
- Public health endpoints
- Admin-only token management at root
- Bearer auth for API token listing
- OAuth for MCP endpoints
- Owner validation for certificates

## Performance Considerations

1. **Caching**: Configurations cached for 60 seconds
2. **Pattern Compilation**: Regex patterns cached in memory
3. **Priority Sorting**: Configs sorted on storage, not runtime
4. **Index-Based Listing**: Efficient Redis set operations

## Security Notes

1. **Admin Only**: All auth config management requires admin token
2. **Default Deny**: Unknown patterns fall back to hardcoded auth
3. **OAuth Validation**: Full JWT signature and audience checking
4. **Owner Validation**: Optional resource ownership checks
5. **Audit Logging**: All config changes logged with admin info

## Troubleshooting

### Auth Not Applied

1. Check pattern matches: `POST /api/v1/auth-config/test`
2. Verify cache cleared: `DELETE /api/v1/auth-config/cache/clear`
3. Check middleware loaded: Look for `AuthConfigMiddleware` in logs
4. Verify full path captured: Check `X-Auth-Pattern` response header

### Pattern Not Matching

1. Ensure path starts with `/`
2. Check method matches (use `*` for all)
3. Verify pattern syntax (wildcards, parameters)
4. Test with pattern tester endpoint

### OAuth Not Working

1. Verify OAuth components initialized
2. Check resource protector in app.state
3. Ensure JWT keys configured
4. Validate token has required scopes

## Future Enhancements

1. **Role-Based Access**: Map OAuth roles to permissions
2. **Time-Based Rules**: Different auth at different times
3. **IP-Based Rules**: Restrict by client IP ranges
4. **Rate Limiting**: Per-auth-type rate limits
5. **Webhook Integration**: Notify on auth config changes
6. **A/B Testing**: Gradual auth migration support