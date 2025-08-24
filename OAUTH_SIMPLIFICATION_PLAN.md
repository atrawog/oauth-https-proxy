# Unified Simplified OAuth-Only Architecture Implementation Plan

## Overview
Transform the entire authentication system to OAuth-only with scope-based access control at the proxy layer, removing all bearer tokens and API-level auth checks.

## Core Architecture Principles
1. **Single Auth Layer**: Proxy handles ALL authentication
2. **OAuth-Only**: No bearer tokens (`acm_*`), only OAuth JWTs
3. **Three Scopes**: `admin` (write), `user` (read), `mcp` (protocol)
4. **Per-Route Control**: Routes can override proxy-level auth
5. **Trust Boundary**: API completely trusts proxy headers

---

## Phase 1: Implement OAuth Scope System in Proxy

### 1.1 Update Proxy Handler for OAuth-Only
**File**: `/src/proxy/simple_async_handler.py`

Add scope checking and per-route OAuth support:
- Implement scope requirements mapping
- Add OAuth JWT validation
- Check required scopes based on path/method
- Validate user access (users, orgs, emails)
- Forward requests with trust headers

### 1.2 Add Per-Route OAuth Configuration
**File**: `/src/proxy/routes.py`

Enhance Route model with OAuth config:
- Add RouteAuthConfig with OAuth-specific fields
- Support required_scopes, allowed_users, allowed_orgs
- Enable all_scopes_required flag for strict checking

---

## Phase 2: Remove All API Authentication

### 2.1 Strip AuthDep from All Endpoints
**Files to modify** (30 files in `/src/api/routers/`):

Remove these imports and dependencies:
- `from src.auth import AuthDep, AuthResult`
- `from src.auth.dependencies import require_auth, require_admin`
- `from src.api.unified_auth import UnifiedAuthContext, get_unified_auth`

Replace with header reading:
- Read `X-Auth-User` header for username
- Read `X-Auth-Scopes` header for scopes
- Trust these headers completely

### 2.2 Update Endpoints to Trust Headers
Transform all endpoints to read headers instead of using auth dependencies.

---

## Phase 3: Delete Token System Components

### 3.1 Remove Token API Endpoints
**Delete entire directory**: `/src/api/routers/tokens/`
- management.py - Token CRUD operations
- admin.py - Admin token operations
- core.py - Core token logic
- ownership.py - Token ownership
- models.py - Token models
- __init__.py - Router init

### 3.2 Remove Token Commands
**File**: `justfile`

Delete lines ~84-127:
- token-admin
- token-generate
- token-list
- token-show
- token-delete
- token-email

### 3.3 Remove Token CLI
**Delete**: `/oauth-https-proxy-client/src/oauth_proxy_client/commands/tokens.py`
**Update**: Remove token import from main CLI

### 3.4 Remove Token MCP Tools
**Delete**: `/src/api/routers/mcp/tools/tokens.py`
**Update**: `/src/api/routers/mcp/tools/__init__.py` - remove TokenTools import

---

## Phase 4: Remove Auth Modules

### 4.1 Delete Auth System
**Delete entire directory**: `/src/auth/`
- service.py - FlexibleAuthService
- dependencies.py - AuthDep, require_auth, require_admin
- models.py - Auth configuration models
- defaults.py - Default auth configurations
- __init__.py - Auth module exports

### 4.2 Delete Auth Configuration Endpoints
**Delete directory**: `/src/api/routers/auth/`
- auth_endpoints.py - Endpoint auth configuration
- auth_config.py - Auth configuration management

### 4.3 Remove Unified Auth
**Delete**: `/src/api/unified_auth.py`

---

## Phase 5: Clean Storage Layer

### 5.1 Remove Token Methods
**File**: `/src/storage/async_redis_storage.py`

Remove these methods:
- `async def create_token(...)`
- `async def get_token(...)`
- `async def delete_token(...)`
- `async def list_tokens(...)`
- `async def validate_token(...)`
- `async def get_token_by_hash(...)`
- `async def validate_bearer_token(...)`

### 5.2 Clean Redis Keys
Create cleanup script to remove all token data from Redis.

---

## Phase 6: Implement Per-Route OAuth

### 6.1 Route OAuth Configuration API
**File**: `/src/api/routers/routes/route_auth.py`

Update to OAuth-only configuration with scopes and user groups.

### 6.2 Add Route Auth Commands
**File**: `justfile`

Add new commands:
- route-auth-oauth: Configure OAuth for route
- route-auth-public: Make route public

---

## Phase 7: Configure Default Routes

### 7.1 Create Default Route Configuration

Default routes with appropriate OAuth scopes:
- Public endpoints: /health, /.well-known/*
- Admin endpoints: All POST, PUT, DELETE operations
- User endpoints: All GET operations
- MCP endpoint: /mcp with mcp scope

---

## Phase 8: Update OAuth Token Generation

### 8.1 Include Scopes in OAuth Tokens
**File**: `/src/api/oauth/auth_authlib.py`

Generate tokens with appropriate scopes based on user's group membership.

---

## Phase 9: Documentation Updates

### 9.1 Remove Documentation
- Delete `/src/auth/CLAUDE.md`
- Remove token sections from all docs

### 9.2 Create New Documentation
Document OAuth-only architecture with scopes.

---

## Phase 10: Testing and Validation

### 10.1 Remove Old Tests
Delete token and bearer auth tests.

### 10.2 Create New Tests
Create OAuth scope and route auth tests.

---

## Implementation Order

### Step 1: Implement OAuth Scope System in Proxy
- Update SimpleAsyncProxyHandler with scope checking
- Add scope requirements mapping
- Implement user/org validation

### Step 2: Remove AuthDep from Certificates Router
- Start with certificates as pilot
- Remove all auth dependencies
- Update to read headers

### Step 3: Remove AuthDep from Services Router
- Apply same pattern to services
- Ensure header reading works

### Step 4: Remove AuthDep from Proxy Router
- Update proxy management endpoints
- Remove auth dependencies

### Step 5: Remove AuthDep from Routes Router
- Update route management
- Keep route auth config endpoints

### Step 6: Remove AuthDep from Resources Router
- Update resource endpoints
- Trust proxy headers

### Step 7: Remove AuthDep from MCP Router
- Update MCP endpoints
- Ensure OAuth scope checking

### Step 8: Delete Token System
- Remove token routers
- Remove token commands
- Clean storage layer

### Step 9: Delete Auth Modules
- Remove auth directory
- Remove unified auth
- Update imports

### Step 10: Configure Default Routes
- Create default route configuration
- Set up scope requirements
- Test end-to-end

---

## Configuration Examples

### Proxy with Scopes
```yaml
proxy:api.example.com:
  admin_users: ["alice", "bob"]
  user_users: "*"  # Any GitHub user
  mcp_users: ["claude-mcp", "openai-mcp"]
```

### Route with OAuth Override
```yaml
route:admin-api:
  path_pattern: "/admin/*"
  auth_config:
    auth_type: "oauth"
    required_scopes: ["admin"]
    allowed_users: ["alice", "bob"]
  override_proxy_auth: true
```

---

## Success Criteria

✅ All `acm_*` token code removed
✅ No AuthDep in any API endpoint
✅ Proxy validates all OAuth tokens
✅ Scopes properly enforced (admin/user/mcp)
✅ Per-route OAuth configuration works
✅ API reads headers only, no auth checks
✅ All tests pass with new architecture

---

## Benefits Summary

1. **90% Less Code**: Removed entire auth system
2. **Single Auth Point**: Only proxy does auth
3. **Fine-Grained Control**: Per-route OAuth config
4. **Clear Scopes**: admin=write, user=read, mcp=protocol
5. **No Token Management**: OAuth-only, no `acm_*` tokens
6. **Trust Model**: API trusts proxy completely
7. **Flexible Routes**: Each route can have custom auth