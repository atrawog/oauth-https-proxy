# Proxy Manager Documentation

## Overview

The Proxy Manager provides dynamic reverse proxy functionality with SSL termination, WebSocket support, and OAuth integration.

## Core Features

- Dynamic reverse proxy with SSL termination
- WebSocket and SSE streaming support
- Per-request certificate provisioning
- Redis-backed configuration
- OAuth authentication integration
- Custom header injection
- Route-based request handling

## Configuration

### Proxy Configuration
- `PROXY_REQUEST_TIMEOUT` - Proxy request timeout in seconds (default: 120)
- `PROXY_CONNECT_TIMEOUT` - Proxy connection timeout in seconds (default: 30)
- `FETCHER_NAVIGATION_TIMEOUT` - Navigation timeout for fetcher service (default: 25)

**Timeout Hierarchy**: The timeout values follow a hierarchy to prevent cascade failures:
1. `FETCHER_NAVIGATION_TIMEOUT` (25s) - Shortest, for browser operations
2. `PROXY_CONNECT_TIMEOUT` (30s) - For establishing proxy connections
3. `PROXY_REQUEST_TIMEOUT` (120s) - Longest, for complete proxy requests

## Proxy Target Schema

```json
{
  "hostname": "api.example.com",
  "target_url": "http://backend:3000",
  "cert_name": "proxy-api-example-com",
  "owner_token_hash": "sha256:...",
  "created_by": "token-name",
  "created_at": "2024-01-15T10:00:00Z",
  "enabled": true,
  "enable_http": true,
  "enable_https": true,
  "preserve_host_header": true,
  "custom_headers": {"X-Custom": "value"},
  "custom_response_headers": {"X-Response": "value"},
  
  // Authentication configuration
  "auth_enabled": false,
  "auth_proxy": null,
  "auth_mode": "forward",
  "auth_required_users": null,  // Per-proxy GitHub user allowlist
  "auth_required_emails": null,
  "auth_required_groups": null,
  "auth_allowed_scopes": null,
  "auth_allowed_audiences": null,
  "auth_pass_headers": true,
  "auth_cookie_name": "unified_auth_token",
  "auth_header_prefix": "X-Auth-",
  "auth_excluded_paths": null,
  
  // Route control
  "route_mode": "all",
  "enabled_routes": [],
  "disabled_routes": [],
  
  // Protected resource metadata (optional)
  "resource_endpoint": null,
  "resource_scopes": null,
  "resource_stateful": false,
  "resource_versions": null,
  "resource_server_info": null,
  "resource_override_backend": false,
  "resource_bearer_methods": null,
  "resource_documentation_suffix": null,
  "resource_custom_metadata": null,
  
  // OAuth Authorization Server Metadata (per-proxy configuration)
  "oauth_server_issuer": null,  // Custom issuer URL
  "oauth_server_scopes": null,  // Supported scopes
  "oauth_server_grant_types": null,  // Grant types
  "oauth_server_response_types": null,  // Response types
  "oauth_server_token_auth_methods": null,  // Token auth methods
  "oauth_server_claims": null,  // Supported claims
  "oauth_server_pkce_required": false,  // Require PKCE
  "oauth_server_custom_metadata": null,  // Custom fields
  "oauth_server_override_defaults": false,  // Use proxy config instead of defaults
  
  // GitHub OAuth Configuration (per-proxy)
  "github_client_id": null,  // Custom GitHub OAuth App Client ID
  "github_client_secret": null  // Custom GitHub OAuth App Client Secret (encrypted)
}
```

## Route Management

Priority-based path routing with Redis storage and scope support:

### Route Target Type (URL-Only)
- **url**: Forward to any URL directly (e.g., `http://api:9000`, `http://backend:3000`, `https://api.example.com`)

**Note**: The system now uses URL-only routing exclusively. Legacy route types (PORT, SERVICE, HOSTNAME) have been deprecated and removed. All routes must specify explicit target URLs.

### Route Scopes
Routes can be scoped to control their applicability:
- **global**: Route applies to all proxies (default)
- **proxy**: Route applies only to specified proxy hostnames

When multiple routes match a request, they are evaluated by:
1. Filtering by scope (global routes + proxy-specific routes for current proxy)
2. Sorting by priority (higher values checked first)
3. Matching path and methods

### Route Authentication Override
Routes can override proxy-level authentication settings:

```json
{
  "route_id": "public-health",
  "path_pattern": "/health",
  "auth_config": {
    "auth_type": "none"  // Make health endpoint public
  },
  "override_proxy_auth": true  // Override proxy's auth settings
}
```

This allows fine-grained auth control where specific routes can have different authentication than the proxy defaults.

## Authentication Integration

### OAuth-Only Authentication

Proxies now use OAuth-only authentication:
- **OAuth Validation**: Proxy validates JWT tokens at the edge
- **Header Forwarding**: Proxy adds `X-Auth-User`, `X-Auth-Scopes`, `X-Auth-Email`
- **No Bearer Tokens**: Removed all `acm_*` token support
- **Trust Model**: API trusts headers from proxy completely

### OAuth Configuration

```json
{
  "auth_enabled": true,
  "auth_type": "oauth",  // none|bearer|admin|oauth
  "auth_proxy": "auth.example.com",
  "auth_mode": "forward",  // forward|redirect|passthrough
  "auth_required_users": ["alice", "bob"],  // Per-proxy GitHub user allowlist (null=global default, ["*"]=all users)
  "auth_required_emails": ["*@example.com"],
  "auth_allowed_scopes": ["mcp:read", "mcp:write"],  // Optional: restrict token scopes
  "auth_allowed_audiences": ["https://api.example.com"],  // Optional: restrict token audiences
  "auth_pass_headers": true,
  "auth_excluded_paths": ["/health", "/.well-known/*"]  // Paths that bypass authentication
}
```

### Per-Proxy User Allowlists
The `auth_required_users` field controls which GitHub users can authenticate for each proxy:
- `null` or `[]` - Use global default from `OAUTH_ADMIN_USERS` environment variable
- `["user1", "user2"]` - Allow only specific GitHub users (no wildcards allowed)

This provides granular control over authentication at the proxy level. The field is checked at two points:
1. **During OAuth callback** - GitHub users not in the list are rejected during authentication
2. **During proxy access** - Token validation ensures the authenticated user is in the allowed list

This dual-check ensures consistent access control throughout the authentication flow.

### Per-Proxy GitHub OAuth Apps
Each proxy can have its own GitHub OAuth App configuration:
- **Custom Credentials**: Configure `github_client_id` and `github_client_secret` per proxy
- **Environment Fallback**: If not configured, falls back to `GITHUB_CLIENT_ID` and `GITHUB_CLIENT_SECRET`
- **Dynamic Resolution**: OAuth flow determines which credentials to use based on proxy hostname
- **Secure Storage**: Client secrets are encrypted in Redis and never exposed in API responses
- **Multi-Tenancy**: Different proxies can authenticate with different GitHub organizations
- **Zero-Downtime Updates**: Change credentials without restarting services

## Protected Resource Metadata Configuration

Enable protected resource metadata endpoints for proxies:
```json
{
  "mcp_enabled": true,
  "mcp_endpoint": "/mcp",  // MCP protocol endpoint path
  "mcp_scopes": ["mcp:read", "mcp:write"],
  "mcp_stateful": false,  // Whether server maintains session state
  "mcp_override_backend": false  // Override backend's metadata endpoint
}
```

When enabled, the proxy automatically serves:
- `/.well-known/oauth-protected-resource` - Protected resource metadata
- Proper WWW-Authenticate headers on 401 responses
- Integration with OAuth for token validation

## API Endpoints

- `POST /proxy/targets/` - Create proxy target
- `GET /proxy/targets/` - List all proxies (requires trailing slash)
- `GET /proxy/targets/{hostname}` - Get proxy details
- `PUT /proxy/targets/{hostname}` - Update proxy
- `DELETE /proxy/targets/{hostname}` - Delete proxy
- `POST /proxy/targets/{hostname}/auth` - Configure auth
- `DELETE /proxy/targets/{hostname}/auth` - Remove auth
- `GET /proxy/targets/{hostname}/auth` - Get auth config
- `POST /proxy/targets/{hostname}/resource` - Configure protected resource metadata (RFC 9728)
- `DELETE /proxy/targets/{hostname}/resource` - Remove protected resource metadata
- `GET /proxy/targets/{hostname}/resource` - Get protected resource configuration
- `POST /proxy/targets/{hostname}/oauth-server` - Configure OAuth authorization server metadata
- `DELETE /proxy/targets/{hostname}/oauth-server` - Remove OAuth server metadata
- `GET /proxy/targets/{hostname}/oauth-server` - Get OAuth server configuration
- `POST /proxy/targets/{hostname}/github-oauth` - Configure GitHub OAuth credentials
- `GET /proxy/targets/{hostname}/github-oauth` - Get GitHub OAuth config (without secret)
- `DELETE /proxy/targets/{hostname}/github-oauth` - Clear GitHub OAuth config
- `GET /proxy/targets/github-oauth/configured` - List all proxies with custom GitHub OAuth
- `GET /proxy/targets/{hostname}/routes` - Get proxy routes
- `PUT /proxy/targets/{hostname}/routes` - Update proxy routes

## Proxy Commands

```bash
# Create proxy with automatic certificate handling
just proxy create <hostname> <target-url> [staging] [preserve-host] [enable-http] [enable-https] [email] [token]
just proxy delete <hostname> [delete-cert] [force] [token]
just proxy list [token]
just proxy show <hostname> [token]

# OAuth proxy authentication
just proxy auth-enable <hostname> [auth-proxy] [mode] [allowed-scopes] [allowed-audiences] [token]
just proxy auth-disable <hostname> [token]
just proxy auth-config <hostname> [users] [emails] [groups] [allowed-scopes] [allowed-audiences] [token]
just proxy auth-show <hostname> [token]

# Examples of per-proxy user configuration:
# Allow specific GitHub users:
just proxy auth-config api.example.com "alice,bob,charlie" "" "" "" "" $TOKEN
# Use global default (OAUTH_ADMIN_USERS):
just proxy auth-config api.example.com "" "" "" "" "" $TOKEN

# Protected resource metadata configuration (OAuth 2.0 RFC 9728)
just proxy resource-set <hostname> [endpoint] [scopes] [stateful] [override-backend] [bearer-methods] [doc-suffix] [server-info] [custom-metadata] [hacker-one-research] [token]
just proxy resource-clear <hostname> [token]
just proxy resource-show <hostname> [token]
just proxy resource-list [token]           # List protected resources

# OAuth authorization server metadata configuration (per-proxy)
just proxy oauth-server-set <hostname> [issuer] [scopes] [grant-types] [response-types] [token-auth-methods] [claims] [pkce-required] [custom-metadata] [override-defaults] [token]
just proxy oauth-server-clear <hostname> [token]
just proxy oauth-server-show <hostname> [token]

# GitHub OAuth credentials configuration (per-proxy)
just proxy github-oauth-set <hostname> <client-id> <client-secret> [token]
just proxy github-oauth-show <hostname> [token]
just proxy github-oauth-clear <hostname> [token]
just proxy github-oauth-list [token]
```

## Proxy Architecture: Simple and Secure

### Component Responsibilities

**HypercornInstance** (Infrastructure Layer):
- PROXY protocol parsing for client IP preservation
- SSL/TLS termination with certificates from Redis
- HTTP server hosting the Starlette app
- Manages temporary certificate files (Python SSL limitation)

**ProxyOnlyApp** (Application Layer):
- Minimal Starlette application
- Routes all requests to UnifiedProxyHandler
- No authentication logic (delegates to handler)
- Handles OAuth metadata endpoint

**UnifiedProxyHandler** (Security & Routing Layer):
- Complete OAuth validation with scope checking
- User allowlist enforcement
- Route matching and backend selection
- Request forwarding with proper headers
- 912 lines of battle-tested logic

### Why Not "OAuth at the Edge"?

We learned that OAuth cannot be properly validated at the TCP/SSL layer because:

1. **You need the full HTTP request to determine required scopes**
   - Different paths require different scopes (/admin/* vs /api/*)
   - Method matters (GET vs POST)
   - Route-specific auth overrides

2. **Path-based routing rules affect authentication requirements**
   - Some paths may be public
   - Others require specific scopes
   - Routes can override proxy-level auth

3. **Different backends may have different auth configurations**
   - Each proxy has its own user allowlists
   - Different OAuth configurations per proxy
   - Backend URLs are determined by routing logic

The handler needs full context to make security decisions.

### The Failed EnhancedProxyInstance Experiment

We tried to create EnhancedProxyInstance that would:
- Parse PROXY protocol at TCP layer
- Terminate SSL
- Validate OAuth
- Forward to Starlette

This failed because:
- It could only do basic JWT validation (is token valid?)
- It couldn't check scopes (no path context)
- It couldn't enforce user allowlists properly
- It didn't know which backend to forward to
- UnifiedProxyHandler had to trust its headers blindly, creating a security hole

## Proxy App Architecture

### Proxy App (Minimal ASGI)
- Lightweight Starlette app with async handlers
- ONLY proxy forwarding, no API
- Per-instance async httpx client (isolated)
- NO lifespan side effects
- Clean shutdown without affecting others
- Streaming response handling for large payloads

### Request Flow

1. **Request Reception**: Incoming request to proxy hostname
2. **Route Matching**: Check routes by priority and scope
3. **Authentication**: If auth enabled, validate via OAuth
4. **Header Processing**: Add custom headers, preserve/modify host header
5. **Target Resolution**: Resolve target URL from configuration
6. **Request Forwarding**: Forward to backend with httpx
7. **Response Streaming**: Stream response back to client
8. **Header Injection**: Add custom response headers

## Smart Certificate Handling

Proxy creation automatically:
1. Checks for existing certificates matching the hostname
2. Creates new certificate if none exists (using environment defaults)
3. Associates certificate with proxy for SSL termination

## Port Allocation Lifecycle

Each proxy instance gets persistent ports allocated via PortManager:

1. **Check Redis**: Look for existing mapping in `proxy:ports:mappings`
2. **Allocate Ports**: If no mapping, allocate from appropriate range
   - HTTP: 12000-12999 (hash-based preferred port)
   - HTTPS: 13000-13999 (hash-based preferred port)
3. **Store Mapping**: Save allocation to Redis for persistence
4. **Register Routes**: Register with dispatcher for traffic routing
5. **Release on Delete**: Return ports to pool when proxy deleted

### Benefits
- **Persistent**: Same ports across restarts
- **Deterministic**: Hash ensures similar ports for same proxy
- **No Conflicts**: Atomic Redis operations prevent duplicates
- **Debuggable**: All mappings visible via `redis-cli`

## Localhost Proxy Configuration

Localhost is treated exactly like any other proxy:
- Gets dynamically allocated ports via PortManager (typically 12000+ range)
- Validates OAuth tokens
- Forwards to API at http://api:9000 (Docker service name)
- Port mappings persist in Redis across restarts
- NO special bypass or direct access

### Docker Networking
- Uses Docker service discovery
- Target URL: http://api:9000 (NOT 127.0.0.1:9000)
- Works across container boundaries

## Certificate Handling for HTTPS

**How Certificates Work:**
1. Certificates are stored in Redis (no filesystem storage)
2. When HTTPS is needed, certificates are written to temporary files
3. Hypercorn loads certificates from these temp files via `config.certfile` and `config.keyfile`
4. The PROXY protocol layer does NOT handle certificates or SSL
5. Temp files are cleaned up when the instance stops

**Note**: Using temporary files is a Python SSL module limitation - it cannot load certificates from memory directly.

### SSL Architecture for Proxy Instances
- **Hypercorn** handles all SSL termination internally
- **PROXY protocol handler** is just a TCP forwarder (no SSL)
- **Certificates** flow: Redis → Temp Files → Hypercorn config
- **Client connections**: Go through PROXY handler as plain TCP, then Hypercorn terminates SSL

## Related Documentation

- [OAuth Service](../api/oauth/CLAUDE.md) - OAuth integration details
- [Certificate Manager](../certmanager/CLAUDE.md) - SSL certificate management
- [Routes](../api/routers/v1/routes.py) - Route management
- [Dispatcher](../dispatcher/CLAUDE.md) - How proxies are served