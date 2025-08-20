# OAuth Service Documentation

## Architecture

OAuth is integrated directly into the proxy service:
- Runs on the same process as the proxy
- Accessed via configured domains (e.g., `auth.example.com`)
- Routes OAuth paths to the integrated OAuth server
- Authlib-based implementation
- Redis for all state
- **MCP 2025-06-18 Compliant**: Full support for resource indicators, audience validation, and protected resource metadata

## Configuration

### OAuth Service Configuration
- `GITHUB_CLIENT_ID` - GitHub OAuth application client ID (required for OAuth)
- `GITHUB_CLIENT_SECRET` - GitHub OAuth application client secret (required for OAuth)
- `BASE_DOMAIN` - Base domain for OAuth service (default: localhost)
- `OAUTH_ACCESS_TOKEN_LIFETIME` - Access token lifetime in seconds (default: 1800 = 30 minutes)
- `OAUTH_REFRESH_TOKEN_LIFETIME` - Refresh token lifetime in seconds (default: 31536000 = 1 year)
- `OAUTH_SESSION_TIMEOUT` - OAuth session timeout in seconds (default: 300 = 5 minutes)
- `OAUTH_CLIENT_LIFETIME` - OAuth client registration lifetime in seconds (default: 7776000 = 90 days)
- `OAUTH_ALLOWED_GITHUB_USERS` - Global default for allowed GitHub users (* = all users, comma-separated list for specific users)
- `OAUTH_MCP_PROTOCOL_VERSION` - MCP protocol version (default: 2025-06-18)

### JWT Configuration
- Algorithm: RS256 
- Access token lifetime: 30 minutes
- Refresh token lifetime: 1 year
- Secure cookies: HttpOnly, Secure, SameSite=Lax
- MCP Scopes: `mcp:read`, `mcp:write`, `mcp:admin`

### JWT Environment Variables
- `OAUTH_JWT_ALGORITHM` - JWT signing algorithm (default: RS256)
- `OAUTH_JWT_SECRET` - JWT secret for fallback/testing (not used with RS256)
- `OAUTH_JWT_PRIVATE_KEY_B64` - Base64-encoded RSA private key for JWT signing
  - Generate with: `openssl genrsa -out private.pem 2048 && base64 -w 0 private.pem`

## ForwardAuth Implementation

1. Proxy sends original request to `/verify`
2. OAuth validates token/cookie
3. Returns user info or 401
4. Proxy validates user against `auth_required_users` (if configured)
5. Proxy adds headers: `X-Auth-User-Id`, `X-Auth-User-Name`, etc.

### OAuth Authorization Flow with Per-Proxy Users
1. Proxy redirects to `/authorize` with `proxy_hostname` parameter
2. OAuth callback checks proxy-specific `auth_required_users`:
   - If proxy has `auth_required_users` set, use that list
   - Otherwise, fall back to global `OAUTH_ALLOWED_GITHUB_USERS`
3. GitHub users are validated during OAuth callback, not just at proxy access

## MCP Specification Compliance

**CRITICAL**: MCP requires HTTPS for authorization servers. Ensure `auth.{domain}` has a valid certificate.

### OAuth Authorization Server Requirements (RFC 8707)
- **Authorization Endpoint**: MUST accept `resource` parameter(s) identifying target MCP servers
- **Token Endpoint**: MUST validate requested resources were authorized
- **JWT Tokens**: MUST include resources in `aud` claim array
- **Server Metadata**: `/.well-known/oauth-authorization-server` MUST include:
  ```json
  {
    "issuer": "https://auth.example.com",
    "authorization_endpoint": "https://auth.example.com/authorize",
    "token_endpoint": "https://auth.example.com/token",
    "jwks_uri": "https://auth.example.com/jwks",
    "resource_indicators_supported": true,
    "scopes_supported": ["mcp:read", "mcp:write", "mcp:admin"]
  }
  ```

### Protected Resource Requirements (RFC 9728)
- **Protected Resource Metadata**: Each MCP server MUST implement `/.well-known/oauth-protected-resource`:
  ```json
  {
    "resource": "https://mcp.example.com",
    "authorization_servers": ["https://auth.example.com"],
    "jwks_uri": "https://auth.example.com/jwks",
    "scopes_supported": ["mcp:read", "mcp:write"],
    "bearer_methods_supported": ["header"],
    "resource_documentation": "https://docs.example.com/mcp"
  }
  ```
- **WWW-Authenticate Header**: On 401 responses:
  ```
  WWW-Authenticate: Bearer realm="Protected Resource",
    as_uri="https://auth.example.com/.well-known/oauth-authorization-server",
    resource_uri="https://mcp.example.com/.well-known/oauth-protected-resource"
  ```
- **Audience Validation**: MCP servers MUST validate token `aud` claim contains server's resource URI

### Token Format Requirements
```json
{
  "iss": "https://auth.example.com",
  "sub": "github-123",
  "aud": ["https://mcp1.example.com", "https://mcp2.example.com"],
  "azp": "mcp_client_12345",
  "exp": 1234567890,
  "iat": 1234567890,
  "scope": "mcp:read mcp:write"
}
```

## OAuth Routes Configuration

**CRITICAL**: Must run `just oauth-routes-setup` to create routes:
```
/authorize → auth.{domain} (priority: 95)
/token → auth.{domain} (priority: 95)
/callback → auth.{domain} (priority: 95)
/verify → auth.{domain} (priority: 95)
/.well-known/oauth-authorization-server → auth.{domain} (priority: 95)
/jwks → auth.{domain} (priority: 95)
/revoke → auth.{domain} (priority: 95)
/introspect → auth.{domain} (priority: 95)
```

## MCP Authorization Flow

1. **Client requests authorization with resource**:
   ```
   GET /authorize?
     client_id=mcp_12345&
     response_type=code&
     resource=https://mcp1.example.com&
     resource=https://mcp2.example.com&
     scope=mcp:read+mcp:write&
     state=abc123
   ```

2. **Token request includes resource**:
   ```
   POST /token
   {
     "grant_type": "authorization_code",
     "code": "auth_code_123",
     "resource": ["https://mcp1.example.com", "https://mcp2.example.com"],
     "client_id": "mcp_12345"
   }
   ```

3. **MCP server validates audience**:
   - Extract token from Authorization header
   - Verify JWT signature with OAuth server's public key
   - Validate `aud` claim contains server's resource URI
   - Check token expiration and scopes

## Auth Modes

- **forward**: Returns 401 if not authenticated (APIs)
- **redirect**: Redirects to OAuth login (web apps)
- **passthrough**: Optional auth, always forwards

## Dynamic Client Registration (RFC 7591)

MCP clients can self-register via `/register` endpoint:
```json
POST /register
{
  "software_id": "mcp-client-example",
  "software_version": "1.0.0",
  "client_name": "Example MCP Client",
  "redirect_uris": ["https://client.example.com/callback"],
  "grant_types": ["authorization_code", "refresh_token"],
  "response_types": ["code"],
  "scope": "mcp:read mcp:write"
}

Response:
{
  "client_id": "mcp_1234567890",
  "client_secret": "secret_abc123...",
  "registration_access_token": "reg_token_xyz...",
  "registration_client_uri": "https://auth.example.com/register/mcp_1234567890"
}
```

## OAuth Protocol Endpoints (Root Level)

- `GET /authorize` - OAuth authorization endpoint
- `POST /token` - Token exchange endpoint
- `GET /callback` - OAuth callback handler
- `POST /verify` - Token verification endpoint
- `POST /revoke` - Token revocation endpoint
- `POST /introspect` - Token introspection (RFC 7662)
- `POST /register` - Dynamic client registration (RFC 7591)
- `GET /jwks` - JSON Web Key Set endpoint
- `GET /.well-known/oauth-authorization-server` - Server metadata

## OAuth Admin API Endpoints

- `GET /oauth/clients` - List OAuth clients
- `GET /oauth/clients/{client_id}` - Client details
- `GET /oauth/clients/{client_id}/tokens` - Client's tokens
- `GET /oauth/tokens` - Token statistics
- `GET /oauth/tokens/{jti}` - Token details
- `GET /oauth/sessions` - Active sessions
- `GET /oauth/sessions/{session_id}` - Session details
- `DELETE /oauth/sessions/{session_id}` - Revoke session
- `GET /oauth/metrics` - System metrics
- `GET /oauth/health` - Integration health
- `GET /oauth/proxies` - OAuth status for proxies
- `GET /oauth/proxies/{hostname}/sessions` - Proxy sessions

## OAuth Status API Endpoints

- `GET /oauth/status` - Overall OAuth system status
- `GET /oauth/status/clients` - Client statistics
- `GET /oauth/status/tokens` - Token statistics
- `GET /oauth/status/sessions` - Session statistics

## Protected Resource Management API Endpoints

**Note**: These management endpoints are optional conveniences, not MCP requirements.
- `GET /resources/` - List registered protected resources (requires trailing slash)
- `POST /resources/` - Register new protected resource
- `GET /resources/{uri}` - Get resource details
- `PUT /resources/{uri}` - Update resource
- `DELETE /resources/{uri}` - Remove resource
- `POST /resources/{uri}/validate-token` - Validate token for resource
- `POST /resources/auto-register` - Auto-discover proxy resources

## Protected Resource Endpoints (Required on each protected resource)

- `GET /.well-known/oauth-protected-resource` - Protected resource metadata (REQUIRED)
- `GET /mcp` or `/mcp/sessions` - MCP protocol endpoints (implementation-specific)

## OAuth Commands

```bash
# OAuth setup and management
just oauth-key-generate [token]                   # Generate RSA key
just oauth-routes-setup <domain> [token]          # Setup OAuth routes (CRITICAL!)
just oauth-client-register <name> [redirect-uri] [scope]  # Register OAuth client for testing

# OAuth status and monitoring
just oauth-clients-list [active-only] [token]     # List OAuth clients
just oauth-sessions-list [token]                  # List active sessions
just oauth-test-tokens <server-url> [token]       # Generate test OAuth tokens for MCP client
```

## Protected Resource Configuration

```bash
# Environment variables for MCP compliance
MCP_RESOURCE_INDICATORS_ENABLED=true
MCP_RESOURCE_VALIDATION_STRICT=true
MCP_MAX_RESOURCES_PER_TOKEN=5

# Redis schema for resources
resource:{resource_uri} = {
  "uri": "https://mcp.example.com",
  "name": "Example Protected Resource",
  "proxy_target": "mcp.example.com",
  "scopes": ["mcp:read", "mcp:write"],
  "metadata_url": "https://mcp.example.com/.well-known/oauth-protected-resource"
}
```

## MCP 2025-06-18 Compliance Summary

The system is **FULLY COMPLIANT** with MCP authorization specification:

### ✅ OAuth Server Compliance
- Resource parameter support in authorization and token endpoints
- Audience-restricted tokens with resource URIs in `aud` claim
- Authorization server metadata endpoint with `resource_indicators_supported: true`
- Dynamic client registration (RFC 7591)
- Token introspection and revocation endpoints

### ✅ Protected Resource Compliance  
- Protected resource metadata endpoint on each protected resource
- WWW-Authenticate headers with metadata URLs
- Audience validation for all protected resources
- Resource-specific scope enforcement

### ✅ Integration Features
- Resource registry for MCP server management
- Automatic resource discovery from proxy configuration
- Token validation with resource context
- Per-resource access control

To ensure MCP compliance for any proxy:
1. Set protected resource metadata: `just proxy-resource-set <hostname> [endpoint] [scopes]`
2. Enable auth on proxy: `just proxy-auth-enable <hostname> [auth-proxy] [mode]`
3. Verify metadata endpoint: `curl https://<proxy>/.well-known/oauth-protected-resource`