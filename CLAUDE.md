# MCP HTTPS OAuth Proxy Specification

## General Development Guidelines

### Execution Requirements
- **Command execution**: ONLY via `just` commands - no direct Python/bash or docker exec execution
- **Configuration**: Single source `.env` file loaded by `just` - all environment variables are documented in their relevant sections below 
- **Python environment**: `pixi` exclusively
- **Testing**: Real systems only - no mocks, stubs, or simulations via `just test-*` commands
- **Debugging**: All debugging via `just` commands (logs, shell, redis-cli)
- **Database**: Redis for everything (key-value, caching, queues, pub/sub, persistence)
  - `REDIS_PASSWORD` - Redis authentication password (required, 32+ random bytes recommended)
  - `REDIS_URL` - Full Redis connection URL including password (format: `redis://:password@host:port/db`)

### Logging
- `LOG_LEVEL` - Application log level (DEBUG, INFO, WARNING, ERROR, CRITICAL) - default: INFO

### Directory Structure
```
./analysis/    # All plans and code or issue analysis (add to .gitignore) 
./scripts/     # All executable scripts
./docs/        # JupyterBook documentation only
./tests/       # Pytest tests only
```

### Root Cause Analysis (Required Before any Code or Configuration Change)
1. Why did it fail? (surface symptom)
2. Why did that condition exist? (enabling circumstance)
3. Why was it allowed? (systemic failure)
4. Why wasn't it caught? (testing blindness)
5. Why will it never happen again? (prevention fix)

### Security Best Practices
- All sensitive values (tokens, passwords, secrets) should be generated securely
- Redis password is required and should be strong (32+ random bytes recommended)
- OAuth JWT private key must be base64-encoded
- ACME URLs can be switched between staging and production for testing
- HTTP routing configuration is managed via Redis, not environment variables
- Docker socket access requires appropriate group permissions (DOCKER_GID)


## Token Management

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

### API Endpoints
- `GET /api/v1/tokens` - List all tokens
- `POST /api/v1/tokens` - Create new token
- `POST /api/v1/tokens/generate` - Generate token for display
- `PUT /api/v1/tokens/email` - Update certificate email for current token
- `GET /api/v1/tokens/info` - Get current token information
- `GET /api/v1/tokens/{name}` - Get specific token details
- `DELETE /api/v1/tokens/{name}` - Delete a token
- `GET /api/v1/tokens/{name}/reveal` - Securely reveal token value

### Token Commands
```bash
just token-generate <n> [cert-email]     # Create token with optional cert email
just token-show <n>                      # Retrieve full token
just token-list                          # List all tokens
just token-delete <n>                    # Delete token + owned resources
just token-show-certs [n]                # Show certificates by token
just token-email-update <n> <email>      # Update token cert email
```

## Service Architecture

### Docker Services
- **proxy**: HTTP/HTTPS gateway with integrated OAuth server, certificate manager, and API  
- **redis**: State storage for all services

**Note**: OAuth functionality is now integrated directly into the proxy service - there is no separate auth service.

### Unified Multi-Instance Dispatcher
**CRITICAL**: UnifiedDispatcher is THE server - FastAPI is just another instance!

#### Server Configuration
- `HTTP_PORT` - HTTP server port (default: 80)
- `HTTPS_PORT` - HTTPS server port (default: 443)
- `SERVER_HOST` - Server bind address (default: 0.0.0.0)
- `SELF_SIGNED_CN` - Common name for self-signed certificates (default: localhost)
- `BASE_URL` - Base URL for API endpoints (default: http://localhost:80)

```
Client → Port 80/443 → UnifiedDispatcher
                              ↓
                    Route by hostname/path
                              ↓
         ├→ localhost → FastAPI App (API/GUI)
         ├→ proxy1.com → Proxy App (forwarding only)
         └→ proxy2.com → Proxy App (forwarding only)
```

### Dual App Architecture

#### API App (FastAPI) - localhost only
- Full FastAPI with lifespan management
- API endpoints, Web GUI, certificate management
- Integrated OAuth 2.1 server functionality
- Global resources (scheduler, Redis)
- Runs on internal port 9000

#### Proxy App (Minimal ASGI) - all proxy domains
- Lightweight Starlette app
- ONLY proxy forwarding, no API
- Per-instance httpx client (isolated)
- NO lifespan side effects
- Clean shutdown without affecting others

### Instance Management
```python
class DomainInstance:
    is_api_instance: bool  # True=FastAPI, False=Proxy
    internal_http_port: int  # 9000+ 
    internal_https_port: int  # 10000+
    ssl_context: Optional[SSLContext]  # Pre-loaded
```

### Key Benefits
- No port conflicts or race conditions
- Instance isolation - delete proxy without affecting others
- Clean resource management per instance
- Dynamic add/remove without side effects

## Certificate Manager

### ACME Implementation
- **Protocol**: ACME v2 with HTTP-01 challenges
- **Storage**: Redis-exclusive (no filesystem)
- **Multi-domain**: Up to 100 domains per certificate
- **Keys**: RSA 2048-bit, new key per certificate

#### ACME Configuration
- `ACME_DIRECTORY_URL` - Production ACME directory URL (default: https://acme-v02.api.letsencrypt.org/directory)
- `ACME_STAGING_URL` - Staging ACME directory URL for testing (default: https://acme-staging-v02.api.letsencrypt.org/directory)
- `ACME_POLL_MAX_ATTEMPTS` - Maximum polling attempts for ACME challenges (default: 60)
- `ACME_POLL_INTERVAL_SECONDS` - Seconds between ACME polling attempts (default: 2)
- `ACME_POLL_INITIAL_WAIT` - Initial wait before polling starts (default: 0)

#### Certificate Management Configuration
- `RENEWAL_CHECK_INTERVAL` - Seconds between certificate renewal checks (default: 86400 = 24 hours)
- `RENEWAL_THRESHOLD_DAYS` - Days before expiry to trigger renewal (default: 30)
- `CERT_STATUS_RETENTION_SECONDS` - How long to retain certificate generation status (default: 300)
- `CERT_GEN_MAX_WORKERS` - Maximum concurrent certificate generation workers (default: 5)
- `RSA_KEY_SIZE` - RSA key size for certificates (default: 2048)
- `SELF_SIGNED_DAYS` - Validity period for self-signed certificates (default: 365)

### Certificate Object Schema
```json
{
  "cert_name": "services-cert",
  "domains": ["api.example.com", "app.example.com"],
  "email": "admin@example.com",
  "acme_directory_url": "https://acme-v02.api.letsencrypt.org/directory",
  "status": "active",
  "expires_at": "2024-03-15T00:00:00Z",
  "fullchain_pem": "-----BEGIN CERTIFICATE-----",
  "private_key_pem": "-----BEGIN PRIVATE KEY-----",
  "owner_token_hash": "sha256:..."
}
```

### Auto-Renewal
- Check interval: 24 hours
- Renewal threshold: 30 days before expiry
- Automatic SSL context updates
- No downtime during renewal

### API Endpoints
- `POST /api/v1/certificates` - Single domain (async)
- `POST /api/v1/certificates/multi-domain` - Multiple domains (async)
- `GET /api/v1/certificates` - List all certificates
- `GET /api/v1/certificates/{cert_name}` - Get certificate details
- `GET /api/v1/certificates/{cert_name}/status` - Generation status
- `POST /api/v1/certificates/{cert_name}/renew` - Manual renewal
- `DELETE /api/v1/certificates/{cert_name}` - Delete certificate
- `GET /.well-known/acme-challenge/{token}` - ACME validation (root level)
- `GET /health` - Service health status (root level)

### Certificate Commands
```bash
# Single-domain certificates
just cert-create <name> <domain> <email> <token> [staging]
just cert-delete <name> <token> [force]
just cert-renew <name> <token> [force]
just cert-list [token]
just cert-show <name> [token] [pem]
just cert-status <name> [token] [wait]
just cert-to-production <name> [token]

# Multi-domain certificates
just cert-create-multi <name> <domains> <email> <token> [staging]
just cert-create-wildcard <name> <base-domain> <email> <token> [staging]
just cert-coverage <name> [token]

# Testing
just test-certs                  # Test certificate operations
just test-multi-domain           # Test multi-domain certificates
```

## Proxy Manager

### Core Features
- Dynamic reverse proxy with SSL termination
- WebSocket and SSE streaming support
- Per-request certificate provisioning
- Redis-backed configuration

#### Proxy Configuration
- `PROXY_REQUEST_TIMEOUT` - Proxy request timeout in seconds (default: 120)
- `PROXY_CONNECT_TIMEOUT` - Proxy connection timeout in seconds (default: 30)
- `FETCHER_NAVIGATION_TIMEOUT` - Navigation timeout for fetcher service (default: 25)

**Timeout Hierarchy**: The timeout values follow a hierarchy to prevent cascade failures:
1. `FETCHER_NAVIGATION_TIMEOUT` (25s) - Shortest, for browser operations
2. `PROXY_CONNECT_TIMEOUT` (30s) - For establishing proxy connections
3. `PROXY_REQUEST_TIMEOUT` (120s) - Longest, for complete proxy requests

### Proxy Target Schema
```json
{
  "hostname": "api.example.com",
  "target_url": "http://backend:8080",
  "cert_name": "proxy-api-example-com",
  "enabled": true,
  "enable_http": true,
  "enable_https": true,
  "preserve_host_header": true,
  "custom_headers": {"X-Custom": "value"},
  "owner_token_hash": "sha256:..."
}
```

### Route Management
Priority-based path routing with Redis storage:

```json
{
  "route_id": "api-v1",
  "path_pattern": "/api/v1/",
  "target_type": "instance",  // port|instance|hostname
  "target_value": "api-backend",
  "priority": 90,  // Higher = checked first
  "methods": ["GET", "POST"],
  "enabled": true
}
```

### Per-Proxy Route Control
Three modes for route filtering:
- **all**: All global routes apply (default)
- **selective**: Only explicitly enabled routes
- **none**: Hostname-based routing only

### OAuth Integration
```json
{
  "auth_enabled": true,
  "auth_proxy": "auth.example.com",
  "auth_mode": "forward",  // forward|redirect|passthrough
  "auth_required_users": ["alice", "bob"],
  "auth_required_emails": ["*@example.com"],
  "auth_pass_headers": true
}
```

### MCP Metadata Configuration
Enable MCP protocol metadata endpoints for proxies:
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
- `/.well-known/oauth-protected-resource` - MCP resource metadata
- Proper WWW-Authenticate headers on 401 responses
- Integration with OAuth for token validation

### API Endpoints
- `POST /api/v1/proxy/targets` - Create proxy target
- `GET /api/v1/proxy/targets` - List all proxies
- `GET /api/v1/proxy/targets/{hostname}` - Get proxy details
- `PUT /api/v1/proxy/targets/{hostname}` - Update proxy
- `DELETE /api/v1/proxy/targets/{hostname}` - Delete proxy
- `POST /api/v1/proxy/targets/{hostname}/auth` - Configure auth
- `DELETE /api/v1/proxy/targets/{hostname}/auth` - Remove auth
- `GET /api/v1/proxy/targets/{hostname}/auth` - Get auth config
- `POST /api/v1/proxy/targets/{hostname}/mcp` - Configure MCP metadata
- `DELETE /api/v1/proxy/targets/{hostname}/mcp` - Remove MCP metadata
- `GET /api/v1/proxy/targets/{hostname}/mcp` - Get MCP configuration
- `GET /api/v1/proxy/targets/{hostname}/routes` - Get proxy routes
- `PUT /api/v1/proxy/targets/{hostname}/routes` - Update proxy routes

### Proxy Commands
```bash
# Basic proxy operations
just proxy-create <hostname> <target-url> <token> [staging] [preserve-host] [enable-http] [enable-https]
just proxy-create-group <group> <hostnames> <target-url> <token> [staging] [preserve-host]
just proxy-update <hostname> <token> [options]
just proxy-delete <hostname> <token> [delete-cert] [force]
just proxy-enable <hostname> <token>
just proxy-disable <hostname> <token>
just proxy-list [token]
just proxy-show <hostname>
just proxy-cleanup [hostname]

# Certificate management for proxies
just proxy-cert-generate <hostname> <token> [staging]
just proxy-cert-attach <hostname> <cert-name> <token>

# OAuth proxy authentication
just proxy-auth-enable <hostname> <token> <auth-proxy> <mode>
just proxy-auth-disable <hostname> <token>
just proxy-auth-config <hostname> <token> users="" emails="" groups=""
just proxy-auth-show <hostname>

# MCP metadata configuration
just proxy-mcp-enable <hostname> <token> [endpoint] [scopes] [stateful] [override-backend]
just proxy-mcp-disable <hostname> <token>
just proxy-mcp-show <hostname>
just test-proxy-mcp <hostname>

# Testing
just test-proxy-basic
just test-proxy-example
just test-websocket-proxy
just test-streaming-proxy
just test-proxy-all
just test-auth-flow <hostname>
```

### Route API Endpoints
- `GET /api/v1/routes` - List all routing rules
- `POST /api/v1/routes` - Create new routing rule
- `GET /api/v1/routes/{route_id}` - Get specific route details
- `PUT /api/v1/routes/{route_id}` - Update route configuration
- `DELETE /api/v1/routes/{route_id}` - Delete route
- `PUT /api/v1/routes/{route_id}/enable` - Enable route
- `PUT /api/v1/routes/{route_id}/disable` - Disable route

### Route Commands
```bash
just route-list
just route-show <route-id>
just route-create <path> <target-type> <target-value> <token> [priority] [methods] [is-regex] [description]
just route-update <route-id> <token> [options]
just route-delete <route-id> <token>
just route-enable <route-id> <token>
just route-disable <route-id> <token>

# Service setup shortcuts
just migrate-service-names       # Migrate old service names

# Per-proxy route control
just proxy-routes-show <hostname>
just proxy-routes-mode <hostname> <token> <all|selective|none>
just proxy-route-enable <hostname> <route-id> <token>
just proxy-route-disable <hostname> <route-id> <token>
just proxy-routes-set <hostname> <token> <enabled-routes> <disabled-routes>
just test-proxy-routes
```

## Docker Service Management

### Overview
The system supports creating and managing Docker containers as services:
- Dynamic container creation with custom images or Dockerfiles
- Automatic port allocation and management
- Integration with proxy for external access
- Resource limits (CPU, memory)
- Container lifecycle management

### Docker Configuration
- `DOCKER_GID` - Docker group GID on host (default: 999, varies by OS)
- `DOCKER_API_VERSION` - Docker API version (default: 1.41)
- `DOCKER_HOST` - Docker socket path (default: unix:///var/run/docker.sock)
- `BASE_DOMAIN` - Base domain for auto-created service proxies

### Service Schema
```json
{
  "service_name": "my-app",
  "image": "nginx:latest",  // OR use dockerfile_path
  "dockerfile_path": "./dockerfiles/custom.Dockerfile",
  "external_port": 8080,  // Optional, auto-allocated if not specified
  "memory_limit": "512m",
  "cpu_limit": 1.0,
  "environment": {"KEY": "value"},
  "command": ["npm", "start"],
  "network": "proxy_network"
}
```

### API Endpoints
- `POST /api/v1/services` - Create new Docker service
- `GET /api/v1/services` - List all services
- `GET /api/v1/services/{name}` - Get service details
- `PUT /api/v1/services/{name}` - Update service configuration
- `DELETE /api/v1/services/{name}` - Delete service
- `POST /api/v1/services/{name}/start` - Start service
- `POST /api/v1/services/{name}/stop` - Stop service
- `POST /api/v1/services/{name}/restart` - Restart service
- `GET /api/v1/services/{name}/logs` - Get service logs
- `GET /api/v1/services/{name}/stats` - Get service statistics
- `POST /api/v1/services/{name}/proxy` - Create proxy for service
- `POST /api/v1/services/cleanup` - Clean up orphaned services

### Service Commands
```bash
# Service lifecycle management
just service-create <name> <image> [dockerfile] [port] [token] [memory] [cpu] [auto-proxy]
just service-list [owned-only] [token]
just service-show <name>
just service-delete <name> [token] [force] [delete-proxy]
just service-start <name> [token]
just service-stop <name> [token]
just service-restart <name> [token]

# Service monitoring
just service-logs <name> [lines] [timestamps]
just service-stats <name>

# Service proxy management
just service-proxy-create <name> [hostname] [enable-https] [token]
just service-cleanup

# Testing
just test-docker-services
just test-docker-api
```

## OAuth Service

### Architecture
OAuth is integrated directly into the proxy service:
- Runs on the same process as the proxy
- Accessed via configured domains (e.g., `auth.example.com`)
- Routes OAuth paths to the integrated OAuth server
- Authlib-based implementation
- Redis for all state
- **MCP 2025-06-18 Compliant**: Full support for resource indicators, audience validation, and protected resource metadata

#### OAuth Service Configuration
- `GITHUB_CLIENT_ID` - GitHub OAuth application client ID (required for OAuth)
- `GITHUB_CLIENT_SECRET` - GitHub OAuth application client secret (required for OAuth)
- `BASE_DOMAIN` - Base domain for OAuth service (default: localhost)
- `OAUTH_ACCESS_TOKEN_LIFETIME` - Access token lifetime in seconds (default: 1800 = 30 minutes)
- `OAUTH_REFRESH_TOKEN_LIFETIME` - Refresh token lifetime in seconds (default: 31536000 = 1 year)
- `OAUTH_SESSION_TIMEOUT` - OAuth session timeout in seconds (default: 300 = 5 minutes)
- `OAUTH_CLIENT_LIFETIME` - OAuth client registration lifetime in seconds (default: 7776000 = 90 days)
- `OAUTH_ALLOWED_GITHUB_USERS` - Allowed GitHub users (* = all users)
- `OAUTH_MCP_PROTOCOL_VERSION` - MCP protocol version (default: 2025-06-18)

### JWT Configuration
- Algorithm: RS256 
- Access token lifetime: 30 minutes
- Refresh token lifetime: 1 year
- Secure cookies: HttpOnly, Secure, SameSite=Lax
- MCP Scopes: `mcp:read`, `mcp:write`, `mcp:admin`

#### JWT Environment Variables
- `OAUTH_JWT_ALGORITHM` - JWT signing algorithm (default: RS256)
- `OAUTH_JWT_SECRET` - JWT secret for fallback/testing (not used with RS256)
- `OAUTH_JWT_PRIVATE_KEY_B64` - Base64-encoded RSA private key for JWT signing
  - Generate with: `openssl genrsa -out private.pem 2048 && base64 -w 0 private.pem`

### ForwardAuth Implementation
1. Proxy sends original request to `/verify`
2. OAuth validates token/cookie
3. Returns user info or 401
4. Proxy adds headers: `X-Auth-User-Id`, `X-Auth-User-Name`, etc.

### MCP Specification Compliance

**CRITICAL**: MCP requires HTTPS for authorization servers. Ensure `auth.{domain}` has a valid certificate.

#### OAuth Authorization Server Requirements (RFC 8707)
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

#### MCP Server Requirements (RFC 9728)
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
  WWW-Authenticate: Bearer realm="MCP Server",
    as_uri="https://auth.example.com/.well-known/oauth-authorization-server",
    resource_uri="https://mcp.example.com/.well-known/oauth-protected-resource"
  ```
- **Audience Validation**: MCP servers MUST validate token `aud` claim contains server's resource URI

#### Token Format Requirements
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

#### OAuth Routes Configuration
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

#### MCP Authorization Flow
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

### Auth Modes
- **forward**: Returns 401 if not authenticated (APIs)
- **redirect**: Redirects to OAuth login (web apps)
- **passthrough**: Optional auth, always forwards

### Dynamic Client Registration (RFC 7591)
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

### OAuth Protocol Endpoints (Root Level)
- `GET /authorize` - OAuth authorization endpoint
- `POST /token` - Token exchange endpoint
- `GET /callback` - OAuth callback handler
- `POST /verify` - Token verification endpoint
- `POST /revoke` - Token revocation endpoint
- `POST /introspect` - Token introspection (RFC 7662)
- `POST /register` - Dynamic client registration (RFC 7591)
- `GET /jwks` - JSON Web Key Set endpoint
- `GET /.well-known/oauth-authorization-server` - Server metadata

### OAuth Admin API Endpoints
- `GET /api/v1/oauth/clients` - List OAuth clients
- `GET /api/v1/oauth/clients/{client_id}` - Client details
- `GET /api/v1/oauth/clients/{client_id}/tokens` - Client's tokens
- `GET /api/v1/oauth/tokens` - Token statistics
- `GET /api/v1/oauth/tokens/{jti}` - Token details
- `GET /api/v1/oauth/sessions` - Active sessions
- `GET /api/v1/oauth/sessions/{session_id}` - Session details
- `DELETE /api/v1/oauth/sessions/{session_id}` - Revoke session
- `GET /api/v1/oauth/metrics` - System metrics
- `GET /api/v1/oauth/health` - Integration health
- `GET /api/v1/oauth/proxies` - OAuth status for proxies
- `GET /api/v1/oauth/proxies/{hostname}/sessions` - Proxy sessions

### MCP Resource Management API Endpoints
**Note**: These management endpoints are optional conveniences, not MCP requirements.
- `GET /api/v1/resources` - List registered MCP resources
- `POST /api/v1/resources` - Register new MCP resource
- `GET /api/v1/resources/{uri}` - Get resource details
- `PUT /api/v1/resources/{uri}` - Update resource
- `DELETE /api/v1/resources/{uri}` - Remove resource
- `POST /api/v1/resources/{uri}/validate-token` - Validate token for resource
- `POST /api/v1/resources/auto-register` - Auto-discover proxy resources

### MCP Server Endpoints (Required on each MCP server)
- `GET /.well-known/oauth-protected-resource` - Protected resource metadata (REQUIRED)
- `GET /mcp` or `/mcp/sessions` - MCP protocol endpoints (implementation-specific)

### OAuth Commands
```bash
# OAuth setup and management
just generate-oauth-key                            # Generate RSA key
just oauth-routes-setup <domain> [token]          # Setup OAuth routes (CRITICAL!)
just oauth-client-register <name> [redirect-uri] [scope]  # Register OAuth client for testing

# MCP resource management (for MCP compliance)
just resource-register <uri> <proxy> <n> [scopes] # Register MCP resource
just resource-list                                # List MCP resources
just resource-show <uri>                          # Show resource details
just resource-validate <uri> <token>              # Validate token for resource

# OAuth status and monitoring
just oauth-clients-list [active-only]
just oauth-client-show <client-id>
just oauth-client-tokens <client-id>
just oauth-client-stats <client-id>
just oauth-tokens-stats
just oauth-token-show <jti>
just oauth-tokens-cleanup
just oauth-sessions-list
just oauth-session-show <session-id>
just oauth-session-revoke <session-id>
just oauth-metrics
just oauth-health
just oauth-proxy-status [hostname]

# Testing
just test-auth [token]
just test-auth-flow <hostname>
just test-oauth-status-api
just test-mcp-compliance                          # Test MCP spec compliance
just test-resource-indicators                     # Test RFC 8707
just test-audience-validation                     # Test audience restrictions
```

### MCP Configuration
```bash
# Environment variables for MCP compliance
MCP_RESOURCE_INDICATORS_ENABLED=true
MCP_RESOURCE_VALIDATION_STRICT=true
MCP_MAX_RESOURCES_PER_TOKEN=5

# Redis schema for resources
resource:{resource_uri} = {
  "uri": "https://mcp.example.com",
  "name": "Example MCP Server",
  "proxy_target": "mcp.example.com",
  "scopes": ["mcp:read", "mcp:write"],
  "metadata_url": "https://mcp.example.com/.well-known/oauth-protected-resource"
}
```

## Instance Management

### Named Instance Registry
The system supports registering named instances for internal services:
- Provides stable names for service discovery
- Maps instance names to target URLs
- Enables route targeting by instance name

### Instance Schema
```json
{
  "name": "api-backend",
  "target_url": "http://service:8080",
  "description": "Backend API service",
  "created_by": "admin",
  "created_at": "2024-01-15T10:00:00Z"
}
```

### Instance API Endpoints
- `GET /api/v1/instances` - List all registered instances
- `POST /api/v1/instances` - Register new instance
- `GET /api/v1/instances/{name}` - Get instance details
- `PUT /api/v1/instances/{name}` - Update instance
- `DELETE /api/v1/instances/{name}` - Delete instance

### Instance Commands
```bash
just instance-list                                        # List all registered instances
just instance-show <name>                                 # Show instance details
just instance-register <name> <target-url> <token> [desc] # Register new instance
just instance-update <name> <target-url> <token> [desc]   # Update instance
just instance-delete <name> <token>                       # Delete instance
just instance-register-oauth <token>                      # Register OAuth server instance
```

## Key Implementation Insights

1. **Dispatcher-Centric**: UnifiedDispatcher owns ports, routes all traffic
2. **Instance Isolation**: Each proxy has dedicated app and resources
3. **Redis-Only**: All configuration and state in Redis
4. **Async Operations**: Certificate generation non-blocking
5. **Token Authentication**: All write operations require bearer tokens
6. **Route Priority**: Higher priority routes checked first
7. **Certificate Sharing**: Multi-domain certs reduce overhead
8. **OAuth Integration**: Integrated into proxy service, accessed via routes
9. **Instance Registry**: Named instances for stable service discovery
10. **Docker Management**: Dynamic container creation via Docker socket
11. **MCP Metadata**: Automatic metadata endpoints for MCP compliance
12. **Resource Limits**: CPU and memory limits for Docker services

## MCP 2025-06-18 Compliance Summary

The system is **FULLY COMPLIANT** with MCP authorization specification:

### ✅ OAuth Server Compliance
- Resource parameter support in authorization and token endpoints
- Audience-restricted tokens with resource URIs in `aud` claim
- Authorization server metadata endpoint with `resource_indicators_supported: true`
- Dynamic client registration (RFC 7591)
- Token introspection and revocation endpoints

### ✅ MCP Server Compliance  
- Protected resource metadata endpoint on each MCP server
- WWW-Authenticate headers with metadata URLs
- Audience validation for all protected resources
- Resource-specific scope enforcement

### ✅ Integration Features
- Resource registry for MCP server management
- Automatic resource discovery from proxy configuration
- Token validation with resource context
- Per-resource access control

To ensure MCP compliance for any proxy:
1. Register as MCP resource: `just resource-register <uri> <proxy> <name>`
2. Enable auth on proxy: `just proxy-auth-enable <proxy> <token> <auth-proxy> forward`
3. Verify metadata endpoint: `curl https://<proxy>/.well-known/oauth-protected-resource`

## System Commands

### Service Management
```bash
just up                      # Start all services
just down                    # Stop all services
just restart                 # Restart all services
just rebuild <service>       # Rebuild specific service
just logs [service]          # View service logs (all or specific)
just shell                   # Shell into proxy container
just redis-cli               # Access Redis CLI
just dev                     # Run development server locally
just setup                   # Quick setup for development
```

### Token Management
```bash
just token-generate <name> [cert-email]     # Create token with optional cert email
just token-show <name>                      # Retrieve full token
just token-list                             # List all tokens
just token-delete <name>                    # Delete token + certs
just token-show-certs [name]                # Show certs by token
just token-email-update <name> <email>      # Update token cert email
```

### Testing & Debugging

#### Testing Configuration
- `TEST_DOMAIN` - Domain for automated testing
- `TEST_EMAIL` - Email for test certificates
- `TEST_DOMAIN_BASE` - Base domain for test subdomains
- `TEST_BASE_URL` - Base URL for test requests (default: http://localhost:80)
- `TEST_PROXY_TARGET_URL` - Target URL for proxy testing (default: https://example.com)
- `TEST_TOKEN` - Token for automated test authentication

#### Administrative Configuration
- `ADMIN_TOKEN` - Administrative token for privileged operations
- `ADMIN_EMAIL` - Administrator email address for certificates
- `MCP_SERVER_URL` - MCP server SSE endpoint URL
- `BASE_DOMAIN` - Base domain for services and OAuth (e.g., yourdomain.com)

```bash
# Comprehensive test suites
just test                    # Run standard test suite
just test-all               # Run comprehensive test suite

# Service tests
just test-certs             # Test certificate operations
just test-proxy-all         # Run all proxy tests
just test-auth [token]      # Test authorization system

# System maintenance
just health                 # Check system health
just stats                  # Show system statistics
just cleanup-orphaned       # Clean up orphaned resources
just web-ui                 # Open web UI
just help                   # Show all available commands

# Additional commands
just generate-admin-token   # Generate admin token
just lint                   # Run linting
just docs-build            # Build documentation
just mcp-test-all          # Run full MCP client test suite
just mcp-test-auth         # Test MCP client authentication
just oauth-test-tokens <server-url>  # Generate test OAuth tokens for MCP client
```