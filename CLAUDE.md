# HTTPS OAuth Proxy with Protected Resources Specification

## General Development Guidelines

### API Design Patterns
- **Collection Endpoints**: All collection endpoints (GET lists) require trailing slashes to avoid HTTP 307 redirects
  - Example: `/api/v1/routes/` not `/api/v1/routes`
  - FastAPI/Starlette automatically redirects non-trailing slash URLs
  - This applies to: tokens, certificates, services, routes, resources, ports, proxy/targets

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

### Advanced Logging Architecture
The system uses a dual-Redis architecture for high-performance logging:
- **Async Redis**: For high-frequency request/response logging with minimal latency
- **Sync Redis**: For configuration and slower operations

#### RequestLogger System
The RequestLogger provides efficient HTTP request/response logging with multiple indexes:

**Key Features**:
- Multiple indexes for efficient querying (IP, hostname, status, user, path)
- Real-time streaming for monitoring
- HyperLogLog for unique visitor tracking
- Response time statistics with sliding windows

**Redis Storage Schema**:
```
req:{timestamp}:{ip}         # Request/response data as hash
idx:req:ip:{ip}              # Index by client IP
idx:req:host:{hostname}      # Index by hostname
idx:req:user:{username}      # Index by authenticated user
idx:req:status:{code}        # Index by HTTP status code
idx:req:errors               # All error responses (4xx/5xx)
idx:req:slow                 # Slow requests (>1s)
idx:req:path:{method}:{path} # Path pattern analysis
stream:requests              # Live request stream
stats:requests:{YYYYMMDD:HH} # Hourly request counts
stats:errors:{YYYYMMDD:HH}   # Hourly error counts
stats:unique_ips:{hostname}:{YYYYMMDD:HH} # Unique visitors
```

#### Log Query API
Access logs via the `/api/v1/logs` endpoints:
- `GET /api/v1/logs/ip/{ip}` - Query by IP address
- `GET /api/v1/logs/client/{client_id}` - Query by OAuth client
- `GET /api/v1/logs/search` - Search logs with filters
- `GET /api/v1/logs/search` - Advanced search with filters
- `GET /api/v1/logs/errors` - Recent errors
- `GET /api/v1/logs/events` - Event statistics

#### Log Query Commands
```bash
just logs [hours] [limit]                    # Show recent logs (default)
just logs-ip <ip> [hours] [limit]            # Query logs by client IP
just logs-host <hostname> [hours]            # Query logs by hostname
just logs-client <client-id> [hours]         # Query logs by OAuth client
just logs-search <query>                     # Search logs with filters
just logs-errors [hours] [limit]             # Show recent errors
just logs-errors-debug [hours] [limit]       # Detailed errors with debugging
just logs-follow [interval]                  # Follow logs in real-time
just logs-oauth <ip> [hours]                 # OAuth activity summary
just logs-oauth-debug <ip> [hours]           # Full OAuth flow debugging
just logs-oauth-flow [client-id] [username]  # Track OAuth flows
just logs-stats [hours]                      # Show event statistics
just logs-test                               # Test logging system
just logs-service [service]                  # Docker container logs
```

#### Performance Optimizations
- Batch processing with 100ms windows
- Pipeline operations for bulk fetches
- Sliding window for response time percentiles
- HyperLogLog for memory-efficient unique counting
- Automatic index expiration

### PROXY Protocol Support
- Port 9000: Direct API access (localhost-only, no PROXY protocol)
- Port 10001: PROXY protocol v1 enabled (for external load balancers/reverse proxies)
- Client IP preservation through Redis side channel for unified HTTP/HTTPS handling

### Directory Structure
```
./analysis/    # All plans and code or issue analysis (add to .gitignore) 
./scripts/     # All executable scripts
./docs/        # JupyterBook documentation only
./tests/       # Pytest tests only
./src/middleware/  # Middleware components including PROXY protocol handler
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
- `GET /api/v1/tokens/` - List all tokens (requires trailing slash)
- `POST /api/v1/tokens/` - Create new token
- `POST /api/v1/tokens/generate` - Generate token for display
- `PUT /api/v1/tokens/email` - Update certificate email for current token
- `GET /api/v1/tokens/info` - Get current token information
- `GET /api/v1/tokens/{name}` - Get specific token details
- `DELETE /api/v1/tokens/{name}` - Delete a token
- `GET /api/v1/tokens/{name}/reveal` - Securely reveal token value

### Token Commands
```bash
just token-generate <name> [cert-email]  # Create token with optional cert email
just token-show <name>                   # Retrieve full token
just token-list                          # List all tokens
just token-delete <name>                 # Delete token + owned resources
just token-show-certs [name]             # Show certificates by token
just token-email-update <name> <email>   # Update token cert email
```

## Service Architecture

### Docker Services
- **api**: HTTP/HTTPS gateway with integrated OAuth server, certificate manager, and API (exposed on ports 80, 443, 9000, 10001)
- **redis**: State storage for all services (including PROXY protocol client info)

**Note**: The "api" service handles everything - proxy, OAuth, certificates, and API endpoints. There is no separate "proxy" or "auth" service. Port 10001 provides PROXY protocol support for external load balancers.

### PROXY Protocol Architecture
The system supports HAProxy PROXY protocol v1 for preserving real client IPs:

```
External LB → Port 10001 (PROXY handler) → Port 9000 (Hypercorn)
              ↓
        Parses & strips PROXY header
        Stores client info in Redis
              ↓
        ASGI middleware retrieves client IP
        Injects X-Real-IP/X-Forwarded-For headers
```

#### Key Components:
- **proxy_protocol_handler.py**: TCP-level handler that parses PROXY headers
- **proxy_client_middleware.py**: ASGI middleware that injects client IPs
- **Redis side channel**: Stores client info keyed by `proxy:client:{server_port}:{client_port}`

### Unified Multi-Instance Dispatcher
**CRITICAL**: UnifiedDispatcher is THE server - FastAPI is just another service it manages!

#### Server Configuration
- `HTTP_PORT` - HTTP server port (default: 80)
- `HTTPS_PORT` - HTTPS server port (default: 443)
- `SERVER_HOST` - Server bind address (default: 0.0.0.0)
- `SELF_SIGNED_CN` - Common name for self-signed certificates (default: localhost)
- `API_URL` - Base URL for API endpoints (default: http://localhost:9000)
- **Internal Ports**:
  - Port 9000: Direct API access (localhost-only)
  - Port 10001: PROXY protocol endpoint (forwards to 9000)

```
Client → Port 80/443 → UnifiedDispatcher (in api container)
                              ↓
                    Route by hostname/path
                              ↓
         ├→ localhost → FastAPI App (API/GUI/OAuth)
         ├→ proxy1.com → Proxy App (forwarding only)
         └→ proxy2.com → Proxy App (forwarding only)

For PROXY protocol support:
External LB → Port 10001 → PROXY Handler → Port 9000 → UnifiedDispatcher
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

### Service Management
```python
class DomainService:
    is_api_service: bool  # True=FastAPI, False=Proxy
    internal_http_port: int  # 9000+ 
    internal_https_port: int  # 10000+
    ssl_context: Optional[SSLContext]  # Pre-loaded
```

### Key Benefits
- No port conflicts or race conditions
- Instance isolation - delete proxy without affecting others
- Clean resource management per instance
- Dynamic add/remove without side effects
- Preserves real client IPs through PROXY protocol
- Unified HTTP/HTTPS client IP handling via Redis

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
- `POST /api/v1/certificates/` - Single domain (async)
- `POST /api/v1/certificates/multi-domain` - Multiple domains (async)
- `GET /api/v1/certificates/` - List all certificates (requires trailing slash)
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
  "resource_custom_metadata": null
}
```

### Route Management
Priority-based path routing with Redis storage and scope support:

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

#### Route Target Types
- **port**: Forward to `localhost:<port>` (e.g., `8080`)
- **service**: Forward to named service - Docker, external, or internal (e.g., `auth`, `api-gateway`)
- **hostname**: Forward to proxy handling that hostname (e.g., `api.example.com`)
- **url**: Forward to any URL directly (e.g., `http://backend:8080` or `https://api.example.com`)

#### Route Scopes
Routes can be scoped to control their applicability:
- **global**: Route applies to all proxies (default)
- **proxy**: Route applies only to specified proxy hostnames

When multiple routes match a request, they are evaluated by:
1. Filtering by scope (global routes + proxy-specific routes for current proxy)
2. Sorting by priority (higher values checked first)
3. Matching path and methods

### OAuth Integration
```json
{
  "auth_enabled": true,
  "auth_proxy": "auth.example.com",
  "auth_mode": "forward",  // forward|redirect|passthrough
  "auth_required_users": ["alice", "bob"],  // Per-proxy GitHub user allowlist (null=global default, ["*"]=all users)
  "auth_required_emails": ["*@example.com"],
  "auth_allowed_scopes": ["mcp:read", "mcp:write"],  // Optional: restrict token scopes
  "auth_allowed_audiences": ["https://api.example.com"],  // Optional: restrict token audiences
  "auth_pass_headers": true
}
```

#### Per-Proxy User Allowlists
The `auth_required_users` field controls which GitHub users can authenticate for each proxy:
- `null` - Use global default from `OAUTH_ALLOWED_GITHUB_USERS` environment variable
- `["*"]` - Allow all GitHub users to authenticate
- `["user1", "user2"]` - Allow only specific GitHub users

This provides granular control over authentication at the proxy level. The field is checked at two points:
1. **During OAuth callback** - GitHub users not in the list are rejected during authentication
2. **During proxy access** - Token validation ensures the authenticated user is in the allowed list

This dual-check ensures consistent access control throughout the authentication flow.

### Protected Resource Metadata Configuration
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

### API Endpoints
- `POST /api/v1/proxy/targets/` - Create proxy target
- `GET /api/v1/proxy/targets/` - List all proxies (requires trailing slash)
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
just proxy-create <hostname> <target-url> <token> [email] [staging] [preserve-host] [enable-http] [enable-https]
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
just proxy-auth-enable <hostname> <token> <auth-proxy> <mode> [allowed-scopes] [allowed-audiences]
just proxy-auth-disable <hostname> <token>
just proxy-auth-config <hostname> <token> [users] [emails] [groups] [allowed-scopes] [allowed-audiences]
just proxy-auth-show <hostname>

# Examples of per-proxy user configuration:
# Allow specific GitHub users:
just proxy-auth-config api.example.com $TOKEN "alice,bob,charlie"
# Allow all GitHub users:
just proxy-auth-config api.example.com $TOKEN "*"
# Use global default (OAUTH_ALLOWED_GITHUB_USERS):
just proxy-auth-config api.example.com $TOKEN ""

# Protected resource metadata configuration (OAuth 2.0 RFC 9728)
# Note: proxy-mcp-* commands have been renamed to proxy-resource-* for clarity
just proxy-resource-set <hostname> <token> [endpoint] [scopes] [stateful] [override-backend] [bearer-methods] [doc-suffix] [server-info] [custom-metadata] [hacker-one-research]
just proxy-resource-clear <hostname> <token>
just proxy-resource-show <hostname>
just test-proxy-resource <hostname>

# Testing
just test-proxy-basic
just test-proxy-example
just test-websocket-proxy
just test-streaming-proxy
just test-proxy-all
just test-auth-flow <hostname>
```

### Route API Endpoints
**Note**: Collection endpoints require trailing slashes to avoid 307 redirects.
- `GET /api/v1/routes/` - List all routing rules (requires trailing slash)
- `POST /api/v1/routes/` - Create new routing rule
- `GET /api/v1/routes/{route_id}` - Get specific route details
- `PUT /api/v1/routes/{route_id}` - Update route configuration
- `DELETE /api/v1/routes/{route_id}` - Delete route
- `GET /api/v1/routes/formatted` - Get routes in formatted table

### Route Commands
```bash
# Basic route operations
just route-list                                      # List all routes in table format
just route-show <route-id>                          # Show route details in JSON
just route-create <path> <target-type> <target-value> [token] [priority] [methods] [is-regex] [description]
just route-delete <route-id> [token]                # Delete a route

# Scope-based route operations
just route-create-global <path> <target-type> <target-value> [token] [priority] [methods] [is-regex] [description]  # Create global route
just route-create-proxy <path> <target-type> <target-value> <proxies> [token] [priority] [methods] [is-regex] [description]  # Create proxy-specific route
just route-list-by-scope [scope]                    # List routes filtered by scope (all|global|proxy)

# Service migration utilities
just migrate-instances-to-services                  # Migrate old instance configs to services
just migrate-service-names [token]                  # Migrate old service names (defaults to ADMIN_TOKEN)

# Testing
just test-proxy-routes                              # Test proxy route functionality
```

## Service Management

### Overview
The system provides unified management for all service types:
- **Docker Services**: Container management with lifecycle control
- **External Services**: Named references to external URLs (replaces instances)
- **Internal Services**: Built-in services like API and auth

### Service Types
```python
class ServiceType(str, Enum):
    DOCKER = "docker"      # Docker container services
    EXTERNAL = "external"  # External URL references (registered via API)
    INTERNAL = "internal"  # Built-in services (currently only 'api')
```

### Internal Services
The system automatically registers these internal services:
- **api**: The main API service (http://api:9000) - handles all API, OAuth, and certificate operations

### Docker Configuration
- `DOCKER_GID` - Docker group GID on host (default: 999, varies by OS)
- `DOCKER_API_VERSION` - Docker API version (default: 1.41)
- `DOCKER_HOST` - Docker socket path (default: unix:///var/run/docker.sock)
- `BASE_DOMAIN` - Base domain for auto-created service proxies

### Docker Service Schema
```json
{
  "service_name": "my-app",
  "service_type": "docker",
  "image": "nginx:latest",  // OR use dockerfile_path
  "dockerfile_path": "./dockerfiles/custom.Dockerfile",
  "internal_port": 8080,  // Port inside container (auto-detected from image if not specified)
  "external_port": 8080,  // DEPRECATED - use port_configs for multi-port support
  "memory_limit": "512m",
  "cpu_limit": 1.0,
  "environment": {"KEY": "value"},
  "command": ["npm", "start"],
  "networks": ["proxy_network"],
  "labels": {"custom": "label"},
  "expose_ports": true,  // Enable port exposure
  "port_configs": [  // Multi-port configuration
    {
      "name": "http",
      "host": 8080,
      "container": 8080,
      "bind": "127.0.0.1",  // or "0.0.0.0" for all interfaces
      "protocol": "tcp",
      "source_token": "optional_access_token"  // For port access control
    }
  ],
  "bind_address": "127.0.0.1"  // Default bind address for ports
}
```

### API Endpoints
- `POST /api/v1/services/` - Create new Docker service
- `GET /api/v1/services/` - List all Docker services (requires trailing slash)
- `GET /api/v1/services/unified` - List all services (Docker + external)
- `POST /api/v1/services/external` - Register external service
- `GET /api/v1/services/external` - List external services
- `DELETE /api/v1/services/external/{name}` - Delete external service
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

#### Port Management Endpoints
- `GET /api/v1/services/{name}/ports` - List all ports for a service
- `POST /api/v1/services/{name}/ports` - Add a port to existing service
- `DELETE /api/v1/services/{name}/ports/{port_name}` - Remove a port from service
- `PUT /api/v1/services/{name}/ports/{port_name}` - Update port configuration

#### Global Port Query Endpoints
- `GET /api/v1/services/ports` - List all allocated ports across all services
- `GET /api/v1/services/ports/available` - Get available port ranges
- `POST /api/v1/services/ports/check` - Check if port is available

### Service Commands
```bash
# Docker service management
just service-create <name> <image> [dockerfile] [port] [token] [memory] [cpu] [auto-proxy]
just service-create-exposed <name> <image> <port> <bind-address> [token] [memory] [cpu]  # Create with exposed port
just service-list [owned-only] [token]  # List Docker services
just service-show <name>
just service-delete <name> [token] [force] [delete-proxy]
just service-start <name> [token]
just service-stop <name> [token]
just service-restart <name> [token]

# External service management (replaces instance commands)
just service-register <name> <target-url> [token] [description]  # Register external service
just service-list-external                                       # List external services
just service-show-external <name>                                # Show external service details
just service-update-external <name> <target-url> [token] [desc] # Update external service
just service-unregister <name> [token]                          # Delete external service
just service-register-oauth [token]                              # Register OAuth as external service

# Unified service views
just service-list-all [type]                                     # List all services (Docker + external)

# Service monitoring
just service-logs <name> [lines] [timestamps]
just service-stats <name>

# Service proxy management
just service-proxy-create <name> [hostname] [enable-https] [token]
just service-cleanup

# Port management
just service-port-add <name> <port> [bind-address] [source-token] [token]
just service-port-remove <name> <port-name> [token]
just service-port-list <name>
just service-port-check <port> [bind-address]
just service-ports-global [available-only]

# Testing
just test-docker-services
just test-docker-api
```

## Port Management Architecture

### Overview
The port management system provides comprehensive control over port allocation and access:
- **Dynamic port allocation** with configurable ranges
- **Multi-port support** per service
- **Bind address control** (localhost vs all interfaces)
- **Source token authentication** for port access
- **Port ownership tracking** by service

### Port Ranges
- **Internal HTTP**: 9000-9999 (for internal services)
- **Internal HTTPS**: 10000-10999 (for internal SSL services)  
- **Exposed Ports**: 11000-65535 (for user services)
- **Restricted Ports**: 22, 25, 53, 80, 443, 3306, 5432, 6379, 27017 (system reserved)

### Port Schema
```json
{
  "service_name": "my-app",
  "port_name": "http",
  "host_port": 8080,
  "container_port": 8080,
  "bind_address": "127.0.0.1",  // or "0.0.0.0"
  "protocol": "tcp",            // or "udp"
  "source_token_hash": "sha256:...",  // Optional access control
  "require_token": false,
  "owner_token_hash": "sha256:...",
  "description": "Main HTTP port"
}
```

### Key Features
- **Atomic port allocation** - No race conditions
- **Service isolation** - Ports owned by services
- **Access control** - Optional source_token for port access
- **Automatic cleanup** - Ports released when service deleted
- **Bind address flexibility** - Choose localhost or public access

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
- `OAUTH_ALLOWED_GITHUB_USERS` - Global default for allowed GitHub users (* = all users, comma-separated list for specific users)
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
4. Proxy validates user against `auth_required_users` (if configured)
5. Proxy adds headers: `X-Auth-User-Id`, `X-Auth-User-Name`, etc.

#### OAuth Authorization Flow with Per-Proxy Users
1. Proxy redirects to `/authorize` with `proxy_hostname` parameter
2. OAuth callback checks proxy-specific `auth_required_users`:
   - If proxy has `auth_required_users` set, use that list
   - Otherwise, fall back to global `OAUTH_ALLOWED_GITHUB_USERS`
3. GitHub users are validated during OAuth callback, not just at proxy access

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

#### Protected Resource Requirements (RFC 9728)
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

### Protected Resource Management API Endpoints
**Note**: These management endpoints are optional conveniences, not MCP requirements.
- `GET /api/v1/resources/` - List registered protected resources (requires trailing slash)
- `POST /api/v1/resources/` - Register new protected resource
- `GET /api/v1/resources/{uri}` - Get resource details
- `PUT /api/v1/resources/{uri}` - Update resource
- `DELETE /api/v1/resources/{uri}` - Remove resource
- `POST /api/v1/resources/{uri}/validate-token` - Validate token for resource
- `POST /api/v1/resources/auto-register` - Auto-discover proxy resources

### Protected Resource Endpoints (Required on each protected resource)
- `GET /.well-known/oauth-protected-resource` - Protected resource metadata (REQUIRED)
- `GET /mcp` or `/mcp/sessions` - MCP protocol endpoints (implementation-specific)

### OAuth Commands
```bash
# OAuth setup and management
just generate-oauth-key                            # Generate RSA key
just oauth-routes-setup <domain> [token]          # Setup OAuth routes (CRITICAL!)
just oauth-client-register <name> [redirect-uri] [scope]  # Register OAuth client for testing

# Protected resource management (for MCP compliance)
just resource-register <uri> <proxy> <n> [scopes] # Register protected resource
just resource-list                                # List protected resources
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

### Protected Resource Configuration
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

### External Service Schema
```json
{
  "service_name": "api-gateway",
  "service_type": "external",
  "target_url": "https://gateway.example.com",
  "description": "API Gateway service",
  "routing_enabled": true,
  "created_by": "admin",
  "created_at": "2024-01-15T10:00:00Z",
  "owner_token_hash": "sha256:..."
}
```

## Redis Storage Schema

### Service Keys
```
service:url:{name}          # Service name to URL mapping (all service types)
service:external:{name}     # External service configuration JSON
docker_service:{name}       # Docker service configuration JSON
services:external           # Set of external service names
```

### Token Keys
```
token:{name}                # Token data by name
token:hash:{hash}           # Token hash to name mapping
```

### Certificate Keys
```
cert:{name}                 # Certificate data JSON
cert:domain:{domain}        # Domain to certificate name mapping
cert:status:{name}          # Certificate generation status
```

### Proxy Keys
```
proxy:{hostname}            # Proxy target configuration JSON
proxy:client:{port}:{port}  # PROXY protocol client info (60s TTL)
```

### Route Keys
```
route:{id}                  # Route configuration JSON
route:unique:{path}:{prio}  # Unique route constraint
route:priority:{prio}:{id}  # Priority-ordered route index
```

### OAuth Keys
```
oauth:client:{id}           # OAuth client data
oauth:state:{state}         # OAuth authorization state
oauth:code:{code}           # OAuth authorization code
oauth:token:{jti}           # OAuth access token data
oauth:refresh:{token}       # OAuth refresh token data
oauth:user_tokens:{user}    # Set of token JTIs for user
```

### Port Management Keys
```
port:{port}                 # Port allocation data
service:ports:{service}     # Hash of service port configurations
```

### Resource Keys (MCP)
```
resource:{uri}              # Protected resource configuration
```

## Key Implementation Insights

1. **Dispatcher-Centric**: UnifiedDispatcher owns ports, routes all traffic
2. **Service Isolation**: Each proxy domain gets its own ASGI app instance
3. **Redis-Only**: All configuration and state in Redis
4. **Async Operations**: Certificate generation non-blocking
5. **Token Authentication**: All write operations require bearer tokens
6. **Route Priority**: Higher priority routes checked first
7. **Certificate Sharing**: Multi-domain certs reduce overhead
8. **OAuth Integration**: Integrated into proxy service, accessed via routes
9. **Unified Service Model**: Single API for Docker, external, and internal services
10. **Docker Management**: Dynamic container creation via Docker socket
11. **MCP Metadata**: Automatic metadata endpoints for MCP compliance
12. **Resource Limits**: CPU and memory limits for Docker services
13. **Port Management**: Comprehensive port allocation with bind address control
14. **Multi-Port Services**: Services can expose multiple ports with different access controls
15. **Port Access Control**: Simple source_token-based access control for exposed ports
16. **Service Port Binding**: Choose between localhost-only or public access per port
17. **Python-on-whales**: Uses tuples for port publishing: `("host_ip:port", container_port)`
18. **PROXY Protocol**: TCP-level handler preserves client IPs for both HTTP and HTTPS
19. **Redis Side Channel**: Connection-based client info storage with 60s TTL
20. **Unified IP Handling**: Same mechanism works for HTTP header injection and HTTPS
21. **Per-Proxy User Allowlists**: Each proxy can specify its own GitHub user allowlist via `auth_required_users`, overriding the global `OAUTH_ALLOWED_GITHUB_USERS` setting

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
1. Register as protected resource: `just resource-register <uri> <proxy> <name>`
2. Enable auth on proxy: `just proxy-auth-enable <proxy> <token> <auth-proxy> forward`
3. Verify metadata endpoint: `curl https://<proxy>/.well-known/oauth-protected-resource`

## System Commands

### Service Management
```bash
just up                      # Start all services
just down                    # Stop all services
just restart                 # Restart all services
just rebuild <service>       # Rebuild specific service (api or redis)
just logs [service]          # View service logs (all or specific)
just shell                   # Shell into api container
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
- `TEST_API_URL` - Base URL for test requests (default: http://localhost:80)
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