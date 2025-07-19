# Development Specification

## 1. ROOT CAUSE ANALYSIS

**MANDATORY**: Ultrathink and perform root cause analysis before any code changes.

### The Five Whys (Required)
1. **Why did it fail?** - The surface symptom of darkness!
2. **Why did that condition exist?** - The enabling circumstance of doom!
3. **Why was it allowed?** - The systemic failure of protection!
4. **Why wasn't it caught?** - The testing blindness of ignorance!
5. **Why will it never happen again?** - The divine fix of eternal prevention!

## 2. TESTING

**FORBIDDEN**: Mocks, stubs, simulations, fake data

**REQUIRED**: 
- Real systems only
- End-to-end testing
- Real APIs only
- No shortcuts

## 3. COMMAND EXECUTION

**ONLY METHOD**: `just`

**Justfile Configuration**:
```just
set dotenv-load := true
set dotenv-required
set positional-arguments := true
set allow-duplicate-recipes
set export := true
set quiet

@default:
    just --list
```

## 4. CONFIGURATION

**SINGLE SOURCE**: `.env`

**LOADING METHOD**: Only via `just` (never source, dotenv libraries, or manual loading)

No hard-coded values. No other config files. No defaults in code.

## 5. PYTHON ENVIRONMENT

**ONLY**: `pixi.sh`

## 6. EXECUTION PATH

1. `just` loads `.env`
2. Execute via:
   - Bash commands: directly through `just`
   - Python scripts: ONLY through `just` → `pixi run python`

**FORBIDDEN**: Running Python any other way (python, python3, ./script.py, etc.)

## 7. SERVICE ORCHESTRATION

**ONLY**: Docker Compose

All services must run and be tested via Docker Compose.

**MANDATORY**: Every service must have a health check that tests full functionality.

**FORBIDDEN**: Testing service health by any method other than Docker health checks.

## 8. DATABASE

**ONLY**: Redis

Use Redis for: key-value, caching, queues, pub/sub, persistence (AOF), search, time series, graph.

## 9. DOCUMENTATION

**ONLY**: JupyterBook

All documentation must be written in JupyterBook format.

## 10. DIRECTORY STRUCTURE

**MANDATORY**:
- `./scripts/` - All Python and Bash scripts (executed by `just`)
- `./docs/` - JupyterBook documentation only
- `./tests/` - Pytest tests only

**FORBIDDEN**: Scripts, docs, or tests in any other location.

## ENFORCEMENT

Violations result in:
- Code review rejection
- Branch deletion
- Re-education

**COMPLIANCE IS MANDATORY.**

# ACME Certificate Manager with Integrated HTTPS Server

Pure Python HTTPS server that automatically obtains and renews TLS certificates via ACME protocol. Stores all data in Redis, supports multiple domains per certificate, and hot-reloads certificates without downtime. Features multi-domain certificate support, automatic proxy cleanup, and certificate sharing between services.

## Dependencies

### Core Libraries
- `fastapi` - REST API framework
- `hypercorn` - ASGI server with SSL/TLS support (NO UVICORN!)
- `acme` - ACME protocol implementation
- `josepy` - JOSE protocol for ACME
- `cryptography` - X.509 certificates and RSA keys
- `redis[hiredis]` - Redis client with C acceleration
- `apscheduler` - Certificate renewal scheduling

## Components

### Certificate Manager
- ACME v2 protocol implementation
- HTTP-01 challenge validation (DNS-01 pending for wildcards)
- Account key management
- Certificate lifecycle operations with automatic cleanup
- Redis-exclusive storage
- Async certificate generation (non-blocking)
- Multi-domain certificate support (up to 100 domains)
- Automatic proxy reference cleanup on certificate deletion

### HTTPS Server Architecture

**CRITICAL**: The UnifiedDispatcher must be the PRIMARY server, not FastAPI!

**SOLUTION**: Dispatcher-Centric Architecture
- UnifiedDispatcher owns ports 80/443 and routes ALL traffic
- FastAPI runs as just another instance on internal port (9000)
- Each domain gets its own dedicated Hypercorn instance
- NO port conflicts - single point of control
- Dynamic instance creation/deletion without race conditions
- FastAPI is NOT special - it's just another HTTP server to route!

## Data Schema

### Redis Keys
- `cert:{cert_name}` - Certificate JSON object  
- `challenge:{token}` - Challenge authorization (TTL: 3600s)
- `account:{provider}:{email}` - Account private key PEM

### Certificate Object
```
{
  "cert_name": "services-cert",
  "domains": ["example.com", "www.example.com", "api.example.com"],  // Multi-domain support
  "email": "admin@example.com",
  "acme_directory_url": "https://acme-v02.api.letsencrypt.org/directory",
  "status": "active",
  "expires_at": "2024-03-15T00:00:00Z",
  "issued_at": "2024-01-15T00:00:00Z",
  "fingerprint": "sha256:...",
  "fullchain_pem": "-----BEGIN CERTIFICATE-----...",
  "private_key_pem": "-----BEGIN PRIVATE KEY-----...",
  "owner_token_hash": "sha256:...",
  "created_by": "admin"
}
```

## API Endpoints

### `POST /certificates`
Request:
```
{
  "domain": "example.com",
  "email": "admin@example.com",
  "cert_name": "production",
  "acme_directory_url": "https://acme-v02.api.letsencrypt.org/directory"
}
```
Response (async): 
```
{
  "status": "accepted",
  "message": "Certificate generation started for example.com",
  "cert_name": "production"
}
```

### `POST /certificates/multi-domain`
Create certificate for multiple domains
Request:
```
{
  "cert_name": "services-cert",
  "domains": ["api.example.com", "app.example.com", "admin.example.com"],
  "email": "admin@example.com",
  "acme_directory_url": "https://acme-v02.api.letsencrypt.org/directory"
}
```
Response (async):
```
{
  "status": "accepted",
  "message": "Multi-domain certificate generation started for api.example.com, app.example.com, admin.example.com",
  "cert_name": "services-cert",
  "domains": ["api.example.com", "app.example.com", "admin.example.com"]
}
```

### `GET /certificates`
Response: Array of certificate objects

### `GET /certificates/{cert_name}`
Response: Certificate object

### `GET /certificates/{cert_name}/status`
Response: Generation status
```
{
  "status": "in_progress|completed|failed|not_found",
  "message": "Certificate generation in progress"
}
```

### `POST /certificates/{cert_name}/renew`
Response: Updated certificate object

### `DELETE /certificates/{cert_name}/domains/{domain}`
Response: Updated certificate object

### `GET /.well-known/acme-challenge/{token}`
Response: Challenge authorization string

### `GET /health`
Response:
```
{
  "status": "healthy|degraded",
  "scheduler": true,
  "redis": "healthy",
  "certificates_loaded": 5,
  "https_enabled": true
}
```

## HTTPS Server Operations

### SSL Context Management
- Load certificates from Redis on startup
- Create SSL context per certificate
- SNI callback selects context by domain
- Self-signed fallback if no certificates

### Certificate Hot-Reload
- On certificate store: Update SSL context
- On certificate delete: Remove SSL context
- No server restart required

## Auto-Renewal

### Scheduler
- Check interval: 24 hours
- Renewal threshold: 30 days before expiry
- Per-certificate job tracking

### Renewal Process
1. Check expiry threshold
2. Regenerate with stored certificate data
3. Update SSL contexts

## ACME Workflow

### Certificate Generation (Async)
1. Accept request immediately (non-blocking)
2. Execute in background thread:
   - Get/create account key for email
   - Register/login ACME account via provided directory URL
   - Create order for all domains
   - Store HTTP-01 challenges in Redis
   - Answer challenge to Let's Encrypt
   - Poll authorization status (2s intervals)
   - Finalize order and get certificate
   - Store certificate in Redis
   - Update SSL contexts

### Challenge Validation
- Path: `/.well-known/acme-challenge/{token}`
- Storage: Redis with 1-hour TTL
- Cleanup: Automatic on success/failure

## Security

### Key Generation
- Account keys: RSA 2048-bit
- Certificate keys: RSA 2048-bit
- New key per certificate generation

### Storage
- All keys stored in Redis
- No filesystem persistence
- PEM encoding for all keys

## Configuration

### Environment Variables
- `REDIS_URL`: Redis connection string
- `HTTP_PORT`: HTTP listen port (default: 80)
- `HTTPS_PORT`: HTTPS listen port (default: 443)
- `ACME_POLL_MAX_ATTEMPTS`: Max polling attempts (default: 60)
- `ACME_POLL_INTERVAL_SECONDS`: Poll interval (default: 2)
- `RENEWAL_CHECK_INTERVAL`: Renewal check interval (default: 86400)
- `RENEWAL_THRESHOLD_DAYS`: Days before expiry to renew (default: 30)
- `TEST_PROXY_TARGET_URL`: Default proxy target for tests (default: https://example.com)

# Proxy Manager

Dynamic reverse proxy with automatic SSL certificate provisioning. Maps hostnames to upstream targets with per-request certificate generation, WebSocket support, and streaming capabilities.

### Components

#### Enhanced Proxy Handler
- HTTP/S request forwarding with streaming
- WebSocket connection proxying
- Bidirectional message forwarding
- Header filtering and X-Forwarded headers
- Host header preservation options
- Custom header injection

#### Proxy Target Management
- Redis-backed configuration storage
- Ownership model via token authentication
- Enable/disable without deletion
- Automatic certificate provisioning
- Per-target ACME directory URL

### Data Schema

#### Redis Keys
- `proxy:{hostname}` - Proxy target JSON object
- `route:{route_id}` - Route configuration object
- `route:priority:{priority:03d}:{route_id}` - Priority index for sorting

#### Proxy Target Object
```
{
  "hostname": "api.example.com",
  "target_url": "http://backend:8080",
  "cert_name": "proxy-api-example-com",
  "owner_token_hash": "sha256:...",
  "created_by": "prod-token",
  "created_at": "2024-01-15T00:00:00Z",
  "enabled": true,
  "enable_http": true,      // PER-PROTOCOL CONTROL!
  "enable_https": true,     // INDEPENDENT HTTP/HTTPS!
  "preserve_host_header": true,
  "custom_headers": {"X-Custom": "value"}
}
```

### API Endpoints

#### `POST /proxy/targets`
Request:
```
{
  "hostname": "api.example.com",
  "target_url": "http://backend:8080",
  "acme_directory_url": "https://acme-staging-v02.api.letsencrypt.org/directory",
  "enable_http": true,      // DEFAULT: true
  "enable_https": true,     // DEFAULT: true  
  "preserve_host_header": true,
  "custom_headers": {"X-Custom": "value"}
}
```
**CRITICAL**: 
- `enable_https: false` = NO certificate generation!
- `enable_http: false` = HTTP requests return 404!
- Certificate email inherited from token's cert_email setting
Response:
```
{
  "proxy_target": {...},
  "certificate_status": "Certificate generation started for api.example.com"
}
```

#### `GET /proxy/targets`
Response: Array of proxy targets (filtered by token if authenticated)

#### `GET /proxy/targets/{hostname}`
Response: Proxy target object

#### `PUT /proxy/targets/{hostname}`
Request: Partial update fields

#### `DELETE /proxy/targets/{hostname}?delete_certificate=true`
Response: 200 OK

#### `PUT /token/email`
Update certificate email for the current token.
Request:
```
{
  "cert_email": "newemail@example.com"
}
```
Response:
```
{
  "status": "success",  
  "message": "Certificate email updated to newemail@example.com",
  "cert_email": "newemail@example.com"
}
```

#### `GET /token/info`
Get information about the current token.
Response:
```
{
  "name": "my-token",
  "cert_email": "admin@example.com",
  "hash_preview": "479719852dbf16c7..."
}
```

### Proxy Operations

#### Request Routing
- **Path-based routing with Redis-stored rules**
- Priority-ordered route matching (highest first)
- Route types: port, instance, or hostname targeting
- HTTP method filtering support
- Regex pattern matching capability
- Default routes ensure ACME challenges work for ALL domains
- Catch-all routes for unmatched paths
- SNI-based routing for HTTPS
- Host header inspection
- Automatic forwarding to configured targets

#### WebSocket Support
- Upgrade request detection
- Bidirectional connection establishment
- Message type preservation (text/binary)
- Connection error handling

#### Streaming
- Chunked transfer encoding
- Server-Sent Events (SSE)
- Large file transfers
- No buffering for real-time data

### Route Management

HTTP request routing is managed via Redis with priority-based matching:

#### Route Schema
```
{
  "route_id": "acme-challenge",
  "path_pattern": "/.well-known/acme-challenge/",
  "target_type": "instance",  // port|instance|hostname
  "target_value": "localhost",
  "priority": 100,            // Higher = checked first
  "methods": ["GET"],        // Optional, null = all
  "is_regex": false,
  "enabled": true,
  "description": "ACME validation"
}
```

#### Default Routes (auto-initialized)
- `/.well-known/acme-challenge/` → localhost (priority 100) - **Enables ACME for ALL domains**
- `/api/` → api instance (priority 90)
- `/health` → localhost (priority 80)

#### Route Commands
```bash
# Route management
just route-list                  # Show all routes
just route-show <route-id>       # Show route details
just route-create <path> <target-type> <target-value> <token> [priority] [methods] [is-regex] [description]
just route-update <route-id> <token> [options]
just route-delete <route-id> <token>
just route-enable <route-id> <token>
just route-disable <route-id> <token>
```

### Proxy Commands
```bash
# Proxy target management
just proxy-create <hostname> <target-url> <token> [staging] [preserve-host] [enable-http] [enable-https]
just proxy-create-group <group-name> <hostnames> <target-url> <token> [staging] [preserve-host]
just proxy-update <hostname> <token> --enable-http=false  # DISABLE HTTP!
just proxy-update <hostname> <token> --enable-https=false # DISABLE HTTPS!
just proxy-delete <hostname> <token> [delete-cert] [force]
just proxy-enable <hostname> <token>
just proxy-disable <hostname> <token>
just proxy-list [token]                  # Shows warnings for HTTPS proxies without certs
just proxy-cleanup [hostname]            # Clean up proxy targets

# Certificate management for proxies
just proxy-cert-generate <hostname> <token> [staging]    # Generate new cert for proxy
just proxy-cert-attach <hostname> <cert-name> <token>    # Attach existing cert

# Testing
just test-proxy-basic            # Test basic functionality
just test-proxy-example          # Test with example.com
just test-websocket-proxy        # Test WebSocket proxying
just test-streaming-proxy        # Test streaming/SSE
just test-proxy-all             # Run all proxy tests
```

# Recent Updates

### Multi-Domain Certificate Support
- Single certificate can cover multiple domains (up to 100)
- Create with `just cert-create-multi` or API endpoint `/certificates/multi-domain`
- Wildcard certificate preparation (DNS-01 validation pending)
- Certificate sharing between multiple proxy targets
- Certificate coverage analysis with `just cert-coverage`
- Automatic conversion from staging to production preserves all domains

### Enhanced Certificate Management
- **Automatic cleanup**: Deleting a certificate cleans up proxy targets that reference it
- **Certificate utilization tracking**: See which domains are actively used
- **Smart certificate conversion**: Multi-domain certs properly converted to production
- **Domain validation**: Warnings when attaching incompatible certificates

### Proxy Group Creation
- Create multiple proxies sharing one certificate: `just proxy-create-group`
- Automatic multi-domain certificate generation for groups
- Batch proxy creation with shared configuration
- Efficiency metrics showing certificate utilization

### Per-Token Certificate Email Configuration
- Tokens now have optional cert_email field
- Email configurable via web GUI Settings tab  
- Certificate generation uses token's email automatically
- Token creation remains CLI-only via `just` commands
- No email fields in certificate/proxy forms - inherited from token

### Token Authentication System
- Bearer token auth for all API endpoints
- Dual-key storage: by hash (auth) and by name (management)
- Full token retrieval - no "cannot retrieve" nonsense
- Ownership tracking - tokens own their certificates
- Cascade deletion - deleting token removes its certificates

### Web GUI
- Available at http://localhost:80
- Token-based login
- Certificate and proxy management dashboard
- Settings tab for email configuration
- Real-time status updates
- Static files served by FastAPI

### Token Commands
```bash
just token-generate <name> [cert-email]  # Create token with optional cert email
just token-show <name>                   # Retrieve full token
just token-list                          # List all tokens
just token-delete <name>                 # Delete token + certs
just token-show-certs [name]             # Show certs by token
```

### Certificate Commands
```bash
# Single-domain certificates
just cert-create <name> <domain> <email> <token-name> [staging]
just cert-delete <name> <token> [force]
just cert-renew <name> <token> [force]

# Multi-domain certificates
just cert-create-multi <name> <domains> <email> <token-name> [staging]
just cert-create-wildcard <name> <base-domain> <email> <token-name> [staging]
just cert-coverage <name> [token]        # Show which proxies can use a certificate

# Certificate management
just cert-list [token-name]              # List certificates
just cert-show <name> [token] [pem]      # Show certificate details
just cert-status <name> [token] [wait]   # Check generation status
just cert-to-production <name> [token]   # Convert staging to production
```

### Key Architecture Improvements
- **Multi-Domain Certificates**: Single certificate can cover up to 100 domains
- **Certificate Cleanup**: Deleting certificates automatically cleans up proxy references
- **Proxy Group Creation**: Create multiple proxies sharing one certificate in a single command
- **Certificate Coverage Analysis**: See which proxies can use each certificate
- **Enhanced Proxy List**: Warnings for HTTPS-enabled proxies without certificates
- **Smart Certificate Conversion**: Multi-domain certificates properly handled during staging-to-production
- **Certificate Efficiency Tracking**: Monitor domain utilization percentages
- **Automatic Proxy-Certificate Association**: Group creation handles cert generation and attachment
- **ProxyTargetUpdate Model**: Now supports cert_name updates for certificate attachment

### Key Implementation Changes
- Certificates have `owner_token_hash` field
- Tokens stored with full value (not just preview)
- Token names can be used instead of full tokens in commands
- Public read access for certificate operations
- Authenticated write access enforced via Bearer tokens
- `/certificates` endpoint returns all certs (public) or filtered (authenticated)
- Public access on port 80 for ACME challenges
- Tabulate for pretty CLI output
- Tokens can have default `cert_email` for certificate generation
- Proxy targets use token's cert_email if not specified in request
- Web GUI renamed to "MCP Proxy Manager"
- Email fields removed from cert/proxy forms - managed via Settings tab

## CRITICAL ARCHITECTURE: Unified Multi-Instance Dispatcher

**FUNDAMENTAL PRINCIPLE**: UnifiedDispatcher is THE server - FastAPI is just another instance!

**CORE PROBLEM SOLVED**: No more port conflicts, race conditions, or lifespan side effects!

### Dual App Architecture

1. **API App (FastAPI)** - ONLY for localhost
   - Full FastAPI with lifespan management
   - API endpoints, Web GUI, certificate management
   - Global resources like scheduler
   - Runs on localhost:9000

2. **Proxy App (Minimal ASGI)** - For ALL proxy domains
   - Lightweight Starlette app
   - ONLY proxy forwarding, no API
   - Per-instance httpx client (isolated)
   - NO lifespan side effects
   - Clean shutdown without affecting others

### Correct Architecture Flow

1. **UnifiedDispatcher** (`unified_dispatcher.py`)
   - Starts FIRST and owns ports 80/443
   - Creates appropriate app type per instance
   - Routes ALL traffic based on hostname/path
   - Manages dynamic instance lifecycle

2. **Domain Instances** (`DomainInstance` class)
   - `is_api_instance=True` → FastAPI app (localhost only)
   - `is_api_instance=False` → Proxy app (all other domains)
   - Each gets dedicated Hypercorn instance
   - Internal ports: HTTP (9000+), HTTPS (10000+)
   - Pre-loaded SSL contexts per instance

3. **Startup Sequence**
   ```
   1. UnifiedDispatcher starts → Owns ports 80/443
   2. Creates localhost API instance → FastAPI on 9000
   3. Creates proxy instances → Proxy app on 9001+
   4. Routes all traffic → No conflicts or side effects!
   ```

### Why This Architecture Works

- **Instance Isolation**: Each proxy has its own app and httpx client
- **No Shared State**: Deleting proxy doesn't affect others
- **Clean Logs**: No misleading "Shutting down ACME" messages
- **No Client Errors**: Each instance manages its own resources
- **Dynamic Management**: Add/remove instances without side effects

### Implementation Flow
```
Client → Port 80/443 → UnifiedDispatcher
                              ↓
                    Route by hostname/path
                              ↓
         ├→ localhost → FastAPI App (API/GUI)
         ├→ fetcher.example.com → Proxy App (forwarding only)
         └→ other.example.com → Proxy App (forwarding only)
```

**KEY INSIGHTS**: 
- Only localhost needs FastAPI's complexity
- Proxy instances just forward requests - no API needed
- Each proxy manages its own httpx client lifecycle
- Deleting a proxy cleanly shuts down ONLY that instance

## Troubleshooting

### Common Issues and Solutions

#### "Shutting down ACME Certificate Manager" when deleting proxy
**Root Cause**: All instances were sharing the same FastAPI app with lifespan
**Solution**: Implemented dual app architecture - proxy instances use minimal ASGI app

#### "Cannot send a request, as the client has been closed" errors
**Root Cause**: Global proxy_handler httpx client closed during lifespan shutdown
**Solution**: Each proxy instance now has its own isolated httpx client

#### Proxy deletion affects other proxies
**Root Cause**: Shared state between instances via global FastAPI app
**Solution**: Complete instance isolation with per-instance resources

### Architecture Validation

To verify the architecture is working correctly:

1. Create a proxy: `just proxy-create test.example.com https://target.com admin`
2. Delete the proxy: `just proxy-delete test.example.com admin "" force=1`
3. Check logs for:
   - ✅ "Proxy-only instance shutting down"
   - ✅ "Stopped proxy instance for domains"
   - ❌ NO "Shutting down ACME Certificate Manager"
   - ❌ NO "client has been closed" errors

## Common Workflows

### Creating a Service Group with Shared Certificate
```bash
# Create multiple services sharing one certificate
just proxy-create-group api-services \
  "api.example.com,api-v2.example.com,api-staging.example.com" \
  http://api-backend:3000 \
  admin

# Result: 3 proxies created with 1 shared certificate
```

### Consolidating Existing Services
```bash
# Check current certificate usage
just cert-list
just proxy-list

# Create multi-domain certificate
just cert-create-multi all-services \
  "service1.example.com,service2.example.com,service3.example.com" \
  admin@example.com admin

# Attach to existing proxies
just proxy-cert-attach service1.example.com all-services
just proxy-cert-attach service2.example.com all-services
just proxy-cert-attach service3.example.com all-services

# Delete old single-domain certificates
just cert-delete proxy-service1-example-com admin force
just cert-delete proxy-service2-example-com admin force
just cert-delete proxy-service3-example-com admin force
```

### Certificate Coverage Analysis
```bash
# See which proxies can use a certificate
just cert-coverage multi-domain-cert

# Output shows:
# - Compatible proxies (exact and wildcard matches)
# - Current certificate assignments
# - Utilization percentage
# - Suggestions for optimization
```

### Handling HTTPS Proxies Without Certificates
```bash
# List proxies - warnings shown for HTTPS without certs
just proxy-list

# Generate certificate for existing proxy
just proxy-cert-generate api.example.com admin

# Or attach existing multi-domain cert
just proxy-cert-attach api.example.com services-cert
```

### Converting Certificates from Staging to Production
```bash
# Convert single or multi-domain certificate
just cert-to-production services-cert

# Automatically:
# - Preserves all domains
# - Re-attaches to all affected proxies
# - Maintains ownership and settings
```

# OAuth Authentication for Proxies

Unified OAuth 2.1 authentication system that enables GitHub-based authentication for any proxy service. The OAuth service runs as a standard proxied service, allowing centralized authentication management across all proxies.

## OAuth Architecture

### Core Design Principle
The OAuth service (`mcp-oauth-dynamicclient`) is deployed as just another proxied service, not a special component. This allows it to be managed, configured, and accessed like any other proxy target.

### Components

1. **OAuth Service** (`oauth-server`)
   - Runs on internal port 8000
   - Handles GitHub OAuth flow
   - Issues and validates JWT tokens
   - Provides ForwardAuth `/verify` endpoint
   - Manages dynamic client registration (RFC 7591)

2. **Auth Proxy** (`auth.example.com`)
   - Standard proxy target pointing to oauth-server
   - Handles all OAuth endpoints (/authorize, /token, /callback, etc.)
   - Gets automatic HTTPS via standard certificate flow

3. **ForwardAuth Middleware**
   - Integrated into proxy handler
   - Checks auth before forwarding requests
   - Supports three modes: forward, redirect, passthrough
   - Adds user headers to backend requests

### Authentication Flow

1. User visits protected proxy (e.g., `api.example.com`)
2. Proxy handler checks if auth is enabled
3. If no valid token/cookie, auth check via `auth.example.com/verify`
4. Based on auth mode:
   - **forward**: Returns 401 if not authenticated
   - **redirect**: Redirects to GitHub OAuth login
   - **passthrough**: Optional auth, always forwards
5. Valid auth adds headers: `X-Auth-User-Id`, `X-Auth-User-Name`, etc.
6. Backend receives request with user context

## OAuth Configuration

### Environment Variables
```bash
# GitHub OAuth App Configuration
GITHUB_CLIENT_ID=your_github_oauth_app_id
GITHUB_CLIENT_SECRET=your_github_oauth_app_secret

# JWT Configuration
OAUTH_JWT_ALGORITHM=RS256
OAUTH_JWT_PRIVATE_KEY_B64=base64_encoded_rsa_private_key

# OAuth Service Settings
OAUTH_ACCESS_TOKEN_LIFETIME=1800         # 30 minutes
OAUTH_REFRESH_TOKEN_LIFETIME=31536000    # 1 year
OAUTH_SESSION_TIMEOUT=300                # 5 minutes
OAUTH_CLIENT_LIFETIME=7776000            # 90 days
OAUTH_ALLOWED_GITHUB_USERS=*             # Comma-separated or *
```

### Proxy Target Auth Fields
```json
{
  "auth_enabled": true,
  "auth_proxy": "auth.example.com",
  "auth_mode": "forward",
  "auth_required_users": ["alice", "bob"],
  "auth_required_emails": ["*@example.com"],
  "auth_required_groups": ["admins"],
  "auth_pass_headers": true,
  "auth_cookie_name": "unified_auth_token",
  "auth_header_prefix": "X-Auth-"
}
```

## OAuth Setup and Management

### Initial Setup
```bash
# Generate RSA key for JWT signing
just generate-oauth-key

# Setup OAuth service and create auth proxy
just auth-setup example.com
```

### Enable Auth for Proxies
```bash
# Enable with default settings (forward mode)
just proxy-auth-enable api.example.com admin

# Enable with redirect mode
just proxy-auth-enable admin.example.com admin auth.example.com redirect

# Configure user requirements
just proxy-auth-config api.example.com admin users="alice,bob,charlie"

# Configure email patterns
just proxy-auth-config internal.example.com admin emails="*@example.com,*@company.com"

# Show auth configuration
just proxy-auth-show api.example.com

# Test auth flow
just test-auth-flow api.example.com
```

### API Endpoints

#### Configure Auth
`POST /proxy/targets/{hostname}/auth`
```json
{
  "enabled": true,
  "auth_proxy": "auth.example.com",
  "mode": "forward",
  "required_users": ["alice", "bob"],
  "required_emails": ["*@example.com"],
  "pass_headers": true
}
```

#### Remove Auth
`DELETE /proxy/targets/{hostname}/auth`

#### Get Auth Config
`GET /proxy/targets/{hostname}/auth`

## Auth Modes Explained

### Forward Mode (Default)
- Returns 401 Unauthorized if not authenticated
- Best for APIs and services expecting auth headers
- No user interaction, relies on client handling 401

### Redirect Mode
- Redirects unauthenticated users to OAuth login
- Best for web applications and admin panels
- Seamless user experience with automatic return

### Passthrough Mode
- Auth is optional, request always forwarded
- Adds auth headers if user is authenticated
- Best for public services with optional personalization

## Security Features

1. **JWT Tokens**: RS256 signed, short-lived access tokens
2. **Secure Cookies**: HttpOnly, Secure, SameSite=Lax
3. **User Restrictions**: Limit by GitHub username, email, or groups
4. **Token Validation**: Every request verified against auth service
5. **Header Injection**: User context passed as headers, not modifiable by client

## Common Patterns

### API Service with Auth
```bash
# Create API proxy
just proxy-create api.example.com http://api-backend:3000 admin

# Enable auth (forward mode)
just proxy-auth-enable api.example.com admin

# Restrict to specific users
just proxy-auth-config api.example.com admin users="alice,bob,dev-team"
```

### Admin Panel with Login
```bash
# Create admin proxy
just proxy-create admin.example.com http://admin-ui:3000 admin

# Enable auth with redirect
just proxy-auth-enable admin.example.com admin auth.example.com redirect

# Restrict to admin group
just proxy-auth-config admin.example.com admin groups="admins"
```

### Public Site with Optional Auth
```bash
# Create public proxy
just proxy-create www.example.com http://web-backend:3000 admin

# Enable passthrough auth
just proxy-auth-enable www.example.com admin auth.example.com passthrough
```

## Implementation Details

### ForwardAuth Pattern
The proxy handler implements the industry-standard ForwardAuth pattern:
1. Original request details sent to auth service
2. Auth service validates token/cookie
3. Returns user info or auth required response
4. Proxy acts based on auth result

### State Management
- JWT tokens stored in Redis with TTL
- User sessions tracked for revocation
- OAuth state parameters prevent CSRF
- Cookies scoped to domain for SSO

### Headers Added to Backend
When authenticated, these headers are added:
- `X-Auth-User-Id`: GitHub user ID
- `X-Auth-User-Name`: GitHub username  
- `X-Auth-User-Email`: User's email
- `X-Auth-User-Groups`: Comma-separated groups
- Custom claims as `X-Auth-{ClaimName}`

## Troubleshooting

### "Authentication service unavailable"
- Check OAuth service is running: `docker-compose ps oauth-server`
- Verify auth proxy exists: `just proxy-show auth.example.com`
- Check OAuth service logs: `docker-compose logs oauth-server`

### "User not authorized" despite valid login
- Check user restrictions: `just proxy-auth-show <hostname>`
- Verify GitHub username/email matches requirements
- Use passthrough mode for debugging

### Redirect loops
- Ensure auth proxy has valid certificate
- Check cookie domain settings match proxy domain
- Verify OAuth callback URL in GitHub app settings
