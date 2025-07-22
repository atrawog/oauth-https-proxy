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

#### Per-Proxy Route Control

Each proxy can have its own route filtering configuration, allowing fine-grained control over which routes apply:

**Route Modes:**
- **`all`** (default): All global routes apply except those explicitly disabled
- **`selective`**: Only explicitly enabled routes apply
- **`none`**: No routes apply - only hostname-based routing

**Per-Proxy Route Commands:**
```bash
# View proxy route configuration
just proxy-routes-show <hostname>

# Set route mode
just proxy-routes-mode <hostname> <token> <all|selective|none>

# Enable specific route for proxy
just proxy-route-enable <hostname> <route-id> <token>

# Disable specific route for proxy
just proxy-route-disable <hostname> <route-id> <token>

# Set multiple routes at once
just proxy-routes-set <hostname> <token> <enabled-routes> <disabled-routes>

# Test per-proxy routes
just test-proxy-routes
```

**Examples:**

```bash
# Create proxy with default route mode (all routes apply)
just proxy-create api.example.com http://backend:8080 admin

# Switch to selective mode (no routes apply by default)
just proxy-routes-mode api.example.com admin selective

# Enable only ACME challenge route
just proxy-route-enable api.example.com acme-challenge admin

# Or use all mode and disable specific routes
just proxy-routes-mode api.example.com admin all
just proxy-route-disable api.example.com debug-route admin

# Set multiple routes at once
just proxy-routes-set api.example.com admin "api-v1,api-v2" ""
```

### OAuth Commands
```bash
# OAuth setup and management
just generate-oauth-key                  # Generate RSA key for JWT signing
just auth-setup <domain>                 # Setup OAuth service and create auth proxy
just oauth-routes-setup <domain>         # Setup OAuth endpoint routes (CRITICAL!)

# OAuth proxy authentication
just proxy-auth-enable <hostname> <token> <auth-proxy> <mode>  # Enable auth (forward/redirect/passthrough)
just proxy-auth-disable <hostname> <token>                      # Disable auth
just proxy-auth-config <hostname> <token> users="" emails="" groups=""  # Configure auth requirements
just proxy-auth-show <hostname>                                 # Show auth configuration
just test-auth-flow <hostname>                                  # Test OAuth flow for a proxy
```

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

### OAuth Route-Based Implementation (2025-07-21)
- **CRITICAL**: OAuth endpoints are now implemented via the routing system
- Added `just oauth-routes-setup` command to create all OAuth endpoint routes
- Routes use priority 95 to ensure OAuth endpoints take precedence
- All OAuth routes target `hostname:auth.{domain}` for proper routing
- OAuth authentication is now fully integrated with the proxy and route system

### Code Fixes (2025-07-21)
- **SSL Verification**: Added `verify=False` to httpx.AsyncClient in proxy_handler_v2.py for internal service connections
- **Missing Parameter**: Fixed `store_proxy_target()` calls to include hostname parameter
- **OAuth Integration**: Fixed OAuth service startup with proper JWT configuration

### Per-Proxy Route Control
- Each proxy can have independent route configuration
- Three route modes: `all` (default), `selective`, `none`
- Enable/disable specific routes per proxy
- Bulk route management with `proxy-routes-set`
- Full API and CLI support for route customization
- Backwards compatible - existing proxies use `all` mode

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

### Complete OAuth Setup Workflow

**CRITICAL**: OAuth requires BOTH proxy setup AND route configuration!

```bash
# 1. Ensure OAuth configuration in .env
# GITHUB_CLIENT_ID=your_github_oauth_app_id
# GITHUB_CLIENT_SECRET=your_github_oauth_app_secret
# OAUTH_JWT_SECRET=your_jwt_secret
# OAUTH_JWT_PRIVATE_KEY_B64=your_base64_rsa_key

# 2. Generate RSA key if needed
just generate-oauth-key

# 3. Setup OAuth service and create auth proxy
just auth-setup yourdomain.com

# 4. CRITICAL: Setup OAuth routes for proper endpoint routing
just oauth-routes-setup yourdomain.com

# 5. Enable OAuth on services
just proxy-auth-enable api.yourdomain.com "" auth.yourdomain.com forward
just proxy-auth-enable admin.yourdomain.com "" auth.yourdomain.com redirect

# 6. Configure user restrictions (optional)
just proxy-auth-config api.yourdomain.com "" users="alice,bob"
just proxy-auth-config admin.yourdomain.com "" emails="*@company.com"

# 7. Verify OAuth is working
just proxy-auth-show api.yourdomain.com
curl -k https://api.yourdomain.com/health  # Should return 401
curl -k https://auth.yourdomain.com/.well-known/oauth-authorization-server  # Should return metadata
```

### Per-Proxy Route Control Use Cases

#### API Version Isolation
```bash
# Create separate proxies for API versions
just proxy-create api-v1.example.com http://api-v1:3000 admin
just proxy-create api-v2.example.com http://api-v2:3000 admin

# Enable only v1 routes for v1 proxy
just proxy-routes-mode api-v1.example.com admin selective
just proxy-route-enable api-v1.example.com api-v1-routes admin

# Enable only v2 routes for v2 proxy
just proxy-routes-mode api-v2.example.com admin selective
just proxy-route-enable api-v2.example.com api-v2-routes admin
```

#### Public vs Internal Services
```bash
# Public service - disable admin routes
just proxy-create public.example.com http://app:3000 admin
just proxy-route-disable public.example.com admin-panel admin
just proxy-route-disable public.example.com debug-endpoints admin

# Internal service - all routes enabled (default)
just proxy-create internal.example.com http://app:3000 admin
```

#### Minimal Routing (Hostname Only)
```bash
# Create proxy with no path-based routing
just proxy-create static.example.com http://cdn:80 admin
just proxy-routes-mode static.example.com admin none
# Now only hostname-based routing applies
```

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

# CRITICAL: Setup OAuth routes for proper endpoint routing
just oauth-routes-setup example.com
```

### OAuth Route Configuration

**CRITICAL**: OAuth endpoints MUST be configured as routes in the routing system!

The `oauth-routes-setup` command creates the following routes:
- `/authorize` → OAuth authorization endpoint (priority: 95)
- `/token` → OAuth token endpoint (priority: 95)
- `/callback` → OAuth callback endpoint (priority: 95)
- `/register` → Dynamic client registration (priority: 95)
- `/verify` → ForwardAuth verification endpoint (priority: 95)
- `/.well-known/oauth-authorization-server` → OAuth metadata (priority: 95)
- `/jwks` → JSON Web Key Set (priority: 95)
- `/revoke` → Token revocation (priority: 95)
- `/introspect` → Token introspection (priority: 95)

All routes use `hostname:auth.{domain}` target type to route to the OAuth server.

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

### SSL Certificate Verification Errors
**Issue**: "SSL certificate problem: unable to get local issuer certificate"
**Root Cause**: Proxy handler trying to verify internal service certificates
**Solution**: Added `verify=False` to httpx.AsyncClient in proxy_handler_v2.py for internal connections

### Missing Hostname Parameter Error
**Issue**: `TypeError: RedisStorage.store_proxy_target() missing 1 required positional argument: 'target'`
**Root Cause**: Missing hostname parameter in store_proxy_target() calls
**Solution**: Fixed all calls to include hostname: `store_proxy_target(hostname, target)`

### OAuth Routes Not Working
**Issue**: OAuth endpoints return 404 or don't route properly
**Root Cause**: OAuth endpoints need to be configured as routes in the routing system
**Solution**: Run `just oauth-routes-setup` after setting up the auth proxy

# MCP Authorization Compliance

**STATUS**: The OAuth implementation is now FULLY COMPLIANT with the [Model Context Protocol authorization specification](https://modelcontextprotocol.io/specification/2025-06-18/basic/authorization).

## MCP Requirements Implementation Status

### 1. Resource Parameter (RFC 8707)

**Specification Requirement**: 
- MUST include `resource` parameter in authorization and token requests
- Identifies target MCP server using canonical URI format
- Enables audience-restricted tokens for specific resource servers

**Current Status**: ✅ IMPLEMENTED

**Required Changes**:
```python
# Authorization endpoint must accept:
resource = request.query_params.get("resource")  # e.g., "https://mcp.example.com"

# Token endpoint must validate:
if resource not in token_request.get("resource", []):
    raise InvalidResourceError()

# JWT must include audience restriction:
{
  "aud": ["https://mcp.example.com"],
  "azp": "client_id",  # Authorized party
  ...
}
```

### 2. Protected Resource Metadata (RFC 9728)

**Specification Requirement**:
- MUST implement `/.well-known/oauth-protected-resource` endpoint on MCP servers
- WWW-Authenticate header must include metadata URL

**Current Status**: ✅ IMPLEMENTED

**Required Endpoint**:
```json
GET /.well-known/oauth-protected-resource
{
  "resource": "https://mcp.example.com",
  "authorization_servers": ["https://auth.example.com"],
  "jwks_uri": "https://auth.example.com/jwks",
  "scopes_supported": ["mcp:read", "mcp:write"],
  "bearer_methods_supported": ["header"],
  "resource_documentation": "https://docs.example.com/mcp"
}
```

**Required WWW-Authenticate Header**:
```
WWW-Authenticate: Bearer realm="MCP Server",
  as_uri="https://auth.example.com/.well-known/oauth-authorization-server",
  resource_uri="https://mcp.example.com/.well-known/oauth-protected-resource"
```

### 3. MCP Protocol Endpoints

**Specification Requirement**:
- MCP servers must implement `/mcp` or `/mcp/sessions` endpoints
- Must validate token audience matches server resource identifier

**Current Status**: ❌ NOT IMPLEMENTED IN OAUTH SERVER

**Note**: MCP endpoints exist in separate services (mcp-echo-*, mcp-fetch) but OAuth server lacks MCP awareness

### 4. Audience Validation

**Specification Requirement**:
- Tokens MUST be audience-restricted
- Resource servers MUST validate token audience

**Current Status**: ⚠️ PARTIALLY IMPLEMENTED
- JWTs include `aud` claim but set to issuer URL
- No validation based on requested resource
- No multi-audience support

## Implementation Status

### Required by MCP Specification (ALL COMPLETED)

#### OAuth Server Requirements (RFC 8707)
✅ **Authorization Endpoint** accepts `resource` parameter
✅ **Token Endpoint** validates resources were authorized
✅ **JWT Generation** includes resources in `aud` claim
✅ **Server Metadata** indicates `resource_indicators_supported: true`

#### MCP Server Requirements (RFC 9728)
✅ **Protected Resource Metadata** endpoint at `/.well-known/oauth-protected-resource`
✅ **WWW-Authenticate Headers** include metadata URLs
✅ **Resource Identification** in metadata responses

### Optional Management Features (NOT Required by MCP)

The following features were added for administrative convenience but are **NOT required** by the MCP specification:

#### Resource Registry API
- `GET /resources` - List registered MCP resources
- `POST /resources` - Register new MCP resource
- `GET /resources/{uri}` - Get resource details
- `PUT /resources/{uri}` - Update resource
- `DELETE /resources/{uri}` - Remove resource
- `POST /resources/{uri}/validate-token` - Validate token for resource
- `POST /resources/auto-register` - Auto-discover proxy resources

These endpoints provide a convenient way to manage MCP resources but are completely optional. The MCP specification only requires proper handling of the `resource` parameter in OAuth flows and the protected resource metadata endpoint on MCP servers.

## Original Implementation Plan (For Reference)

### Phase 1: Resource Parameter Support (RFC 8707)

**Priority**: CRITICAL

**Tasks**:
1. **Update OAuth Authorization Endpoint**
   - Add `resource` parameter to `/authorize` endpoint
   - Validate resource parameter format (must be valid URI)
   - Store resource(s) with authorization code
   - Support multiple resource parameters

2. **Update Token Endpoint**
   - Accept `resource` parameter in token requests
   - Validate requested resources were authorized
   - Include resources in JWT `aud` claim
   - Return `invalid_target` error for unauthorized resources

3. **Update JWT Token Generation**
   - Set `aud` claim to array of authorized resources
   - Include `azp` (authorized party) claim
   - Add resource-specific scopes if applicable

**Implementation Location**: `mcp-oauth-dynamicclient/src/mcp_oauth_dynamicclient/routes.py`

### Phase 2: Protected Resource Metadata

**Priority**: HIGH

**Tasks**:
1. **Add Protected Resource Metadata Endpoint**
   - Implement `/.well-known/oauth-protected-resource` in each MCP server
   - Return metadata about resource requirements
   - Include supported scopes and authentication methods

2. **Update WWW-Authenticate Headers**
   - Modify `async_resource_protector.py` to include metadata URLs
   - Add `as_uri` parameter pointing to auth server metadata
   - Add `resource_uri` parameter for resource metadata

3. **Create MCP Resource Registry**
   - Redis-based registry of MCP resources
   - Map resource URIs to proxy targets
   - Enable resource discovery

**Implementation Locations**: 
- `mcp-oauth-dynamicclient/src/mcp_oauth_dynamicclient/resource_protector.py`
- Each MCP service (mcp-echo-*, mcp-fetch)

### Phase 3: Resource-Aware Token Validation

**Priority**: HIGH

**Tasks**:
1. **Update Token Validation**
   - Check token audience matches requested resource
   - Support multiple audiences for token portability
   - Implement audience intersection logic

2. **Add Resource-Specific Scopes**
   - Define MCP-specific scopes (mcp:read, mcp:write, mcp:session)
   - Map resources to required scopes
   - Validate scope sufficiency per resource

3. **Update ForwardAuth Integration**
   - Pass resource identifier in auth check
   - Validate token is valid for specific resource
   - Return resource-specific error messages

**Implementation Location**: `mcp-oauth-dynamicclient/src/mcp_oauth_dynamicclient/async_resource_protector.py`

### Phase 4: MCP Protocol Integration

**Priority**: MEDIUM

**Tasks**:
1. **Add MCP Awareness to OAuth Server**
   - Understand MCP session management
   - Support MCP-specific token claims
   - Enable MCP service registration

2. **Create MCP Service Base Class**
   - Automatic protected resource metadata
   - Built-in audience validation
   - MCP protocol compliance helpers

3. **Update Existing MCP Services**
   - Add resource identifiers
   - Implement audience validation
   - Add protected resource metadata endpoint

**Implementation Locations**: 
- New file: `mcp_base_service.py`
- Update all MCP services

### Phase 5: Authorization Server Metadata Updates

**Priority**: LOW

**Tasks**:
1. **Update Authorization Server Metadata**
   - Add `resource_indicators_supported: true`
   - Add `resource_parameter_supported: true`
   - Document supported resource types

2. **Add Resource Documentation**
   - Document resource URI format
   - Provide examples of resource parameters
   - Create resource registration guide

**Implementation Location**: `mcp-oauth-dynamicclient/src/mcp_oauth_dynamicclient/routes.py` (metadata endpoint)

## Testing Requirements

### Unit Tests
- Resource parameter validation
- Audience restriction enforcement
- Multi-resource authorization flows
- Invalid resource rejection

### Integration Tests
- End-to-end flow with resource parameters
- Cross-resource token rejection
- Resource metadata discovery
- MCP protocol compliance

### Compliance Tests
- Full MCP specification compliance
- RFC 8707 compliance
- RFC 9728 compliance
- Security boundary validation

## Configuration Updates

### New Environment Variables
```bash
# Resource Indicators
MCP_RESOURCE_INDICATORS_ENABLED=true
MCP_MAX_RESOURCES_PER_TOKEN=5
MCP_RESOURCE_VALIDATION_STRICT=true

# MCP Protocol
MCP_PROTOCOL_VERSION=1.0
MCP_SESSION_TIMEOUT=3600
MCP_MAX_SESSIONS_PER_CLIENT=10
```

### Redis Schema Updates
```
# Resource Registry
resource:{resource_uri} = {
  "uri": "https://mcp.example.com",
  "name": "Example MCP Server",
  "proxy_target": "mcp.example.com",
  "scopes": ["mcp:read", "mcp:write"],
  "metadata_url": "https://mcp.example.com/.well-known/oauth-protected-resource"
}

# Authorization with Resources
auth_code:{code} = {
  ...existing fields...,
  "resources": ["https://mcp1.example.com", "https://mcp2.example.com"]
}
```

## Migration Strategy

1. **Backwards Compatibility**
   - Resource parameter optional initially
   - Fallback to current behavior without resource
   - Gradual enforcement via configuration

2. **Phased Rollout**
   - Phase 1: Add support, keep optional
   - Phase 2: Log warnings for missing resources
   - Phase 3: Require resources for new clients
   - Phase 4: Full enforcement

3. **Client Migration**
   - Provide migration guide
   - Update client libraries
   - Support period for legacy clients

## Security Considerations

1. **Resource Validation**
   - Prevent resource injection attacks
   - Validate resource ownership
   - Enforce resource boundaries

2. **Audience Confusion**
   - Clear audience validation rules
   - Prevent token misuse across resources
   - Audit token usage patterns

3. **Scope Isolation**
   - Resource-specific scope namespaces
   - Prevent scope elevation
   - Clear scope inheritance rules

## Architectural Decision: OAuth Service Separation

### Should OAuth be moved into FastAPI? ❌ NO

After careful analysis, the OAuth service should remain separate from the FastAPI service for the following reasons:

#### 1. **MCP Specification Compliance**
The MCP specification explicitly expects:
- Separate authorization servers from resource servers
- OAuth 2.1 authorization server as an independent entity
- Clear separation between authentication and resources

**Verdict**: Keeping OAuth separate aligns with MCP architecture principles.

#### 2. **Current Architecture Strengths**
- **Elegant Design**: OAuth is just another proxied service, proving the proxy system's versatility
- **No Special Cases**: OAuth doesn't require special handling in the dispatcher
- **Consistent Pattern**: All services (including auth) follow the same proxy pattern
- **Demonstration Value**: Shows that even complex services like OAuth work through the proxy

#### 3. **Separation of Concerns**
- **Single Responsibility**: OAuth server handles only authentication
- **FastAPI Focus**: Certificate management and proxy orchestration
- **Clear Boundaries**: Each service has distinct responsibilities
- **Independent Development**: Teams can work on OAuth without touching core proxy logic

#### 4. **Operational Benefits**
- **Independent Scaling**: OAuth can scale separately based on auth load
- **Isolated Updates**: Update OAuth without touching proxy infrastructure
- **Separate Testing**: OAuth can be tested in complete isolation
- **Flexible Deployment**: OAuth server can be deployed anywhere

#### 5. **Technical Advantages**
- **Authlib Integration**: Current OAuth server uses battle-tested Authlib
- **Clean Interfaces**: Clear HTTP APIs between services
- **Microservices Pattern**: Follows established distributed system patterns
- **Replaceability**: OAuth implementation can be swapped without proxy changes

#### 6. **Consolidation Drawbacks**
Moving OAuth into FastAPI would:
- Violate single responsibility principle
- Create a monolithic service with mixed concerns
- Make FastAPI unnecessarily complex
- Require rewriting proven OAuth implementation
- Break the elegant "OAuth as a service" pattern
- Make testing more difficult
- Reduce deployment flexibility

### Recommended Approach for MCP Compliance

Instead of consolidation, enhance the **integration** between services:

1. **Shared Resource Registry**
   - Store MCP resource metadata in Redis
   - Both OAuth and proxy services access same registry
   - Maintain service separation with shared data

2. **Enhanced Communication**
   - Add internal APIs for resource validation
   - OAuth server queries proxy for resource details
   - Proxy validates tokens with resource context

3. **Unified Configuration**
   - Shared environment variables for MCP settings
   - Consistent resource URI formats
   - Coordinated feature flags

4. **Integration Layer**
   - Add MCP compliance module used by both services
   - Shared libraries for resource validation
   - Common token validation logic

### Architecture Diagram
```
┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐
│   MCP Client    │────▶│  Proxy (FastAPI)│────▶│   MCP Server    │
└─────────────────┘     └─────────────────┘     └─────────────────┘
         │                       │                         │
         │                       ▼                         │
         │              ┌─────────────────┐               │
         └─────────────▶│  OAuth Server   │◀──────────────┘
                        └─────────────────┘
                                 │
                                 ▼
                        ┌─────────────────┐
                        │     Redis       │
                        │ (Shared State)  │
                        └─────────────────┘
```

### Conclusion

The current architecture with OAuth as a separate proxied service is **correct** and should be maintained. MCP compliance should be achieved through enhanced integration, not consolidation.

## Summary: MCP Specification Compliance

### What the MCP Specification Actually Requires

After careful review of the MCP specification and relevant RFCs:

**Required by MCP (ALL IMPLEMENTED ✅)**:
1. OAuth servers must accept and validate `resource` parameter (RFC 8707)
2. JWT tokens must include resources in `aud` claim
3. MCP servers must implement `/.well-known/oauth-protected-resource` endpoint (RFC 9728)
4. WWW-Authenticate headers must include metadata URLs

**NOT Required by MCP (Optional Management Features)**:
- `/resources` API endpoints for resource management
- `MCPResourceRegistry` class for tracking resources
- Resource registration/validation endpoints

The resource registry features are administrative conveniences, not MCP requirements. They are clearly marked as optional in the code documentation.

## Complete Command Reference

### System Commands
```bash
just up                  # Start all services
just down                # Stop all services
just rebuild <service>   # Rebuild specific service
just logs                # View service logs
just shell               # Shell into certmanager container
just redis-cli           # Access Redis CLI
```

### Token Management
```bash
just token-generate <name> [cert-email]     # Create token with optional cert email
just token-show <name>                      # Retrieve full token
just token-list                             # List all tokens
just token-delete <name>                    # Delete token + certs
just token-show-certs [name]                # Show certs by token
```

### Certificate Management
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
```

### Proxy Management
```bash
# Basic proxy operations
just proxy-create <hostname> <target-url> <token> [staging] [preserve-host] [enable-http] [enable-https]
just proxy-create-group <group-name> <hostnames> <target-url> <token> [staging] [preserve-host]
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
```

### OAuth Management
```bash
# OAuth setup
just generate-oauth-key                          # Generate RSA key for JWT signing
just auth-setup <domain>                         # Setup OAuth service and create auth proxy
just oauth-routes-setup <domain> [token]         # Setup OAuth endpoint routes (CRITICAL!)

# OAuth proxy authentication
just proxy-auth-enable <hostname> <token> <auth-proxy> <mode>  # Enable auth (forward/redirect/passthrough)
just proxy-auth-disable <hostname> <token>                      # Disable auth
just proxy-auth-config <hostname> <token> users="" emails="" groups=""  # Configure auth requirements
just proxy-auth-show <hostname>                                 # Show auth configuration
just test-auth-flow <hostname>                                  # Test OAuth flow for a proxy
```

### Route Management
```bash
just route-list                                                        # Show all routes
just route-show <route-id>                                            # Show route details
just route-create <path> <target-type> <target-value> <token> [priority] [methods] [is-regex] [description]
just route-update <route-id> <token> [options]
just route-delete <route-id> <token>
just route-enable <route-id> <token>
just route-disable <route-id> <token>
```

### Per-Proxy Route Control
```bash
just proxy-routes-show <hostname>                                     # View proxy route configuration
just proxy-routes-mode <hostname> <token> <all|selective|none>       # Set route mode
just proxy-route-enable <hostname> <route-id> <token>                # Enable specific route
just proxy-route-disable <hostname> <route-id> <token>               # Disable specific route
just proxy-routes-set <hostname> <token> <enabled-routes> <disabled-routes>  # Set multiple routes
```

### Testing Commands
```bash
# Certificate tests
just test-certs                  # Test certificate operations
just test-multi-domain           # Test multi-domain certificates
just test-cert-email            # Test certificate email configuration

# Proxy tests
just test-proxy-basic           # Test basic functionality
just test-proxy-example         # Test with example.com
just test-websocket-proxy       # Test WebSocket proxying
just test-streaming-proxy       # Test streaming/SSE
just test-proxy-all            # Run all proxy tests
just test-proxy-routes         # Test per-proxy routes

# Auth tests
just test-auth [token]          # Test authorization system
just test-auth-flow <hostname>  # Test auth flow for a proxy

# All tests
just test                       # Run standard test suite
just test-all                   # Run comprehensive test suite
```

### Service-Specific Commands
```bash
# Fetcher service
just fetcher-setup <hostname> [staging]
just fetcher-status
just fetcher-logs

# Echo services
just echo-stateful-setup <hostname> [staging]
just echo-stateless-setup <hostname> [staging]
```

### MCP Compliance Commands (Future)
```bash
# Resource Management
just resource-register <resource-uri> <proxy-hostname> <name> [scopes]  # Register MCP resource
just resource-list                                                      # List all MCP resources
just resource-show <resource-uri>                                      # Show resource details
just resource-delete <resource-uri>                                    # Delete resource registration
just resource-validate <resource-uri> <token>                          # Validate token for resource

# MCP Protocol Testing
just test-mcp-compliance                      # Run MCP specification compliance tests
just test-resource-indicators                 # Test RFC 8707 implementation
just test-protected-resource                  # Test protected resource metadata
just test-audience-validation                 # Test audience restriction

# MCP Configuration
just mcp-enable-resource-indicators          # Enable resource parameter support
just mcp-status                              # Show MCP compliance status
just mcp-metadata <hostname>                 # Show MCP server metadata
```

# OAuth Status API

The FastAPI service provides comprehensive OAuth client and token status information through dedicated API endpoints. This enables monitoring, debugging, and management of OAuth authentication state across the proxy system.

## Architecture

### Data Access Pattern
- **Direct Redis Access**: FastAPI reads OAuth data directly from shared Redis
- **Read-Only Operations**: No modifications to OAuth state via status API
- **Real-Time Data**: Live view of OAuth server's Redis-stored state
- **Security Filtering**: Sensitive data (tokens, secrets) never exposed

### Redis OAuth Data Schema
```
# OAuth Clients
client:{client_id} = {
  "client_id": "mcp_1234567890",
  "client_name": "MCP Test Client",
  "created_at": 1234567890,
  "expires_at": 1234567890,
  "client_secret_hash": "...",  // Never exposed
  "registration_access_token_hash": "...",  // Never exposed
  "metadata": {...}
}

# OAuth Tokens  
token:{jti} = {
  "jti": "unique-token-id",
  "user_id": "github-user-id",
  "client_id": "mcp_1234567890",
  "issued_at": 1234567890,
  "expires_at": 1234567890,
  "scope": "read write",
  "token_type": "access_token"
}

# User Sessions
session:{session_id} = {
  "user_id": "github-user-id",
  "username": "alice",
  "email": "alice@example.com",
  "created_at": 1234567890,
  "last_activity": 1234567890,
  "active_tokens": ["jti1", "jti2"]
}
```

## OAuth Status Endpoints

### Client Management Endpoints

#### `GET /oauth/clients`
List all registered OAuth clients with filtering and pagination.

Query Parameters:
- `active_only`: Show only non-expired clients (default: true)
- `page`: Page number (default: 1)
- `per_page`: Items per page (default: 20, max: 100)
- `sort_by`: Sort field (created_at, expires_at, name)
- `order`: Sort order (asc, desc)

Response:
```json
{
  "clients": [
    {
      "client_id": "mcp_1234567890",
      "client_name": "MCP Test Client",
      "created_at": "2024-01-15T10:00:00Z",
      "expires_at": "2024-04-15T10:00:00Z",
      "is_active": true,
      "days_until_expiry": 45,
      "token_count": 5,
      "last_token_issued": "2024-01-20T15:30:00Z"
    }
  ],
  "pagination": {
    "total": 25,
    "page": 1,
    "per_page": 20,
    "pages": 2
  },
  "summary": {
    "total_clients": 25,
    "active_clients": 20,
    "expired_clients": 5
  }
}
```

#### `GET /oauth/clients/{client_id}`
Get detailed information about a specific OAuth client.

Response:
```json
{
  "client_id": "mcp_1234567890",
  "client_name": "MCP Test Client",
  "created_at": "2024-01-15T10:00:00Z",
  "expires_at": "2024-04-15T10:00:00Z",
  "is_active": true,
  "metadata": {
    "software_id": "mcp-test-client",
    "software_version": "1.0.0",
    "redirect_uris": ["https://client.example.com/callback"]
  },
  "usage_stats": {
    "total_tokens_issued": 150,
    "active_tokens": 5,
    "total_authorizations": 200,
    "failed_authorizations": 10,
    "last_authorization": "2024-01-20T15:30:00Z"
  },
  "proxy_associations": [
    {
      "hostname": "api.example.com",
      "auth_enabled": true,
      "auth_mode": "forward",
      "active_sessions": 3
    }
  ]
}
```

#### `GET /oauth/clients/{client_id}/tokens`
List tokens issued to a specific client.

Response:
```json
{
  "tokens": [
    {
      "jti": "token-id-hash",  // Hashed for security
      "token_type": "access_token",
      "user_id": "github-123",
      "username": "alice",
      "issued_at": "2024-01-20T15:00:00Z",
      "expires_at": "2024-01-20T15:30:00Z",
      "is_expired": false,
      "scope": "read write",
      "used_by_proxies": ["api.example.com", "admin.example.com"]
    }
  ],
  "summary": {
    "total_tokens": 5,
    "active_tokens": 3,
    "expired_tokens": 2
  }
}
```

### Token Status Endpoints

#### `GET /oauth/tokens`
Get OAuth token statistics and overview.

Query Parameters:
- `token_type`: Filter by type (access_token, refresh_token)
- `include_expired`: Include expired tokens (default: false)
- `user_id`: Filter by user ID
- `client_id`: Filter by client ID

Response:
```json
{
  "summary": {
    "total_access_tokens": 150,
    "active_access_tokens": 45,
    "total_refresh_tokens": 120,
    "active_refresh_tokens": 100,
    "tokens_expiring_soon": 5,  // Within 5 minutes
    "average_token_lifetime": 1800
  },
  "by_client": [
    {
      "client_id": "mcp_1234567890",
      "client_name": "MCP Test Client",
      "active_tokens": 15,
      "percentage": 33.3
    }
  ],
  "by_user": [
    {
      "user_id": "github-123",
      "username": "alice",
      "active_tokens": 5,
      "last_activity": "2024-01-20T15:45:00Z"
    }
  ],
  "recent_activity": [
    {
      "timestamp": "2024-01-20T15:45:00Z",
      "event": "token_issued",
      "client_id": "mcp_1234567890",
      "user_id": "github-123"
    }
  ]
}
```

#### `GET /oauth/tokens/{jti}`
Get specific token information (requires admin token or token ownership).

Response:
```json
{
  "jti": "token-id-hash",
  "token_type": "access_token",
  "client_id": "mcp_1234567890",
  "client_name": "MCP Test Client",
  "user": {
    "user_id": "github-123",
    "username": "alice",
    "email": "alice@example.com"
  },
  "issued_at": "2024-01-20T15:00:00Z",
  "expires_at": "2024-01-20T15:30:00Z",
  "is_expired": false,
  "time_until_expiry": 300,
  "scope": "read write",
  "claims": {
    "sub": "github-123",
    "aud": ["https://auth.example.com"],
    "azp": "mcp_1234567890"
  },
  "usage": {
    "last_used": "2024-01-20T15:25:00Z",
    "use_count": 45,
    "used_by_proxies": ["api.example.com"],
    "user_agent": "MCP-Client/1.0"
  }
}
```

### Session Management Endpoints

#### `GET /oauth/sessions`
List active user sessions.

Response:
```json
{
  "sessions": [
    {
      "session_id": "sess_abc123",
      "user_id": "github-123",
      "username": "alice",
      "email": "alice@example.com",
      "created_at": "2024-01-20T14:00:00Z",
      "last_activity": "2024-01-20T15:45:00Z",
      "duration_minutes": 105,
      "active_tokens": 2,
      "accessed_proxies": ["api.example.com", "admin.example.com"]
    }
  ],
  "summary": {
    "total_sessions": 25,
    "unique_users": 20,
    "average_session_duration": 45
  }
}
```

#### `GET /oauth/sessions/{session_id}`
Get detailed session information.

#### `DELETE /oauth/sessions/{session_id}`
Revoke a session and all associated tokens (requires admin or session owner).

### Monitoring Endpoints

#### `GET /oauth/metrics`
Get OAuth system metrics for monitoring.

Response:
```json
{
  "timestamp": "2024-01-20T16:00:00Z",
  "clients": {
    "total": 25,
    "active": 20,
    "expiring_soon": 2
  },
  "tokens": {
    "access_tokens": {
      "total": 150,
      "active": 45,
      "issued_last_hour": 20,
      "expired_last_hour": 15
    },
    "refresh_tokens": {
      "total": 120,
      "active": 100,
      "used_last_hour": 10
    }
  },
  "auth_flows": {
    "authorization_requests": {
      "last_hour": 50,
      "success_rate": 0.92
    },
    "token_requests": {
      "last_hour": 45,
      "success_rate": 0.95
    }
  },
  "errors": {
    "invalid_client": 2,
    "invalid_grant": 3,
    "unauthorized_client": 1
  }
}
```

#### `GET /oauth/health`
Check OAuth integration health.

Response:
```json
{
  "status": "healthy",
  "checks": {
    "redis_connection": "ok",
    "oauth_server_reachable": "ok",
    "token_validation": "ok",
    "jwks_endpoint": "ok"
  },
  "last_successful_auth": "2024-01-20T15:55:00Z",
  "auth_proxy": {
    "hostname": "auth.example.com",
    "status": "active",
    "certificate_valid": true
  }
}
```

### Proxy Integration Endpoints

#### `GET /oauth/proxies`
Show OAuth status for all proxies.

Response:
```json
{
  "proxies": [
    {
      "hostname": "api.example.com",
      "auth_enabled": true,
      "auth_mode": "forward",
      "auth_proxy": "auth.example.com",
      "active_sessions": 5,
      "recent_auth_failures": 2,
      "last_auth_success": "2024-01-20T15:50:00Z"
    }
  ],
  "summary": {
    "total_proxies": 10,
    "auth_enabled_proxies": 6,
    "proxies_with_active_sessions": 4
  }
}
```

#### `GET /oauth/proxies/{hostname}/sessions`
List active sessions for a specific proxy.

## Implementation Details

### Redis Access Pattern
```python
# FastAPI service reads OAuth data directly
async def get_oauth_clients():
    # Scan for client:* keys
    clients = []
    async for key in redis.scan_iter("client:*"):
        client_data = await redis.get(key)
        # Filter sensitive fields
        safe_data = filter_sensitive(client_data)
        clients.append(safe_data)
    return clients
```

### Security Filtering
```python
SENSITIVE_FIELDS = {
    "client_secret", "client_secret_hash",
    "registration_access_token", "token_value",
    "refresh_token", "access_token"
}

def filter_sensitive(data):
    return {k: v for k, v in data.items() 
            if k not in SENSITIVE_FIELDS}
```

### Caching Strategy
- Cache client lists for 60 seconds
- Cache token statistics for 30 seconds
- Real-time data for specific lookups
- Use Redis pub/sub for cache invalidation

## Usage Examples

### Dashboard Integration
```javascript
// Fetch OAuth overview for dashboard
const response = await fetch('/oauth/metrics');
const metrics = await response.json();

// Display client status
const clients = await fetch('/oauth/clients?active_only=true');
const clientList = await clients.json();
```

### Monitoring Integration
```bash
# Prometheus metrics endpoint
curl https://api.example.com/oauth/metrics

# Health check for monitoring
curl https://api.example.com/oauth/health
```

### Admin Operations
```bash
# List all active sessions
just oauth-sessions-list

# Show client details
just oauth-client-show mcp_1234567890

# Revoke specific session
just oauth-session-revoke sess_abc123

# Show token statistics
just oauth-token-stats
```

## OAuth Status Commands
```bash
# OAuth Client Management
just oauth-clients-list [active-only]           # List OAuth clients
just oauth-client-show <client-id>              # Show client details
just oauth-client-tokens <client-id>            # List client's tokens
just oauth-client-stats <client-id>             # Show client statistics

# OAuth Token Management  
just oauth-tokens-stats                         # Token statistics
just oauth-token-show <jti>                     # Show token details
just oauth-tokens-cleanup                       # Remove expired tokens

# OAuth Session Management
just oauth-sessions-list                        # List active sessions
just oauth-session-show <session-id>            # Show session details
just oauth-session-revoke <session-id>          # Revoke session

# OAuth Monitoring
just oauth-metrics                              # Show OAuth metrics
just oauth-health                               # Check OAuth health
just oauth-proxy-status [hostname]              # OAuth status by proxy

# OAuth Testing
just test-oauth-status-api                      # Test status endpoints
```
