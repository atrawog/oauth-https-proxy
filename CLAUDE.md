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

Pure Python HTTPS server that automatically obtains and renews TLS certificates via ACME protocol. Stores all data in Redis, supports multiple domains per certificate, and hot-reloads certificates without downtime.

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
- HTTP-01 challenge validation
- Account key management
- Certificate lifecycle operations
- Redis-exclusive storage
- Async certificate generation (non-blocking)

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
  "domains": ["example.com", "www.example.com"],
  "email": "admin@example.com",
  "acme_directory_url": "https://acme-v02.api.letsencrypt.org/directory",
  "status": "active",
  "expires_at": "2024-03-15T00:00:00Z",
  "issued_at": "2024-01-15T00:00:00Z",
  "fingerprint": "sha256:...",
  "fullchain_pem": "-----BEGIN CERTIFICATE-----...",
  "private_key_pem": "-----BEGIN PRIVATE KEY-----..."
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

## Proxy Manager

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
# Proxy target management - NOW WITH PROTOCOL CONTROL!
just proxy-create <hostname> <target-url> <token> [staging] [preserve-host] [enable-http] [enable-https]
just proxy-update <hostname> <token> --enable-http=false  # DISABLE HTTP!
just proxy-update <hostname> <token> --enable-https=false # DISABLE HTTPS!
just proxy-cleanup [hostname]     # Clean up proxy targets
just test-proxy-basic            # Test basic functionality
just test-proxy-example          # Test with example.com
just test-websocket-proxy        # Test WebSocket proxying
just test-streaming-proxy        # Test streaming/SSE
just test-proxy-all             # Run all proxy tests
```

## Recent Updates

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
# Public access (no token required)
just cert-list [token-name]          # List certificates
just cert-show <name> [token] [pem]  # Show certificate details
just cert-status <name> [token] [wait] # Check generation status

# Authenticated access (token required)
just cert-create <name> <domain> <email> <token-name> [staging] # Create cert
just cert-delete <name> <token> [force]  # Delete certificate
just cert-renew <name> <token> [force]   # Renew certificate
```

### Key Changes
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
