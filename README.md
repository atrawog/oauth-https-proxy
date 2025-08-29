# OAuth HTTPS Proxy

A production-ready HTTP/HTTPS proxy with integrated OAuth 2.1 server, automatic ACME certificate management, and unified event-driven architecture. This proxy provides secure, authenticated access to backend services with automatic SSL/TLS certificate provisioning and zero-restart dynamic configuration.

## Production Configuration Example

The system is currently running with the following configuration:

### Auto-Generated Components (Created on Startup)

1. **localhost proxy**
   - Target: http://api:9000 (internal API)
   - Authentication: Disabled by default
   - Purpose: Internal API access and web UI
   - Auto-created from DEFAULT_PROXIES in src/proxy/models.py

2. **Default Routes** (ACME and OAuth endpoints)
   - `/.well-known/acme-challenge/` → API service (ACME certificate validation)
   - `/.well-known/oauth-protected-resource` → API service (MCP OAuth metadata)
   - `/.well-known/oauth-authorization-server` → API service (OAuth server metadata)
   - Auto-created from DEFAULT_ROUTES in src/proxy/routes.py

### Manually Configured Proxies (Example Production Setup)

1. **auth.example.com** (OAuth Server)
   ```bash
   # Create OAuth server proxy
   just proxy create auth.example.com http://127.0.0.1:9000
   just cert create proxy-auth-example-com auth.example.com
   ```
   - Purpose: OAuth authentication server
   - Endpoints: /authorize, /token, /callback, /device/*, /mcp

2. **claude.example.com** (Application Proxy)
   ```bash
   # Create application proxy with OAuth protection
   just proxy create claude.example.com http://127.0.0.1:9000
   just cert create proxy-claude-example-com claude.example.com
   just proxy auth enable claude.example.com
   
   # Configure GitHub user access (optional)
   just proxy auth config claude.example.com --users alice,bob
   ```
   - Purpose: OAuth-protected application endpoint
   - Authentication: OAuth required

## Features

### Core Proxy Capabilities
- **Zero-Restart Architecture**: Dynamic proxy creation/deletion without service restarts
- **Unified Event System**: Simple 3-event architecture (proxy_created, proxy_deleted, certificate_ready)
- **Dynamic Reverse Proxy**: Route traffic to multiple backend services
- **Automatic HTTPS**: Obtain and renew Let's Encrypt certificates via ACME
- **OAuth 2.1 Integration**: Built-in OAuth server with GitHub authentication
- **Per-Proxy GitHub OAuth Apps**: Each proxy can have its own GitHub OAuth credentials with environment fallback
- **WebSocket Support**: Proxy WebSocket and Server-Sent Events (SSE) connections
- **Route Management**: Priority-based path routing with regex support
- **External Service Management**: Named service registration for external URLs
- **Docker Service Management**: Create and manage Docker containers dynamically
- **Redis-Based Port Management**: Persistent port allocation with atomic operations
- **Deterministic Port Assignment**: Hash-based preferred ports for consistency
- **Multi-Port Services**: Services can expose multiple ports with access controls
- **Non-Blocking Operations**: All operations use async/await for maximum performance

### Security Features
- **OAuth-Only Authentication**: Pure OAuth 2.1 with GitHub integration, no bearer tokens (`acm_*`)
- **Single Auth Layer**: Proxy validates OAuth, API trusts headers - 90% code reduction
- **GitHub Device Flow**: CLI-friendly authentication without localhost callbacks
- **Three Simple Scopes**: `admin` (write), `user` (read), `mcp` (Model Context Protocol)
- **Per-Proxy User Allowlists**: Each proxy can specify its own GitHub user allowlist via `auth_required_users`
- **Per-Proxy Scope Assignment**: Configure which GitHub users get which scopes via `oauth_admin_users`, `oauth_user_users`, `oauth_mcp_users`
- **Per-Proxy GitHub OAuth Apps**: Each proxy can have its own GitHub OAuth credentials
- **Trust-Based API**: API reads `X-Auth-User`, `X-Auth-Scopes` headers from proxy
- **Certificate Isolation**: Multi-domain certificates with automatic management
- **Redis-Only Storage**: No filesystem persistence for enhanced security
- **Client IP Preservation**: HAProxy PROXY protocol v1 support for real client IPs
- **Advanced Logging**: High-performance request logging with multiple indexes

### Developer Experience
- **Web UI**: Built-in management interface at http://localhost
- **Comprehensive API**: RESTful API for all operations at root level
- **API Documentation**: Interactive Swagger UI at https://example.com/docs
- **Health Monitoring**: Service health checks and metrics
- **Hot Reload**: Update certificates and routes without downtime

## OAuth-Only Architecture

This system uses **pure OAuth 2.1** authentication - completely removing the bearer token system:

### How Authentication Works

1. **Single Authentication Layer**
   - Proxy validates OAuth JWT tokens
   - API trusts headers from proxy (`X-Auth-User`, `X-Auth-Scopes`, `X-Auth-Email`)
   - No dual validation, no token lookups, no ownership checks
   - 90% reduction in authentication code (~80KB removed)

2. **GitHub Device Flow Authentication**
   - Use `just oauth login` to authenticate via GitHub
   - No localhost callbacks needed - perfect for CLI/server use
   - JWT tokens with 30-minute lifetime, refresh tokens for persistence

3. **Three Simple Scopes**
   - **admin**: Write access (all POST, PUT, DELETE, PATCH operations)
   - **user**: Read access (all GET, HEAD, OPTIONS operations)
   - **mcp**: Model Context Protocol access (/mcp endpoints)
   - Scopes enforced at proxy level, API trusts completely

4. **Per-Proxy Configuration**
   - Each proxy can have custom GitHub user allowlists (`auth_required_users`)
   - Each proxy can configure scope assignments per user (`oauth_admin_users`, `oauth_user_users`, `oauth_mcp_users`)
   - Each proxy can use different GitHub OAuth App credentials
   - Fine-grained access control without complexity

### OAuth Configuration

Configure OAuth authentication and user access:

```bash
# In your .env file:
OAUTH_ADMIN_USERS=alice,bob               # Users with admin scope (no wildcards)
OAUTH_USER_USERS=charlie,dave             # Users with read-only scope
OAUTH_LOCALHOST_ADMIN_USERS=alice,bob     # Admin scope for localhost proxy
OAUTH_LOCALHOST_USER_USERS=charlie,dave   # User scope for localhost proxy  
OAUTH_LOCALHOST_MCP_USERS=emily           # MCP scope for localhost proxy

# Per-proxy user allowlists (controls who can access the proxy):
just proxy auth config api.example.com --users alice,bob

# Per-proxy scope assignment (which users get which scopes) - via direct API:
curl -X PUT http://localhost/proxy/targets/api.example.com \
  -H "Authorization: Bearer $OAUTH_ACCESS_TOKEN" \
  -d '{"oauth_admin_users": ["alice"], "oauth_user_users": ["charlie", "dave"], "oauth_mcp_users": ["bob"]}'
```

## System Bootstrapping

### Automatic Localhost Proxy

The system automatically creates a localhost proxy on startup to provide unified access to the API:

1. **Why Localhost Proxy Exists**:
   - **Unified Architecture**: ALL traffic goes through dispatcher → proxy → backend
   - **No Direct API Access**: Port 9000 is internal only (Docker service communication)
   - **Consistent Routing**: Localhost follows same path as all other proxies
   - **Web UI Access**: Provides http://localhost for management interface
   - **OAuth Ready**: Can be configured with authentication if needed

2. **Automatic Creation**:
   - Created during `initialize_default_proxies()` on startup
   - Points to `http://127.0.0.1:9000` (API service)
   - Gets port 12000 (first HTTP proxy port) via PortManager
   - Configuration stored in Redis and survives restarts

3. **OAuth Scope Configuration**:
   ```bash
   # Configure in .env before starting:
   OAUTH_LOCALHOST_ADMIN_USERS=alice,bob     # Admin scope
   OAUTH_LOCALHOST_USER_USERS=*              # User scope for all
   OAUTH_LOCALHOST_MCP_USERS=charlie         # MCP scope
   ```

## Internal PROXY Protocol Architecture

This system uses PROXY protocol **internally only** for preserving real client IPs:

### How It Works

```
INTERNAL PROXY PROTOCOL FLOW (Dispatcher to Proxy Instances):

Client → Dispatcher (80/443) → [PROXY protocol] → Proxy Instance (12000+)
                            ↓
                  Proxy validates OAuth
                            ↓
                  Forwards to target (API/Backend)

**CRITICAL**: PROXY protocol is used INTERNALLY between dispatcher and proxy instances only!
There are NO external load balancers using PROXY protocol.
```

### Port Architecture

The system uses Redis-based PortManager for persistent port allocation:

- **80/443**: Public-facing dispatcher
- **9000**: Internal API (Docker service name: api)
- **12000-12999**: HTTP proxy instances (Redis-allocated, persistent)
- **13000-13999**: HTTPS proxy instances (Redis-allocated, persistent)
- **14000+**: User services (exposed ports)

Port mappings are stored in Redis (`proxy:ports:mappings`) and survive restarts. Each proxy gets deterministic ports based on hostname hash for consistency.

### Docker Networking

Services communicate using Docker service names:
- API: `http://api:9000`
- Redis: `redis:6379`

This ensures proper container networking and future scalability.

### Request Flow

ALL requests follow the same path:
1. Client connects to Dispatcher (port 80/443)
2. Dispatcher routes to appropriate Proxy Instance (12000+)
3. Proxy Instance validates OAuth
4. Proxy Instance adds auth headers
5. Proxy Instance forwards to target (API or external service)

Localhost is NOT special - it follows the same flow through port 12000.

### Client IP Preservation

The PROXY protocol (used internally between dispatcher and proxy instances) preserves real client IPs for logging, rate limiting, and security purposes without requiring external load balancers.

## Quick Start

### Prerequisites
- Docker and Docker Compose
- A domain pointing to your server (e.g., example.com)
- GitHub OAuth App with Device Flow enabled
- Docker socket access (for container management features)
- Redis password (32+ random bytes recommended)

**Important**: Your GitHub OAuth App MUST have Device Flow enabled:
1. Go to GitHub Settings → Developer Settings → OAuth Apps
2. Edit your OAuth App
3. Check "Enable Device Flow"
4. Save changes

### 1. Clone and Configure

```bash
git clone https://github.com/atrawog/oauth-https-proxy
cd oauth-https-proxy

# Copy and edit environment file
cp .env.example .env
# Edit .env with your configuration
```

### 2. Generate Required Secrets

```bash
# Generate Redis password
openssl rand -hex 32

# Generate OAuth JWT private key
openssl genrsa -out private.pem 2048
base64 -w 0 private.pem
# Add the base64 output to OAUTH_JWT_PRIVATE_KEY_B64 in .env
```

### 3. Start Services

```bash
# Start all services (api and redis)
just up
# This automatically creates:
# - localhost proxy → API (http://api:9000)
# - Default ACME/OAuth routes

# Create OAuth server proxy (required for OAuth functionality)
just proxy create auth.example.com http://127.0.0.1:9000
just cert create proxy-auth-example-com auth.example.com

# Login via OAuth (device flow)
just oauth login
# Follow the prompts to authenticate with GitHub
```

### 4. Access the Web UI

Open http://localhost in your browser to access the management interface.

## Production Deployment Guide

This guide walks you through deploying a complete OAuth-protected infrastructure with automatic SSL certificates.

### Prerequisites
1. A domain name (e.g., `example.com`) with DNS control
2. Server with Docker and Docker Compose installed
3. GitHub OAuth App credentials (with Device Flow enabled)
4. Ports 80 and 443 open for HTTP/HTTPS traffic

### Step 1: Environment Setup

```bash
# Clone the repository
git clone https://github.com/atrawog/oauth-https-proxy
cd oauth-https-proxy

# Generate required secrets first
REDIS_PASSWORD=$(openssl rand -hex 32)
JWT_KEY_B64=$(openssl genrsa 2048 2>/dev/null | base64 -w 0)
DOCKER_GID=$(getent group docker | cut -d: -f3)

# Create .env file with your configuration
cat > .env << EOF
# Redis configuration
REDIS_URL=redis://redis:6379/0
REDIS_PASSWORD=$REDIS_PASSWORD

# Server configuration
HTTP_PORT=80
HTTPS_PORT=443
BASE_DOMAIN=example.com

# ACME configuration
ACME_DIRECTORY_URL=https://acme-v02.api.letsencrypt.org/directory
ACME_STAGING_URL=https://acme-staging-v02.api.letsencrypt.org/directory
RENEWAL_CHECK_INTERVAL=86400
RENEWAL_THRESHOLD_DAYS=30
CERT_GEN_MAX_WORKERS=5

# GitHub OAuth Configuration (Global defaults - can be overridden per-proxy)
GITHUB_CLIENT_ID=your_github_client_id
GITHUB_CLIENT_SECRET=your_github_client_secret

# OAuth JWT Configuration
OAUTH_JWT_ALGORITHM=RS256
OAUTH_JWT_PRIVATE_KEY_B64=$JWT_KEY_B64
OAUTH_ACCESS_TOKEN_LIFETIME=1800
OAUTH_REFRESH_TOKEN_LIFETIME=31536000
OAUTH_SESSION_TIMEOUT=300
OAUTH_CLIENT_LIFETIME=7776000

# OAuth User Configuration (no wildcards allowed)
OAUTH_ADMIN_USERS=alice,bob               # Users with admin scope
OAUTH_USER_USERS=charlie,dave             # Users with read-only scope

# OAuth Scope Configuration for localhost proxy
OAUTH_LOCALHOST_ADMIN_USERS=alice,bob     # Admin scope
OAUTH_LOCALHOST_USER_USERS=charlie,dave   # User scope
OAUTH_LOCALHOST_MCP_USERS=emily           # MCP scope

# Admin configuration
ADMIN_EMAIL=admin@example.com

# Docker configuration
DOCKER_GID=$DOCKER_GID
DOCKER_API_VERSION=1.41

# Logging
LOG_LEVEL=INFO
EOF
```

### Step 2: Start Core Services

```bash
# Start Redis and API services
docker-compose up -d

# Wait for services to be healthy
just health

# Login via OAuth Device Flow
just oauth login
# Follow the instructions to authenticate with GitHub
# Your OAuth token is automatically saved and used by the CLI
```

### Step 3: Setup OAuth Server

```bash
# Create OAuth server proxy with staging certificate (for testing)
just proxy create auth.example.com http://127.0.0.1:9000 --staging

# Once verified working, recreate with production certificate
just proxy delete auth.example.com
just proxy create auth.example.com http://127.0.0.1:9000
```

### Step 4: Create Main Website Proxy

```bash
# Create main website proxy with staging certificate
just proxy create example.com http://127.0.0.1:9000 --staging

# Once verified, switch to production
just proxy delete example.com
just proxy create example.com http://127.0.0.1:9000
```

### Step 5: Deploy Protected Services

Example: Deploy a service with OAuth protection

```bash
# Run your service
docker run -d --name my-service \
  --network oauth-https-proxy_proxy_network \
  -p 127.0.0.1:3000:3000 \
  my-service:latest

# Register as external service
just service external register my-service http://my-service:3000 --description "My Service"

# Create proxy for the service
just proxy create service.example.com http://my-service:3000
just cert create proxy-service-example-com service.example.com

# Enable OAuth protection
just proxy auth enable service.example.com

# Configure GitHub user access
just proxy auth config service.example.com --users alice,bob,charlie

# Optional: Configure custom GitHub OAuth App for this proxy
# just proxy-github-oauth-set service.example.com <client-id> <client-secret>
```

### Step 6: DNS Configuration

Configure your DNS records:
```
A     @              → your_server_ip
A     auth           → your_server_ip  
A     echo           → your_server_ip
A     www            → your_server_ip
```

### Step 7: Verify Setup

```bash
# Check system health
just health

# List all proxies
just proxy-list

# Test OAuth flow
curl https://echo.example.com
# Should redirect to GitHub OAuth

# Check OAuth metadata
curl https://auth.example.com/.well-known/oauth-authorization-server
```

### Migration from Staging to Production

When ready to switch from staging to production certificates:

```bash
# For each proxy with staging certificate:
just cert-delete <cert-name>
just proxy-update <hostname> --production-cert

# Or recreate the proxy:
just proxy delete <hostname>
just proxy create <hostname> <target-url>  # Without --staging flag
```

### Troubleshooting

```bash
# Check logs
just log search                  # Show recent logs (chronological order)
just log follow                  # Follow logs in real-time with ANSI colors
just log errors                  # View recent errors
just service logs api            # View Docker container logs

# Debug certificate issues
just cert-show <cert-name>

# Check proxy configuration
just proxy-show <hostname>

# Monitor OAuth activity
just log oauth <ip>
```

### Security Considerations

1. **OAuth Security**: Use GitHub Device Flow for secure authentication
2. **GitHub Users**: Configure per-proxy user allowlists for fine-grained access control
3. **Certificate Email**: Use a valid email for Let's Encrypt notifications
4. **Redis Password**: Use a strong, randomly generated password
5. **Network Isolation**: Use Docker networks to isolate services

## Basic Usage

### OAuth-Only Authentication

The system uses pure OAuth 2.1 authentication with a simplified architecture:

#### Key Changes from Previous Versions
- **No Bearer Tokens**: Removed entire `acm_*` token system
- **Single Auth Layer**: Proxy validates OAuth, API trusts headers
- **90% Code Reduction**: Removed ~80KB of authentication code
- **Trust Model**: API reads `X-Auth-User`, `X-Auth-Scopes` headers from proxy

#### Authentication Flow
1. **OAuth Login**: Use `just oauth login` for GitHub Device Flow
2. **Proxy Validation**: Proxy validates JWT tokens and extracts user/scopes
3. **Header Forwarding**: Proxy adds trusted headers for API
4. **API Trust**: API reads headers without re-validation

#### Getting Started
```bash
# Login via Device Flow (CLI-friendly, no localhost needed)
just oauth login

# Check your token status
just oauth-status

# Refresh token if needed
just oauth-refresh

# All just commands automatically use your saved token
just proxy-list
just cert-list
```

#### Configure Scope-Based Access
```bash
# Configure which GitHub users get which scopes on localhost proxy
# Set in .env before starting services:
OAUTH_LOCALHOST_ADMIN_USERS=alice,bob   # Admin scope for specific users
OAUTH_LOCALHOST_USER_USERS=*            # User scope for all users
OAUTH_LOCALHOST_MCP_USERS=charlie,dave  # MCP scope for specific users

# Configure per-proxy user allowlist (who can access):
just proxy auth config api.example.com --users alice,bob,charlie

# Configure per-proxy scope assignment (which users get which scopes) - via API:
curl -X PUT http://localhost/proxy/targets/api.example.com \
  -H "Authorization: Bearer $OAUTH_ACCESS_TOKEN" \
  -d '{
    "oauth_admin_users": ["alice"],
    "oauth_user_users": ["*"],
    "oauth_mcp_users": ["bob"]
  }'
```

#### Configure Proxy Authentication
```bash
# Enable OAuth on a proxy
just proxy auth enable api.example.com --auth-proxy auth.example.com --mode forward

# Or configure programmatically
curl -X POST http://localhost/proxy/targets/api.example.com/auth \
  -H "Authorization: Bearer $OAUTH_ACCESS_TOKEN" \
  -d '{
    "enabled": true,
    "auth_proxy": "auth.example.com",
    "mode": "redirect",
    "required_users": ["alice", "bob"],
    "allowed_scopes": ["api:read", "api:write"]
  }'
```

### Create a Proxy

```bash
# Create proxy with automatic certificate handling
just proxy create api.example.com http://backend:8080

# The proxy will automatically:
# - Check for existing certificates and use them
# - Create production Let's Encrypt certificate if needed
# - Set up HTTP and HTTPS routing
# - Handle certificate generation asynchronously

# For staging/testing (creates staging certificate)
just proxy create api.example.com http://backend:8080 --staging

# Common scenarios:
# 1. First-time proxy with production cert
just proxy create echo.example.com http://service:3000

# 2. Proxy with existing certificate (automatically detected)
just proxy create echo.example.com http://service:3000

# 3. Testing with staging certificate
just proxy create echo.example.com http://service:3000 --staging

# 4. HTTP-only proxy (no certificate needed)
just proxy create internal.local http://service:3000 --preserve-host --enable-http --no-enable-https
```

### Enable OAuth Protection

```bash
# Create the auth proxy
just proxy create auth.example.com http://localhost:9000

# Enable OAuth on your API proxy
just proxy auth enable api.example.com --auth-proxy auth.example.com --mode forward
```

### Docker Service Management

Create and manage Docker containers with automatic port exposure:

```bash
# Create a service with exposed port on localhost
just service create-exposed my-app nginx:alpine 8080 --bind-address 127.0.0.1

# Create a service accessible from all interfaces
just service create-exposed public-api node:18 3000 --bind-address 0.0.0.0

# Real example: Create service on port 3000
just service create-exposed my-service my-service-image:latest 3000 --bind-address 127.0.0.1

# Add additional ports to existing service
just service port add my-app 8081 --bind-address 127.0.0.1

# List all services and their ports
just service list
just service port list my-app

# Create proxy for service (optional) - makes it accessible via HTTPS
just service proxy-create my-app --hostname service.example.com --enable-https

# Full example: Service accessible at both localhost:3000 and https://service.example.com
just service create-exposed my-service my-service-image:latest 3000 --bind-address 127.0.0.1
just proxy create service.example.com http://my-service:3000
```

### Port Management

Services can expose ports with fine-grained control:

```bash
# Check if a port is available
just service port check 8080 --bind-address 127.0.0.1

# Add/remove ports from services
just service port add <service> <port> --bind-address 127.0.0.1
just service port remove <service> <port-name>
just service port list <service>
```

## Architecture

### Service Components

```
┌─────────────────┐     ┌──────────────────────────┐
│                 │     │                          │
│  HTTP Client    │───▶│    Unified Dispatcher    │
│                 │     │  - HTTP/HTTPS Gateway    │
└─────────────────┘     │  - Event Handler         │
                        │  - OAuth Server          │
                        │  - Certificate Manager   │
                        │  - Docker Manager        │
                        └────────────┬─────────────┘
                                     │
                    ┌────────────────┼────────────────┐
                    │                │                │
              ┌─────▼────┐     ┌─────▼────┐    ┌────▼─────┐
              │  Redis   │     │  Docker  │    │          │
              │ Storage/ │     │  Socket  │    │ Backend  │
              │  Events  │     │          │    │ Services │
              └──────────┘     └──────────┘    └──────────┘
```

#### Internal PROXY Protocol Architecture

```
┌───────────────┐     ┌─────────────────┐     ┌─────────────────┐
│   Client      │───▶│ Dispatcher      │───▶│ Proxy Instance  │
│               │     │ (80/443)        │     │ (12xxx/13xxx)   │
└───────────────┘     └─────────────────┘     └─────────────────┘
                              │
                     [PROXY protocol header]
                              │
                              ▼
                      Preserves real client IP
```

The PROXY protocol is used INTERNALLY only:
- Dispatcher adds PROXY headers when forwarding to proxy instances
- Proxy instances (HypercornInstance) parse PROXY headers
- Real client IPs are preserved for logging and security
- No external load balancers required
- Essential for client IP preservation (without it, all requests appear from 127.0.0.1)

- **Unified Dispatcher**: Single component handling HTTP/HTTPS gateway, event processing, OAuth server, and certificate management
- **Redis Storage/Events**: Stores all configuration, certificates, tokens, and processes events via Redis Streams
- **Event System**: Just 3 simple events (proxy_created, proxy_deleted, certificate_ready) for all dynamic operations
- **Docker Socket**: Enables dynamic container creation and management
- **Backend Services**: Your applications (protected resources, APIs, Docker containers)

### Request Flow

1. **Incoming Request** → API service receives on port 80/443
2. **Route Matching** → Finds target based on hostname/path
3. **Auth Check** → Validates OAuth token if required
4. **Certificate** → Loads SSL certificate for HTTPS
5. **Forward** → Proxies request to backend service
6. **Response** → Returns backend response to client

### Internal PROXY Protocol Flow

1. **Client Connection** → Client connects to Dispatcher on port 80/443
2. **Route Resolution** → Dispatcher determines target proxy instance
3. **PROXY Header Addition** → Dispatcher adds PROXY protocol header with real client IP
4. **Forward to Proxy** → Connection forwarded to proxy instance (12xxx/13xxx)
5. **Header Parsing** → HypercornInstance extracts real client IP
6. **OAuth Validation** → Proxy validates authentication with real client context

## Configuration

### Environment Variables

Key configuration in `.env`:

```bash
# Domain Configuration
BASE_DOMAIN=example.com          # Your base domain
ADMIN_EMAIL=admin@example.com   # Email for certificates
API_URL=http://localhost:9000       # Base URL for API endpoints

# Security
REDIS_PASSWORD=<strong-password>    # Redis password (required)

# OAuth Configuration
GITHUB_CLIENT_ID=<github-client-id>         # GitHub OAuth App Client ID
GITHUB_CLIENT_SECRET=<github-client-secret> # GitHub OAuth App Client Secret
OAUTH_JWT_PRIVATE_KEY_B64=<base64-key>      # RSA key for JWT signing

# OAuth Bootstrap Users for localhost proxy (configure which GitHub users get which scopes)
OAUTH_LOCALHOST_ADMIN_USERS=alice,bob   # Admin scope users
OAUTH_LOCALHOST_USER_USERS=*            # User scope (* = all users)
OAUTH_LOCALHOST_MCP_USERS=charlie       # MCP scope users

# Docker Management
DOCKER_GID=999                      # Docker group GID (varies by OS)
DOCKER_API_VERSION=1.41             # Docker API version

# Advanced (usually defaults are fine)
ACME_DIRECTORY_URL=https://acme-v02.api.letsencrypt.org/directory
HTTP_PORT=80
HTTPS_PORT=443
LOG_LEVEL=INFO

# Internal Architecture Notes
# Port 9000: API service (internal only, accessed via Docker service name)
# Ports 12xxx/13xxx: Proxy instances with PROXY protocol support
```

### Route Configuration

Routes are managed dynamically via API/CLI:

```bash
# Create a route
just route create / service backend-api

# List all routes
just route-list

# Routes have priorities (higher = checked first)
# - 100: ACME challenges
# - 95: OAuth endpoints  
# - 90: API routes
# - 50: Default priority
```

## Advanced Usage

### Per-Proxy OAuth Server Metadata

Each proxy can serve its own OAuth authorization server metadata with custom configuration:

```bash
# Configure custom OAuth server metadata for a proxy
just proxy-oauth-server-set service.example.com \
  "https://auth.example.com" \                    # Custom issuer
  "read,write,admin" \                               # Custom scopes
  "authorization_code,refresh_token" \               # Grant types
  "code" \                                           # Response types
  "client_secret_post,client_secret_basic" \        # Token auth methods
  "sub,name,email,preferred_username" \             # Claims
  true \                                             # PKCE required
  '{"custom_field": "value"}' \                     # Custom metadata
  true \                                             # Override defaults
  [token]

# View OAuth server configuration
just proxy-oauth-server-show everything.example.com

# Clear custom OAuth server metadata (revert to defaults)
just proxy-oauth-server-clear everything.example.com
```

This allows different proxies to:
- Use different OAuth issuers
- Support different scopes per environment (dev vs prod)
- Require PKCE for specific proxies
- Add custom metadata fields for specific clients

### Multi-Domain Certificates

```bash
# Create certificate for multiple domains (Note: These commands may not exist in current implementation)
# Use individual cert create commands for each domain instead:
just cert create api-cert api.domain.com --email admin@domain.com
just cert create app-cert app.domain.com --email admin@domain.com
```

### External Service Management

```bash
# Register named services for route targeting
just service external register backend-api http://api:8080 --description "Backend API"
just service external register frontend http://frontend:3000 --description "Frontend"

# Create routes targeting services
just route create /api/ service backend-api --priority 50
just route create / service frontend --priority 50
```

### OAuth Client Management

```bash
# Register OAuth client for testing
just oauth-client-register my-app https://myapp.com/callback "read write"

# Monitor OAuth activity
just oauth-sessions-list
just oauth-clients-list
```

### Docker Service Management

```bash
# Create a service from Docker image
just service create my-nginx nginx:latest --port 80 --memory 512m --cpu 1.0

# Manage service lifecycle
just service start my-app
just service stop my-app
just service restart my-app

# Monitor services
just service list
just service logs my-app --lines 100
just service stats my-app

# Create proxy for service
just service proxy-create my-app --hostname my-app.domain.com --enable-https
```

### Logging and Monitoring

The proxy includes a high-performance logging system with efficient querying:

```bash
# Query logs by client IP
just log ip 192.168.1.100 --hours 24

# Query logs by proxy hostname  
just log proxy api.domain.com --hours 24

# View recent errors
just log errors --hours 1 --limit 50

# Follow logs in real-time
just log follow --interval 2

# Test logging system
just log test
```

**Features**:
- Request/response correlation tracking
- Multiple indexes for efficient querying (IP, hostname, status, user, path)
- Real-time streaming and monitoring
- Automatic retention (24 hours default)
- Response time statistics
- Unique visitor tracking with HyperLogLog

**Log Query API** (requires OAuth token with admin scope):
- `GET /logs/ip/{ip}` - Query by client IP
- `GET /logs/client/{client_id}` - Query by OAuth client
- `GET /logs/correlation/{id}` - Complete request flow
- `GET /logs/search` - Advanced search
- `GET /logs/errors` - Recent errors

## API Reference

### Base URL
All API endpoints are served at the root level with clean URLs (e.g., `/tokens/`, `/certificates/`, `/routes/`).

**Note**: When accessing the API directly, use port 9000 (e.g., `http://localhost:9000`). Port 80/443 is for proxied traffic only.

### Authentication
The API uses OAuth 2.1 authentication with GitHub:
- **OAuth Tokens**: All API operations require OAuth access tokens
- **Scope-Based Access**: Users are assigned scopes (admin/user/mcp) based on GitHub username
- **Device Flow**: CLI-friendly authentication without localhost callbacks
- **Auto-Bootstrap**: System creates localhost proxy with OAuth on startup

All API operations require authentication:
```
Authorization: Bearer your-oauth-access-token
```

### Main API Categories

#### OAuth Management (`/oauth/*`)
- Device Flow authentication for CLI access
- Session management and token introspection
- Dynamic client registration (RFC 7591)
- Key endpoints:
  - `GET /auth/endpoints` - List endpoint auth configs
  - `POST /auth/endpoints` - Create endpoint auth config
  - `PUT /auth/endpoints/{config_id}` - Update config
  - `DELETE /auth/endpoints/{config_id}` - Delete config
  - `POST /auth/endpoints/test` - Test path matching
  - `PUT /routes/{route_id}/auth` - Configure route auth
  - `POST /proxy/targets/{hostname}/auth` - Configure proxy auth

#### Certificate Management (`/certificates/*`)
- Create, list, renew, and delete SSL certificates
- Multi-domain certificate support
- ACME challenge handling at `/.well-known/acme-challenge/*`

#### Proxy Management (`/proxy/targets/*`)
- Create and manage reverse proxy configurations
- OAuth authentication settings per proxy
- Protected resource metadata configuration (RFC 9728)
- OAuth authorization server metadata per proxy
- Per-proxy GitHub OAuth credentials configuration
- Route filtering configuration
- Key endpoints:
  - `POST /proxy/targets/{hostname}/resource` - Configure protected resource metadata
  - `POST /proxy/targets/{hostname}/oauth-server` - Configure OAuth server metadata
  - `POST /proxy/targets/{hostname}/github-oauth` - Configure GitHub OAuth credentials
  - `GET /proxy/targets/{hostname}/github-oauth` - Get GitHub OAuth config (without secret)
  - `DELETE /proxy/targets/{hostname}/github-oauth` - Clear GitHub OAuth config
  - `POST /proxy/targets/{hostname}/auth` - Configure authentication

#### Token Management (`/tokens/*`)
- API token creation and management
- Token-based ownership tracking

#### Route Management (`/routes/*`)
- Priority-based path routing
- Support for regex patterns
- Method-specific routing

#### External Service Management (`/services/external/*`)
- Named service registration for external URLs
- Service discovery for routing

#### OAuth Admin (`/oauth/*`)
- Client and session management
- Token introspection
- System metrics

#### Protected Resources (`/resources/*`)
- Protected resource registration
- Resource validation
- Auto-discovery

#### Docker Services (`/services/*`)
- Container creation and management
- Service lifecycle control (start/stop/restart)
- Log retrieval and statistics
- Automatic proxy creation for services
- Multi-port configuration with bind address control
- Port management endpoints:
  - `GET /services/{name}/ports` - List service ports
  - `POST /services/{name}/ports` - Add port to service
  - `DELETE /services/{name}/ports/{port_name}` - Remove port

#### Port Management (`/ports/*`)
- Dynamic port allocation tracking
- Available port range queries
- Port access token management
- Fine-grained access control for exposed ports

### OAuth Protocol Endpoints (Root Level)
- `/authorize` - OAuth authorization
- `/token` - Token exchange
- `/callback` - OAuth callback
- `/verify` - Token verification
- `/register` - Dynamic client registration
- `/.well-known/oauth-authorization-server` - Server metadata

### Interactive API Documentation
Access the full interactive API documentation at:
- Local: http://localhost:9000/docs (direct API access)
- Local via proxy: http://localhost/docs
- Production: https://example.com/docs

## Development

### Local Development

```bash
# Install pixi (Python environment manager)
curl -fsSL https://pixi.sh/install.sh | bash

# Set up development environment
just setup

# Run locally (without Docker)
just dev

# Run tests
just test-all
```

### Testing

All tests run against real services (no mocks):

```bash
just test                # Basic tests
just test-proxy-all      # All proxy tests
just test-auth           # OAuth tests
```

### Project Structure

```
oauth-https-proxy/
├── src/
│   ├── api/            # FastAPI application
│   │   ├── oauth/      # OAuth server implementation
│   │   ├── endpoints/  # REST API endpoints
│   │   └── routers/    # API route definitions
│   ├── certmanager/    # ACME certificate management
│   ├── dispatcher/     # HTTP/HTTPS request dispatcher
│   ├── docker/         # Docker service management
│   ├── proxy/          # Reverse proxy implementation
│   └── storage/        # Redis storage layer
├── tests/              # Pytest test suite
├── scripts/            # Utility scripts
├── dockerfiles/        # Custom Dockerfiles for services
├── contexts/           # Docker build contexts
├── docker-compose.yml  # Service orchestration
├── justfile           # Task automation
└── .env.example       # Example configuration
```

## Recent Updates

### Per-Proxy OAuth Server Metadata (NEW)
- **Custom OAuth Metadata**: Each proxy can now serve its own OAuth authorization server metadata
- **Environment-Specific Scopes**: Different scopes for dev/staging/production environments
- **PKCE Control**: Require PKCE for specific proxies
- **Custom Issuers**: Override the default issuer URL per proxy
- **Flexible Configuration**: Mix and match OAuth settings across different proxies

### Internal PROXY Protocol Support
- **Client IP Preservation**: PROXY protocol v1 used internally between dispatcher and proxy instances
- **Essential for Security**: Without it, all connections appear from 127.0.0.1
- **HypercornInstance**: Handles both PROXY protocol parsing and SSL termination
- **No External LB Required**: PROXY protocol is internal-only architecture
- **Unified Handling**: Same mechanism for both HTTP (12xxx) and HTTPS (13xxx) proxy instances
- **Real IPs for OAuth**: Enables proper rate limiting, logging, and security

### Port Management System (NEW)
- **Multi-Port Services**: Services can now expose multiple ports with different bind addresses
- **Port Allocation**: Comprehensive port management with automatic allocation and tracking
- **Access Control**: Optional token-based access control for exposed ports
- **Bind Address Control**: Choose between localhost-only (127.0.0.1) or public (0.0.0.0) access per port
- **New Commands**: Added `service-create-exposed` for easy service creation with ports
- **Port API**: New endpoints for managing service ports dynamically

### Docker Service Enhancements
- **Improved Schema**: Support for `port_configs` array for multi-port configuration
- **Backward Compatibility**: Existing `external_port` field still supported
- **Python-on-whales**: Fixed port publishing format for proper Docker integration
- **Resource Tracking**: Ports are automatically released when services are deleted

### Command Improvements
- **Consistent Naming**: All service-related commands now use `service-` prefix
- **Port Commands**: New `service-port-*` commands for port management
- **Token Commands**: New `port-token-*` commands for access control

## Troubleshooting

### Common Issues

1. **Certificate Generation Fails**
   ```bash
   # Check ACME challenge accessibility
   curl http://example.com/.well-known/acme-challenge/test
   
   # Use staging certificates for testing
   just cert create test-cert example.com --email admin@domain.com --staging
   ```

2. **OAuth Login Issues**
   ```bash
   # Verify OAuth routes are set up
   just route-list | grep -E "(authorize|token|callback)"
   
   # Check OAuth health
   just oauth-health
   ```

3. **Proxy Connection Errors**
   ```bash
   # Check proxy target health
   just proxy-show problematic.domain.com
   
   # View service logs
   just service logs api
   ```

4. **Docker Service Creation Fails**
   ```bash
   # Check Docker socket permissions
   # Find your Docker GID:
   getent group docker | cut -d: -f3
   
   # Update DOCKER_GID in .env to match
   # Restart the proxy service
   just restart
   ```

5. **OAuth Protection Bypassed**
   ```bash
   # IMPORTANT: Never create specific routes for paths already handled by proxies!
   # The proxy already forwards ALL paths to the backend.
   # Adding specific routes creates a bypass that skips OAuth.
   
   # Check for redundant routes:
   just route-list | grep "your-path"
   
   # Delete any redundant routes:
   just route-delete <route-id>
   ```

### Debugging Commands

```bash
just health              # System health check
just stats               # Resource statistics
just cleanup    # Clean up orphaned resources
just redis-cli          # Direct Redis access
just shell              # Shell into api container
```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Run tests: `just test-all`
4. Submit a pull request

Please ensure:
- All tests pass
- No mocking in tests (test against real services)
- Follow existing code style
- Update documentation as needed

## License

MIT License - see LICENSE file for details