# OAuth HTTPS Proxy

A production-ready HTTP/HTTPS proxy with integrated OAuth 2.1 server, automatic ACME certificate management, and unified event-driven architecture. This proxy provides secure, authenticated access to backend services with automatic SSL/TLS certificate provisioning and zero-restart dynamic configuration.

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
- **Port Management**: Comprehensive port allocation with bind address control
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
- **API Documentation**: Interactive Swagger UI at https://yourdomain.com/docs
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
   - Use `just oauth-login` to authenticate via GitHub
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
OAUTH_ALLOWED_GITHUB_USERS=*              # Global default (* = all users)
OAUTH_LOCALHOST_ADMIN_USERS=alice,bob     # Admin scope for localhost proxy
OAUTH_LOCALHOST_USER_USERS=*              # User scope for localhost proxy  
OAUTH_LOCALHOST_MCP_USERS=charlie         # MCP scope for localhost proxy

# Per-proxy user allowlists (controls who can access the proxy):
just proxy-auth-config api.example.com "alice,bob" "" "" "" ""

# Per-proxy scope assignment (which users get which scopes) - via direct API:
curl -X PUT http://localhost/proxy/targets/api.example.com \
  -H "Authorization: Bearer $OAUTH_ACCESS_TOKEN" \
  -d '{"oauth_admin_users": ["alice"], "oauth_user_users": ["*"], "oauth_mcp_users": ["bob"]}'
```

## Quick Start

### Prerequisites
- Docker and Docker Compose
- A domain pointing to your server (for HTTPS)
- GitHub OAuth App with Device Flow enabled (for authentication)
- Docker socket access (for container management features)

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

# Login via OAuth (device flow)
just oauth-login

# The system uses OAuth-only authentication:
# - No bearer tokens (acm_*) 
# - Proxy validates OAuth, API trusts headers
# - Configure user access via environment variables
```

### 4. Access the Web UI

Open http://localhost in your browser to access the management interface.

## Production Deployment Guide

This guide walks you through deploying a complete OAuth-protected infrastructure with automatic SSL certificates.

### Prerequisites
1. A domain name (e.g., `yourdomain.com`) with DNS control
2. Server with Docker and Docker Compose installed
3. GitHub OAuth App credentials
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
BASE_DOMAIN=yourdomain.com

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
OAUTH_ALLOWED_GITHUB_USERS=*

# OAuth Scope Configuration for localhost proxy
OAUTH_LOCALHOST_ADMIN_USERS=alice,bob     # Admin scope
OAUTH_LOCALHOST_USER_USERS=*              # User scope for all
OAUTH_LOCALHOST_MCP_USERS=charlie         # MCP scope

# Admin configuration
ADMIN_EMAIL=admin@yourdomain.com

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
just oauth-login
# Follow the instructions to authenticate with GitHub
# Your OAuth token is automatically saved and used by the CLI
```

### Step 3: Setup OAuth Server

```bash
# Create OAuth server proxy with staging certificate (for testing)
just proxy-create auth.yourdomain.com "http://127.0.0.1:9000" staging=true

# Once verified working, recreate with production certificate
just proxy-delete auth.yourdomain.com
just proxy-create auth.yourdomain.com "http://127.0.0.1:9000"
```

### Step 4: Create Main Website Proxy

```bash
# Create main website proxy with staging certificate
just proxy-create yourdomain.com "http://127.0.0.1:9000" staging=true

# Once verified, switch to production
just proxy-delete yourdomain.com
just proxy-create yourdomain.com "http://127.0.0.1:9000"
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
just service-register my-service "http://my-service:3000" "My Service"

# Create proxy with staging certificate
just proxy-create service.yourdomain.com "http://my-service:3000" staging=true

# Enable OAuth protection
just proxy-auth-enable service.yourdomain.com auth.yourdomain.com redirect

# Optional: Configure custom GitHub OAuth App for this proxy
# just proxy-github-oauth-set service.yourdomain.com <client-id> <client-secret>

# Once verified, switch to production certificate
just cert-delete proxy-service-yourdomain-com
just proxy-update service.yourdomain.com --production-cert
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
curl https://echo.yourdomain.com
# Should redirect to GitHub OAuth

# Check OAuth metadata
curl https://auth.yourdomain.com/.well-known/oauth-authorization-server
```

### Migration from Staging to Production

When ready to switch from staging to production certificates:

```bash
# For each proxy with staging certificate:
just cert-delete <cert-name>
just proxy-update <hostname> --production-cert

# Or recreate the proxy:
just proxy-delete <hostname>
just proxy-create <hostname> <target-url>  # Without --staging flag
```

### Troubleshooting

```bash
# Check logs
just logs                        # Show recent logs (chronological order)
just logs-follow                 # Follow logs in real-time with ANSI colors
just logs-errors                 # View recent errors
just logs-docker                 # View Docker container logs only

# Debug certificate issues
just cert-show <cert-name>

# Check proxy configuration
just proxy-show <hostname>

# Monitor OAuth activity
just logs-oauth <ip>
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
1. **OAuth Login**: Use `just oauth-login` for GitHub Device Flow
2. **Proxy Validation**: Proxy validates JWT tokens and extracts user/scopes
3. **Header Forwarding**: Proxy adds trusted headers for API
4. **API Trust**: API reads headers without re-validation

#### Getting Started
```bash
# Login via Device Flow (CLI-friendly, no localhost needed)
just oauth-login

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
just proxy-auth-config api.example.com "alice,bob,charlie" "" "" "" ""

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
just proxy-auth-enable api.yourdomain.com auth.yourdomain.com forward

# Or configure programmatically
curl -X POST http://localhost/proxy/targets/api.yourdomain.com/auth \
  -H "Authorization: Bearer $OAUTH_ACCESS_TOKEN" \
  -d '{
    "enabled": true,
    "auth_proxy": "auth.yourdomain.com",
    "mode": "redirect",
    "required_users": ["alice", "bob"],
    "allowed_scopes": ["api:read", "api:write"]
  }'
```

### Create a Proxy

```bash
# Create proxy with automatic certificate handling
just proxy-create api.yourdomain.com http://backend:8080

# The proxy will automatically:
# - Check for existing certificates and use them
# - Create production Let's Encrypt certificate if needed
# - Set up HTTP and HTTPS routing
# - Handle certificate generation asynchronously

# For staging/testing (creates staging certificate)
just proxy-create api.yourdomain.com http://backend:8080 staging=true

# Common scenarios:
# 1. First-time proxy with production cert
just proxy-create echo.yourdomain.com http://service:3000

# 2. Proxy with existing certificate (automatically detected)
just proxy-create echo.yourdomain.com http://service:3000

# 3. Testing with staging certificate
just proxy-create echo.yourdomain.com http://service:3000 staging=true

# 4. HTTP-only proxy (no certificate needed)
just proxy-create internal.local http://service:3000 staging=false preserve-host=true enable-http=true enable-https=false
```

### Enable OAuth Protection

```bash
# Create the auth proxy
just proxy-create auth.yourdomain.com http://localhost:9000

# Enable OAuth on your API proxy
just proxy-auth-enable api.yourdomain.com auth.yourdomain.com forward
```

### Docker Service Management

Create and manage Docker containers with automatic port exposure:

```bash
# Create a service with exposed port on localhost
just service-create-exposed my-app nginx:alpine 8080 127.0.0.1

# Create a service accessible from all interfaces
just service-create-exposed public-api node:18 3000 0.0.0.0

# Real example: Create service on port 3000
just service-create-exposed my-service my-service-image:latest 3000 127.0.0.1

# Add additional ports to existing service
just service-port-add my-app 8081 127.0.0.1

# List all services and their ports
just service-list
just service-port-list my-app

# Create proxy for service (optional) - makes it accessible via HTTPS
just service-proxy-create my-app hostname=service.yourdomain.com enable-https=true

# Full example: Service accessible at both localhost:3000 and https://service.yourdomain.com
just service-create-exposed my-service my-service-image:latest 3000 127.0.0.1
just proxy-create service.yourdomain.com http://my-service:3000
```

### Port Management

Services can expose ports with fine-grained control:

```bash
# Check if a port is available
just service-port-check 8080 bind-address=127.0.0.1

# Add/remove ports from services
just service-port-add <service> <port> bind-address=127.0.0.1
just service-port-remove <service> <port-name>
just service-port-list <service>
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

#### PROXY Protocol Support

```
┌───────────────┐     ┌─────────────────┐     ┌─────────────────┐
│ External LB   │───▶│ Port 10001      │───▶│ Port 9000       │
│ w/ PROXY v1   │     │ PROXY Handler   │     │ Hypercorn/API   │
└───────────────┘     └─────────────────┘     └─────────────────┘
                              │
                              ▼
                          Redis Cache
                     (Client IP storage)
```

The PROXY protocol handler:
- Listens on port 10001 for connections with PROXY headers
- Parses and strips PROXY protocol v1 headers
- Stores real client IP in Redis with connection identifiers
- Forwards clean traffic to port 9000 (Hypercorn)
- ASGI middleware retrieves client IP and injects headers

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

### PROXY Protocol Flow (for Load Balancers)

1. **LB Connection** → External LB connects to port 10001 with PROXY header
2. **Header Parsing** → PROXY handler extracts real client IP from header
3. **IP Storage** → Client info stored in Redis with connection identifiers
4. **Clean Forward** → Strips PROXY header, forwards to port 9000
5. **Middleware** → ASGI middleware retrieves client IP from Redis
6. **Header Injection** → Adds X-Real-IP and X-Forwarded-For headers

## Configuration

### Environment Variables

Key configuration in `.env`:

```bash
# Domain Configuration
BASE_DOMAIN=yourdomain.com          # Your base domain
ADMIN_EMAIL=admin@yourdomain.com   # Email for certificates
API_URL=http://localhost:9000       # Base URL for API endpoints

# Security
REDIS_PASSWORD=<strong-password>    # Redis password (required)

# OAuth Configuration
GITHUB_CLIENT_ID=<github-client-id>         # GitHub OAuth App Client ID
GITHUB_CLIENT_SECRET=<github-client-secret> # GitHub OAuth App Client Secret
OAUTH_JWT_PRIVATE_KEY_B64=<base64-key>      # RSA key for JWT signing

# OAuth Bootstrap Users (configure which GitHub users get which scopes)
OAUTH_LOCALHOST_ADMIN_USERS=     # Admin scope users (e.g., "alice,bob")
OAUTH_LOCALHOST_USER_USERS=*     # User scope (* = all users)
OAUTH_LOCALHOST_MCP_USERS=       # MCP scope users

# Docker Management
DOCKER_GID=999                      # Docker group GID (varies by OS)
DOCKER_API_VERSION=1.41             # Docker API version

# Advanced (usually defaults are fine)
ACME_DIRECTORY_URL=https://acme-v02.api.letsencrypt.org/directory
HTTP_PORT=80
HTTPS_PORT=443
LOG_LEVEL=INFO

# Internal Ports (for PROXY protocol support)
# Port 9000: Direct API access (localhost-only)
# Port 10001: PROXY protocol endpoint (accepts connections from load balancers)
```

### Route Configuration

Routes are managed dynamically via API/CLI:

```bash
# Create a route
just route-create / service backend-api [token]

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
just proxy-oauth-server-set service.yourdomain.com \
  "https://auth.yourdomain.com" \                    # Custom issuer
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
just proxy-oauth-server-show everything.yourdomain.com

# Clear custom OAuth server metadata (revert to defaults)
just proxy-oauth-server-clear everything.yourdomain.com
```

This allows different proxies to:
- Use different OAuth issuers
- Support different scopes per environment (dev vs prod)
- Require PKCE for specific proxies
- Add custom metadata fields for specific clients

### Multi-Domain Certificates

```bash
# Create certificate for multiple domains (Note: These commands may not exist in current implementation)
# Use individual cert-create commands for each domain instead:
just cert-create api-cert api.domain.com email=admin@domain.com
just cert-create app-cert app.domain.com email=admin@domain.com
```

### External Service Management

```bash
# Register named services for route targeting
just service-register backend-api http://api:8080 description="Backend API"
just service-register frontend http://frontend:3000 description="Frontend"

# Create routes targeting services
just route-create /api/ service backend-api priority=50
just route-create / service frontend priority=50
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
just service-create my-nginx nginx:latest port=80 memory=512m cpu=1.0

# Manage service lifecycle
just service-start my-app
just service-stop my-app
just service-restart my-app

# Monitor services
just service-list
just service-logs my-app lines=100
just service-stats my-app

# Create proxy for service
just service-proxy-create my-app hostname=my-app.domain.com enable-https=true
```

### Logging and Monitoring

The proxy includes a high-performance logging system with efficient querying:

```bash
# Query logs by client IP
just logs-ip 192.168.1.100 hours=24

# Query logs by proxy hostname  
just logs-proxy api.domain.com hours=24

# View recent errors
just logs-errors hours=1 limit=50

# Follow logs in real-time
just logs-follow interval=2

# Test logging system
just logs-test
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
- Production: https://yourdomain.com/docs

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

### PROXY Protocol Support (NEW)
- **Client IP Preservation**: HAProxy PROXY protocol v1 support for real client IPs
- **Unified HTTP/HTTPS**: Same mechanism works for both HTTP and HTTPS traffic
- **Redis Side Channel**: Connection-based client info storage with 60s TTL
- **TCP-Level Handler**: Parses and strips PROXY headers before forwarding
- **ASGI Middleware**: Automatically injects X-Real-IP and X-Forwarded-For headers
- **Port Configuration**: Port 10001 accepts PROXY protocol, forwards to port 9000

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
   curl http://yourdomain.com/.well-known/acme-challenge/test
   
   # Use staging certificates for testing
   just cert-create test-cert yourdomain.com admin@domain.com [token] [staging]
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
   just logs api
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
just service-cleanup-orphaned    # Clean up orphaned resources
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