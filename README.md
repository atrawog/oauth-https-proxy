# OAuth HTTPS Proxy

A production-ready HTTP/HTTPS proxy with integrated OAuth 2.1 server, automatic ACME certificate management, and Model Context Protocol (MCP) compliance. This proxy provides secure, authenticated access to backend services with automatic SSL/TLS certificate provisioning.

## Features

### Core Proxy Capabilities
- **Dynamic Reverse Proxy**: Route traffic to multiple backend services
- **Automatic HTTPS**: Obtain and renew Let's Encrypt certificates via ACME
- **OAuth 2.1 Integration**: Built-in OAuth server with GitHub authentication
- **MCP Compliance**: Full support for Model Context Protocol with OAuth protection
- **WebSocket Support**: Proxy WebSocket and Server-Sent Events (SSE) connections
- **Route Management**: Priority-based path routing with regex support
- **External Service Management**: Named service registration for external URLs
- **Docker Service Management**: Create and manage Docker containers dynamically
- **MCP Metadata**: Automatic metadata endpoints for MCP-compliant services
- **Port Management**: Comprehensive port allocation with bind address control
- **Multi-Port Services**: Services can expose multiple ports with access controls

### Security Features
- **Token-Based API**: All administrative operations require bearer tokens
- **OAuth Protection**: Protect any proxied service with OAuth authentication
- **Per-Proxy User Allowlists**: Each proxy can specify its own GitHub user allowlist
- **Per-Proxy OAuth Metadata**: Each proxy can serve custom OAuth authorization server metadata
- **Certificate Isolation**: Multi-domain certificates with ownership tracking
- **Redis-Only Storage**: No filesystem persistence for enhanced security
- **Client IP Preservation**: HAProxy PROXY protocol v1 support for real client IPs
- **Advanced Logging**: High-performance request logging with multiple indexes

### Developer Experience
- **Web UI**: Built-in management interface at http://localhost
- **Comprehensive API**: RESTful API for all operations at `/api/v1/`
- **API Documentation**: Interactive Swagger UI at https://yourdomain.com/docs
- **Health Monitoring**: Service health checks and metrics
- **Hot Reload**: Update certificates and routes without downtime

## Quick Start

### Prerequisites
- Docker and Docker Compose
- A domain pointing to your server (for HTTPS)
- GitHub OAuth App (for authentication)
- Docker socket access (for container management features)

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

# Generate an admin token
just token-admin
# Save this token - you'll need it for all admin operations!
```

### 4. Access the Web UI

Open http://localhost in your browser to access the management interface.

## Basic Usage

### Create a Proxy

```bash
# Create proxy with automatic certificate handling
just proxy-create api.yourdomain.com http://backend:8080 [token]

# The proxy will automatically:
# - Check for existing certificates and use them
# - Create production Let's Encrypt certificate if needed
# - Set up HTTP and HTTPS routing
# - Handle certificate generation asynchronously

# For staging/testing (creates staging certificate)
just proxy-create api.yourdomain.com http://backend:8080 true [token]

# Common scenarios:
# 1. First-time proxy with production cert
just proxy-create echo.yourdomain.com http://service:3000

# 2. Proxy with existing certificate (automatically detected)
just proxy-create echo.yourdomain.com http://service:3000

# 3. Testing with staging certificate
just proxy-create echo.yourdomain.com http://service:3000 true

# 4. HTTP-only proxy (no certificate needed)
just proxy-create internal.local http://service:3000 false true true false
```

### Enable OAuth Protection

```bash
# First, ensure OAuth routes are set up
just oauth-routes-setup auth.yourdomain.com [token]

# Create the auth proxy
just proxy-create auth.yourdomain.com http://localhost:9000 [token]

# Enable OAuth on your API proxy
just proxy-auth-enable api.yourdomain.com [token] auth.yourdomain.com [mode]
```

### Docker Service Management

Create and manage Docker containers with automatic port exposure:

```bash
# Create a service with exposed port on localhost
just service-create-exposed my-app nginx:alpine 8080 127.0.0.1 [token]

# Create a service accessible from all interfaces
just service-create-exposed public-api node:18 3000 0.0.0.0 [token]

# Real example: Create mcp-everything service on port 3000
just service-create-exposed mcp-everything mcp-service-mcp-everything:latest 3000 127.0.0.1 [token]

# Add additional ports to existing service
just service-port-add my-app 8081 [bind-address] [source-token] [token]

# List all services and their ports
just service-list
just service-port-list my-app

# Create proxy for service (optional) - makes it accessible via HTTPS
just service-proxy-create my-app [hostname] [enable-https] [token]

# Full example: Service accessible at both localhost:3000 and https://everything.yourdomain.com
just service-create-exposed mcp-everything mcp-service-mcp-everything:latest 3000 127.0.0.1 [token]
just proxy-create everything.yourdomain.com http://mcp-everything:3000 [token]
just proxy-resource-set everything.yourdomain.com [token] [endpoint] [scopes]
```

### Port Management

Services can expose ports with fine-grained control:

```bash
# Check if a port is available
just service-port-check 8080 [bind-address]

# Add/remove ports from services
just service-port-add <service> <port> [bind-address] [source-token] [token]
just service-port-remove <service> <port-name> [token]
just service-port-list <service>
```

### Set Up MCP Echo Servers (Example)

```bash
# One command to set up example protected resources with OAuth
just mcp-echo-setup

# Access them at:
# https://echo-stateless.yourdomain.com/mcp
# https://echo-stateful.yourdomain.com/mcp
```

## Architecture

### Service Components

```
┌─────────────────┐     ┌──────────────────────────┐
│                 │     │                          │
│  HTTP Client    │───▶│       API Service        │
│                 │     │  - HTTP/HTTPS Gateway    │
└─────────────────┘     │  - OAuth Server          │
                        │  - Certificate Manager   │
                        │  - Docker Manager        │
                        └────────────┬─────────────┘
                                     │
                    ┌────────────────┼────────────────┐
                    │                │                │
              ┌─────▼────┐     ┌─────▼────┐    ┌────▼─────┐
              │          │     │  Docker  │    │          │
              │  Redis   │     │  Socket  │    │ Backend  │
              │          │     │          │    │ Services │
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

- **API Service**: All-in-one container with HTTP/HTTPS gateway, OAuth server, certificate manager, and Docker management
- **Redis**: Stores all configuration, certificates, tokens, and session data
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

## MCP (Model Context Protocol) Support

This proxy is fully compliant with MCP 2025-06-18 specification:

### For Protected Resources

```bash
# 1. Create proxy for your protected resource
just proxy-create mcp.yourdomain.com http://mcp-server:3000 [token]

# 2. Enable OAuth protection
just proxy-auth-enable mcp.yourdomain.com [token] auth.yourdomain.com [mode]

# 3. Enable MCP metadata (for automatic metadata endpoints)
just proxy-resource-set mcp.yourdomain.com [token] [endpoint] [scopes]

# Your protected resource is now accessible at https://mcp.yourdomain.com/mcp
# with full OAuth protection and MCP compliance!

# IMPORTANT: Do NOT create specific routes for paths that proxies already handle!
# The proxy automatically forwards ALL paths to the backend - adding routes
# for specific paths like /mcp will bypass OAuth protection.
```

### For Claude Desktop

Add to your Claude configuration:

```json
{
  "mcpServers": {
    "my-server": {
      "url": "https://mcp.yourdomain.com/mcp",
      "auth": {
        "type": "oauth2",
        "authorization_url": "https://auth.yourdomain.com/authorize",
        "token_url": "https://auth.yourdomain.com/token",
        "client_id": "your_client_id",
        "scope": "mcp:read mcp:write"
      }
    }
  }
}
```

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
ADMIN_TOKEN=<your-admin-token>      # Admin API token

# OAuth
GITHUB_CLIENT_ID=<github-client-id>
GITHUB_CLIENT_SECRET=<github-client-secret>
OAUTH_JWT_PRIVATE_KEY_B64=<base64-encoded-private-key>
OAUTH_ALLOWED_GITHUB_USERS=*        # Or comma-separated list

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
just route-create /api/v1/ service backend-api [token]

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
just proxy-oauth-server-set everything.yourdomain.com \
  "https://auth.yourdomain.com" \                    # Custom issuer
  "mcp:read,mcp:write,everything:admin" \            # Custom scopes
  "authorization_code,refresh_token" \               # Grant types
  "code" \                                           # Response types
  "client_secret_post,client_secret_basic" \        # Token auth methods
  "sub,name,email,preferred_username" \             # Claims
  true \                                             # PKCE required
  '{"custom_field": "value"}' \                     # Custom metadata
  true \                                             # Override defaults
  [token]

# View OAuth server configuration
just proxy-oauth-server-show everything.yourdomain.com [token]

# Clear custom OAuth server metadata (revert to defaults)
just proxy-oauth-server-clear everything.yourdomain.com [token]
```

This allows different proxies to:
- Use different OAuth issuers
- Support different scopes per environment (dev vs prod)
- Require PKCE for specific proxies
- Add custom metadata fields for specific clients

### Multi-Domain Certificates

```bash
# Create certificate for multiple domains
just cert-create-multi shared-cert "api.domain.com,app.domain.com,www.domain.com" admin@domain.com [token]

# Attach to proxies
just proxy-cert-attach api.domain.com shared-cert [token]
just proxy-cert-attach app.domain.com shared-cert [token]
```

### External Service Management

```bash
# Register named services for route targeting
just service-register backend-api http://api:8080 [token] [description]
just service-register frontend http://frontend:3000 [token] [description]

# Create routes targeting services
just route-create /api/ service backend-api [token]
just route-create / service frontend [token]
```

### OAuth Client Management

```bash
# Register OAuth client for testing
just oauth-client-register my-app https://myapp.com/callback "mcp:read mcp:write"

# Monitor OAuth activity
just oauth-sessions-list
just oauth-clients-list
just oauth-metrics
```

### Docker Service Management

```bash
# Create a service from Docker image
just service-create my-nginx nginx:latest [dockerfile] [port] [token] [memory] [cpu] [auto-proxy]

# Create a service from Dockerfile
just service-create my-app "" ./dockerfiles/app.Dockerfile 3000 [token]

# Manage service lifecycle
just service-start my-app [token]
just service-stop my-app [token]
just service-restart my-app [token]

# Monitor services
just service-list
just service-logs my-app [lines] [timestamps]
just service-stats my-app

# Create proxy for service
just service-proxy-create my-app [hostname] [enable-https] [token]
```

### Logging and Monitoring

The proxy includes a high-performance logging system with efficient querying:

```bash
# Query logs by client IP
just app-logs-by-ip 192.168.1.100 24

# Query logs by hostname  
just app-logs-by-host api.domain.com 24

# View recent errors
just app-logs-errors 1 50

# Follow logs in real-time
just app-logs-follow 2

# Get complete request flow by correlation ID
just app-logs-correlation 1735689600-https-a7b3c9d2

# Test logging system
just app-logs-test
```

**Features**:
- Request/response correlation tracking
- Multiple indexes for efficient querying (IP, hostname, status, user, path)
- Real-time streaming and monitoring
- Automatic retention (24 hours default)
- Response time statistics
- Unique visitor tracking with HyperLogLog

**Log Query API** (requires admin token):
- `GET /api/v1/logs/ip/{ip}` - Query by client IP
- `GET /api/v1/logs/client/{client_id}` - Query by OAuth client
- `GET /api/v1/logs/correlation/{id}` - Complete request flow
- `GET /api/v1/logs/search` - Advanced search
- `GET /api/v1/logs/errors` - Recent errors

## API Reference

### Base URL
All API endpoints are served under `/api/v1/` prefix, except for OAuth protocol endpoints which are at the root level.

**Note**: When accessing the API directly, use port 9000 (e.g., `http://localhost:9000/api/v1/`). Port 80/443 is for proxied traffic only.

### Authentication
All write operations require a Bearer token in the Authorization header:
```
Authorization: Bearer your-admin-token
```

### Main API Categories

#### Certificate Management (`/api/v1/certificates/*`)
- Create, list, renew, and delete SSL certificates
- Multi-domain certificate support
- ACME challenge handling at `/.well-known/acme-challenge/*`

#### Proxy Management (`/api/v1/proxy/targets/*`)
- Create and manage reverse proxy configurations
- OAuth authentication settings per proxy
- Protected resource metadata configuration (RFC 9728)
- OAuth authorization server metadata per proxy
- Route filtering configuration
- Key endpoints:
  - `POST /api/v1/proxy/targets/{hostname}/resource` - Configure protected resource metadata
  - `POST /api/v1/proxy/targets/{hostname}/oauth-server` - Configure OAuth server metadata
  - `POST /api/v1/proxy/targets/{hostname}/auth` - Configure authentication

#### Token Management (`/api/v1/tokens/*`)
- API token creation and management
- Token-based ownership tracking

#### Route Management (`/api/v1/routes/*`)
- Priority-based path routing
- Support for regex patterns
- Method-specific routing

#### External Service Management (`/api/v1/services/external/*`)
- Named service registration for external URLs
- Service discovery for routing

#### OAuth Admin (`/api/v1/oauth/*`)
- Client and session management
- Token introspection
- System metrics

#### Protected Resources (`/api/v1/resources/*`)
- Protected resource registration
- Resource validation
- Auto-discovery

#### Docker Services (`/api/v1/services/*`)
- Container creation and management
- Service lifecycle control (start/stop/restart)
- Log retrieval and statistics
- Automatic proxy creation for services
- Multi-port configuration with bind address control
- Port management endpoints:
  - `GET /api/v1/services/{name}/ports` - List service ports
  - `POST /api/v1/services/{name}/ports` - Add port to service
  - `DELETE /api/v1/services/{name}/ports/{port_name}` - Remove port

#### Port Management (`/api/v1/ports/*`)
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
just test-mcp-compliance # MCP specification tests
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
   # Example of WRONG approach:
   # just route-create /mcp url http://backend:3000  # DON'T DO THIS!
   
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