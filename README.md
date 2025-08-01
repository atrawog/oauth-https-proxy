# MCP HTTP/HTTPS OAuth Proxy

A production-ready HTTP/HTTPS proxy with integrated OAuth 2.1 server, automatic ACME certificate management, and Model Context Protocol (MCP) compliance. This proxy provides secure, authenticated access to backend services with automatic SSL/TLS certificate provisioning.

## Features

### Core Proxy Capabilities
- **Dynamic Reverse Proxy**: Route traffic to multiple backend services
- **Automatic HTTPS**: Obtain and renew Let's Encrypt certificates via ACME
- **OAuth 2.1 Integration**: Built-in OAuth server with GitHub authentication
- **MCP Compliance**: Full support for Model Context Protocol with OAuth protection
- **WebSocket Support**: Proxy WebSocket and Server-Sent Events (SSE) connections
- **Route Management**: Priority-based path routing with regex support
- **Instance Registry**: Named service discovery for internal services
- **Docker Service Management**: Create and manage Docker containers dynamically
- **MCP Metadata**: Automatic metadata endpoints for MCP-compliant services
- **Port Management**: Comprehensive port allocation with bind address control
- **Multi-Port Services**: Services can expose multiple ports with access controls

### Security Features
- **Token-Based API**: All administrative operations require bearer tokens
- **OAuth Protection**: Protect any proxied service with OAuth authentication
- **Certificate Isolation**: Multi-domain certificates with ownership tracking
- **Redis-Only Storage**: No filesystem persistence for enhanced security

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
git clone https://github.com/yourusername/mcp-http-proxy
cd mcp-http-proxy

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
# Start all services
just up

# Generate an admin token
just generate-admin-token
# Save this token - you'll need it for all admin operations!
```

### 4. Access the Web UI

Open http://localhost in your browser to access the management interface.

## Basic Usage

### Create a Proxy

```bash
# Proxy example.com to a backend service
just proxy-create api.yourdomain.com http://backend:8080 $ADMIN_TOKEN

# The proxy will automatically:
# - Obtain an HTTPS certificate
# - Set up HTTP and HTTPS routing
# - Start forwarding traffic
```

### Enable OAuth Protection

```bash
# First, ensure OAuth routes are set up
just oauth-routes-setup auth.yourdomain.com $ADMIN_TOKEN

# Create the auth proxy
just proxy-create auth.yourdomain.com http://localhost:9000 $ADMIN_TOKEN

# Enable OAuth on your API proxy
just proxy-auth-enable api.yourdomain.com $ADMIN_TOKEN auth.yourdomain.com forward
```

### Docker Service Management

Create and manage Docker containers with automatic port exposure:

```bash
# Create a service with exposed port on localhost
just service-create-exposed my-app nginx:alpine 8080 127.0.0.1 $ADMIN_TOKEN

# Create a service accessible from all interfaces
just service-create-exposed public-api node:18 3000 0.0.0.0 $ADMIN_TOKEN

# Real example: Create mcp-everything service on port 3000
just service-create-exposed mcp-everything mcp-service-mcp-everything:latest 3000 127.0.0.1 $ADMIN_TOKEN

# Add additional ports to existing service
just service-port-add my-app admin 8081 8081 127.0.0.1 $ADMIN_TOKEN

# List all services and their ports
just service-list
just service-port-list my-app

# Create proxy for service (optional) - makes it accessible via HTTPS
just service-proxy-create my-app my-app.yourdomain.com true $ADMIN_TOKEN

# Full example: Service accessible at both localhost:3000 and https://everything.yourdomain.com
just service-create-exposed mcp-everything mcp-service-mcp-everything:latest 3000 127.0.0.1 $ADMIN_TOKEN
just proxy-create everything.yourdomain.com http://mcp-everything:3000 $ADMIN_TOKEN
just proxy-mcp-enable everything.yourdomain.com $ADMIN_TOKEN /mcp
```

### Port Management

Control port allocation and access:

```bash
# View all allocated ports
just port-list

# Check available port ranges
just port-available

# Create port access token for specific services/ports
just port-token-create api-access "my-app,api-service" "8080,8081" 30d

# Revoke port access
just port-token-revoke api-access
```

### Set Up MCP Echo Servers (Example)

```bash
# One command to set up example MCP servers with OAuth
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
│  HTTP Client    │────▶│     Proxy Service        │
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

- **Proxy Service**: All-in-one container with HTTP/HTTPS gateway, OAuth server, certificate manager, and Docker management
- **Redis**: Stores all configuration, certificates, tokens, and session data
- **Docker Socket**: Enables dynamic container creation and management
- **Backend Services**: Your applications (MCP servers, APIs, Docker containers)

### Request Flow

1. **Incoming Request** → Proxy receives on port 80/443
2. **Route Matching** → Finds target based on hostname/path
3. **Auth Check** → Validates OAuth token if required
4. **Certificate** → Loads SSL certificate for HTTPS
5. **Forward** → Proxies request to backend service
6. **Response** → Returns backend response to client

## MCP (Model Context Protocol) Support

This proxy is fully compliant with MCP 2025-06-18 specification:

### For MCP Servers

```bash
# 1. Create proxy for your MCP server
just proxy-create mcp.yourdomain.com http://mcp-server:3000 $ADMIN_TOKEN

# 2. Enable OAuth protection
just proxy-auth-enable mcp.yourdomain.com $ADMIN_TOKEN auth.yourdomain.com forward

# 3. Register as MCP resource
just resource-register https://mcp.yourdomain.com mcp.yourdomain.com "My MCP Server"

# 4. Enable MCP metadata (optional - for automatic metadata endpoints)
just proxy-mcp-enable mcp.yourdomain.com $ADMIN_TOKEN /mcp "mcp:read mcp:write"

# Your MCP server is now accessible at https://mcp.yourdomain.com/mcp
# with full OAuth protection and MCP compliance!
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
```

### Route Configuration

Routes are managed dynamically via API/CLI:

```bash
# Create a route
just route-create /api/v1/ instance backend-api $ADMIN_TOKEN

# List all routes
just route-list

# Routes have priorities (higher = checked first)
# - 100: ACME challenges
# - 95: OAuth endpoints  
# - 90: API routes
# - 50: Default priority
```

## Advanced Usage

### Multi-Domain Certificates

```bash
# Create certificate for multiple domains
just cert-create-multi shared-cert "api.domain.com,app.domain.com,www.domain.com" admin@domain.com $ADMIN_TOKEN

# Attach to proxies
just proxy-cert-attach api.domain.com shared-cert $ADMIN_TOKEN
just proxy-cert-attach app.domain.com shared-cert $ADMIN_TOKEN
```

### Instance Registry

```bash
# Register named services for route targeting
just instance-register backend-api http://api:8080 $ADMIN_TOKEN "Backend API"
just instance-register frontend http://frontend:3000 $ADMIN_TOKEN "Frontend"

# Create routes targeting instances
just route-create /api/ instance backend-api $ADMIN_TOKEN
just route-create / instance frontend $ADMIN_TOKEN
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
just service-create my-nginx nginx:latest "" 8080 $ADMIN_TOKEN "512m" "1.0" true

# Create a service from Dockerfile
just service-create my-app "" ./dockerfiles/app.Dockerfile 3000 $ADMIN_TOKEN

# Manage service lifecycle
just service-start my-app
just service-stop my-app
just service-restart my-app

# Monitor services
just service-list
just service-logs my-app 100 true
just service-stats my-app

# Create proxy for service
just service-proxy-create my-app app.domain.com true $ADMIN_TOKEN
```

## API Reference

### Base URL
All API endpoints are served under `/api/v1/` prefix, except for OAuth protocol endpoints which are at the root level.

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
- Route filtering configuration

#### Token Management (`/api/v1/tokens/*`)
- API token creation and management
- Token-based ownership tracking

#### Route Management (`/api/v1/routes/*`)
- Priority-based path routing
- Support for regex patterns
- Method-specific routing

#### Instance Registry (`/api/v1/instances/*`)
- Named service registration
- Internal service discovery

#### OAuth Admin (`/api/v1/oauth/*`)
- Client and session management
- Token introspection
- System metrics

#### MCP Resources (`/api/v1/resources/*`)
- MCP server registration
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
- Local: http://localhost/docs
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
mcp-http-proxy/
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
   just cert-create test-cert yourdomain.com admin@domain.com $ADMIN_TOKEN staging
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
   
   # View proxy logs
   just logs proxy
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

### Debugging Commands

```bash
just health              # System health check
just stats               # Resource statistics
just cleanup-orphaned    # Clean up orphaned resources
just redis-cli          # Direct Redis access
just shell              # Shell into proxy container
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