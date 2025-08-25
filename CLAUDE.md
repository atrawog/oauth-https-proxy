# HTTPS OAuth Proxy with Protected Resources - Development Guidelines

This document provides comprehensive development and testing guidelines for the OAuth HTTPS Proxy system. For quick start and usage instructions, see [README.md](README.md).

## General Development Guidelines

### API Design Patterns
- **Collection Endpoints**: All collection endpoints (GET lists) require trailing slashes to avoid HTTP 307 redirects
  - Example: `/routes/` not `/routes`
  - FastAPI/Starlette automatically redirects non-trailing slash URLs
  - This applies to: tokens, certificates, services, routes, resources, ports, proxy/targets
- **Root-Level API**: All API endpoints are mounted at the root level (no `/api/v1/` prefix)
  - Clean URLs: `/tokens/`, `/certificates/`, `/proxies/`, etc.

### Execution Requirements
- **Command execution**: ONLY via `just` commands - no direct Python/bash or docker exec execution
- **Configuration**: Single source `.env` file loaded by `just` - all environment variables are documented in their relevant sections
- **Python environment**: `pixi` exclusively
- **Testing**: Real systems only - no mocks, stubs, or simulations via `just test-*` commands
- **Debugging**: All debugging via `just` commands (logs, shell, redis-cli)
- **Database**: Redis for everything (key-value, caching, queues, pub/sub, persistence)

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

## System Architecture

The system provides a complete reverse proxy solution with:
- **Dynamic Reverse Proxy**: Route requests based on hostname and path
- **OAuth 2.1 Server**: Integrated authentication with GitHub OAuth
- **MCP Server**: Model Context Protocol endpoints for LLM integration
- **ACME Certificate Manager**: Automatic SSL from Let's Encrypt
- **Docker Service Management**: Container lifecycle and port management
- **Redis Storage**: All configuration and state in Redis
- **Redis-Based Port Management**: Persistent port allocation with atomic operations
- **Zero-Restart Operations**: Dynamic updates without service restarts

### High-Level Components

```
┌─────────────────────────────────────────────────────────┐
│                   Unified Dispatcher                     │
│                    (Ports 80/443)                       │
│           Event-Driven Dynamic Proxy Manager            │
├─────────────────────────────────────────────────────────┤
│                                                         │
│  ┌──────────┐  ┌──────────────┐  ┌──────────────────┐ │
│  │   API    │  │ Proxy        │  │  OAuth Server    │ │
│  │  (9000)  │  │ Instances    │  │(auth.domain.com) │ │
│  └──────────┘  │(12000-13999) │  └──────────────────┘ │
│                └──────────────┘                        │
│  ┌──────────────────────────────────────────────────┐ │
│  │           MCP Server (/mcp endpoint)             │ │
│  │      Streamable HTTP Transport (SSE/JSON)        │ │
│  └──────────────────────────────────────────────────┘ │
│                                                         │
├─────────────────────────────────────────────────────────┤
│  ┌──────────┐  ┌──────────┐  ┌──────────────────────┐ │
│  │   Cert   │  │  Docker  │  │    Port Manager      │ │
│  │  Manager │  │ Services │  │  (Redis-backed)      │ │
│  └──────────┘  └──────────┘  └──────────────────────┘ │
│                                                         │
├─────────────────────────────────────────────────────────┤
│                    Redis Storage                        │
│    (Configuration, State, Logs, Events, Port Maps)     │
└─────────────────────────────────────────────────────────┘
```

## Current Architecture

### The Proven Architecture Flow
```
Dispatcher → HypercornInstance → ProxyOnlyApp → UnifiedProxyHandler → Backend
(Port 80/443) (PROXY + SSL)      (Starlette)    (OAuth + Routing)
```

### How It Works
1. **Dispatcher** (Ports 80/443): Routes requests to proxy instances based on hostname (SNI for HTTPS)
2. **HypercornInstance**: 
   - Handles PROXY protocol (preserves client IPs)
   - Terminates SSL with certificates from Redis
   - Runs on ports 12xxx (HTTP) and 13xxx (HTTPS)
3. **ProxyOnlyApp**: Minimal Starlette app that forwards all requests to UnifiedProxyHandler
4. **UnifiedProxyHandler**: 
   - Complete OAuth validation with scope checking
   - Route matching and backend selection
   - User allowlist enforcement
   - 912 lines of battle-tested logic

### Why This Architecture Works
1. **PROXY Protocol is Essential**: Without it, we lose client IPs (everything would be 127.0.0.1)
2. **SSL at Hypercorn**: Has access to certificates and application context
3. **OAuth in UnifiedProxyHandler**: Full context for validation (routes, scopes, backends)
4. **Clear Separation**: Each component has one responsibility
5. **Standard Headers**: X-Forwarded-* headers are industry standard
6. **Secure Trust Boundaries**: External X-Auth-* headers are never trusted

## Documentation Structure

This documentation is organized into modular component-specific files:

### Core Documentation

- **[Development Guidelines](src/CLAUDE.md)** - General development practices, environment setup, async architecture
- **[Just Commands Reference](justfile.md)** - Complete reference for all `just` commands
- **[Python CLI Client](oauth-https-proxy-client/CLAUDE.md)** - Enhanced CLI with smart formatting
- **[OAuth Implementation Summary](OAUTH_IMPLEMENTATION_SUMMARY.md)** - Complete OAuth-only system documentation

### Component Documentation

#### API & Web Interface
- **[API Documentation](src/api/CLAUDE.md)** - FastAPI application, routers, web GUI
- **[OAuth Service](src/api/oauth/CLAUDE.md)** - OAuth 2.1 implementation, MCP compliance
- **[MCP Server](src/api/routers/mcp/CLAUDE.md)** - Model Context Protocol server implementation

#### Core Services
- **[Certificate Manager](src/certmanager/CLAUDE.md)** - ACME/Let's Encrypt automation
- **[Proxy Manager](src/proxy/CLAUDE.md)** - Reverse proxy configuration and routing
- **[Docker Services](src/docker/CLAUDE.md)** - Container management and orchestration
- **[Port Management](src/ports/CLAUDE.md)** - Port allocation and access control

#### Infrastructure
- **[Storage Layer](src/storage/CLAUDE.md)** - Redis schema and async operations
- **[Dispatcher](src/dispatcher/CLAUDE.md)** - Request routing and SSL termination
- **[Unified Event System](src/dispatcher/CLAUDE.md#unified-event-architecture)** - Simplified event-driven lifecycle management
- **[Middleware](src/middleware/CLAUDE.md)** - PROXY protocol and request processing
- **[Logging System](src/logging/CLAUDE.md)** - Advanced logging and analytics

## Key Features

### OAuth-Only Authentication System
- **Pure OAuth 2.1**: No bearer tokens (`acm_*`), only OAuth JWT tokens
- **Single Authentication Layer**: Proxy validates OAuth, API trusts headers
- **Three Simple Scopes**: `admin` (write access), `user` (read access), `mcp` (Model Context Protocol)
- **GitHub Integration**: OAuth via GitHub with device flow support
- **Per-Proxy User Allowlists**: Fine-grained access control per domain via `auth_required_users`
- **Per-Proxy Scope Assignment**: Configure which GitHub users get which scopes via `oauth_admin_users`, `oauth_user_users`, `oauth_mcp_users`
- **Trust Headers**: API reads `X-Auth-User`, `X-Auth-Scopes`, `X-Auth-Email` from proxy
- **90% Code Reduction**: Removed ~80KB of authentication complexity

### OAuth Token Management
- **GitHub Device Flow**: CLI-friendly authentication without localhost callbacks
- **JWT Tokens**: RS256 signed with configurable lifetime (30 min default)
- **Refresh Tokens**: Long-lived tokens for session persistence (1 year default)
- **Scope-Based Access**: Tokens include scopes that determine permissions
- **Audience Validation**: Tokens validated for specific resource URIs
- **No Token Storage**: Stateless JWT validation, no token database

### Certificate Management
- ACME v2 protocol with HTTP-01 challenges
- Multi-domain certificates (up to 100 domains)
- Automatic renewal 30 days before expiry
- Redis-exclusive storage (no filesystem)

### Proxy Management
- Dynamic reverse proxy with SSL termination
- WebSocket and SSE streaming support
- Per-proxy OAuth authentication configuration
- Custom header injection and modification
- Route-based request handling with priorities

### Service Management
- Docker container lifecycle management
- External service registration
- Resource limits (CPU, memory)
- Multi-port support with access control
- Automatic port allocation

### OAuth 2.1 Compliance
- GitHub OAuth integration
- Dynamic client registration (RFC 7591)
- Resource indicators (RFC 8707)
- Protected resource metadata (RFC 9728)
- Per-proxy user allowlists

### Per-Proxy GitHub OAuth Configuration
- **Individual GitHub Apps**: Each proxy can have its own GitHub OAuth App credentials
- **Environment Fallback**: Automatically falls back to `GITHUB_CLIENT_ID` and `GITHUB_CLIENT_SECRET` environment variables
- **Dynamic Switching**: OAuth credentials are resolved per-request based on proxy hostname
- **Secure Storage**: Client secrets are stored securely in Redis (never exposed in API responses)
- **Multi-Tenancy Support**: Different proxies can authenticate with different GitHub organizations
- **Zero Downtime**: Update credentials without restarting services
- **Per-Proxy User Access Control**:
  - `auth_required_users`: Which GitHub users can access the proxy (allowlist)
  - `oauth_admin_users`: Which GitHub users get admin scope
  - `oauth_user_users`: Which GitHub users get user scope (* = all)
  - `oauth_mcp_users`: Which GitHub users get mcp scope

### Unified Async Logging Architecture
- **Fire-and-Forget Pattern**: All logging operations are non-blocking using `asyncio.create_task()`
- **Component Isolation**: Each component has immutable component name to prevent contamination
- **Redis Streams Backend**: All logs written to Redis Streams for persistence and querying
- **TRACE Level Support**: Custom level (value=5) for very verbose debugging, below DEBUG
- **Multiple Indexes**: Efficient querying by IP, hostname, status, user, path, etc.
- **Real-Time Streaming**: Live log following with ANSI color support
- **Request Analytics**: Response time percentiles, unique visitor tracking, error analysis
- **No Logger Objects**: Direct function calls (`log_info()`, `log_debug()`, etc.) instead of logger instances

## MCP (Model Context Protocol) Support

The system provides **FULL MCP SUPPORT** for LLM integration:

### MCP Server Implementation ✅
- **Endpoint**: Available at `/mcp` on any configured domain (e.g., `https://auth.domain.com/mcp`)
- **Transport**: Streamable HTTP with SSE (Server-Sent Events) and JSON responses
- **Protocol Versions**: Supports 2024-11-05, 2025-03-26, and 2025-06-18
- **Session Management**: Stateful sessions with persistent context
- **Tool Integration**: 10+ built-in tools for system management

### MCP Tools Available
- `echo` - Test connectivity and message handling
- `health_check` - System health status monitoring
- `list_proxies` - View configured proxy targets
- `create_proxy` - Create new proxy configurations
- `delete_proxy` - Remove proxy configurations
- `list_certificates` - View SSL certificates
- `list_services` - Docker service management
- `get_logs` - Access system logs
- `run_command` - Execute system commands (admin only)

### Claude.ai Integration ✅
- Direct connection support via `https://domain.com/mcp`
- Automatic tool discovery and execution
- Persistent session management
- Full streaming support for real-time responses

### MCP OAuth Compliance ✅
- Resource parameter support in authorization and token endpoints
- Audience-restricted tokens with resource URIs in `aud` claim
- Authorization server metadata endpoint with `resource_indicators_supported: true`
- Dynamic client registration (RFC 7591)
- Token introspection and revocation endpoints
- Protected resource metadata endpoints
- Resource-specific scope enforcement

## Key Implementation Insights

1. **OAuth-Only Authentication**: Complete removal of bearer token system, pure OAuth 2.1
2. **Single Auth Layer**: Proxy validates OAuth, API trusts headers - no dual validation
3. **90% Code Reduction**: Removed ~80KB auth code, 35+ files, 15+ storage methods
4. **Simplified Mental Model**: Three scopes, one auth layer, one trust boundary
5. **Zero-Restart Design**: Unified dispatcher enables dynamic updates without restarts
6. **Simplified Event System**: Just 3 event types (proxy_created, proxy_deleted, certificate_ready)
7. **Direct Event Handling**: Dispatcher directly handles all events without intermediate orchestrator
8. **Non-Blocking Reconciliation**: Uses `asyncio.create_task()` for background proxy reconciliation
9. **Unified Dispatcher**: Single entry point for all HTTP/HTTPS traffic and event processing
10. **Redis-Only Storage**: All configuration and state in Redis, no filesystem dependencies
11. **Smart Certificate Handling**: Automatic detection and creation of certificates
12. **Per-Proxy User Allowlists**: Granular GitHub user access control per proxy
13. **Per-Proxy GitHub OAuth Apps**: Each proxy can have its own GitHub OAuth credentials
14. **PROXY Protocol Support**: Internal use only - preserves real client IPs between dispatcher and proxy instances
15. **Unified Async Logging**: Fire-and-forget logging with Redis Streams, multiple indexes
16. **Trust-Based API**: API endpoints read auth headers without validation
17. **Redis-Based Port Management**: All port allocations stored persistently in Redis with atomic operations
18. **Deterministic Port Allocation**: Hash-based preferred ports ensure consistency across restarts

## Port Configuration

The system uses Redis-based PortManager for all port allocations:

### Port Ranges
- **80/443**: Dispatcher (public-facing)
- **9000**: API (internal only, accessed via Docker service name)
- **12000-12999**: HTTP proxy instances (Redis-allocated, persistent)
- **13000-13999**: HTTPS proxy instances (Redis-allocated, persistent)
- **14000+**: User services (exposed ports)

### Redis Port Management
- **Persistent Mappings**: Stored in `proxy:ports:mappings` Redis hash
- **Atomic Allocation**: No conflicts via Redis locks
- **Deterministic**: Hash-based preferred ports for consistency
- **Auto-Recovery**: Port mappings survive service restarts

## System Bootstrapping and Initialization

### Automatic Localhost Proxy Creation

The system automatically creates a localhost proxy during startup to ensure the API is always accessible:

1. **On System Start** (`src/main.py`):
   - `initialize_default_proxies()` is called during component initialization
   - This function is defined in `src/storage/redis_storage.py`

2. **Default Proxy Configuration** (`src/proxy/models.py:DEFAULT_PROXIES`):
   ```python
   {
       "proxy_hostname": "localhost",
       "target_url": "http://127.0.0.1:9000",  # Points to API service
       "enable_http": True,
       "enable_https": False,
       "auth_enabled": False,  # No auth by default for local access
       "resource_scopes": ["admin", "user", "mcp"],
       # Protected resource metadata for OAuth compliance
   }
   ```

3. **Why Localhost Proxy is Essential**:
   - **Unified Architecture**: ALL traffic goes through the dispatcher → proxy flow
   - **No Direct Access**: Port 9000 (API) is internal only
   - **Consistent Behavior**: Localhost follows same path as all other proxies
   - **OAuth Ready**: Can enable OAuth protection if needed
   - **MCP Support**: Provides protected resource metadata

4. **Port Allocation**:
   - Localhost proxy typically gets port 12000 (first HTTP proxy port)
   - Port mapping stored in Redis: `proxy:ports:mappings`
   - Survives restarts due to Redis persistence

### Startup Sequence

1. **Initialize Components** (`src/main.py:initialize_components()`):
   - Redis storage connection
   - Certificate manager
   - Async components (logger, metrics, etc.)
   
2. **Initialize Default Routes** (`storage.initialize_default_routes()`):
   - OAuth endpoints (`/authorize`, `/token`, `/callback`)
   - ACME challenges (`/.well-known/acme-challenge/*`)
   - Well-known endpoints (`/.well-known/*`)

3. **Initialize Default Proxies** (`storage.initialize_default_proxies()`):
   - Creates localhost proxy if missing
   - Updates existing proxy with latest metadata
   - Preserves user modifications (auth settings, etc.)

4. **Start Dispatcher** (`src/dispatcher/unified_dispatcher.py`):
   - Reconciles all proxies from Redis
   - Creates HypercornInstance for each proxy
   - Allocates ports via PortManager
   - Starts event consumer for dynamic updates

5. **API Registration** (`src/api/routers/registry.py`):
   - All routers registered on single FastAPI app
   - OAuth endpoints available immediately
   - Web UI accessible at http://localhost

### OAuth Bootstrap Configuration

For localhost proxy, OAuth scopes are configured via environment variables:

```bash
# Who gets which scopes on localhost proxy
OAUTH_LOCALHOST_ADMIN_USERS=alice,bob     # Admin scope
OAUTH_LOCALHOST_USER_USERS=*              # User scope for all
OAUTH_LOCALHOST_MCP_USERS=charlie         # MCP scope

# Global default for new proxies
OAUTH_ALLOWED_GITHUB_USERS=*              # Who can authenticate
```

This configuration is read during OAuth callback to determine scope assignment.

## Docker Best Practices

- Services reference each other by name (api, redis)
- No hardcoded IPs for internal communication
- API binds to 0.0.0.0:9000 for container access
- Environment-aware configuration via RUNNING_IN_DOCKER

## Environment Configuration

Key environment variables (see component docs for complete list):

```bash
# Core Configuration
REDIS_PASSWORD=<strong-password>    # Required, 32+ bytes
BASE_DOMAIN=example.com            # Base domain for services
LOG_LEVEL=INFO                     # Logging level (TRACE, DEBUG, INFO, WARNING, ERROR, CRITICAL)

# OAuth Configuration  
GITHUB_CLIENT_ID=<github-app-id>          # Global default, can be overridden per-proxy
GITHUB_CLIENT_SECRET=<github-secret>      # Global default, can be overridden per-proxy
OAUTH_JWT_PRIVATE_KEY_B64=<base64-key>    # RSA private key for JWT signing
OAUTH_ALLOWED_GITHUB_USERS=*              # Global default (* = all users)
OAUTH_LOCALHOST_ADMIN_USERS=alice,bob     # Admin scope for localhost proxy
OAUTH_LOCALHOST_USER_USERS=*              # User scope for localhost proxy
OAUTH_LOCALHOST_MCP_USERS=charlie         # MCP scope for localhost proxy

# Testing
TEST_DOMAIN=test.example.com
TEST_EMAIL=test@example.com
```

## Docker Services

The system runs two Docker services:

### api Service
- **Ports**: 80, 443 (Dispatcher), 9000 (API - internal only)
- **Functions**: Dispatcher, Proxy instances, OAuth, certificates, API, web GUI
- **Networks**: proxy_network

### redis Service  
- **Port**: 6379 (internal only)
- **Functions**: Configuration, state, logs, events
- **Persistence**: Optional volume mount

## Development Workflow

### Local Development Setup
```bash
# Install pixi (Python environment manager)
curl -fsSL https://pixi.sh/install.sh | bash

# Clone repository
git clone <repository>
cd oauth-https-proxy

# Set up development environment
pixi install

# Configure environment
cp .env.example .env
# Edit .env with your configuration

# Start services
just up
```

### Development Commands
```bash
# Run locally without Docker
pixi run python src/main.py

# Shell into container for debugging
just shell

# Access Redis CLI
just redis-cli

# View logs
just logs                      # Show recent logs (chronological order)
just logs-follow               # Follow logs in real-time with ANSI colors
just logs-errors              # Show recent errors
just logs-docker               # View Docker container logs only
```

## Testing Guidelines

### Testing Philosophy
- **No Mocking**: All tests run against real services
- **Integration First**: Test the full stack, not isolated units
- **Real Dependencies**: Use actual Redis, Docker, and network services
- **Environment Parity**: Test environment matches production

### Test Execution
```bash
# Run standard test suite
just test

# Run comprehensive test suite with integration tests
just test-all

# Test specific component
just test tests/test_oauth.py

# Test with verbose output
just test-verbose

# Specific test categories
just test-proxy-all      # All proxy tests
just test-auth          # OAuth tests
just test-certificates  # Certificate tests
just test-docker        # Docker service tests
```

### Test Configuration
```bash
# Testing environment variables
TEST_DOMAIN=test.example.com
TEST_EMAIL=test@example.com
TEST_PROXY_TARGET_URL=https://example.com
# OAuth tokens are obtained via just oauth-login
# No bearer tokens (acm_*) or admin tokens anymore - pure OAuth JWT only
```

### Debugging Tests
```bash
# Run tests with debugging output
LOG_LEVEL=DEBUG just test

# Check test logs
just logs-errors 1 100

# Monitor test execution
just logs-follow | grep TEST
```

## Project Structure

```
oauth-https-proxy/
├── src/                    # Source code (see src/CLAUDE.md)
│   ├── api/               # FastAPI application and routers
│   ├── certmanager/       # ACME certificate management
│   ├── dispatcher/        # Unified HTTP/HTTPS dispatcher with event handling
│   ├── docker/            # Docker service management
│   ├── logging/           # Advanced logging system
│   ├── middleware/        # PROXY protocol and middleware
│   ├── ports/             # Port management
│   ├── proxy/             # Reverse proxy implementation
│   └── storage/           # Redis storage layer
├── tests/                  # Pytest test suite
├── scripts/                # Utility and testing scripts
├── docs/                   # JupyterBook documentation
├── oauth-https-proxy-client/ # Python CLI client
├── docker-compose.yml      # Service orchestration
├── justfile               # Task automation commands
├── pixi.toml              # Python environment config
├── .env.example           # Example configuration
└── CLAUDE.md files        # Component documentation
```

## Architecture Decisions and Lessons Learned

### Why We Don't Do "OAuth at the Edge"

We attempted to implement OAuth validation at the TCP/SSL termination layer (EnhancedProxyInstance) but discovered this approach is fundamentally flawed:

1. **Incomplete Context**: The edge layer doesn't know:
   - Which backend to route to
   - What scopes are required for each path
   - User allowlists per proxy
   - Route-specific authentication overrides
   
2. **Security Hole**: Partial validation creates vulnerabilities:
   - Basic JWT validation (is token valid?) isn't enough
   - You need scope checking (does user have required permissions?)
   - You need user allowlists (is this user allowed for this proxy?)
   - Trusting partially-validated headers is dangerous
   
3. **Duplication**: To do OAuth properly at the edge would require:
   - Duplicating all routing logic
   - Duplicating all scope requirements
   - Duplicating all backend configurations
   - This creates maintenance nightmares and bugs

### The Correct Architecture

```
Dispatcher → HypercornInstance → ProxyOnlyApp → UnifiedProxyHandler → Backend
             (PROXY + SSL)        (Starlette)    (OAuth + Routing)
```

- **HypercornInstance**: Handles PROXY protocol and SSL termination
- **ProxyOnlyApp**: Minimal Starlette wrapper
- **UnifiedProxyHandler**: Complete OAuth validation with full context
- **Single Responsibility**: Each component does one thing well

### Key Lessons Learned

1. **Authentication needs context**: You can't validate OAuth without knowing the application requirements
2. **Trust boundaries matter**: Never trust partial validation - either fully validate or don't
3. **Working code > clever architecture**: The simpler solution that works is better than complex ideas
4. **Security first**: A security hole from incomplete validation is worse than slightly later validation

## Contributing

When contributing to this project:

1. **Read Component Documentation**: Review relevant CLAUDE.md files
2. **Use Just Commands**: Never run commands directly
3. **Follow Async Patterns**: All new code should be async
4. **Update Documentation**: Keep CLAUDE.md files current
5. **Test Thoroughly**: Use real services, no mocks
6. **Follow Development Guidelines**: Adhere to patterns described above

## License

[See LICENSE file]

## Support

For issues or questions:
- Review component documentation in respective CLAUDE.md files
- Check [justfile.md](justfile.md) for available commands
- Examine logs with `just logs` commands

---
