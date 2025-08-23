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
- **Zero-Restart Operations**: Dynamic updates without service restarts

### High-Level Components

```
┌─────────────────────────────────────────────────────────┐
│                   Unified Dispatcher                     │
│                    (Ports 80/443)                       │
│           Event-Driven Dynamic Proxy Manager            │
├─────────────────────────────────────────────────────────┤
│                                                         │
│  ┌──────────┐  ┌──────────┐  ┌──────────────────────┐ │
│  │   API    │  │  Proxy   │  │    OAuth Server      │ │
│  │  (9000)  │  │ Instances│  │  (auth.domain.com)   │ │
│  └──────────┘  └──────────┘  └──────────────────────┘ │
│                                                         │
│  ┌──────────────────────────────────────────────────┐ │
│  │           MCP Server (/mcp endpoint)             │ │
│  │      Streamable HTTP Transport (SSE/JSON)        │ │
│  └──────────────────────────────────────────────────┘ │
│                                                         │
├─────────────────────────────────────────────────────────┤
│  ┌──────────┐  ┌──────────┐  ┌──────────────────────┐ │
│  │   Cert   │  │  Docker  │  │   Redis Streams      │ │
│  │  Manager │  │ Services │  │   Event Consumer     │ │
│  └──────────┘  └──────────┘  └──────────────────────┘ │
│                                                         │
├─────────────────────────────────────────────────────────┤
│                    Redis Storage                        │
│         (Configuration, State, Logs, Events)           │
└─────────────────────────────────────────────────────────┘
```

## Documentation Structure

This documentation is organized into modular component-specific files:

### Core Documentation

- **[Development Guidelines](src/CLAUDE.md)** - General development practices, environment setup, async architecture
- **[Just Commands Reference](justfile.md)** - Complete reference for all `just` commands
- **[Python CLI Client](oauth-https-proxy-client/CLAUDE.md)** - Enhanced CLI with smart formatting
- **[Flexible Authentication](src/auth/CLAUDE.md)** - Unified auth system with multiple auth types and configuration layers

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

### Flexible Authentication System
- **Four Authentication Types**: `none` (public), `bearer` (API token), `admin` (admin-only), `oauth` (OAuth 2.1)
- **Three Configuration Layers**: API endpoints, routes, and proxies - each with independent auth settings
- **Pattern-Based Matching**: Wildcard patterns with priority-based resolution
- **Dynamic Configuration**: Configure auth per endpoint/route/proxy via API or Redis
- **Resource Ownership**: Automatic ownership validation for bearer tokens
- **OAuth Integration**: Full OAuth 2.1 with scope, audience, and user allowlist support
- **Performance Optimized**: Built-in caching with configurable TTL
- **Backward Compatible**: Existing auth patterns continue to work

### Token Management
- Bearer token authentication with flexible configuration
- Ownership tracking - tokens own certificates and proxies
- Cascade deletion - removing token removes owned resources
- Certificate email configuration per token
- Admin token for privileged operations

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
- `list_tokens` - Manage API tokens
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

1. **Fully Async Architecture**: All components use async/await for non-blocking operations
2. **Zero-Restart Design**: Unified dispatcher enables dynamic updates without restarts
3. **Simplified Event System**: Just 3 event types (proxy_created, proxy_deleted, certificate_ready) vs 15+ previously
4. **Direct Event Handling**: Dispatcher directly handles all events without intermediate orchestrator
5. **Non-Blocking Reconciliation**: Uses `asyncio.create_task()` for background proxy reconciliation
6. **Unified Dispatcher**: Single entry point for all HTTP/HTTPS traffic and event processing
7. **Redis-Only Storage**: All configuration and state in Redis, no filesystem dependencies
8. **Smart Certificate Handling**: Automatic detection and creation of certificates
9. **Per-Proxy User Allowlists**: Granular GitHub user access control per proxy
10. **PROXY Protocol Support**: Preserves real client IPs through load balancers
11. **Enhanced CLI Client**: Smart table formatting with context-aware display
12. **Exactly-Once Processing**: Redis Streams with single consumer group ensure reliability
13. **Root-Level API**: Clean URLs without version prefixes (`/tokens/`, `/certificates/`, etc.)
14. **Unified Async Logging**: Fire-and-forget logging with Redis Streams, multiple indexes, and real-time analytics
15. **Robust Error Handling**: Comprehensive null checks and graceful degradation throughout

## Environment Configuration

Key environment variables (see component docs for complete list):

```bash
# Core Configuration
REDIS_PASSWORD=<strong-password>    # Required, 32+ bytes
BASE_DOMAIN=example.com            # Base domain for services
LOG_LEVEL=INFO                     # Logging level (TRACE, DEBUG, INFO, WARNING, ERROR, CRITICAL)

# OAuth Configuration  
GITHUB_CLIENT_ID=<github-app-id>
GITHUB_CLIENT_SECRET=<github-secret>
OAUTH_JWT_PRIVATE_KEY_B64=<base64-key>

# Testing
TEST_DOMAIN=test.example.com
TEST_EMAIL=test@example.com
ADMIN_TOKEN=acm_admin_token_here
```

## Docker Services

The system runs two Docker services:

### api Service
- **Ports**: 80, 443, 9000 (API), 10001 (PROXY protocol)
- **Functions**: Proxy, OAuth, certificates, API, web GUI
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
TEST_TOKEN=acm_test_token_here
ADMIN_TOKEN=acm_admin_token_here
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
