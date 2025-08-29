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
- **Testing**: Real systems only - no mocks, stubs, or simulations via `just test` commands
- **Debugging**: All debugging via `just` commands (logs, shell, redis-cli)
- **Database**: Redis for everything (key-value, caching, queues, pub/sub, persistence)

### Environment Variable Chain (CRITICAL)
The environment variable chain for `just` commands works as follows:
1. **Just loads .env**: The `justfile` has `set dotenv-load := true` and `set export := true`
2. **Just exports to shell**: All loaded variables are exported to the shell environment
3. **Pixi inherits environment**: When `just` runs `pixi run`, pixi inherits the full environment
4. **Python receives variables**: Python scripts access via `os.getenv()`

**IMPORTANT**: The `.env` file is loaded from the justfile's directory, NOT the current working directory.
This means when testing, you must either:
- Run commands from the project root directory
- Use absolute paths in `set dotenv-path`
- Create test justfiles with proper dotenv-path settings

### Code Change Verification (CRITICAL - Required After EVERY Change)

**ALWAYS follow these steps after ANY code change, no matter how small:**

1. **Restart the API Service**
   ```bash
   just restart  # or docker compose restart api
   ```
   - Code changes are NOT hot-reloaded
   - The container must be restarted to load new code
   - Verify restart completed: `just health`

2. **Test the Changed Component**
   ```bash
   # Example: After changing proxy code
   just proxy list
   just proxy show localhost
   
   # Example: After changing services code
   just service list
   just status
   ```

3. **Check All Affected Services**
   ```bash
   just status        # Overall system health
   just health        # API health check
   just log errors    # Check for new errors
   ```

4. **Verify with the Actual Commands That Failed**
   - Re-run the EXACT command that was failing
   - Don't assume it works - VERIFY it works
   - Test with proper authentication (Bearer tokens)

5. **Check for Side Effects**
   ```bash
   # Check logs for errors or warnings
   just log errors --limit 20
   
   # Monitor real-time logs while testing
   just log follow
   
   # Check specific component logs
   docker compose logs api --tail=100 | grep -i error
   ```

**Common Mistakes to Avoid:**
- ❌ Making multiple changes without testing each one
- ❌ Assuming the change works without verification
- ❌ Testing with cached tokens - always refresh: `just oauth refresh`
- ❌ Not checking logs for hidden errors
- ❌ Forgetting that Docker doesn't hot-reload Python code

**Why This Matters:**
- Docker containers cache the code at startup
- Import errors might only appear after restart
- Dependencies between modules can cause cascade failures
- Authentication state might be cached
- A "small" change can break unrelated functionality

### Root Cause Analysis (Required Before any Code or Configuration Change)
1. Why did it fail? (surface symptom)
2. Why did that condition exist? (enabling circumstance)
3. Why was it allowed? (systemic failure)
4. Why wasn't it caught? (testing blindness)
5. Why will it never happen again? (prevention fix)

### Quick Verification Checklist

**After EVERY code change, run these commands in order:**

```bash
# 1. Restart the API service
just restart

# 2. Wait for service to be ready
sleep 5

# 3. Check system health
just health

# 4. Verify overall status
just status

# 5. Check for recent errors
just log errors --limit 10

# 6. Test the specific feature you changed
# (Replace with appropriate command for your change)
just proxy list  # for proxy changes
just service list  # for service changes
just cert list  # for certificate changes
```

**If ANY step fails:**
- Check logs: `docker compose logs api --tail=200`
- Look for import errors or exceptions
- Verify your code changes are correct
- Check if dependencies are properly imported
- Ensure type hints match actual types (e.g., UnifiedStorage vs RedisStorage)

### Security Best Practices
- All sensitive values (tokens, passwords, secrets) should be generated securely
- Redis password is required and should be strong (32+ random bytes recommended)
- OAuth JWT private key must be base64-encoded
- ACME URLs can be switched between staging and production for testing
- HTTP routing configuration is managed via Redis, not environment variables
- Docker socket access requires appropriate group permissions (DOCKER_GID)

### System Diagnostics and Debugging

When diagnosing issues or accessing the system for debugging, use these `just` commands to interact with different system layers:

#### Understanding the Two Logging Systems

The system has two distinct logging mechanisms that serve different purposes:

1. **Docker/Container Logs** (stdout/stderr):
   - Raw output from container processes
   - Accessed via `docker logs` or `just service logs <name>`
   - Contains startup messages, crash reports, uncaught exceptions
   - Useful for: Container health, startup issues, fatal errors
   - Limited retention (based on Docker logging driver)
   - Unstructured text format

2. **Redis Application Logs** (Structured Logs):
   - Application-level logs written to Redis Streams
   - Accessed via `just log` commands
   - Contains HTTP requests, OAuth flows, proxy operations, API calls
   - Useful for: Request tracing, performance analysis, security auditing
   - Persistent storage with configurable retention
   - Structured with multiple indexes (IP, hostname, user, status, etc.)
   - Supports real-time following with color output

#### Log Commands for Diagnostics

```bash
# View recent application logs (Redis-based)
just log show                     # Last 100 logs chronologically
just log errors                   # Recent errors only
just log follow                   # Real-time log following with colors

# Search logs by various criteria
just log ip 192.168.1.1          # Logs from specific IP
just log hostname api.example.com # Logs for specific hostname
just log user alice              # Logs for specific user
just log status 401              # Logs with specific HTTP status
just log path /oauth/token       # Logs for specific path
just log method POST             # Logs for specific HTTP method

# OAuth-specific debugging
just log oauth                   # All OAuth-related logs
just log oauth-flow              # OAuth flow tracking
just log oauth-debug             # Detailed OAuth debugging
just log oauth-user bob          # OAuth logs for specific user

# Performance analysis
just log slow                    # Slow requests (>1s)
just log stats                   # Request statistics and analytics

# Container logs (Docker-based)
just service logs api            # Docker logs for API container
just service logs redis          # Docker logs for Redis container
```

#### Redis Commands for State Inspection

```bash
# Interactive Redis CLI (with password authentication)
just redis-cli                   # Opens Redis interactive shell

# Direct Redis commands
just redis 'KEYS proxy:*'        # List all proxy-related keys
just redis 'GET proxy:localhost' # Get specific proxy configuration
just redis 'HGETALL proxy:ports:mappings' # View port allocations
just redis 'ZRANGE log:recent 0 10' # View recent log entries
just redis 'INFO memory'         # Check Redis memory usage

# Utility commands
just redis-keys 'oauth:*'        # List keys matching pattern
just redis-info                  # Show Redis server stats
```

#### Python Commands for Advanced Debugging

```bash
# Interactive Python shell in container environment
just python                      # Starts Python REPL with full environment

# Execute Python code directly
just python "import redis; print('Connected')"
just python "from src.storage import RedisStorage; print(RedisStorage())"

# Run diagnostic scripts
just script scripts/test_oauth.py
just script scripts/check_proxies.py --verbose
```

#### Shell Access for Direct Investigation

```bash
# Open bash shell in API container
just shell                       # Full shell access with pixi environment

# Execute commands in container
just exec ls -la /app           # List application files
just exec cat /app/.env         # View environment (be careful with secrets!)
just exec pixi run pip list     # List installed packages
```

#### Common Diagnostic Workflows

##### 1. OAuth Authentication Issues
```bash
# Check OAuth configuration
just oauth status                # View current token status
just log oauth-debug             # Detailed OAuth logs
just redis 'KEYS oauth:*'        # Inspect OAuth state in Redis
just python "from src.api.oauth import *; print(get_oauth_config())"
```

##### 2. Proxy Not Working
```bash
# Check proxy configuration
just proxy show <hostname>       # View proxy configuration
just log hostname <hostname>     # View logs for this proxy
just redis "GET proxy:<hostname>" # Check Redis state
just service logs api | grep <hostname> # Check container logs
```

##### 3. Certificate Issues
```bash
# Check certificate status
just cert list                   # List all certificates
just cert show <name>           # View specific certificate
just log search "acme"          # ACME-related logs
just redis 'KEYS cert:*'        # Certificate keys in Redis
```

##### 4. Performance Problems
```bash
# Analyze performance
just log stats                  # Overall statistics
just log slow                   # Identify slow requests
just redis-info | grep memory   # Check memory usage
just service stats api          # Container resource usage
```

##### 5. Startup Issues
```bash
# Debug startup problems
just service logs api | head -100  # Initial startup logs
just shell                         # Interactive debugging
cat /var/log/supervisor/*.log     # Supervisor logs (if applicable)
just python "from src.main import *" # Test imports
```

#### Best Practices for Diagnostics

1. **Start with Application Logs**: Use `just log` commands first - they contain structured, searchable information
2. **Check Container Logs for Crashes**: Use `just service logs` when services won't start or crash
3. **Use Redis CLI for State**: Inspect actual stored state when configuration seems wrong
4. **Python REPL for Complex Debugging**: Import modules and test functionality interactively
5. **Correlate Log Sources**: Match timestamps between Redis logs and Docker logs for full picture
6. **Follow Real-Time During Testing**: Use `just log follow` while reproducing issues
7. **Export Logs for Analysis**: Pipe log output to files for detailed analysis

#### Example: Complete Diagnostic Session
```bash
# 1. Check system health
just health

# 2. View recent errors
just log errors --limit 50

# 3. Check specific user's activity
just log user alice --hours 1

# 4. Inspect OAuth state
just redis 'KEYS oauth:session:*' 

# 5. Test in Python environment
just python
>>> from src.storage import RedisStorage
>>> storage = RedisStorage()
>>> await storage.get_proxy("localhost")

# 6. Monitor live traffic
just log follow | grep POST

# 7. Check container health
just service stats api
```

### OAuth Authentication Requirements (CRITICAL)
**Circular Dependency Prevention**: The following OAuth endpoints MUST be excluded from authentication on the localhost proxy to prevent circular dependencies:

#### Required OAuth Exclusions
These endpoints must be accessible without authentication:
- `/token` - Token refresh endpoint (prevents "need token to get token" deadlock)
- `/device/code` - Device flow initiation
- `/device/token` - Device flow polling  
- `/authorize` - OAuth authorization
- `/callback` - OAuth callback
- `/jwks` - Public key distribution
- `/.well-known/oauth-authorization-server` - OAuth metadata
- `/register` - Dynamic client registration (RFC 7591)

#### Additional Public Endpoints
- `/health` - Health check endpoint
- `/.well-known/*` - All well-known endpoints (OAuth metadata, MCP resource metadata)

**Configuration**: Set `auth_excluded_paths` on the localhost proxy:
```python
auth_excluded_paths = [
    "/token",
    "/device/",  # Covers /device/code and /device/token
    "/authorize",
    "/callback",
    "/jwks",
    "/.well-known/",
    "/register",
    "/health"
]
```

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
(Pure TCP)    (Port 12xxx/13xxx)               (All HTTP logic)
```

### How It Works
1. **Dispatcher** (Ports 80/443): Pure TCP forwarder
   - Extracts hostname using h11 (HTTP) or SNI (HTTPS)
   - Looks up target port in Redis
   - Adds PROXY protocol header
   - Forwards raw TCP bidirectionally
   - NO HTTP parsing, routing, or modification
   
2. **HypercornInstance**: 
   - Handles PROXY protocol (preserves client IPs)
   - Terminates SSL with certificates from Redis
   - Runs on ports 12xxx (HTTP) and 13xxx (HTTPS)
   
3. **ProxyOnlyApp**: Minimal Starlette app that forwards all requests to UnifiedProxyHandler

4. **UnifiedProxyHandler**: 
   - Complete OAuth validation with scope checking
   - Route matching and backend selection
   - User allowlist enforcement
   - All HTTP-aware logic happens here

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
- **Special Architecture**: MCP requests are intercepted BEFORE FastAPI to bypass middleware bugs (see [Architecture Decisions](#why-mcp-bypasses-fastapi-middleware))

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

### MCP Compliance Testing

The system includes comprehensive MCP compliance testing tools that verify full specification compliance:

#### Quick Test Commands
```bash
# Run full MCP compliance test suite
just mcp-test

# Test against a specific MCP endpoint
just mcp-test https://auth.example.com/mcp

# Run specific test category
just mcp-test https://localhost/mcp session_basic
just mcp-test https://localhost/mcp tools_advanced
just mcp-test https://localhost/mcp protocol

# Run with verbose output for debugging
just mcp-test-verbose https://auth.example.com/mcp

# Run stress tests (50 concurrent sessions)
just mcp-stress https://auth.example.com/mcp 50
```

#### Test Categories
- **session_basic**: Session ID format, cryptographic security
- **session_advanced**: State persistence, timeout, header handling
- **tools_basic**: Unique names, descriptions, schema validation
- **tools_advanced**: Error handling, parameter validation, concurrent execution
- **protocol**: Version negotiation, capabilities, JSON-RPC compliance
- **all**: Run all test categories (default)

#### Compliance Requirements Tested
The test suite verifies compliance with:
- [Session Management](https://modelcontextprotocol.io/specification/2025-06-18/basic/transports#session-management)
  - Session IDs contain only visible ASCII (0x21-0x7E)
  - Session IDs are cryptographically secure with high entropy
  - Session state persists across requests
  - Session timeout mechanisms work correctly
  - Header case sensitivity follows HTTP standards
  
- [Server Tools](https://modelcontextprotocol.io/specification/2025-06-18/server/tools)
  - Tools have unique names
  - Tools have descriptions
  - Tool parameters follow JSON Schema
  - Invalid tool calls return proper errors
  - Parameter validation works correctly
  - Concurrent tool execution is supported

- [Protocol Features](https://modelcontextprotocol.io/specification/2025-06-18/basic/transports#streamable-http)
  - Protocol version negotiation works correctly
  - Capabilities are properly defined
  - List changed notifications are declared
  - JSON-RPC 2.0 compliance
  - Large payload handling

#### Test Output
Tests produce detailed compliance reports showing:
- Pass/Fail status for each requirement
- Specification references for each test
- Detailed error messages and warnings
- Performance metrics for tool execution
- Overall compliance percentage

Example output:
```
======================================================================
📊 MCP COMPLIANCE TEST REPORT
======================================================================
Total Tests: 16
Passed: 16
Failed: 0
Pass Rate: 100.0%

🎉 FULLY COMPLIANT - ALL TESTS PASSED!
======================================================================
```

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
19. **URL-Only Routing**: Eliminated PORT/SERVICE/HOSTNAME types - all routes use explicit URLs (`http://api:9000`)
20. **Clean Route IDs**: Routes have predictable IDs matching endpoints (`token` not `token-80c106aa`)
21. **Pure TCP Forwarding**: Dispatcher is a Layer 4 forwarder using h11 only for hostname extraction - no HTTP handling
22. **h11 for Safety**: Uses the same HTTP/1.1 parser as httpx/uvicorn for safe hostname extraction without manual parsing
23. **MCP ASGI Interception**: MCP requests bypass FastAPI middleware via MCPASGIMiddleware to avoid BaseHTTPMiddleware SSE bugs

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
   - All routes created from `DEFAULT_ROUTES` in `src/proxy/routes.py`
   - OAuth endpoints (`/authorize`, `/token`, `/callback`, `/device/*`, etc.)
   - ACME challenges (`/.well-known/acme-challenge/*`)
   - Well-known endpoints (`/.well-known/*`)
   - All routes use URL type exclusively (`http://api:9000`)
   - Clean route IDs matching endpoints (e.g., `token` not `token-80c106aa`)

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
OAUTH_LOCALHOST_USER_USERS=charlie,dave   # User scope (no wildcards)
OAUTH_LOCALHOST_MCP_USERS=emily           # MCP scope

# Global defaults for new proxies (explicit users only)
OAUTH_ADMIN_USERS=alice,bob               # Users with admin scope
OAUTH_USER_USERS=charlie,dave             # Users with read-only scope
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
OAUTH_ADMIN_USERS=alice,bob               # Users with admin scope (no wildcards)
OAUTH_USER_USERS=charlie,dave             # Users with read-only scope
OAUTH_LOCALHOST_ADMIN_USERS=alice,bob     # Admin scope for localhost proxy
OAUTH_LOCALHOST_USER_USERS=charlie,dave   # User scope for localhost proxy
OAUTH_LOCALHOST_MCP_USERS=emily           # MCP scope for localhost proxy

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

# Common development commands (see "System Diagnostics and Debugging" section for comprehensive guide)
just shell                     # Shell into container for debugging
just redis-cli                 # Access Redis CLI
just python                    # Interactive Python REPL
just log follow                # Follow logs in real-time with ANSI colors
just log errors                # Show recent errors
just service logs api          # View Docker container logs
```

For comprehensive debugging and diagnostic commands, see the **[System Diagnostics and Debugging](#system-diagnostics-and-debugging)** section above.

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
LOG_LEVEL=DEBUG just test

# Specific test categories
just test tests/test_proxy.py      # All proxy tests
just test tests/test_oauth.py      # OAuth tests  
just test tests/test_certificates.py  # Certificate tests
just test tests/test_docker.py     # Docker service tests

# MCP compliance testing
just mcp-test                      # Full MCP compliance suite
just mcp-test-verbose              # Verbose compliance testing
just mcp-stress                    # MCP stress testing (50 sessions)
```

### Test Configuration
```bash
# Testing environment variables
TEST_DOMAIN=test.example.com
TEST_EMAIL=test@example.com
TEST_PROXY_TARGET_URL=https://example.com
# OAuth tokens are obtained via just oauth login
# No bearer tokens (acm_*) or admin tokens anymore - pure OAuth JWT only
```

### Debugging Tests
```bash
# Run tests with debugging output
LOG_LEVEL=DEBUG just test

# Check test logs
just log errors --hours 1 --limit 100

# Monitor test execution
just log follow | grep TEST
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

### Why MCP Bypasses FastAPI Middleware

We discovered that Starlette's BaseHTTPMiddleware has a critical bug with Server-Sent Events (SSE) that affects MCP's streaming responses:

1. **The Bug**: BaseHTTPMiddleware crashes with `RuntimeError: Unexpected message received: http.request` when HTTP/1.1 connections are reused after SSE responses
   - SSE keeps connections open for streaming
   - HTTP/1.1 keep-alive reuses connections  
   - BaseHTTPMiddleware's disconnect listener doesn't expect new requests
   - The middleware crashes on connection reuse

2. **Failed Approaches**: Standard mounting methods all go through middleware
   - FastAPI routes: Processed after middleware
   - Starlette Mount: Still within FastAPI's middleware stack
   - Custom BaseRoute: Routes are handled after middleware
   - The fundamental issue: Can't bypass middleware from within FastAPI

3. **The Solution**: MCPASGIMiddleware intercepts before FastAPI
   ```
   Hypercorn → MCPASGIMiddleware → MCP SDK (for /mcp)
                      ↓
                   FastAPI (for everything else)
   ```
   - ASGI wrapper sits between Hypercorn and FastAPI
   - Checks if path == "/mcp"
   - Routes directly to MCP SDK, bypassing ALL middleware
   - Everything else goes through normal FastAPI flow

4. **Benefits of This Architecture**:
   - Complete bypass of BaseHTTPMiddleware bug
   - No SSE disconnect errors
   - Clean separation of concerns
   - MCP performance improvement (skips middleware)
   - All other endpoints work normally
   - Future-proof against Starlette changes

## Troubleshooting

### OAuth Token Refresh Failures

#### Symptom
```
Token refresh failed - please run: proxy-client oauth login
```

#### Root Causes and Solutions

1. **Circular Authentication Dependency**
   - **Cause**: The `/token` endpoint requires authentication to access
   - **Solution**: Ensure localhost proxy has correct `auth_excluded_paths` (see OAuth Authentication Requirements above)
   - **Test**: `curl -X POST http://localhost/token` should NOT return 401

2. **Environment Variables Not Loaded**
   - **Cause**: Running commands outside project root or `.env` not found
   - **Solution**: Always run `just` commands from project root directory
   - **Test**: Check `.env` file contains both OAUTH_ACCESS_TOKEN and OAUTH_REFRESH_TOKEN

3. **Token Actually Expired**
   - **Cause**: Refresh token has expired (1 year lifetime)
   - **Solution**: Run `just oauth login` to get new tokens
   - **Test**: Check token expiry with `just oauth status`

4. **API Connection Issues**
   - **Cause**: API service not running or not accessible
   - **Solution**: Ensure services are up with `just up`
   - **Test**: `curl http://localhost/health` should return 200

#### Prevention
- Always configure `auth_excluded_paths` for OAuth endpoints on localhost proxy
- Use `just oauth status` to monitor token validity
- Run `just oauth refresh` proactively before tokens expire
- Ensure `.env` file has valid OAUTH_ACCESS_TOKEN and OAUTH_REFRESH_TOKEN

### Testing OAuth Token Refresh
```bash
# Test that token endpoint is accessible without auth
curl -X POST http://localhost/token -d "grant_type=refresh_token&refresh_token=${OAUTH_REFRESH_TOKEN}&client_id=device_flow_client"

# Test token refresh via client
just oauth refresh

# Verify new token works
just proxy list
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
- Examine logs with `just log` commands

---
