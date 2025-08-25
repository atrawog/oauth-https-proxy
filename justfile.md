# Justfile Commands Documentation

## Overview

All system operations are executed via `just` commands. This ensures consistent environment loading, proper execution context, and simplified command syntax.

## System Management

### Service Management
```bash
just up                      # Start all services
just down                    # Stop all services
just restart                 # Restart all services
just rebuild <service>       # Rebuild specific service (api or redis)
just logs-service [service] [lines]  # View Docker container logs
just shell                   # Shell into api container
just redis-cli               # Access Redis CLI
```

### Health and Maintenance
```bash
just health                  # Check system health
just service-cleanup-orphaned [token]  # Clean up orphaned resources
just help                    # Show all available commands
```

## Quick Start Commands

```bash
just quickstart <hostname> <target-url> [enable-auth]  # Quick setup proxy + cert
just setup-oauth <domain>                              # Setup OAuth server
just create-app <name> <image>                         # Create containerized app
```

## Certificate Management

```bash
# Certificate operations
just cert-create <name> <domain> [staging] [email] [token]
just cert-delete <name> [force] [token]
just cert-list [token]
just cert-show <name> [pem] [token]
```

## Proxy Management

### Basic Proxy Operations
```bash
just proxy-create <hostname> <target-url> [staging] [preserve-host] [enable-http] [enable-https] [email] [token]
just proxy-delete <hostname> [delete-cert] [force] [token]
just proxy-list [token]
just proxy-show <hostname> [token]
```

### OAuth Proxy Authentication
```bash
just proxy-auth-enable <hostname> [auth-proxy] [mode] [allowed-scopes] [allowed-audiences] [token]
just proxy-auth-disable <hostname> [token]
just proxy-auth-config <hostname> [users] [emails] [groups] [allowed-scopes] [allowed-audiences] [token]
just proxy-auth-show <hostname> [token]
```

### Protected Resource Metadata (RFC 9728)
```bash
just proxy-resource-set <hostname> [endpoint] [scopes] [stateful] [override-backend] [bearer-methods] [doc-suffix] [server-info] [custom-metadata] [hacker-one-research] [token]
just proxy-resource-clear <hostname> [token]
just proxy-resource-show <hostname> [token]
just proxy-resource-list [token]
```

### OAuth Authorization Server Metadata
```bash
just proxy-oauth-server-set <hostname> [issuer] [scopes] [grant-types] [response-types] [token-auth-methods] [claims] [pkce-required] [custom-metadata] [override-defaults] [token]
just proxy-oauth-server-clear <hostname> [token]
just proxy-oauth-server-show <hostname> [token]
```

### GitHub OAuth Credentials (Per-Proxy)
```bash
just proxy-github-oauth-set <hostname> <client-id> <client-secret> [token]  # Set GitHub OAuth credentials
just proxy-github-oauth-show <hostname> [token]                            # Show config (without secret)
just proxy-github-oauth-clear <hostname> [token]                           # Clear config (use env vars)
just proxy-github-oauth-list [token]                                       # List proxies with custom GitHub OAuth
```

## Route Management

### Basic Route Operations
```bash
just route-list [token]
just route-show <route-id> [token]
just route-create <path> <target-type> <target-value> [priority] [methods] [is-regex] [description] [token]
just route-delete <route-id> [token]
```

### Scope-Based Route Operations
```bash
just route-create-global <path> <target-type> <target-value> [priority] [methods] [is-regex] [description] [token]
just route-create-proxy <path> <target-type> <target-value> <proxies> [priority] [methods] [is-regex] [description] [token]
just route-list-by-scope [scope] [token]
```

## Service Management

### Docker Service Management
```bash
just service-create <name> [image] [dockerfile] [port] [memory] [cpu] [auto-proxy] [token]
just service-create-exposed <name> <image> <port> [bind-address] [memory] [cpu] [token]
just service-list [owned-only] [token]
just service-show <name> [token]
just service-delete <name> [force] [delete-proxy] [token]
just service-start <name> [token]
just service-stop <name> [token]
just service-restart <name> [token]
```

### External Service Management
```bash
just service-register <name> <target-url> [description] [token]
just service-list-external [token]
just service-show-external <name> [token]
just service-update-external <name> <target-url> [description] [token]
just service-unregister <name> [token]
just service-register-oauth [token]
```

### Service Monitoring
```bash
just service-logs <name> [lines] [timestamps] [token]
just service-stats <name> [token]
just service-proxy-create <name> [hostname] [enable-https] [token]
just service-cleanup [token]
```

### Port Management
```bash
just service-port-add <name> <port> [bind-address] [source-token] [token]
just service-port-remove <name> <port-name> [token]
just service-port-list <name> [token]
just service-port-check <port> [bind-address] [token]
just service-ports-global [available-only] [token]
```

### Unified Service Views
```bash
just service-list-all [type] [token]
```

## OAuth Management

### OAuth Authentication (Device Flow)
```bash
just oauth-login                    # Login via GitHub Device Flow
just oauth-refresh                  # Refresh access token
just oauth-status                   # Check token status
just oauth-key-generate             # Generate OAuth JWT keys
```

### OAuth Client Management
```bash
just oauth-client-register <name> [redirect-uri] [scope]  # Register OAuth client
just oauth-clients-list [active-only] [page] [per-page]   # List OAuth clients
just oauth-token-list [type] [client-id] [username] [page] [per-page] [include-expired]
```

### OAuth Monitoring
```bash
just oauth-sessions-list            # List active OAuth sessions
just oauth-test-tokens <server-url> # Test OAuth token endpoints
just oauth-clients-list [active-only] [page] [per-page]  # List OAuth clients
```

## Logging

### Log Query Commands
```bash
just logs [hours] [event] [level] [hostname] [limit]                # Recent logs
just logs-ip <ip> [hours] [event] [level] [limit]                  # Logs by client IP
just logs-proxy <hostname> [hours] [limit]                         # Logs by proxy hostname
just logs-hostname <hostname> [hours] [limit]                      # Logs by hostname
just logs-oauth-client <client-id> [hours] [event] [level] [limit] # Logs by OAuth client
just logs-errors [hours] [limit]                                   # Recent errors only
just logs-errors-debug [hours] [include-warnings] [limit]          # Detailed error logs
just logs-follow [interval] [event] [level] [hostname]             # Follow logs real-time
just logs-docker [lines] [follow]                                  # Docker container logs
just logs-service [service] [lines]                                # Service logs
```

### Log Analysis Commands
```bash
just logs-oauth <ip> [hours] [limit]                        # OAuth activity by IP
just logs-oauth-debug <ip> [hours] [limit]                  # OAuth debug logs
just logs-oauth-flow [client-id] [username] [hours]         # OAuth flow trace
just logs-oauth-user <username> [hours] [limit]             # OAuth logs by user
just logs-search <query> [hours] [event] [level] [hostname] [limit]  # Search logs
just logs-stats [hours]                                     # Log statistics
just logs-user <user-id> [hours] [limit]                   # Logs by user ID
just logs-session <session-id> [hours] [limit]             # Logs by session
just logs-method <method> [hours] [limit]                  # Logs by HTTP method
just logs-status <code> [hours] [limit]                    # Logs by HTTP status
just logs-slow [threshold-ms] [hours] [limit]              # Slow requests
just logs-path <pattern> [hours] [limit]                   # Logs by path pattern
```

### Log Management Commands
```bash
just logs-clear                     # Clear all logs
just logs-test                      # Test logging system
just logs-help                      # Show log command help
just log-level-set <level> [component]        # Set log level
just log-level-get [component]                # Get current log level
just log-level-reset <component>              # Reset to default level
just log-filter-set <component> [patterns]    # Set log filters
just log-filter-get <component>               # Get current filters
just log-filter-reset <component>             # Clear filters
just log-filter-stats                         # Filter statistics
just log-reduce-verbose                       # Reduce verbose logging
just log-debug-enable <component>             # Enable debug for component
just log-trace-enable <component>             # Enable trace for component
```

## Configuration Management

```bash
just config-save [filename]        # Save full configuration to YAML backup
just config-load <filename> [force]  # Load configuration from YAML backup
```

## System Cleanup

```bash
just cleanup-resources       # Clean up all resources
just service-cleanup         # Clean up orphaned services
just service-cleanup-orphaned  # Clean up orphaned resources
```

## Development & Testing

```bash
just test [files]           # Run standard test suite
just test-all               # Run comprehensive test suite
just docs-build             # Build documentation
just dry-run <command> [args]  # Test command without execution
```

## Environment Variables

The justfile automatically loads environment variables from `.env` file. Key variables include:

### Core Configuration
- `ADMIN_TOKEN` - Administrative token for privileged operations
- `TOKEN` - Default authentication token
- `API_URL` - Base URL for API endpoints
- `BASE_DOMAIN` - Base domain for services

### Testing Configuration
- `TEST_DOMAIN` - Domain for automated testing
- `TEST_EMAIL` - Email for test certificates
- `TEST_TOKEN` - Token for automated test authentication

### Service Configuration
- `REDIS_PASSWORD` - Redis authentication password
- `DOCKER_GID` - Docker group GID on host
- `LOG_LEVEL` - Application log level

## Command Patterns

### Token Parameter
Most commands accept an optional `[token]` parameter. If not provided, uses `$TOKEN` environment variable:
```bash
just proxy-list                    # Uses $TOKEN
just proxy-list $ADMIN_TOKEN       # Uses specific token
```

### Boolean Parameters
Boolean parameters use "true"/"false" strings:
```bash
just cert-create test example.com true   # Use staging
just cert-create prod example.com false  # Use production
```

### Multiple Values
Some parameters accept comma-separated values:
```bash
just proxy-auth-config api.example.com "alice,bob,charlie" "" ""
```

### Optional Parameters
Square brackets indicate optional parameters:
```bash
just service-create my-app          # Minimal
just service-create my-app nginx:latest "" 3000 512m 1.0  # Full options
```

## Command Examples

### Complete Proxy Setup
```bash
# Create token
just token-generate developer dev@example.com

# Create proxy with certificate
just proxy-create api.example.com http://backend:3000

# Enable authentication
just proxy-auth-enable api.example.com auth.example.com forward

# Configure allowed users
just proxy-auth-config api.example.com "alice,bob" "" ""
```

### Docker Service with Proxy
```bash
# Create service
just service-create my-app nginx:latest "" 3000

# Create proxy for service
just service-proxy-create my-app app.example.com true

# Check logs
just service-logs my-app 100 true
```

### OAuth Setup
```bash
# Generate RSA key
just oauth-key-generate

# Setup OAuth routes
just oauth-routes-setup example.com

# Register test client
just oauth-client-register test-client https://localhost/callback "mcp:read mcp:write"
```

## Best Practices

1. **Always Use Just**: Never run Python scripts or docker commands directly
2. **Environment Variables**: Set common values in `.env` file
3. **Token Security**: Use environment variables for tokens, not command line
4. **Check Status First**: Use list/show commands before create/delete
5. **Use Staging Certificates**: Test with staging before production

## Troubleshooting

### Command Not Found
```bash
just help  # List all available commands
```

### Authentication Errors
```bash
just token-list  # Verify token exists
export TOKEN=acm_your_token  # Set token
```

### Service Issues
```bash
just logs-service api 100  # Check service logs
just health  # Check system health
```

## Related Documentation

- [General Guidelines](src/CLAUDE.md) - Development guidelines
- [API Documentation](src/api/CLAUDE.md) - API endpoints
- [Client Documentation](oauth-https-proxy-client/CLAUDE.md) - Python CLI client