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

## Token Management

```bash
just token-generate <name> [email] [token]  # Create token with optional cert email
just token-show <name> [token]              # Retrieve full token
just token-list [token]                     # List all tokens
just token-delete <name> [token]            # Delete token + owned resources
just token-email <name> <email> [token]     # Update token cert email
just token-admin                            # Generate admin token
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

### OAuth Setup
```bash
just oauth-key-generate [token]
just oauth-routes-setup <domain> [token]
just oauth-client-register <name> [redirect-uri] [scope]
```

### OAuth Status and Monitoring
```bash
just oauth-clients-list [active-only] [token]
just oauth-sessions-list [token]
just oauth-test-tokens <server-url> [token]
```

## Logging

### Log Query Commands
```bash
just logs [hours] [event] [level] [hostname] [limit] [token]
just logs-ip <ip> [hours] [event] [level] [limit] [token]
just logs-host <hostname> [hours] [limit] [token]
just logs-client <client-id> [hours] [event] [level] [limit] [token]
just logs-search [query] [hours] [event] [level] [hostname] [limit] [token]
just logs-errors [hours] [limit] [token]
just logs-errors-debug [hours] [include-warnings] [limit] [token]
just logs-follow [service]
just logs-oauth <ip> [hours] [limit] [token]
just logs-oauth-debug <ip> [hours] [limit] [token]
just logs-oauth-flow [client-id] [username] [hours] [token]
just logs-stats [hours] [token]
just logs-test [token]
just logs-all [lines] [hours] [token]
just logs-clear [token]
just logs-help
```

## Configuration Management

```bash
just config-save [filename]        # Save full configuration to YAML backup
just config-load <filename> [force]  # Load configuration from YAML backup
```

## Testing

```bash
just test [files]           # Run standard test suite
just test-all               # Run comprehensive test suite
```

## Documentation

```bash
just docs-build            # Build documentation
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