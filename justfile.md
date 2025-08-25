# Justfile Commands Documentation

## Quick Start

The OAuth HTTPS Proxy system is managed through `just` commands that provide a unified interface to the `proxy-client` CLI tool. All commands automatically handle environment configuration and authentication.

### Essential Commands

```bash
# System lifecycle
just up                  # Start all services
just down                # Stop all services
just status              # Show system status
just health              # Check system health

# OAuth authentication
just oauth login         # Authenticate via GitHub
just oauth status        # Check authentication status

# Quick setup
just quickstart api.example.com http://localhost:3000  # Create proxy with certificate
just init                # Initialize system with defaults
```

## Unified Command Interface (NEW - Recommended)

The new unified interface provides intuitive access to all system features. Each command follows the pattern:
```bash
just <resource> <action> [arguments...]
```

### Certificate Management
```bash
just cert create <name> <domain> [--staging] [--email admin@example.com]
just cert list
just cert show <name> [--pem]
just cert renew <name> [--force]
just cert delete <name> [--force]
just cert convert-to-production <name>
```

### Proxy Management
```bash
just proxy create <hostname> <target-url> [--staging] [--enable-https]
just proxy list
just proxy show <hostname>
just proxy update <hostname> [options...]
just proxy delete <hostname> [--delete-cert]

# Authentication
just proxy auth enable <hostname> [--auth-proxy auth.localhost]
just proxy auth disable <hostname>
just proxy auth config <hostname> [--users alice,bob] [--scopes admin,user]
just proxy auth show <hostname>

# Protected Resources (RFC 9728)
just proxy resource set <hostname> [--endpoint /api] [--scopes read,write]
just proxy resource show <hostname>
just proxy resource clear <hostname>
just proxy resource list

# OAuth Server Configuration
just proxy oauth-server set <hostname> [--scopes "admin user mcp"]
just proxy oauth-server show <hostname>
just proxy oauth-server clear <hostname>

# GitHub OAuth (Per-Proxy)
just proxy-github set <hostname> <client-id> <client-secret>
just proxy-github show <hostname>
just proxy-github clear <hostname>
just proxy-github list
```

### Service Management
```bash
just service create <name> <image> [--port 3000] [--memory 512m] [--cpu 1.0]
just service list [--type docker|external|all]
just service show <name>
just service start|stop|restart <name>
just service delete <name> [--force]
just service logs <name> [--lines 100]
just service stats <name>

# Port management
just service port add <name> <port> [--bind-address 127.0.0.1]
just service port remove <name> <port-name>
just service port list <name>
just service ports  # List all allocated ports

# External services
just service external register <name> <url> [--description "..."]
just service external list
just service external unregister <name>
```

### Route Management
```bash
just route create <path> <target-type> <target-value> [--priority 50]
just route list
just route show <route-id>
just route delete <route-id>

# Scope-based routes
just route create-global <path> <target-type> <target-value>
just route create-proxy <path> <target-type> <target-value> <proxies>
just route list-by-scope [global|proxy]
```

### OAuth Management
```bash
just oauth login                      # GitHub Device Flow authentication
just oauth status                     # Check token status
just oauth refresh                    # Refresh access token
just oauth logout                     # Clear tokens

# Client management
just oauth client list [--active-only]
just oauth register <name> [--redirect-uri ...] [--scope "read write"]

# Token management
just oauth token list [--token-type access|refresh] [--username ...]

# Session management
just oauth session list

# Administration
just oauth admin [subcommands...]
just oauth metrics
```

### Log Management
```bash
just log search [--hours 1] [--hostname ...] [--limit 50]
just log errors [--hours 1] [--limit 20]
just log follow [--interval 2] [--hostname ...]

# Query by dimension
just log ip <ip> [--hours 1]
just log proxy <hostname> [--hours 1]
just log user <username> [--hours 1]
just log oauth-client <client-id> [--hours 1]
just log session <session-id> [--hours 1]
just log status <code> [--hours 1]
just log method <method> [--hours 1]
just log path <pattern> [--hours 1]
just log slow [--threshold 1000] [--hours 1]

# Analytics
just log stats [--hours 1]
just log oauth-flow [--client-id ...] [--username ...]

# Management
just log clear [--force]
just log test

# Log levels and filtering
just log level set <level> [--component ...]
just log level get [--component ...]
just log filter set <component> [--suppress ".*health.*"]
just log filter stats
```

### System Management
```bash
just system health [--check-config]
just system config export [--output backup.yaml] [--include-tokens]
just system config import <filename> [--force]
```

### Workflow Commands
```bash
just workflow proxy-quickstart <hostname> <target-url> [--enable-auth]
just workflow oauth-setup <domain> [--generate-key]
just workflow service-with-proxy <name> <image> [--enable-https]
just workflow cleanup [--orphaned-only] [--force]
```

### Resource Management
```bash
just resource list
just resource show <resource-id>
just resource [other subcommands...]
```

## Convenience Commands

These commands provide quick access to common operations:

```bash
just status              # Comprehensive system status
just backup [filename]   # Create full system backup
just restore <filename>  # Restore from backup
just init               # Initialize with defaults
just validate           # Validate configuration
just troubleshoot       # Run diagnostics
just cleanup            # Clean orphaned resources
```

## System Management

### Docker Operations
```bash
just up                  # Start all services
just down                # Stop all services
just restart             # Restart all services
just rebuild [service]   # Rebuild specific service
just shell              # Open shell in API container
just redis-cli          # Access Redis CLI
```

### Development & Testing
```bash
just test [files]        # Run tests
just test-all           # Run comprehensive test suite
just docs-build         # Build documentation
just dry-run <command>  # Test command without execution
```

## Command Patterns

### Positional Arguments
Commands use positional arguments for clarity:
```bash
just proxy create api.example.com http://localhost:3000
# Instead of: just proxy-create hostname=api.example.com target-url=http://localhost:3000
```

### Options and Flags
Optional parameters use standard CLI conventions:
```bash
just cert create my-cert example.com --staging --email admin@example.com
just service logs my-app --lines 100 --follow
```

### Subcommands
Complex resources use subcommands for organization:
```bash
just proxy auth enable api.example.com
just service port add my-app 8080
just log level set DEBUG --component proxy
```

## Environment Configuration

The justfile automatically loads environment variables from `.env`:

```bash
# Core configuration
REDIS_PASSWORD=<strong-password>      # Required
BASE_DOMAIN=example.com              # Base domain for services
API_URL=http://localhost:80          # API endpoint

# OAuth configuration
GITHUB_CLIENT_ID=<github-app-id>     # GitHub OAuth App ID
GITHUB_CLIENT_SECRET=<github-secret> # GitHub OAuth App Secret
OAUTH_JWT_PRIVATE_KEY_B64=<key>     # JWT signing key (base64)
OAUTH_ACCESS_TOKEN=<token>          # Current access token
OAUTH_REFRESH_TOKEN=<token>         # Current refresh token

# Logging
LOG_LEVEL=INFO                      # Global log level
```

## Common Workflows

### Setting Up a New Proxy
```bash
# Quick setup with auto-certificate
just quickstart api.example.com http://localhost:3000

# Or step-by-step
just proxy create api.example.com http://localhost:3000
just cert create api api.example.com
just proxy auth enable api.example.com
```

### Deploying a Docker Service
```bash
# Create service with automatic proxy
just workflow service-with-proxy my-app nginx:latest --enable-https

# Or manual steps
just service create my-app nginx:latest --port 3000
just proxy create app.example.com http://my-app:3000
```

### OAuth Configuration
```bash
# Initial setup
just oauth login                    # Authenticate
just workflow oauth-setup example.com --generate-key

# Per-proxy GitHub App
just proxy-github set api.example.com gh_app_id gh_app_secret
```

### Debugging Issues
```bash
just troubleshoot                   # Run full diagnostics
just log errors --hours 1           # Recent errors
just log follow --hostname api.example.com  # Live logs
just service logs my-app --lines 100
```

### Backup and Restore
```bash
# Create backup
just backup                         # Auto-named with timestamp
just backup production-backup.yaml  # Named backup

# Restore
just restore production-backup.yaml
```

## Migration Guide

### Old Command → New Command Mapping

| Old Command | New Command |
|------------|-------------|
| `just proxy-create ...` | `just proxy create ...` |
| `just cert-list` | `just cert list` |
| `just service-logs ...` | `just service logs ...` |
| `just logs-errors` | `just log errors` |
| `just proxy-auth-enable ...` | `just proxy auth enable ...` |
| `just oauth-login` | `just oauth login` |
| `just service-port-add ...` | `just service port add ...` |
| `just logs-ip ...` | `just log ip ...` |
| `just proxy-github-oauth-set ...` | `just proxy-github set ...` |

### Deprecated Commands

The following commands are deprecated and will be removed in a future version:
- `logs-docker` - Use `service logs` instead
- `service-list` - Use `service list --type docker` instead  
- `logs-errors-debug` - Use `log errors --include-warnings` instead
- `service-register-oauth` - Use `service external register oauth ...` instead

## Troubleshooting

### Command Not Found
```bash
just --list              # List all available commands
just <command> --help    # Get help for specific command
```

### Authentication Issues
```bash
just oauth status        # Check current authentication
just oauth refresh       # Refresh expired token
just oauth login         # Re-authenticate
```

### Service Problems
```bash
just status              # Check overall system status
just troubleshoot        # Run diagnostics
just log errors --hours 1  # Check recent errors
```

### Connection Issues
```bash
just health              # Check if services are responding
docker compose ps        # Check Docker containers
just redis-cli           # Test Redis connection
```

## Best Practices

1. **Use Unified Commands**: Prefer the new unified interface (`just proxy create`) over old-style commands
2. **Check Status First**: Run `just status` before making changes
3. **Use Staging Certificates**: Test with `--staging` before production certificates
4. **Regular Backups**: Run `just backup` before major changes
5. **Monitor Logs**: Use `just log follow` during deployments
6. **Validate Changes**: Run `just validate` after configuration updates

## Advanced Usage

### Custom Scripts
```bash
# Run any proxy-client command directly
just proxy-client <any-command>

# Dry-run mode for testing
just dry-run proxy create test.example.com http://localhost:3000
```

### Direct API Access
```bash
# The unified commands wrap proxy-client, which calls the API
# You can also use proxy-client directly for advanced operations:
pixi run proxy-client --format json proxy list | jq '.'
```

## Related Documentation

- [General Development Guidelines](CLAUDE.md)
- [API Documentation](src/api/CLAUDE.md)
- [Python CLI Client](oauth-https-proxy-client/CLAUDE.md)
- [OAuth Implementation](OAUTH_IMPLEMENTATION_SUMMARY.md)
- [Component Documentation](src/)