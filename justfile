# OAuth HTTPS Proxy Management
# Unified interface to the proxy-client CLI tool

# Variables
container_name := `docker ps --format "{{.Names}}" | grep -E "oauth-https-proxy[_-]api[_-]1" | head -1 || echo "oauth-https-proxy-api-1"`
default_api_url := "http://localhost:80"

# Load environment from .env
set dotenv-load := true
set dotenv-required
set positional-arguments := true
set allow-duplicate-recipes
set export := true
set quiet

# Show help and available commands (default)
@default:
    echo ""
    echo "OAuth HTTPS Proxy - Command Interface"
    echo "======================================"
    echo ""
    echo "QUICK START:"
    echo "  just up                    # Start all services"
    echo "  just status                # Show system status"
    echo "  just oauth login           # Authenticate with GitHub"
    echo ""
    echo "UNIFIED COMMANDS (93 Total Actions):"
    echo ""
    echo "  just cert <convert-to-production|create|create-multi|delete|export|list|renew|show|status|to-production>"
    echo ""
    echo "  just log <clear|errors|filter|follow|hostname|ip|level|method|oauth|oauth-client|oauth-debug|"
    echo "            oauth-flow|oauth-user|path|proxy|search|session|slow|stats|status|test|user>"
    echo ""
    echo "  just oauth <admin|client|health|login|logout|metrics|proxy|refresh|register|session|status|token>"
    echo ""
    echo "  just proxy <auth|create|delete|list|list-formatted|oauth-server|resource|routes|show|update>"
    echo ""
    echo "  just resource <list|show>"
    echo ""
    echo "  just route <create|create-global|create-proxy|delete|list|list-by-scope|list-formatted|show|update>"
    echo ""
    echo "  just service <cleanup|create|create-exposed|delete|external|list|logs|port|port-check-api|ports|"
    echo "                ports-global|proxy-create|restart|show|start|stats|stop|update>"
    echo ""
    echo "  just system <config|health|info|stats|validate|version>"
    echo ""
    echo "SYSTEM COMMANDS:"
    echo "  just down                  # Stop services"
    echo "  just exec <cmd>            # Run command in container"
    echo "  just health                # Check health"
    echo "  just python <code>         # Run Python code"
    echo "  just rebuild [service]     # Rebuild service"
    echo "  just redis <cmd>           # Run Redis command"
    echo "  just redis-cli             # Redis interactive CLI"
    echo "  just restart               # Restart services"
    echo "  just script <file>         # Run Python script"
    echo "  just shell                 # Open bash shell"
    echo "  just up                    # Start services"
    echo ""
    echo "CONVENIENCE:"
    echo "  just backup [file]         # Backup configuration"
    echo "  just cleanup               # Clean orphaned resources"
    echo "  just restore <file>        # Restore configuration"
    echo "  just status                # Full system status"
    echo ""
    echo "WORKFLOWS:"
    echo "  just create-app <name> <img>  # Deploy containerized app"
    echo "  just proxy-github <action>    # GitHub OAuth (clear/list/set/show)"
    echo "  just setup-oauth <domain>     # Configure OAuth server"
    echo ""
    echo "CONFIGURATION:"
    echo "  just config-load <file>    # Import configuration"
    echo "  just config-save [file]    # Export configuration"
    echo ""
    echo "DEVELOPMENT:"
    echo "  just docs-build            # Build documentation"
    echo "  just test [files]          # Run tests"
    echo "  just test-all              # Run all tests"
    echo ""
    echo "REDIS TOOLS:"
    echo "  just redis-info            # Show Redis stats"
    echo "  just redis-keys [pattern]  # List matching keys"
    echo ""
    echo "COMMON EXAMPLES:"
    echo "  just proxy create api.example.com http://localhost:3000"
    echo "  just cert list"
    echo "  just service logs my-app"
    echo "  just log errors --hours 1"
    echo "  just oauth login"
    echo "  just proxy-github set api.example.com <client-id> <secret>"
    echo ""
    echo "Total: 37 commands with 96 available actions"
    echo "Run 'just --list' for complete command list"
    echo "Run 'just <command> --help' for action details"
    echo ""

# ============================================================================
# UNIFIED COMMAND INTERFACE
# ============================================================================
# Usage: just <command> <action> [args...]
# Example: just proxy create api.example.com http://localhost:3000

# Certificate management
cert *args:
    @pixi run proxy-client cert {{args}}

# Proxy management
proxy *args:
    @pixi run proxy-client proxy {{args}}

# Service management
service *args:
    @pixi run proxy-client service {{args}}

# Route management
route *args:
    @pixi run proxy-client route {{args}}

# OAuth management
oauth *args:
    @pixi run proxy-client oauth {{args}}

# Log management
log *args:
    @pixi run proxy-client log {{args}}

# Generate comprehensive connection report for IP to proxy
report ip proxy hours="24" output="":
    #!/usr/bin/env bash
    if [ -z "{{output}}" ]; then
        pixi run proxy-client report connection {{ip}} {{proxy}} --hours {{hours}}
    else
        pixi run proxy-client report connection {{ip}} {{proxy}} --hours {{hours}} --output {{output}}
    fi

# Generate summary report for IP to proxy connections
report-summary ip proxy hours="24":
    @pixi run proxy-client report summary {{ip}} {{proxy}} --hours {{hours}}

# System management
system *args:
    @pixi run proxy-client system {{args}}

# Resource management
resource *args:
    @pixi run proxy-client resource {{args}}

# ============================================================================
# CONVENIENCE COMMANDS
# ============================================================================

# Show comprehensive system status
status:
    @echo "=== System Health ==="
    @pixi run proxy-client system health
    @echo ""
    @echo "=== Active Proxies ==="
    @pixi run proxy-client --format table proxy list
    @echo ""
    @echo "=== Running Services ==="
    @pixi run proxy-client --format table service list --type docker

# Create full system backup
backup filename="backup-$(date +%Y%m%d-%H%M%S).yaml":
    @echo "Creating system backup..."
    @pixi run proxy-client system config export --output {{filename}} --include-tokens
    @echo "✓ Backup saved to {{filename}}"

# Restore system from backup
restore filename:
    @echo "Restoring from {{filename}}..."
    @pixi run proxy-client system config import {{filename}} --force
    @echo "✓ System restored from {{filename}}"

# Quick cleanup of all resources
cleanup:
    @pixi run proxy-client workflow cleanup --orphaned-only --force

# ============================================================================
# SYSTEM MANAGEMENT
# ============================================================================

# Start all services
up:
    docker compose up -d
    @echo "Waiting for services to be healthy..."
    @sleep 5
    @just health || echo "Services may still be starting..."

# Stop all services
down:
    docker compose down

# Restart all services
restart: down up

# Rebuild a specific service (defaults to api)
rebuild service="api":
    docker compose build {{service}}
    docker compose up -d {{service}}

# Open shell in container
shell:
    docker exec -it {{container_name}} /bin/bash

# Execute command in container with pixi environment
exec *cmd:
    #!/usr/bin/env bash
    # Use -it for interactive terminals, -t otherwise
    if [ -t 0 ]; then
        docker exec -it {{container_name}} pixi run {{cmd}}
    else
        docker exec {{container_name}} pixi run {{cmd}}
    fi

# Run Python code in container with pixi environment
python code="":
    #!/usr/bin/env bash
    if [ -z "{{code}}" ]; then
        echo "Starting interactive Python shell in container..."
        if [ -t 0 ]; then
            docker exec -it {{container_name}} pixi run python
        else
            echo "Error: Interactive Python requires a TTY. Use 'just python \"<code>\"' for non-interactive execution."
            exit 1
        fi
    else
        echo "Running Python code: {{code}}"
        docker exec {{container_name}} pixi run python -c "{{code}}"
    fi

# Run Python script file in container with pixi environment
script file *args:
    @echo "Running Python script: {{file}} {{args}}"
    @docker exec {{container_name}} pixi run python {{file}} {{args}}

# Access Redis interactive CLI with password
redis-cli:
    @echo "Connecting to Redis (password from .env)..."
    docker compose exec redis redis-cli -a "${REDIS_PASSWORD}"

# Execute Redis command with password (non-interactive)
redis *cmd:
    #!/usr/bin/env bash
    if [ -z "{{cmd}}" ]; then
        echo "Usage: just redis <command>"
        echo "Examples:"
        echo "  just redis 'KEYS *'                    # List all keys"
        echo "  just redis 'GET proxy:localhost'       # Get specific key"
        echo "  just redis 'HGETALL proxy:ports:mappings'  # Get hash"
        echo "  just redis 'ZRANGE log:recent 0 10'    # Get sorted set range"
        echo "  just redis 'INFO'                      # Server info"
        echo "  just redis 'PING'                      # Test connection"
        exit 1
    fi
    echo "Executing Redis command: {{cmd}}"
    docker compose exec -T redis redis-cli -a "${REDIS_PASSWORD}" {{cmd}}

# Check system health
health:
    @pixi run proxy-client system health

# ============================================================================
# DEVELOPER TOOLS & UTILITIES
# ============================================================================

# List all Redis keys matching pattern
redis-keys pattern="*":
    @echo "Redis keys matching '{{pattern}}':"
    @docker compose exec -T redis redis-cli -a "${REDIS_PASSWORD}" KEYS "{{pattern}}"

# Show Redis memory usage
redis-info:
    @echo "Redis server info:"
    @docker compose exec -T redis redis-cli -a "${REDIS_PASSWORD}" INFO server
    @echo ""
    @echo "Redis memory info:"
    @docker compose exec -T redis redis-cli -a "${REDIS_PASSWORD}" INFO memory | grep "used_memory_human"

# ============================================================================
# PROXY GITHUB OAUTH MANAGEMENT (Custom Implementation)
# ============================================================================
# These commands manage per-proxy GitHub OAuth credentials
# Usage: just proxy-github <action> [args...]

# Manage per-proxy GitHub OAuth credentials
proxy-github action hostname="" client_id="" client_secret="":
    #!/usr/bin/env bash
    set -euo pipefail
    API_URL="${API_URL:-http://localhost:80}"
    TOKEN="${TOKEN:-${OAUTH_ACCESS_TOKEN:-}}"
    
    case "{{action}}" in
        set)
            if [ -z "{{hostname}}" ] || [ -z "{{client_id}}" ] || [ -z "{{client_secret}}" ]; then
                echo "Usage: just proxy-github set <hostname> <client-id> <client-secret>"
                exit 1
            fi
            echo "Setting GitHub OAuth credentials for proxy: {{hostname}}"
            response=$(curl -s -w "\n%{http_code}" -X POST \
                "${API_URL}/proxy/targets/{{hostname}}/github-oauth" \
                -H "Authorization: Bearer ${TOKEN}" \
                -H "Content-Type: application/json" \
                -d '{
                    "github_client_id": "{{client_id}}",
                    "github_client_secret": "{{client_secret}}"
                }')
            http_code=$(echo "$response" | tail -n1)
            body=$(echo "$response" | head -n-1)
            if [ "$http_code" -eq 200 ] || [ "$http_code" -eq 201 ]; then
                echo "$body" | jq -r '.'
                echo "✓ GitHub OAuth credentials configured successfully"
            else
                echo "Failed to set GitHub OAuth credentials (HTTP $http_code)"
                echo "$body" | jq -r '.' 2>/dev/null || echo "$body"
                exit 1
            fi
            ;;
        show)
            if [ -z "{{hostname}}" ]; then
                echo "Usage: just proxy-github show <hostname>"
                exit 1
            fi
            echo "Getting GitHub OAuth configuration for proxy: {{hostname}}"
            response=$(curl -s -w "\n%{http_code}" -X GET \
                "${API_URL}/proxy/targets/{{hostname}}/github-oauth" \
                -H "Authorization: Bearer ${TOKEN}")
            http_code=$(echo "$response" | tail -n1)
            body=$(echo "$response" | head -n-1)
            if [ "$http_code" -eq 200 ]; then
                echo "$body" | jq -r '.'
            else
                echo "Failed to get GitHub OAuth configuration (HTTP $http_code)"
                echo "$body" | jq -r '.' 2>/dev/null || echo "$body"
                exit 1
            fi
            ;;
        clear)
            if [ -z "{{hostname}}" ]; then
                echo "Usage: just proxy-github clear <hostname>"
                exit 1
            fi
            echo "Clearing GitHub OAuth configuration for proxy: {{hostname}}"
            response=$(curl -s -w "\n%{http_code}" -X DELETE \
                "${API_URL}/proxy/targets/{{hostname}}/github-oauth" \
                -H "Authorization: Bearer ${TOKEN}")
            http_code=$(echo "$response" | tail -n1)
            body=$(echo "$response" | head -n-1)
            if [ "$http_code" -eq 200 ] || [ "$http_code" -eq 204 ]; then
                echo "$body" | jq -r '.'
                echo "✓ GitHub OAuth configuration cleared - will use environment variables"
            else
                echo "Failed to clear GitHub OAuth configuration (HTTP $http_code)"
                echo "$body" | jq -r '.' 2>/dev/null || echo "$body"
                exit 1
            fi
            ;;
        list)
            echo "Listing proxies with custom GitHub OAuth configurations:"
            response=$(curl -s -w "\n%{http_code}" -X GET \
                "${API_URL}/proxy/targets/github-oauth/configured" \
                -H "Authorization: Bearer ${TOKEN}")
            http_code=$(echo "$response" | tail -n1)
            body=$(echo "$response" | head -n-1)
            if [ "$http_code" -eq 200 ]; then
                echo "$body" | jq -r '.'
            else
                echo "Failed to list GitHub OAuth configurations (HTTP $http_code)"
                echo "$body" | jq -r '.' 2>/dev/null || echo "$body"
                exit 1
            fi
            ;;
        *)
            echo "Usage: just proxy-github <action> [args...]"
            echo ""
            echo "Actions:"
            echo "  set <hostname> <client-id> <client-secret>  - Set GitHub OAuth credentials"
            echo "  show <hostname>                             - Show GitHub OAuth configuration"
            echo "  clear <hostname>                            - Clear GitHub OAuth configuration"
            echo "  list                                        - List proxies with custom configs"
            exit 1
            ;;
    esac

# ============================================================================
# WORKFLOW SHORTCUTS
# ============================================================================

# Setup OAuth for a domain
setup-oauth domain:
    @pixi run proxy-client workflow oauth-setup {{domain}} --generate-key

# Create app with automatic proxy
create-app name image:
    @pixi run proxy-client workflow service-with-proxy {{name}} {{image}} --enable-https

# ============================================================================
# TESTING & DEVELOPMENT
# ============================================================================

# Run tests
test *files="":
    {{ if files != "" { "pixi run pytest tests/" + files + " -v" } else { "pixi run pytest tests/ -v" } }}

# Run comprehensive tests
test-all:
    pixi run pytest tests/ -v --tb=short


# Build documentation
docs-build:
    pixi run jupyter-book build docs

# ============================================================================
# CONFIGURATION MANAGEMENT
# ============================================================================

# Save configuration
config-save filename="":
    @pixi run proxy-client system config export \
        {{ if filename != "" { "--output " + filename } else { "" } }} \
        --include-tokens

# Load configuration
config-load filename force="":
    @pixi run proxy-client system config import {{filename}} \
        {{ if force == "true" { "--force" } else { "" } }}