# OAuth HTTPS Proxy Management - Migrated to proxy-client
# All API operations now use the proxy-client CLI tool for better consistency and maintainability

# Variables
container_name := "oauth-https-proxy-api-1"
default_api_url := "http://localhost:80"
staging_cert_email := env_var_or_default("TEST_EMAIL", env_var_or_default("ACME_EMAIL", "test@example.com"))

# Load environment from .env
set dotenv-load := true
set dotenv-required
set positional-arguments := true
set allow-duplicate-recipes
# Export all variables as environment variables
set export := true
set quiet

# Default recipe - show available commands
[private]
default:
    @just --list

# ============================================================================
# UNIFIED COMMAND INTERFACE (NEW - Recommended)
# ============================================================================
# These commands provide a cleaner, more intuitive interface to proxy-client
# Usage: just <command> <action> [args...]
# Example: just proxy create api.example.com http://localhost:3000

# Unified certificate management
cert *args:
    @pixi run proxy-client cert {{args}}

# Unified proxy management
proxy *args:
    @pixi run proxy-client proxy {{args}}

# Unified service management
service *args:
    @pixi run proxy-client service {{args}}

# Unified route management
route *args:
    @pixi run proxy-client route {{args}}

# Unified OAuth management
oauth *args:
    @pixi run proxy-client oauth {{args}}

# Unified log management
log *args:
    @pixi run proxy-client log {{args}}

# Unified system management
system *args:
    @pixi run proxy-client system {{args}}

# Unified workflow commands
workflow *args:
    @pixi run proxy-client workflow {{args}}

# Unified resource management
resource *args:
    @pixi run proxy-client resource {{args}}

# ============================================================================
# CONVENIENCE COMMANDS (NEW)
# ============================================================================

# Show comprehensive system status
status:
    @echo "=== System Health ==="
    @pixi run proxy-client system health
    @echo ""
    @echo "=== Active Proxies ==="
    @pixi run proxy-client proxy list --format table
    @echo ""
    @echo "=== Running Services ==="
    @pixi run proxy-client service list --format table --type docker

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

# Initialize system with defaults
init:
    @echo "Initializing system with default configuration..."
    @just up
    @sleep 5
    @pixi run proxy-client oauth status --quiet || echo "Note: Run 'just oauth login' to authenticate"
    @echo "✓ System initialized"

# Validate configuration
validate:
    @echo "Validating system configuration..."
    @pixi run proxy-client system health --check-config
    @echo "✓ Configuration valid"

# Run system diagnostics
troubleshoot:
    @echo "Running system diagnostics..."
    @echo ""
    @echo "=== Checking Docker Services ==="
    @docker compose ps
    @echo ""
    @echo "=== Checking System Health ==="
    @pixi run proxy-client system health || true
    @echo ""
    @echo "=== Checking Redis Connection ==="
    @docker compose exec -T redis redis-cli -a "${REDIS_PASSWORD}" ping || echo "Redis not responding"
    @echo ""
    @echo "=== Recent Errors ==="
    @pixi run proxy-client log errors --hours 1 --limit 5 || true
    @echo ""
    @echo "Diagnostics complete. Check output above for issues."

# Quick cleanup of all resources
cleanup:
    @pixi run proxy-client workflow cleanup --orphaned-only --force

# ============================================================================
# SYSTEM MANAGEMENT (Docker Operations - Not Migrated)
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
    docker exec -i {{container_name}} /bin/bash

# Access Redis CLI
redis-cli:
    docker compose exec redis redis-cli -a "${REDIS_PASSWORD}"

# Check system health
health:
    @pixi run proxy-client system health

# Show all available commands
help:
    @echo "OAuth HTTPS Proxy Management Commands"
    @echo ""
    @echo "This justfile provides thin wrappers around proxy-client commands."
    @echo "For detailed help on any command category, use:"
    @echo "  proxy-client <category> --help"
    @echo ""
    @echo "Available categories:"
    @echo "  token      - Manage API tokens"
    @echo "  cert       - Manage TLS certificates"
    @echo "  proxy      - Manage proxy targets and authentication"
    @echo "  route      - Manage routing rules"
    @echo "  service    - Manage Docker and external services"
    @echo "  oauth      - OAuth administration"
    @echo "  log        - Query and analyze logs"
    @echo "  system     - System health and configuration"
    @echo "  workflow   - High-level workflow commands"
    @echo ""
    @just --list

# ============================================================================
# TOKEN MANAGEMENT (Migrated to proxy-client)
# ============================================================================

# Token management removed - OAuth only authentication

# ============================================================================
# CERTIFICATE MANAGEMENT (Migrated to proxy-client)
# ============================================================================

# DEPRECATED: Use 'just cert create ...' instead
# Create a new certificate
cert-create name domain staging="false" email=env_var_or_default("ADMIN_EMAIL", ""):
    @echo "⚠️  DEPRECATED: Use 'just cert create {{name}} {{domain}} $(if [ '{{staging}}' = 'true' ]; then echo '--staging'; fi) --email {{email}}' instead"
    pixi run proxy-client cert create {{name}} {{domain}} \
        {{ if staging == "true" { "--staging" } else { "" } }} \
        --email {{email}}

# DEPRECATED: Use 'just cert list' instead
# List all certificates
cert-list:
    @echo "⚠️  DEPRECATED: Use 'just cert list' instead"
    pixi run proxy-client cert list

# Show certificate details
cert-show name pem="false":
    pixi run proxy-client cert show {{name}} \
        {{ if pem == "true" { "--pem" } else { "" } }}

# Delete a certificate
cert-delete name force="true":
    pixi run proxy-client cert delete {{name}} --force

# Renew a certificate
cert-renew name force="true" wait="true":
    pixi run proxy-client cert renew {{name}} --force \
        {{ if wait == "false" { "--no-wait" } else { "" } }}

# Convert staging certificate to production
cert-convert-to-production name wait="true" force="true":
    pixi run proxy-client cert convert-to-production {{name}} \
        {{ if wait == "false" { "--no-wait" } else { "" } }} --force

# ============================================================================
# PROXY MANAGEMENT (Migrated to proxy-client)
# ============================================================================

# DEPRECATED: Use 'just proxy create ...' instead
# Create a new proxy with automatic certificate handling
# Will check for existing certificates and create new ones if needed
proxy-create hostname target-url staging="false" preserve-host="true" enable-http="true" enable-https="true" email=env_var_or_default("ADMIN_EMAIL", ""):
    @echo "⚠️  DEPRECATED: Use 'just proxy create {{hostname}} {{target-url}} [options]' instead"
    pixi run proxy-client proxy create {{hostname}} {{target-url}} \
        {{ if staging == "true" { "--staging" } else { "" } }} \
        {{ if preserve-host == "false" { "--no-preserve-host" } else { "" } }} \
        {{ if enable-http == "false" { "--no-enable-http" } else { "" } }} \
        {{ if enable-https == "false" { "--no-enable-https" } else { "" } }} \
        --email {{email}}

# DEPRECATED: Use 'just proxy list' instead
# List all proxies
proxy-list:
    @echo "⚠️  DEPRECATED: Use 'just proxy list' instead"
    pixi run proxy-client --format table proxy list

# Show proxy details
proxy-show hostname:
    pixi run proxy-client proxy show {{hostname}}

# Delete a proxy
proxy-delete hostname delete-cert="false" force="true":
    pixi run proxy-client proxy delete {{hostname}} --force \
        {{ if delete-cert == "true" { "--delete-cert" } else { "" } }}

# DEPRECATED: Use 'just proxy auth enable ...' instead
# Enable authentication for a proxy
proxy-auth-enable hostname auth-proxy="auth.localhost" mode="forward" allowed-scopes="" allowed-audiences="":
    @echo "⚠️  DEPRECATED: Use 'just proxy auth enable {{hostname}} [options]' instead"
    pixi run proxy-client proxy auth enable {{hostname}} \
        {{auth-proxy}} \
        {{mode}} \
        {{ if allowed-scopes != "" { "--allowed-scopes " + allowed-scopes } else { "" } }} \
        {{ if allowed-audiences != "" { "--allowed-audiences " + allowed-audiences } else { "" } }}

# Disable authentication for a proxy
proxy-auth-disable hostname:
    pixi run proxy-client proxy auth disable {{hostname}}

# Configure authentication for a proxy
proxy-auth-config hostname users="" emails="" groups="" allowed-scopes="" allowed-audiences="":
    pixi run proxy-client proxy auth config {{hostname}} \
        {{ if users != "" { "--users " + users } else { "" } }} \
        {{ if emails != "" { "--emails " + emails } else { "" } }} \
        {{ if groups != "" { "--groups " + groups } else { "" } }} \
        {{ if allowed-scopes != "" { "--scopes " + allowed-scopes } else { "" } }} \
        {{ if allowed-audiences != "" { "--audiences " + allowed-audiences } else { "" } }}

# Show authentication configuration
proxy-auth-show hostname:
    pixi run proxy-client proxy auth show {{hostname}}

# Set protected resource metadata
proxy-resource-set hostname endpoint="/api" scopes="read,write" stateful="false" override-backend="false" bearer-methods="header" doc-suffix="/docs" server-info="{}" custom-metadata="{}" hacker-one-research="":
    pixi run proxy-client proxy resource set {{hostname}} \
        --endpoint {{endpoint}} \
        --scopes "{{scopes}}" \
        {{ if stateful == "true" { "--stateful" } else { "--stateless" } }} \
        {{ if override-backend == "true" { "--override-backend" } else { "" } }} \
        --bearer-methods {{bearer-methods}} \
        --doc-suffix {{doc-suffix}} \
        --server-info '{{server-info}}' \
        --custom-metadata '{{custom-metadata}}'

# Show protected resource metadata
proxy-resource-show hostname:
    pixi run proxy-client proxy resource show {{hostname}}

# Clear protected resource metadata
proxy-resource-clear hostname:
    pixi run proxy-client proxy resource clear {{hostname}} --force

# List all protected resources
proxy-resource-list:
    pixi run proxy-client proxy resource list

# OAuth Authorization Server Management
# ============================================

# Set OAuth authorization server metadata for a proxy
proxy-oauth-server-set hostname issuer="" scopes="" grant-types="" response-types="" token-auth-methods="" claims="" pkce-required="false" custom-metadata="{}" override-defaults="false":
    pixi run proxy-client proxy oauth-server set {{hostname}} \
        {{ if issuer != "" { "--issuer " + issuer } else { "" } }} \
        {{ if scopes != "" { "--scopes '" + scopes + "'" } else { "" } }} \
        {{ if grant-types != "" { "--grant-types '" + grant-types + "'" } else { "" } }} \
        {{ if response-types != "" { "--response-types '" + response-types + "'" } else { "" } }} \
        {{ if token-auth-methods != "" { "--token-auth-methods '" + token-auth-methods + "'" } else { "" } }} \
        {{ if claims != "" { "--claims '" + claims + "'" } else { "" } }} \
        {{ if pkce-required == "true" { "--pkce-required" } else { "--no-pkce-required" } }} \
        {{ if custom-metadata != "{}" { "--custom-metadata '" + custom-metadata + "'" } else { "" } }} \
        {{ if override-defaults == "true" { "--override-defaults" } else { "--no-override-defaults" } }}

# Show OAuth server configuration for a proxy
proxy-oauth-server-show hostname:
    pixi run proxy-client proxy oauth-server show {{hostname}}

# Clear OAuth server configuration for a proxy
proxy-oauth-server-clear hostname:
    pixi run proxy-client proxy oauth-server clear {{hostname}} --force

# List proxies with custom OAuth server configurations
proxy-oauth-server-list:
    pixi run proxy-client proxy oauth-server list

# DEPRECATED: Use 'just proxy-github set ...' instead
# Set GitHub OAuth credentials for a proxy (per-proxy GitHub OAuth App)
proxy-github-oauth-set hostname client-id client-secret:
    @echo "⚠️  DEPRECATED: Use 'just proxy-github set {{hostname}} {{client-id}} {{client-secret}}' instead"
    @just proxy-github set {{hostname}} {{client-id}} {{client-secret}}

# DEPRECATED: Use 'just proxy-github show ...' instead
# Show GitHub OAuth configuration for a proxy (without revealing the secret)
proxy-github-oauth-show hostname:
    @echo "⚠️  DEPRECATED: Use 'just proxy-github show {{hostname}}' instead"
    @just proxy-github show {{hostname}}

# DEPRECATED: Use 'just proxy-github clear ...' instead
# Clear GitHub OAuth configuration for a proxy (falls back to environment variables)
proxy-github-oauth-clear hostname:
    @echo "⚠️  DEPRECATED: Use 'just proxy-github clear {{hostname}}' instead"
    @just proxy-github clear {{hostname}}

# DEPRECATED: Use 'just proxy-github list' instead
# List all proxies with custom GitHub OAuth configurations
proxy-github-oauth-list:
    @echo "⚠️  DEPRECATED: Use 'just proxy-github list' instead"
    @just proxy-github list

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
# ROUTE MANAGEMENT (Migrated to proxy-client)
# ============================================================================

# Create a new route
route-create path target-type target-value priority="50" methods="ALL" is-regex="false" description="":
    pixi run proxy-client route create {{path}} {{target-type}} {{target-value}} \
        --priority {{priority}} \
        {{ if methods != "ALL" { "--methods " + methods } else { "" } }} \
        {{ if is-regex == "true" { "--regex" } else { "" } }}

# Create a global route
route-create-global path target-type target-value priority="50" methods="*" is-regex="false" description="":
    pixi run proxy-client route create-global {{path}} {{target-type}} {{target-value}} \
        --priority {{priority}} \
        {{ if methods != "*" { "--methods " + methods } else { "" } }} \
        {{ if is-regex == "true" { "--is-regex" } else { "" } }} \
        {{ if description != "" { "--description '" + description + "'" } else { "" } }}

# Create a proxy-specific route
route-create-proxy path target-type target-value proxies priority="500" methods="*" is-regex="false" description="":
    pixi run proxy-client route create-proxy {{path}} {{target-type}} {{target-value}} {{proxies}} \
        --priority {{priority}} \
        {{ if methods != "*" { "--methods " + methods } else { "" } }} \
        {{ if is-regex == "true" { "--is-regex" } else { "" } }} \
        {{ if description != "" { "--description '" + description + "'" } else { "" } }}

# List all routes
route-list:
    pixi run proxy-client route list

# Show route details
route-show route-id:
    pixi run proxy-client route show {{route-id}}

# Delete a route
route-delete route-id:
    pixi run proxy-client route delete {{route-id}} --force

# List routes by scope
route-list-by-scope scope="all":
    pixi run proxy-client route list-by-scope {{scope}}

# ============================================================================
# SERVICE MANAGEMENT (Migrated to proxy-client)
# ============================================================================

# Create a Docker service
service-create name image="" dockerfile="" port="" memory="512m" cpu="1.0" auto-proxy="false":
    pixi run proxy-client service create {{name}} {{image}} \
        {{ if port != "" { "--port " + port } else { "" } }} \
        --memory {{memory}} --cpu {{cpu}}

# Create a Docker service with exposed port
service-create-exposed name image port bind-address="127.0.0.1" memory="512m" cpu="1.0":
    pixi run proxy-client service create-exposed {{name}} {{image}} {{port}} \
        --bind-address {{bind-address}} \
        --memory {{memory}} --cpu {{cpu}}

# List all services (Docker + external)
service-list-all type="":
    pixi run proxy-client service list \
        {{ if type != "" { "--type " + type } else { "--type all" } }}

# Show service details
service-show name:
    pixi run proxy-client service show {{name}}

# Delete a service
service-delete name force="true" delete-proxy="true":
    pixi run proxy-client service delete {{name}} --force

# Start a service
service-start name:
    pixi run proxy-client service start {{name}}

# Stop a service
service-stop name:
    pixi run proxy-client service stop {{name}}

# Restart a service
service-restart name:
    pixi run proxy-client service restart {{name}}

# View service logs
service-logs name lines="100" timestamps="false":
    pixi run proxy-client service logs {{name}} --lines {{lines}}

# Show service statistics
service-stats name:
    pixi run proxy-client service stats {{name}}

# Create proxy for service
service-proxy-create name hostname="" enable-https="false":
    pixi run proxy-client service proxy-create {{name}} \
        {{ if hostname != "" { "--hostname " + hostname } else { "" } }} \
        {{ if enable-https == "true" { "--enable-https" } else { "--no-enable-https" } }}

# Clean up services
service-cleanup:
    pixi run proxy-client service cleanup --force

# Clean up orphaned services
service-cleanup-orphaned:
    pixi run proxy-client workflow cleanup --orphaned-only --force

# Add port to service
service-port-add name port bind-address="127.0.0.1" source-token="":
    pixi run proxy-client service port add {{name}} {{port}} \
        --bind-address {{bind-address}} \
        {{ if source-token != "" { "--source-token " + source-token } else { "" } }}

# Remove port from service
service-port-remove name port-name:
    pixi run proxy-client service port remove {{name}} {{port-name}} --force

# List service ports
service-port-list name:
    pixi run proxy-client service port list {{name}}

# Check port availability
service-port-check port bind-address="127.0.0.1":
    pixi run proxy-client service port check {{port}} --bind-address {{bind-address}}

# List global port allocation
service-ports-global available-only="false":
    pixi run proxy-client service ports \
        {{ if available-only == "true" { "--available-only" } else { "" } }}

# Register external service
service-register name target-url description="":
    pixi run proxy-client service external register {{name}} {{target-url}} \
        {{ if description != "" { "--description '" + description + "'" } else { "" } }}

# Unregister external service
service-unregister name:
    pixi run proxy-client service external unregister {{name}} --force

# List external services
service-list-external:
    pixi run proxy-client service external list

# Show external service details
service-show-external name:
    pixi run proxy-client service external show {{name}}

# Update external service
service-update-external name target-url description="":
    pixi run proxy-client service external update {{name}} {{target-url}} \
        {{ if description != "" { "--description '" + description + "'" } else { "" } }}

# ============================================================================
# OAUTH MANAGEMENT (Migrated to proxy-client)
# ============================================================================

# DEPRECATED: Use 'just oauth login' instead
# Login via OAuth Device Flow (for SSH/remote sessions)
oauth-login:
    @echo "⚠️  DEPRECATED: Use 'just oauth login' instead"
    @pixi run proxy-client oauth login --no-browser

# Check OAuth token status
oauth-status:
    @pixi run proxy-client oauth status

# Refresh OAuth token
oauth-refresh:
    @pixi run proxy-client oauth refresh

# Register OAuth client
oauth-client-register name redirect-uri="urn:ietf:wg:oauth:2.0:oob" scope="read write":
    pixi run proxy-client oauth register {{name}} \
        --redirect-uri {{redirect-uri}} --scope "{{scope}}"

# List OAuth clients (default: 50 per page, use page parameter for pagination)
oauth-clients-list active-only="" page="1" per-page="50":
    pixi run proxy-client --format table oauth client list \
        --page {{page}} --per-page {{per-page}} \
        {{ if active-only == "true" { "--active-only" } else { "" } }}

# List OAuth tokens (access and refresh tokens)
oauth-token-list token_type="" client_id="" username="" page="1" per_page="50" include_expired="false":
    pixi run proxy-client --format table oauth token list \
        --page {{page}} --per-page {{per_page}} \
        {{ if token_type != "" { "--token-type " + token_type } else { "" } }} \
        {{ if client_id != "" { "--client-id " + client_id } else { "" } }} \
        {{ if username != "" { "--username " + username } else { "" } }} \
        {{ if include_expired == "true" { "--include-expired" } else { "" } }}

# List OAuth sessions
oauth-sessions-list:
    pixi run proxy-client oauth session list

# Generate OAuth JWT key (special case - uses openssl)
oauth-key-generate:
    #!/usr/bin/env bash
    set -euo pipefail
    echo "Generating RSA key pair for JWT signing..."
    openssl genrsa -out /tmp/jwt_private.pem 2048 2>/dev/null
    echo ""
    echo "Add this to your .env file:"
    echo "OAUTH_JWT_PRIVATE_KEY_B64=$(base64 -w 0 /tmp/jwt_private.pem)"
    rm /tmp/jwt_private.pem

# Test OAuth tokens
oauth-test-tokens server-url:
    @echo "Testing OAuth configuration..."
    pixi run proxy-client oauth health

# Additional OAuth commands are defined above (lines 489-503)

# ============================================================================
# LOG MANAGEMENT (Migrated to proxy-client)
# ============================================================================

# DEPRECATED: Use 'just log search ...' instead
# Search logs
logs hours="1" event="" level="" hostname="" limit="50":
    @echo "⚠️  DEPRECATED: Use 'just log search [options]' instead"
    pixi run proxy-client log search \
        --hours {{hours}} --limit {{limit}} \
        {{ if hostname != "" { "--hostname " + hostname } else { "" } }}

# Query logs by client IP
logs-ip ip hours="1" event="" level="" limit="100":
    pixi run proxy-client log ip {{ip}} --hours {{hours}} --limit {{limit}}

# Query logs by proxy hostname
logs-proxy hostname hours="1" limit="100":
    pixi run proxy-client log proxy {{hostname}} --hours {{hours}} --limit {{limit}}

# Query logs by client hostname (reverse DNS of client IP)
logs-hostname hostname hours="1" limit="100":
    pixi run proxy-client log hostname {{hostname}} --hours {{hours}} --limit {{limit}}

# Query logs by OAuth client ID
logs-oauth-client client-id hours="1" event="" level="" limit="100":
    pixi run proxy-client log oauth-client {{client-id}} --hours {{hours}} --limit {{limit}}

# DEPRECATED: Use 'just log errors ...' instead
# Show errors
logs-errors hours="1" limit="20":
    @echo "⚠️  DEPRECATED: Use 'just log errors [options]' instead"
    pixi run proxy-client log errors --hours {{hours}} --limit {{limit}}

# DEPRECATED: Use 'just log follow ...' instead
# Follow logs
logs-follow interval="2" event="" level="" hostname="":
    @echo "⚠️  DEPRECATED: Use 'just log follow [options]' instead"
    pixi run proxy-client log follow --interval {{interval}} \
        {{ if hostname != "" { "--hostname " + hostname } else { "" } }}

# OAuth activity for an IP
logs-oauth ip hours="1" limit="100":
    pixi run proxy-client log oauth {{ip}} --hours {{hours}} --limit {{limit}}

# OAuth debugging for an IP
logs-oauth-debug ip hours="1" limit="100":
    pixi run proxy-client log oauth-debug {{ip}} --hours {{hours}} --limit {{limit}}

# OAuth flow tracking
logs-oauth-flow client-id="" username="" hours="1":
    pixi run proxy-client log oauth-flow \
        {{ if client-id != "" { "--client-id " + client-id } else { "" } }} \
        {{ if username != "" { "--username " + username } else { "" } }} \
        --hours {{hours}}

# Search logs with query
logs-search query="" hours="1" event="" level="" hostname="" limit="100":
    pixi run proxy-client log search \
        {{ if query != "" { "--query '" + query + "'" } else { "" } }} \
        --hours {{hours}} --limit {{limit}} \
        {{ if hostname != "" { "--hostname " + hostname } else { "" } }}

# Log statistics
logs-stats hours="1":
    pixi run proxy-client log stats --hours {{hours}}

# Clear logs
logs-clear:
    pixi run proxy-client log clear --force

# Test logging system
logs-test:
    pixi run proxy-client log test

# Query logs by authenticated user ID
logs-user user-id hours="1" limit="100":
    pixi run proxy-client log user {{user-id}} --hours {{hours}} --limit {{limit}}

# Query logs by session ID
logs-session session-id hours="1" limit="100":
    pixi run proxy-client log session {{session-id}} --hours {{hours}} --limit {{limit}}

# Query logs by HTTP method
logs-method method hours="1" limit="100":
    pixi run proxy-client log method {{method}} --hours {{hours}} --limit {{limit}}

# Query logs by status code
logs-status code hours="1" limit="100":
    pixi run proxy-client log status {{code}} --hours {{hours}} --limit {{limit}}

# Query slow requests
logs-slow threshold-ms="1000" hours="1" limit="50":
    pixi run proxy-client log slow --threshold {{threshold-ms}} --hours {{hours}} --limit {{limit}}

# Query logs by path pattern
logs-path pattern hours="1" limit="100":
    pixi run proxy-client log path "{{pattern}}" --hours {{hours}} --limit {{limit}}

# Query logs by OAuth username
logs-oauth-user username hours="1" limit="100":
    pixi run proxy-client log oauth-user {{username}} --hours {{hours}} --limit {{limit}}

# Docker service logs (not migrated - Docker specific)
logs-service service="" lines="100":
    -{{ if service != "" { "docker-compose logs --tail=" + lines + " " + service + " 2>/dev/null || true" } else { "docker-compose logs --tail=" + lines + " 2>/dev/null || true" } }}

# Help for logging commands
logs-help:
    @echo "Logging Commands Help"
    @echo ""
    @echo "Available log commands:"
    @echo "  logs              - Search application logs"
    @echo "  logs-ip           - Query by client IP address"
    @echo "  logs-host         - Query by client FQDN (reverse DNS)"
    @echo "  logs-proxy        - Query by proxy hostname"
    @echo "  logs-client       - Query by OAuth client"
    @echo "  logs-errors       - Show recent errors"
    @echo "  logs-oauth        - OAuth activity for an IP"
    @echo "  logs-stats        - Statistics and metrics"
    @echo "  logs-service      - Docker container logs"
    @echo ""
    @echo "Log Level Management:"
    @echo "  log-level-set     - Set log level (e.g., just log-level-set DEBUG proxy)"
    @echo "  log-level-get     - Get current log levels"
    @echo "  log-level-reset   - Reset component to default level"
    @echo ""
    @echo "Log Filter Management:"
    @echo "  log-filter-set    - Set filters (e.g., just log-filter-set proxy '.*health.*')"
    @echo "  log-filter-get    - Get filter configuration"
    @echo "  log-filter-reset  - Remove filters for component"
    @echo "  log-filter-stats  - Get filtering statistics"
    @echo ""
    @echo "Quick Presets:"
    @echo "  log-reduce-verbose - Reduce verbose logging (suppress health checks, etc.)"
    @echo "  log-debug-enable   - Enable DEBUG for a component"
    @echo "  log-trace-enable   - Enable TRACE for a component (very verbose!)"
    @echo ""
    @echo "For detailed help: proxy-client log --help"

# ============================================================================
# LOG LEVEL & FILTER MANAGEMENT
# ============================================================================

# Set log level for global or specific component
log-level-set level component="":
    #!/usr/bin/env bash
    set -euo pipefail
    source .env 2>/dev/null || true
    
    if [ -z "{{ component }}" ]; then
        echo "Setting global log level to {{ level }}..."
        pixi run proxy-client log level set {{ level }}
    else
        echo "Setting log level for {{ component }} to {{ level }}..."
        pixi run proxy-client log level set {{ level }} --component {{ component }}
    fi

# Get current log levels
log-level-get component="":
    #!/usr/bin/env bash
    set -euo pipefail
    source .env 2>/dev/null || true
    
    if [ -z "{{ component }}" ]; then
        pixi run proxy-client log level get
    else
        pixi run proxy-client log level get --component {{ component }}
    fi

# Reset component log level to default
log-level-reset component:
    #!/usr/bin/env bash
    set -euo pipefail
    source .env 2>/dev/null || true
    
    echo "Resetting log level for {{ component }} to default..."
    pixi run proxy-client log level reset {{ component }} --confirm

# Set log filter with suppress patterns (example: just log-filter-set proxy ".*health.*,.*OPTIONS.*")
log-filter-set component patterns="":
    #!/usr/bin/env bash
    set -euo pipefail
    source .env 2>/dev/null || true
    
    if [ -n "{{ patterns }}" ]; then
        # Split comma-separated patterns and add -s flag for each
        IFS=',' read -ra PATTERN_ARRAY <<< "{{ patterns }}"
        PATTERN_FLAGS=""
        for pattern in "${PATTERN_ARRAY[@]}"; do
            PATTERN_FLAGS="$PATTERN_FLAGS -s \"$pattern\""
        done
        echo "Setting suppress patterns for {{ component }}: {{ patterns }}"
        eval "pixi run proxy-client log filter set {{ component }} $PATTERN_FLAGS"
    else
        echo "Usage: just log-filter-set <component> \"pattern1,pattern2\""
        echo "Example: just log-filter-set proxy \".*health.*,.*OPTIONS.*\""
    fi

# Get log filter configuration for a component
log-filter-get component:
    #!/usr/bin/env bash
    set -euo pipefail
    source .env 2>/dev/null || true
    
    pixi run proxy-client log filter get {{ component }}

# Reset (remove) log filters for a component
log-filter-reset component:
    #!/usr/bin/env bash
    set -euo pipefail
    source .env 2>/dev/null || true
    
    echo "Removing all filters for {{ component }}..."
    pixi run proxy-client log filter reset {{ component }} --confirm

# Get statistics about filtered logs
log-filter-stats:
    #!/usr/bin/env bash
    set -euo pipefail
    source .env 2>/dev/null || true
    
    pixi run proxy-client log filter stats

# Reduce verbose logging (suppress health checks, sample TRACE/DEBUG)
log-reduce-verbose:
    #!/usr/bin/env bash
    set -euo pipefail
    source .env 2>/dev/null || true
    
    echo "Applying verbose reduction preset..."
    
    # Set global level to INFO
    just log-level-set INFO
    
    # Suppress health checks for common components
    for component in proxy api dispatcher redis_storage; do
        echo "Configuring $component..."
        pixi run proxy-client log filter set $component \
            -s ".*health.*" \
            -s ".*OPTIONS.*" \
            -r "TRACE:0.01" \
            -r "DEBUG:0.1" \
            -l "same_message:10/minute"
    done
    
    echo "Verbose reduction applied!"

# Enable debug logging for a component
log-debug-enable component:
    just log-level-set DEBUG {{ component }}
    @echo "Debug logging enabled for {{ component }}"

# Enable trace logging (very verbose) for a component
log-trace-enable component:
    just log-level-set TRACE {{ component }}
    @echo "TRACE logging enabled for {{ component }} (very verbose!)"

# ============================================================================
# SYSTEM & CONFIG MANAGEMENT (Migrated to proxy-client)
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

# ============================================================================
# WORKFLOW SHORTCUTS (New high-level commands)
# ============================================================================

# Quick proxy setup with certificate and optional auth
quickstart hostname target-url enable-auth="false":
    @pixi run proxy-client workflow proxy-quickstart {{hostname}} {{target-url}} \
        {{ if enable-auth == "true" { "--enable-auth" } else { "" } }}

# Setup OAuth for a domain
setup-oauth domain:
    @pixi run proxy-client workflow oauth-setup {{domain}} --generate-key

# Create app with automatic proxy
create-app name image:
    @pixi run proxy-client workflow service-with-proxy {{name}} {{image}} --enable-https

# Clean up orphaned resources
cleanup-resources:
    @pixi run proxy-client workflow cleanup --orphaned-only --force

# ============================================================================
# TESTING & DOCUMENTATION (Not migrated - local operations)
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
# DRY RUN MODE
# ============================================================================

# Test commands without making changes
dry-run command *args:
    @pixi run proxy-client --dry-run {{command}} {{args}}