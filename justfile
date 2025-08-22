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

# Generate admin token (special case - uses openssl)
token-admin:
    #!/usr/bin/env bash
    set -euo pipefail
    
    if [ -n "${ADMIN_TOKEN:-}" ]; then
        echo "Admin token already exists in environment"
        exit 0
    fi
    
    # Generate secure token
    token="acm_$(openssl rand -hex 32)"
    
    # Get admin email
    admin_email="${ADMIN_EMAIL:-admin@example.com}"
    
    echo "Creating admin token..."
    pixi run proxy-client token create ADMIN --cert-email "$admin_email" --token "$token" 2>/dev/null || true
    
    echo ""
    echo "Admin token generated:"
    echo "export ADMIN_TOKEN=$token"
    echo ""
    echo "Add this to your .env file"

# Generate a new token
token-generate name email=env_var_or_default("ADMIN_EMAIL", "") token=env_var_or_default("ADMIN_TOKEN", ""):
    TOKEN={{token}} pixi run proxy-client token create {{name}} --cert-email {{email}}

# List all tokens
token-list token=env_var_or_default("ADMIN_TOKEN", ""):
    TOKEN={{token}} pixi run proxy-client token list

# Show token details
token-show name token=env_var_or_default("ADMIN_TOKEN", ""):
    TOKEN={{token}} pixi run proxy-client token show {{name}}

# Delete a token
token-delete name token=env_var_or_default("ADMIN_TOKEN", ""):
    TOKEN={{token}} pixi run proxy-client token delete {{name}} --force

# Update token's certificate email (for current token only)
token-email email token=env_var_or_default("ADMIN_TOKEN", ""):
    TOKEN={{token}} pixi run proxy-client token update-email {{email}}

# ============================================================================
# CERTIFICATE MANAGEMENT (Migrated to proxy-client)
# ============================================================================

# Create a new certificate
cert-create name domain staging="false" email=env_var_or_default("ADMIN_EMAIL", "") token=env_var_or_default("ADMIN_TOKEN", ""):
    TOKEN={{token}} pixi run proxy-client cert create {{name}} {{domain}} \
        {{ if staging == "true" { "--staging" } else { "" } }} \
        --email {{email}}

# List all certificates
cert-list token=env_var_or_default("ADMIN_TOKEN", ""):
    TOKEN={{token}} pixi run proxy-client cert list

# Show certificate details
cert-show name pem="false" token=env_var_or_default("ADMIN_TOKEN", ""):
    TOKEN={{token}} pixi run proxy-client cert show {{name}} \
        {{ if pem == "true" { "--pem" } else { "" } }}

# Delete a certificate
cert-delete name force="false" token=env_var_or_default("ADMIN_TOKEN", ""):
    TOKEN={{token}} pixi run proxy-client cert delete {{name}} \
        {{ if force == "true" { "--force" } else { "" } }}

# Renew a certificate
cert-renew name force="false" wait="true" token=env_var_or_default("ADMIN_TOKEN", ""):
    TOKEN={{token}} pixi run proxy-client cert renew {{name}} \
        {{ if force == "true" { "--force" } else { "" } }} \
        {{ if wait == "false" { "--no-wait" } else { "" } }}

# Convert staging certificate to production
cert-convert-to-production name wait="true" force="false" token=env_var_or_default("ADMIN_TOKEN", ""):
    TOKEN={{token}} pixi run proxy-client cert convert-to-production {{name}} \
        {{ if wait == "false" { "--no-wait" } else { "" } }} \
        {{ if force == "true" { "--force" } else { "" } }}

# ============================================================================
# PROXY MANAGEMENT (Migrated to proxy-client)
# ============================================================================

# Create a new proxy with automatic certificate handling
# Will check for existing certificates and create new ones if needed
proxy-create hostname target-url staging="false" preserve-host="true" enable-http="true" enable-https="true" email=env_var_or_default("ADMIN_EMAIL", "") token=env_var_or_default("ADMIN_TOKEN", ""):
    TOKEN={{token}} pixi run proxy-client proxy create {{hostname}} {{target-url}} \
        {{ if staging == "true" { "--staging" } else { "" } }} \
        {{ if preserve-host == "false" { "--no-preserve-host" } else { "" } }} \
        {{ if enable-http == "false" { "--no-enable-http" } else { "" } }} \
        {{ if enable-https == "false" { "--no-enable-https" } else { "" } }} \
        --email {{email}}

# List all proxies
proxy-list token=env_var_or_default("ADMIN_TOKEN", ""):
    TOKEN={{token}} pixi run proxy-client --format table proxy list

# Show proxy details
proxy-show hostname token=env_var_or_default("ADMIN_TOKEN", ""):
    TOKEN={{token}} pixi run proxy-client proxy show {{hostname}}

# Delete a proxy
proxy-delete hostname delete-cert="false" force="false" token=env_var_or_default("ADMIN_TOKEN", ""):
    TOKEN={{token}} pixi run proxy-client proxy delete {{hostname}} --force \
        {{ if delete-cert == "true" { "--delete-cert" } else { "" } }} \
        {{ if force == "true" { "--force" } else { "" } }}

# Enable authentication for a proxy
proxy-auth-enable hostname auth-proxy="auth.localhost" mode="forward" allowed-scopes="" allowed-audiences="" token=env_var_or_default("ADMIN_TOKEN", ""):
    TOKEN={{token}} pixi run proxy-client proxy auth enable {{hostname}} \
        {{auth-proxy}} \
        {{mode}} \
        {{ if allowed-scopes != "" { "--allowed-scopes " + allowed-scopes } else { "" } }} \
        {{ if allowed-audiences != "" { "--allowed-audiences " + allowed-audiences } else { "" } }}

# Disable authentication for a proxy
proxy-auth-disable hostname token=env_var_or_default("ADMIN_TOKEN", ""):
    TOKEN={{token}} pixi run proxy-client proxy auth disable {{hostname}}

# Configure authentication for a proxy
proxy-auth-config hostname users="" emails="" groups="" allowed-scopes="" allowed-audiences="" token=env_var_or_default("ADMIN_TOKEN", ""):
    TOKEN={{token}} pixi run proxy-client proxy auth config {{hostname}} \
        {{ if users != "" { "--users " + users } else { "" } }} \
        {{ if emails != "" { "--emails " + emails } else { "" } }} \
        {{ if groups != "" { "--groups " + groups } else { "" } }} \
        {{ if allowed-scopes != "" { "--scopes " + allowed-scopes } else { "" } }} \
        {{ if allowed-audiences != "" { "--audiences " + allowed-audiences } else { "" } }}

# Show authentication configuration
proxy-auth-show hostname token=env_var_or_default("ADMIN_TOKEN", ""):
    TOKEN={{token}} pixi run proxy-client proxy auth show {{hostname}}

# Set protected resource metadata
proxy-resource-set hostname endpoint="/api" scopes="read,write" stateful="false" override-backend="false" bearer-methods="header" doc-suffix="/docs" server-info="{}" custom-metadata="{}" hacker-one-research="" token=env_var_or_default("ADMIN_TOKEN", ""):
    TOKEN={{token}} pixi run proxy-client proxy resource set {{hostname}} \
        --endpoint {{endpoint}} \
        --scopes "{{scopes}}" \
        {{ if stateful == "true" { "--stateful" } else { "--stateless" } }} \
        {{ if override-backend == "true" { "--override-backend" } else { "" } }} \
        --bearer-methods {{bearer-methods}} \
        --doc-suffix {{doc-suffix}} \
        --server-info '{{server-info}}' \
        --custom-metadata '{{custom-metadata}}'

# Show protected resource metadata
proxy-resource-show hostname token=env_var_or_default("ADMIN_TOKEN", ""):
    TOKEN={{token}} pixi run proxy-client proxy resource show {{hostname}}

# Clear protected resource metadata
proxy-resource-clear hostname token=env_var_or_default("ADMIN_TOKEN", ""):
    TOKEN={{token}} pixi run proxy-client proxy resource clear {{hostname}} --force

# List all protected resources
proxy-resource-list token=env_var_or_default("ADMIN_TOKEN", ""):
    TOKEN={{token}} pixi run proxy-client proxy resource list

# OAuth Authorization Server Management
# ============================================

# Set OAuth authorization server metadata for a proxy
proxy-oauth-server-set hostname issuer="" scopes="" grant-types="" response-types="" token-auth-methods="" claims="" pkce-required="false" custom-metadata="{}" override-defaults="false" token=env_var_or_default("ADMIN_TOKEN", ""):
    TOKEN={{token}} pixi run proxy-client proxy oauth-server set {{hostname}} \
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
proxy-oauth-server-show hostname token=env_var_or_default("ADMIN_TOKEN", ""):
    TOKEN={{token}} pixi run proxy-client proxy oauth-server show {{hostname}}

# Clear OAuth server configuration for a proxy
proxy-oauth-server-clear hostname token=env_var_or_default("ADMIN_TOKEN", ""):
    TOKEN={{token}} pixi run proxy-client proxy oauth-server clear {{hostname}} --force

# List proxies with custom OAuth server configurations
proxy-oauth-server-list token=env_var_or_default("ADMIN_TOKEN", ""):
    TOKEN={{token}} pixi run proxy-client proxy oauth-server list

# ============================================================================
# ROUTE MANAGEMENT (Migrated to proxy-client)
# ============================================================================

# Create a new route
route-create path target-type target-value priority="50" methods="ALL" is-regex="false" description="" token=env_var_or_default("ADMIN_TOKEN", ""):
    TOKEN={{token}} pixi run proxy-client route create {{path}} {{target-type}} {{target-value}} \
        --priority {{priority}} \
        {{ if methods != "ALL" { "--methods " + methods } else { "" } }} \
        {{ if is-regex == "true" { "--regex" } else { "" } }}

# Create a global route
route-create-global path target-type target-value priority="50" methods="*" is-regex="false" description="" token=env_var_or_default("ADMIN_TOKEN", ""):
    TOKEN={{token}} pixi run proxy-client route create-global {{path}} {{target-type}} {{target-value}} \
        --priority {{priority}} \
        {{ if methods != "*" { "--methods " + methods } else { "" } }} \
        {{ if is-regex == "true" { "--is-regex" } else { "" } }} \
        {{ if description != "" { "--description '" + description + "'" } else { "" } }}

# Create a proxy-specific route
route-create-proxy path target-type target-value proxies priority="500" methods="*" is-regex="false" description="" token=env_var_or_default("ADMIN_TOKEN", ""):
    TOKEN={{token}} pixi run proxy-client route create-proxy {{path}} {{target-type}} {{target-value}} {{proxies}} \
        --priority {{priority}} \
        {{ if methods != "*" { "--methods " + methods } else { "" } }} \
        {{ if is-regex == "true" { "--is-regex" } else { "" } }} \
        {{ if description != "" { "--description '" + description + "'" } else { "" } }}

# List all routes
route-list token=env_var_or_default("ADMIN_TOKEN", ""):
    TOKEN={{token}} pixi run proxy-client route list

# Show route details
route-show route-id token=env_var_or_default("ADMIN_TOKEN", ""):
    TOKEN={{token}} pixi run proxy-client route show {{route-id}}

# Delete a route
route-delete route-id token=env_var_or_default("ADMIN_TOKEN", ""):
    TOKEN={{token}} pixi run proxy-client route delete {{route-id}} --force

# List routes by scope
route-list-by-scope scope="all" token=env_var_or_default("ADMIN_TOKEN", ""):
    TOKEN={{token}} pixi run proxy-client route list-by-scope {{scope}}

# ============================================================================
# SERVICE MANAGEMENT (Migrated to proxy-client)
# ============================================================================

# Create a Docker service
service-create name image="" dockerfile="" port="" memory="512m" cpu="1.0" auto-proxy="false" token=env_var_or_default("ADMIN_TOKEN", ""):
    TOKEN={{token}} pixi run proxy-client service create {{name}} {{image}} \
        {{ if port != "" { "--port " + port } else { "" } }} \
        --memory {{memory}} --cpu {{cpu}}

# Create a Docker service with exposed port
service-create-exposed name image port bind-address="127.0.0.1" memory="512m" cpu="1.0" token=env_var_or_default("ADMIN_TOKEN", ""):
    TOKEN={{token}} pixi run proxy-client service create-exposed {{name}} {{image}} {{port}} \
        --bind-address {{bind-address}} \
        --memory {{memory}} --cpu {{cpu}}

# List Docker services
service-list owned-only="false" token=env_var_or_default("ADMIN_TOKEN", ""):
    TOKEN={{token}} pixi run proxy-client service list --type docker

# List all services (Docker + external)
service-list-all type="" token=env_var_or_default("ADMIN_TOKEN", ""):
    TOKEN={{token}} pixi run proxy-client service list \
        {{ if type != "" { "--type " + type } else { "--type all" } }}

# Show service details
service-show name token=env_var_or_default("ADMIN_TOKEN", ""):
    TOKEN={{token}} pixi run proxy-client service show {{name}}

# Delete a service
service-delete name force="false" delete-proxy="true" token=env_var_or_default("ADMIN_TOKEN", ""):
    TOKEN={{token}} pixi run proxy-client service delete {{name}} \
        {{ if force == "true" { "--force" } else { "" } }}

# Start a service
service-start name token=env_var_or_default("ADMIN_TOKEN", ""):
    TOKEN={{token}} pixi run proxy-client service start {{name}}

# Stop a service
service-stop name token=env_var_or_default("ADMIN_TOKEN", ""):
    TOKEN={{token}} pixi run proxy-client service stop {{name}}

# Restart a service
service-restart name token=env_var_or_default("ADMIN_TOKEN", ""):
    TOKEN={{token}} pixi run proxy-client service restart {{name}}

# View service logs
service-logs name lines="100" timestamps="false" token=env_var_or_default("ADMIN_TOKEN", ""):
    TOKEN={{token}} pixi run proxy-client service logs {{name}} --lines {{lines}}

# Show service statistics
service-stats name token=env_var_or_default("ADMIN_TOKEN", ""):
    TOKEN={{token}} pixi run proxy-client service stats {{name}}

# Create proxy for service
service-proxy-create name hostname="" enable-https="false" token=env_var_or_default("ADMIN_TOKEN", ""):
    TOKEN={{token}} pixi run proxy-client service proxy-create {{name}} \
        {{ if hostname != "" { "--hostname " + hostname } else { "" } }} \
        {{ if enable-https == "true" { "--enable-https" } else { "--no-enable-https" } }}

# Clean up services
service-cleanup token=env_var_or_default("ADMIN_TOKEN", ""):
    TOKEN={{token}} pixi run proxy-client service cleanup --force

# Clean up orphaned services
service-cleanup-orphaned token=env_var_or_default("ADMIN_TOKEN", ""):
    TOKEN={{token}} pixi run proxy-client workflow cleanup --orphaned-only --force

# Add port to service
service-port-add name port bind-address="127.0.0.1" source-token="" token=env_var_or_default("ADMIN_TOKEN", ""):
    TOKEN={{token}} pixi run proxy-client service port add {{name}} {{port}} \
        --bind-address {{bind-address}} \
        {{ if source-token != "" { "--source-token " + source-token } else { "" } }}

# Remove port from service
service-port-remove name port-name token=env_var_or_default("ADMIN_TOKEN", ""):
    TOKEN={{token}} pixi run proxy-client service port remove {{name}} {{port-name}} --force

# List service ports
service-port-list name token=env_var_or_default("ADMIN_TOKEN", ""):
    TOKEN={{token}} pixi run proxy-client service port list {{name}}

# Check port availability
service-port-check port bind-address="127.0.0.1" token=env_var_or_default("ADMIN_TOKEN", ""):
    TOKEN={{token}} pixi run proxy-client service port check {{port}} --bind-address {{bind-address}}

# List global port allocation
service-ports-global available-only="false" token=env_var_or_default("ADMIN_TOKEN", ""):
    TOKEN={{token}} pixi run proxy-client service ports \
        {{ if available-only == "true" { "--available-only" } else { "" } }}

# Register external service
service-register name target-url description="" token=env_var_or_default("ADMIN_TOKEN", ""):
    TOKEN={{token}} pixi run proxy-client service external register {{name}} {{target-url}} \
        {{ if description != "" { "--description '" + description + "'" } else { "" } }}

# Unregister external service
service-unregister name token=env_var_or_default("ADMIN_TOKEN", ""):
    TOKEN={{token}} pixi run proxy-client service external unregister {{name}} --force

# List external services
service-list-external token=env_var_or_default("ADMIN_TOKEN", ""):
    TOKEN={{token}} pixi run proxy-client service external list

# Show external service details
service-show-external name token=env_var_or_default("ADMIN_TOKEN", ""):
    TOKEN={{token}} pixi run proxy-client service external show {{name}}

# Update external service
service-update-external name target-url description="" token=env_var_or_default("ADMIN_TOKEN", ""):
    TOKEN={{token}} pixi run proxy-client service external update {{name}} {{target-url}} \
        {{ if description != "" { "--description '" + description + "'" } else { "" } }}

# Register OAuth as external service
service-register-oauth token=env_var_or_default("ADMIN_TOKEN", ""):
    TOKEN={{token}} pixi run proxy-client service external register oauth https://auth.${BASE_DOMAIN} \
        --description "OAuth 2.1 Authorization Server"

# ============================================================================
# OAUTH MANAGEMENT (Migrated to proxy-client)
# ============================================================================

# Register OAuth client
oauth-client-register name redirect-uri="urn:ietf:wg:oauth:2.0:oob" scope="read write" token=env_var_or_default("ADMIN_TOKEN", ""):
    TOKEN={{token}} pixi run proxy-client oauth register {{name}} \
        --redirect-uri {{redirect-uri}} --scope "{{scope}}"

# List OAuth clients (default: 50 per page, use page parameter for pagination)
oauth-clients-list active-only="" page="1" per-page="50" token=env_var_or_default("ADMIN_TOKEN", ""):
    TOKEN={{token}} pixi run proxy-client --format table oauth client list \
        --page {{page}} --per-page {{per-page}} \
        {{ if active-only == "true" { "--active-only" } else { "" } }}

# List OAuth tokens (access and refresh tokens)
oauth-token-list token_type="" client_id="" username="" page="1" per_page="50" include_expired="false" token=env_var_or_default("ADMIN_TOKEN", ""):
    TOKEN={{token}} pixi run proxy-client --format table oauth token list \
        --page {{page}} --per-page {{per_page}} \
        {{ if token_type != "" { "--token-type " + token_type } else { "" } }} \
        {{ if client_id != "" { "--client-id " + client_id } else { "" } }} \
        {{ if username != "" { "--username " + username } else { "" } }} \
        {{ if include_expired == "true" { "--include-expired" } else { "" } }}

# List OAuth sessions
oauth-sessions-list token=env_var_or_default("ADMIN_TOKEN", ""):
    TOKEN={{token}} pixi run proxy-client oauth session list

# Generate OAuth JWT key (special case - uses openssl)
oauth-key-generate token=env_var_or_default("ADMIN_TOKEN", ""):
    #!/usr/bin/env bash
    set -euo pipefail
    echo "Generating RSA key pair for JWT signing..."
    openssl genrsa -out /tmp/jwt_private.pem 2048 2>/dev/null
    echo ""
    echo "Add this to your .env file:"
    echo "OAUTH_JWT_PRIVATE_KEY_B64=$(base64 -w 0 /tmp/jwt_private.pem)"
    rm /tmp/jwt_private.pem

# Setup OAuth routes for a domain
oauth-routes-setup domain token=env_var_or_default("ADMIN_TOKEN", ""):
    TOKEN={{token}} pixi run proxy-client workflow oauth-setup {{domain}}

# Test OAuth tokens
oauth-test-tokens server-url token=env_var_or_default("ADMIN_TOKEN", ""):
    @echo "Testing OAuth configuration..."
    TOKEN={{token}} pixi run proxy-client oauth health

# ============================================================================
# LOG MANAGEMENT (Migrated to proxy-client)
# ============================================================================

# Search logs
logs hours="1" event="" level="" hostname="" limit="50" token=env_var_or_default("ADMIN_TOKEN", ""):
    TOKEN={{token}} pixi run proxy-client log search \
        --hours {{hours}} --limit {{limit}} \
        {{ if hostname != "" { "--hostname " + hostname } else { "" } }}

# Query logs by client IP
logs-ip ip hours="1" event="" level="" limit="100" token=env_var_or_default("ADMIN_TOKEN", ""):
    TOKEN={{token}} pixi run proxy-client log ip {{ip}} --hours {{hours}} --limit {{limit}}

# Query logs by proxy hostname
logs-proxy hostname hours="1" limit="100" token=env_var_or_default("ADMIN_TOKEN", ""):
    TOKEN={{token}} pixi run proxy-client log proxy {{hostname}} --hours {{hours}} --limit {{limit}}

# Query logs by client hostname (reverse DNS of client IP)
logs-hostname hostname hours="1" limit="100" token=env_var_or_default("ADMIN_TOKEN", ""):
    TOKEN={{token}} pixi run proxy-client log hostname {{hostname}} --hours {{hours}} --limit {{limit}}

# Query logs by OAuth client ID
logs-oauth-client client-id hours="1" event="" level="" limit="100" token=env_var_or_default("ADMIN_TOKEN", ""):
    TOKEN={{token}} pixi run proxy-client log oauth-client {{client-id}} --hours {{hours}} --limit {{limit}}

# Show errors
logs-errors hours="1" limit="20" token=env_var_or_default("ADMIN_TOKEN", ""):
    TOKEN={{token}} pixi run proxy-client log errors --hours {{hours}} --limit {{limit}}

# Debug errors
logs-errors-debug hours="1" include-warnings="false" limit="50" token=env_var_or_default("ADMIN_TOKEN", ""):
    TOKEN={{token}} pixi run proxy-client log errors --hours {{hours}} \
        {{ if include-warnings == "true" { "--include-warnings" } else { "" } }} \
        --limit {{limit}}

# Follow logs
logs-follow interval="2" event="" level="" hostname="" token=env_var_or_default("ADMIN_TOKEN", ""):
    TOKEN={{token}} pixi run proxy-client log follow --interval {{interval}} \
        {{ if hostname != "" { "--hostname " + hostname } else { "" } }}

# OAuth activity for an IP
logs-oauth ip hours="1" limit="100" token=env_var_or_default("ADMIN_TOKEN", ""):
    TOKEN={{token}} pixi run proxy-client log oauth {{ip}} --hours {{hours}} --limit {{limit}}

# OAuth debugging for an IP
logs-oauth-debug ip hours="1" limit="100" token=env_var_or_default("ADMIN_TOKEN", ""):
    TOKEN={{token}} pixi run proxy-client log oauth-debug {{ip}} --hours {{hours}} --limit {{limit}}

# OAuth flow tracking
logs-oauth-flow client-id="" username="" hours="1" token=env_var_or_default("ADMIN_TOKEN", ""):
    TOKEN={{token}} pixi run proxy-client log oauth-flow \
        {{ if client-id != "" { "--client-id " + client-id } else { "" } }} \
        {{ if username != "" { "--username " + username } else { "" } }} \
        --hours {{hours}}

# Search logs with query
logs-search query="" hours="1" event="" level="" hostname="" limit="100" token=env_var_or_default("ADMIN_TOKEN", ""):
    TOKEN={{token}} pixi run proxy-client log search \
        {{ if query != "" { "--query '" + query + "'" } else { "" } }} \
        --hours {{hours}} --limit {{limit}} \
        {{ if hostname != "" { "--hostname " + hostname } else { "" } }}

# Log statistics
logs-stats hours="1" token=env_var_or_default("ADMIN_TOKEN", ""):
    TOKEN={{token}} pixi run proxy-client log stats --hours {{hours}}

# Clear logs
logs-clear token=env_var_or_default("ADMIN_TOKEN", ""):
    TOKEN={{token}} pixi run proxy-client log clear --force

# Test logging system
logs-test token=env_var_or_default("ADMIN_TOKEN", ""):
    TOKEN={{token}} pixi run proxy-client log test

# Query logs by authenticated user ID
logs-user user-id hours="1" limit="100" token=env_var_or_default("ADMIN_TOKEN", ""):
    TOKEN={{token}} pixi run proxy-client log user {{user-id}} --hours {{hours}} --limit {{limit}}

# Query logs by session ID
logs-session session-id hours="1" limit="100" token=env_var_or_default("ADMIN_TOKEN", ""):
    TOKEN={{token}} pixi run proxy-client log session {{session-id}} --hours {{hours}} --limit {{limit}}

# Query logs by HTTP method
logs-method method hours="1" limit="100" token=env_var_or_default("ADMIN_TOKEN", ""):
    TOKEN={{token}} pixi run proxy-client log method {{method}} --hours {{hours}} --limit {{limit}}

# Query logs by status code
logs-status code hours="1" limit="100" token=env_var_or_default("ADMIN_TOKEN", ""):
    TOKEN={{token}} pixi run proxy-client log status {{code}} --hours {{hours}} --limit {{limit}}

# Query slow requests
logs-slow threshold-ms="1000" hours="1" limit="50" token=env_var_or_default("ADMIN_TOKEN", ""):
    TOKEN={{token}} pixi run proxy-client log slow --threshold {{threshold-ms}} --hours {{hours}} --limit {{limit}}

# Query logs by path pattern
logs-path pattern hours="1" limit="100" token=env_var_or_default("ADMIN_TOKEN", ""):
    TOKEN={{token}} pixi run proxy-client log path "{{pattern}}" --hours {{hours}} --limit {{limit}}

# Query logs by OAuth username
logs-oauth-user username hours="1" limit="100" token=env_var_or_default("ADMIN_TOKEN", ""):
    TOKEN={{token}} pixi run proxy-client log oauth-user {{username}} --hours {{hours}} --limit {{limit}}

# Docker container logs only
logs-docker lines="50" follow="false":
    {{ if follow == "true" { "docker-compose logs --tail=" + lines + " --follow" } else { "docker-compose logs --tail=" + lines } }}

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
    @echo "For detailed help: proxy-client log --help"

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