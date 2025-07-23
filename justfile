# MCP HTTP Proxy - Refactored Modular Justfile
# This is a refactored version with modular approach and API-first design

# Variables
container_name := "mcp-http-proxy-proxy-1"
default_base_url := "http://localhost"
staging_cert_email := env_var_or_default("TEST_EMAIL", "test@example.com")

# Load environment from .env
set dotenv-load := true
set dotenv-required
set positional-arguments := true
set allow-duplicate-recipes
# Export all variables as environment variables
set export := true
set quiet

# ============================================================================
# SYSTEM MANAGEMENT
# ============================================================================

# Show all available commands
help:
    @just --list --unsorted

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

# Rebuild a specific service
rebuild service="proxy":
    docker compose build {{service}}
    docker compose up -d {{service}}

# View logs (optionally for specific service)
logs service="":
    #!/usr/bin/env bash
    if [ -n "{{service}}" ]; then
        docker compose logs -f {{service}}
    else
        docker compose logs -f
    fi

# Open shell in container
shell:
    docker exec -it {{container_name}} /bin/bash

# Access Redis CLI
redis-cli:
    docker compose exec redis redis-cli -a "${REDIS_PASSWORD}"

# Check system health
health:
    #!/usr/bin/env bash
    set -euo pipefail
    
    BASE_URL="${BASE_URL:-{{default_base_url}}}"
    
    response=$(curl -sL "${BASE_URL}/health")
    echo "$response" | jq '.'

# ============================================================================
# TOKEN MANAGEMENT
# ============================================================================

# Generate a new API token
token-generate name email="":
    #!/usr/bin/env bash
    set -euo pipefail
    
    # Use provided email or ADMIN_EMAIL or prompt
    if [ -n "{{email}}" ]; then
        cert_email="{{email}}"
    elif [ -n "${ADMIN_EMAIL:-}" ]; then
        cert_email="$ADMIN_EMAIL"
        echo "Using ADMIN_EMAIL: $cert_email"
    else
        read -p "Certificate email for {{name}}: " cert_email
    fi
    
    docker exec {{container_name}} pixi run python scripts/generate_token.py "{{name}}" "$cert_email"

# Show token value
token-show name:
    #!/usr/bin/env bash
    if [ "{{name}}" = "ADMIN" ] && [ -n "${ADMIN_TOKEN:-}" ]; then
        echo "Token: ${ADMIN_TOKEN}"
    else
        docker exec {{container_name}} pixi run python scripts/show_token.py "{{name}}"
    fi

# List all tokens
token-list:
    docker exec {{container_name}} pixi run python scripts/list_tokens.py

# Delete token and owned resources
token-delete name:
    #!/usr/bin/env bash
    set -euo pipefail
    
    # Confirm deletion
    read -p "Delete token '{{name}}' and all owned resources? [y/N] " -n 1 -r
    echo
    [[ $REPLY =~ ^[Yy]$ ]] || exit 1
    
    docker exec {{container_name}} pixi run python scripts/delete_token.py "{{name}}"

# Update certificate email for token
token-email-update name email token="":
    #!/usr/bin/env bash
    set -euo pipefail
    
    # Default to ADMIN_TOKEN if no token specified
    if [ -z "{{token}}" ]; then
        # For token-email-update, we need to get the token for the specified name
        if [ "{{name}}" = "ADMIN" ]; then
            token_value="${ADMIN_TOKEN:-}"
            if [ -z "$token_value" ]; then
                echo "Error: ADMIN_TOKEN not set in environment" >&2
                exit 1
            fi
        else
            token_value=$(docker exec {{container_name}} pixi run python scripts/show_token.py "{{name}}" 2>/dev/null | grep "^Token: " | cut -d' ' -f2 || true)
            if [ -z "$token_value" ]; then
                echo "Error: Token '{{name}}' not found" >&2
                exit 1
            fi
        fi
    elif [[ "{{token}}" == acm_* ]]; then
        token_value="{{token}}"
    else
        token_value=$(docker exec {{container_name}} pixi run python scripts/show_token.py "{{token}}" 2>/dev/null | grep "^Token: " | cut -d' ' -f2 || true)
        if [ -z "$token_value" ]; then
            echo "Error: Token '{{token}}' not found" >&2
            exit 1
        fi
    fi
    
    BASE_URL="${BASE_URL:-{{default_base_url}}}"
    data=$(jq -n --arg email "{{email}}" '{email: $email}')
    
    response=$(curl -s -w '\n%{http_code}' -X PUT "${BASE_URL}/tokens/email" \
        -H "Authorization: Bearer $token_value" \
        -H "Content-Type: application/json" \
        -d "$data")
    
    http_code=$(echo "$response" | tail -n1)
    body=$(echo "$response" | head -n -1)
    
    if [[ ! "$http_code" =~ ^2 ]]; then
        echo "Error: HTTP $http_code"
        echo "$body" | jq '.' 2>/dev/null || echo "$body"
        exit 1
    fi
    
    echo "$body" | jq '.'

# Generate admin token
generate-admin-token:
    #!/usr/bin/env bash
    set -euo pipefail
    
    if [ -n "${ADMIN_TOKEN:-}" ]; then
        echo "Admin token already exists in environment"
        exit 0
    fi
    
    # Get admin email
    if [ -n "${ADMIN_EMAIL:-}" ]; then
        admin_email="$ADMIN_EMAIL"
    else
        read -p "Admin email: " admin_email
    fi
    
    docker exec {{container_name}} pixi run python scripts/generate_token.py "ADMIN" "$admin_email" | tee admin_token.txt
    echo
    echo "Save the token above as ADMIN_TOKEN in your .env file"

# ============================================================================
# CERTIFICATE MANAGEMENT  
# ============================================================================

# Create a new certificate
cert-create name domain email="" token="" staging="false":
    #!/usr/bin/env bash
    set -euo pipefail
    
    # Default to ADMIN_TOKEN if no token specified
    if [ -z "{{token}}" ]; then
        token_value="${ADMIN_TOKEN:-}"
        if [ -z "$token_value" ]; then
            echo "Error: ADMIN_TOKEN not set in environment" >&2
            exit 1
        fi
    elif [ "{{token}}" = "ADMIN" ]; then
        token_value="${ADMIN_TOKEN:-}"
        if [ -z "$token_value" ]; then
            echo "Error: ADMIN_TOKEN not set in environment" >&2
            exit 1
        fi
    elif [[ "{{token}}" == acm_* ]]; then
        token_value="{{token}}"
    else
        token_value=$(docker exec {{container_name}} pixi run python scripts/show_token.py "{{token}}" 2>/dev/null | grep "^Token: " | cut -d' ' -f2 || true)
        if [ -z "$token_value" ]; then
            echo "Error: Token '{{token}}' not found" >&2
            exit 1
        fi
    fi
    
    BASE_URL="${BASE_URL:-{{default_base_url}}}"
    
    # Get certificate email if not provided
    if [ -z "{{email}}" ]; then
        # Try to get from token first
        response=$(curl -s -H "Authorization: Bearer $token_value" "${BASE_URL}/tokens/info")
        cert_email=$(echo "$response" | jq -r '.cert_email // empty')
        
        # Fall back to ADMIN_EMAIL if token has no email
        if [ -z "$cert_email" ]; then
            cert_email="${ADMIN_EMAIL:-}"
            if [ -z "$cert_email" ]; then
                echo "Error: No email provided, token has no default email, and ADMIN_EMAIL not set"
                exit 1
            fi
        fi
    else
        cert_email="{{email}}"
    fi
    
    # Build request data
    data=$(jq -n \
        --arg cert_name "{{name}}" \
        --arg domain "{{domain}}" \
        --arg email "$cert_email" \
        --arg staging "{{staging}}" \
        '{
            cert_name: $cert_name,
            domain: $domain,
            email: $email,
            acme_directory_url: (if $staging == "true" then env.ACME_STAGING_URL else env.ACME_DIRECTORY_URL end)
        }')
    
    # Create certificate
    response=$(curl -sL -w '\n%{http_code}' -X POST "${BASE_URL}/certificates/" \
        -H "Authorization: Bearer $token_value" \
        -H "Content-Type: application/json" \
        -d "$data")
    
    http_code=$(echo "$response" | tail -n1)
    body=$(echo "$response" | head -n -1)
    
    if [[ ! "$http_code" =~ ^2 ]]; then
        echo "Error: HTTP $http_code"
        echo "$body" | jq '.' 2>/dev/null || echo "$body"
        exit 1
    fi
    
    echo "$body" | jq '.'

# List certificates (requires authentication)
cert-list token="":
    #!/usr/bin/env bash
    set -euo pipefail
    
    BASE_URL="${BASE_URL:-{{default_base_url}}}"
    
    # Default to ADMIN_TOKEN if no token specified
    if [ -z "{{token}}" ]; then
        token_value="${ADMIN_TOKEN:-}"
        if [ -z "$token_value" ]; then
            echo "Error: ADMIN_TOKEN not set in environment" >&2
            exit 1
        fi
    elif [ "{{token}}" = "ADMIN" ]; then
        token_value="${ADMIN_TOKEN:-}"
        if [ -z "$token_value" ]; then
            echo "Error: ADMIN_TOKEN not set in environment" >&2
            exit 1
        fi
    elif [[ "{{token}}" == acm_* ]]; then
        token_value="{{token}}"
    else
        token_value=$(docker exec {{container_name}} pixi run python scripts/show_token.py "{{token}}" 2>/dev/null | grep "^Token: " | cut -d' ' -f2 || true)
        if [ -z "$token_value" ]; then
            echo "Error: Token '{{token}}' not found" >&2
            exit 1
        fi
    fi
    
    # Get certificates with auth
    response=$(curl -sL "${BASE_URL}/certificates/" -H "Authorization: Bearer $token_value")
    
    # Format as table
    echo "=== Certificates ==="
    echo "$response" | jq -r '.[] | [
        .cert_name, 
        (.domains | join(",")), 
        .status, 
        .expires_at[0:10], 
        (if .acme_directory_url | contains("staging") then "Staging" else "Production" end)
    ] | @tsv' | \
        column -t -s $'\t' -N "Name,Domains,Status,Expires,Environment" | \
        awk 'NR==1 {print $0} NR>1 {if ($NF == "Staging") {print "\033[33m" $0 "\033[0m"} else if ($NF == "Production") {print "\033[32m" $0 "\033[0m"} else {print $0}}'

# Show certificate details
cert-show name token="" pem="false":
    #!/usr/bin/env bash
    set -euo pipefail
    
    BASE_URL="${BASE_URL:-{{default_base_url}}}"
    
    # Default to ADMIN_TOKEN if no token specified
    if [ -z "{{token}}" ]; then
        token_value="${ADMIN_TOKEN:-}"
        if [ -z "$token_value" ]; then
            echo "Error: ADMIN_TOKEN not set in environment" >&2
            exit 1
        fi
    elif [ "{{token}}" = "ADMIN" ]; then
        token_value="${ADMIN_TOKEN:-}"
        if [ -z "$token_value" ]; then
            echo "Error: ADMIN_TOKEN not set in environment" >&2
            exit 1
        fi
    elif [[ "{{token}}" == acm_* ]]; then
        token_value="{{token}}"
    else
        token_value=$(docker exec {{container_name}} pixi run python scripts/show_token.py "{{token}}" 2>/dev/null | grep "^Token: " | cut -d' ' -f2 || true)
        if [ -z "$token_value" ]; then
            echo "Error: Token '{{token}}' not found" >&2
            exit 1
        fi
    fi
    
    # Get certificate with auth
    response=$(curl -s "${BASE_URL}/certificates/{{name}}" -H "Authorization: Bearer $token_value")
    
    # Show formatted or PEM
    if [ "{{pem}}" = "true" ]; then
        echo "$response" | jq -r '.fullchain_pem'
        echo
        echo "$response" | jq -r '.private_key_pem'
    else
        echo "$response" | jq '.'
    fi

# Delete certificate
cert-delete name token="" force="false":
    #!/usr/bin/env bash
    set -euo pipefail
    
    # Default to ADMIN_TOKEN if no token specified
    if [ -z "{{token}}" ]; then
        token_value="${ADMIN_TOKEN:-}"
        if [ -z "$token_value" ]; then
            echo "Error: ADMIN_TOKEN not set in environment" >&2
            exit 1
        fi
    elif [ "{{token}}" = "ADMIN" ]; then
        token_value="${ADMIN_TOKEN:-}"
        if [ -z "$token_value" ]; then
            echo "Error: ADMIN_TOKEN not set in environment" >&2
            exit 1
        fi
    elif [[ "{{token}}" == acm_* ]]; then
        token_value="{{token}}"
    else
        token_value=$(docker exec {{container_name}} pixi run python scripts/show_token.py "{{token}}" 2>/dev/null | grep "^Token: " | cut -d' ' -f2 || true)
        if [ -z "$token_value" ]; then
            echo "Error: Token '{{token}}' not found" >&2
            exit 1
        fi
    fi
    
    # Confirm unless forced
    if [ "{{force}}" != "true" ]; then
        read -p "Delete certificate '{{name}}'? [y/N] " -n 1 -r
        echo
        [[ $REPLY =~ ^[Yy]$ ]] || exit 1
    fi
    
    BASE_URL="${BASE_URL:-{{default_base_url}}}"
    
    # Delete certificate
    response=$(curl -s -w '\n%{http_code}' -X DELETE "${BASE_URL}/certificates/{{name}}" \
        -H "Authorization: Bearer $token_value")
    
    http_code=$(echo "$response" | tail -n1)
    body=$(echo "$response" | head -n -1)
    
    if [[ ! "$http_code" =~ ^2 ]]; then
        echo "Error: HTTP $http_code"
        echo "$body" | jq '.' 2>/dev/null || echo "$body"
        exit 1
    fi
    
    echo "$body" | jq '.'

# ============================================================================
# PROXY MANAGEMENT
# ============================================================================

# Create proxy target
proxy-create hostname target-url token="" email="" staging="false" preserve-host="true" enable-http="true" enable-https="true":
    #!/usr/bin/env bash
    set -euo pipefail
    
    # Default to ADMIN_TOKEN if no token specified
    if [ -z "{{token}}" ]; then
        token_value="${ADMIN_TOKEN:-}"
        if [ -z "$token_value" ]; then
            echo "Error: ADMIN_TOKEN not set in environment" >&2
            exit 1
        fi
    elif [ "{{token}}" = "ADMIN" ]; then
        token_value="${ADMIN_TOKEN:-}"
        if [ -z "$token_value" ]; then
            echo "Error: ADMIN_TOKEN not set in environment" >&2
            exit 1
        fi
    elif [[ "{{token}}" == acm_* ]]; then
        token_value="{{token}}"
    else
        token_value=$(docker exec {{container_name}} pixi run python scripts/show_token.py "{{token}}" 2>/dev/null | grep "^Token: " | cut -d' ' -f2 || true)
        if [ -z "$token_value" ]; then
            echo "Error: Token '{{token}}' not found" >&2
            exit 1
        fi
    fi
    
    BASE_URL="${BASE_URL:-{{default_base_url}}}"
    
    # Get certificate email - use parameter first, then token, then ADMIN_EMAIL
    if [ -n "{{email}}" ]; then
        cert_email="{{email}}"
    else
        # Try to get from token
        response=$(curl -s -H "Authorization: Bearer $token_value" "${BASE_URL}/tokens/info")
        cert_email=$(echo "$response" | jq -r '.cert_email // empty')
        
        # Fall back to ADMIN_EMAIL if token has no email
        if [ -z "$cert_email" ]; then
            cert_email="${ADMIN_EMAIL:-}"
            if [ -z "$cert_email" ]; then
                echo "Error: No email provided, token has no certificate email, and ADMIN_EMAIL not set"
                exit 1
            fi
        fi
    fi
    
    # Build request data
    data=$(jq -n \
        --arg hostname "{{hostname}}" \
        --arg target_url "{{target-url}}" \
        --arg cert_email "$cert_email" \
        --arg staging "{{staging}}" \
        --arg preserve_host "{{preserve-host}}" \
        --arg enable_http "{{enable-http}}" \
        --arg enable_https "{{enable-https}}" \
        '{
            hostname: $hostname,
            target_url: $target_url,
            cert_email: $cert_email,
            preserve_host_header: ($preserve_host == "true"),
            enable_http: ($enable_http == "true"),
            enable_https: ($enable_https == "true"),
            acme_directory_url: (if $staging == "true" then env.ACME_STAGING_URL else env.ACME_DIRECTORY_URL end)
        }')
    
    # Create proxy
    response=$(curl -sL -w '\n%{http_code}' -X POST "${BASE_URL}/proxy/targets/" \
        -H "Authorization: Bearer $token_value" \
        -H "Content-Type: application/json" \
        -d "$data")
    
    http_code=$(echo "$response" | tail -n1)
    body=$(echo "$response" | head -n -1)
    
    if [[ ! "$http_code" =~ ^2 ]]; then
        echo "Error: HTTP $http_code"
        echo "$body" | jq '.' 2>/dev/null || echo "$body"
        exit 1
    fi
    
    echo "$body" | jq '.'

# List proxy targets (requires authentication)
proxy-list token="":
    #!/usr/bin/env bash
    set -euo pipefail
    
    BASE_URL="${BASE_URL:-{{default_base_url}}}"
    
    # Default to ADMIN_TOKEN if no token specified
    if [ -z "{{token}}" ]; then
        token_value="${ADMIN_TOKEN:-}"
        if [ -z "$token_value" ]; then
            echo "Error: ADMIN_TOKEN not set in environment" >&2
            exit 1
        fi
    elif [ "{{token}}" = "ADMIN" ]; then
        token_value="${ADMIN_TOKEN:-}"
        if [ -z "$token_value" ]; then
            echo "Error: ADMIN_TOKEN not set in environment" >&2
            exit 1
        fi
    elif [[ "{{token}}" == acm_* ]]; then
        token_value="{{token}}"
    else
        token_value=$(docker exec {{container_name}} pixi run python scripts/show_token.py "{{token}}" 2>/dev/null | grep "^Token: " | cut -d' ' -f2 || true)
        if [ -z "$token_value" ]; then
            echo "Error: Token '{{token}}' not found" >&2
            exit 1
        fi
    fi
    
    # Get proxies with auth
    response=$(curl -sL "${BASE_URL}/proxy/targets" -H "Authorization: Bearer $token_value")
    
    # Format as table
    echo "=== Proxy Targets ==="
    echo "$response" | jq -r '.[] | [.hostname, .target_url, (if .enabled then "✓" else "✗" end), .cert_name // "none"] | @tsv' | \
        column -t -s $'\t' -N "Hostname,Target,Enabled,Certificate"

# Show proxy details
proxy-show hostname:
    #!/usr/bin/env bash
    set -euo pipefail
    
    BASE_URL="${BASE_URL:-{{default_base_url}}}"
    curl -s "${BASE_URL}/proxy/targets/{{hostname}}" | jq '.'

# Delete proxy target
proxy-delete hostname token="" delete-cert="false" force="false":
    #!/usr/bin/env bash
    set -euo pipefail
    
    # Default to ADMIN_TOKEN if no token specified
    if [ -z "{{token}}" ]; then
        token_value="${ADMIN_TOKEN:-}"
        if [ -z "$token_value" ]; then
            echo "Error: ADMIN_TOKEN not set in environment" >&2
            exit 1
        fi
    elif [ "{{token}}" = "ADMIN" ]; then
        token_value="${ADMIN_TOKEN:-}"
        if [ -z "$token_value" ]; then
            echo "Error: ADMIN_TOKEN not set in environment" >&2
            exit 1
        fi
    elif [[ "{{token}}" == acm_* ]]; then
        token_value="{{token}}"
    else
        token_value=$(docker exec {{container_name}} pixi run python scripts/show_token.py "{{token}}" 2>/dev/null | grep "^Token: " | cut -d' ' -f2 || true)
        if [ -z "$token_value" ]; then
            echo "Error: Token '{{token}}' not found" >&2
            exit 1
        fi
    fi
    
    # Confirm unless forced
    if [ "{{force}}" != "true" ]; then
        read -p "Delete proxy '{{hostname}}'? [y/N] " -n 1 -r
        echo
        [[ $REPLY =~ ^[Yy]$ ]] || exit 1
    fi
    
    BASE_URL="${BASE_URL:-{{default_base_url}}}"
    
    # Build query params
    query=""
    if [ "{{delete-cert}}" = "true" ]; then
        query="?delete_certificate=true"
    fi
    
    # Delete proxy
    response=$(curl -s -w '\n%{http_code}' -X DELETE "${BASE_URL}/proxy/targets/{{hostname}}$query" \
        -H "Authorization: Bearer $token_value")
    
    http_code=$(echo "$response" | tail -n1)
    body=$(echo "$response" | head -n -1)
    
    if [[ ! "$http_code" =~ ^2 ]]; then
        echo "Error: HTTP $http_code"
        echo "$body" | jq '.' 2>/dev/null || echo "$body"
        exit 1
    fi
    
    echo "$body" | jq '.'

# ============================================================================
# TESTING COMMANDS
# ============================================================================

# Run tests (optionally specify test files)
test *files="tests/test_health.py":
    #!/usr/bin/env bash
    if [ "$#" -eq 0 ]; then
        echo "Running basic API tests..."
        docker exec {{container_name}} pixi run pytest tests/test_health.py -v
    else
        echo "Running specified tests: $@"
        docker exec {{container_name}} pixi run pytest "$@" -v
    fi

# Run comprehensive test suite
test-all:
    docker exec {{container_name}} pixi run pytest tests/ -v

# Test certificate operations
test-certs:
    docker exec {{container_name}} pixi run pytest tests/test_certificates.py -v

# Test proxy operations
test-proxy-basic:
    docker exec {{container_name}} pixi run pytest tests/test_proxy.py -v -k "basic"

# Run sidecar tests with coverage
test-sidecar-coverage:
    docker exec {{container_name}} pixi run pytest tests/test_sidecar_coverage.py::test_all_with_json_report -v

# Test token management
test-tokens:
    docker exec {{container_name}} pixi run pytest tests/test_tokens.py -v

# Test all proxy operations
test-proxy-all:
    docker exec {{container_name}} pixi run pytest tests/test_proxy.py -v

# Test proxy authentication
test-proxy-auth:
    docker exec {{container_name}} pixi run pytest tests/test_proxy.py -v -k "TestProxyAuthentication"

# Test OAuth functionality
test-auth token="${ADMIN_TOKEN}":
    docker exec {{container_name}} pixi run pytest tests/test_oauth.py -v

# Test OAuth flow for a specific hostname
test-auth-flow hostname:
    @echo "Testing OAuth flow for {{hostname}}..."
    @echo "This test would validate the complete OAuth flow"
    docker exec {{container_name}} pixi run pytest tests/test_oauth.py::TestOAuthFlow::test_complete_flow -v --hostname={{hostname}}

# Test route management
test-routes:
    docker exec {{container_name}} pixi run pytest tests/test_routes.py -v

# Test instance management
test-instances:
    docker exec {{container_name}} pixi run pytest tests/test_instances.py -v

# Test with specific marks
test-mark mark:
    docker exec {{container_name}} pixi run pytest tests/ -v -m {{mark}}

# Test MCP functionality
test-mcp:
    docker exec {{container_name}} pixi run pytest tests/test_mcp_client.py -v

# Test OAuth status API
test-oauth-status-api:
    docker exec {{container_name}} pixi run pytest tests/test_oauth.py::TestOAuthStatus -v

# Test WebSocket proxy
test-websocket-proxy:
    docker exec {{container_name}} pixi run pytest tests/test_proxy.py -v -k "websocket"

# Test streaming proxy
test-streaming-proxy:
    docker exec {{container_name}} pixi run pytest tests/test_proxy.py -v -k "streaming"

# Test multi-domain certificates
test-multi-domain:
    docker exec {{container_name}} pixi run pytest tests/test_certificates.py::TestMultiDomainCertificates -v

# Test proxy routes
test-proxy-routes:
    docker exec {{container_name}} pixi run pytest tests/test_routes.py::TestProxyRouteControl -v

# Test MCP compliance
test-mcp-compliance:
    docker exec {{container_name}} pixi run pytest tests/test_mcp_client.py::TestMCPProtocolCompliance -v

# Test resource indicators
test-resource-indicators:
    docker exec {{container_name}} pixi run pytest tests/test_oauth.py::TestMCPResourceManagement -v

# Test audience validation  
test-audience-validation:
    docker exec {{container_name}} pixi run pytest tests/test_oauth.py -v -k "audience"

# ============================================================================
# UTILITY COMMANDS
# ============================================================================

# Show system statistics
stats:
    #!/usr/bin/env bash
    set -euo pipefail
    
    echo "=== System Statistics ==="
    
    BASE_URL="${BASE_URL:-{{default_base_url}}}"
    
    # Get health status
    health=$(curl -s "${BASE_URL}/health")
    
    echo "Certificates: $(echo "$health" | jq -r '.certificates_loaded')"
    echo "Redis: $(echo "$health" | jq -r '.redis')"
    echo "Scheduler: $(echo "$health" | jq -r '.scheduler')"
    echo "HTTPS: $(echo "$health" | jq -r '.https_enabled')"
    echo "Orphaned resources: $(echo "$health" | jq -r '.orphaned_resources')"

# Open web UI
web-ui:
    @echo "Opening web UI at http://localhost/"
    @command -v xdg-open >/dev/null 2>&1 && xdg-open http://localhost/ || \
     command -v open >/dev/null 2>&1 && open http://localhost/ || \
     echo "Please open http://localhost/ in your browser"

# ============================================================================
# DEVELOPMENT HELPERS
# ============================================================================

# Quick setup for development
setup: generate-admin-token
    @echo "Setup complete!"
    @echo "1. Copy the admin token to your .env file as ADMIN_TOKEN"
    @echo "2. Start services with: just up"
    @echo "3. Open the web UI with: just web-ui"

# Run development server locally
dev:
    pixi run python run.py

# Run linting
lint:
    pixi run ruff check .
    pixi run ruff format .

# Build documentation
docs-build:
    pixi run jupyter-book build docs

# Clean up orphaned resources
cleanup-orphaned:
    docker exec {{container_name}} pixi run python scripts/cleanup_orphaned.py

# OAuth Commands
# Generate RSA private key for OAuth JWT signing
generate-oauth-key:
    #!/usr/bin/env bash
    set -euo pipefail
    echo "Generating RSA private key for OAuth JWT signing..."
    
    # Generate key and convert to base64
    key_b64=$(openssl genrsa 2048 2>/dev/null | base64 -w 0)
    
    # Check if OAUTH_JWT_PRIVATE_KEY_B64 already exists in .env
    if grep -q "^OAUTH_JWT_PRIVATE_KEY_B64=" .env 2>/dev/null; then
        # Update existing key
        sed -i.bak "s|^OAUTH_JWT_PRIVATE_KEY_B64=.*|OAUTH_JWT_PRIVATE_KEY_B64=${key_b64}|" .env
        echo "Updated OAUTH_JWT_PRIVATE_KEY_B64 in .env"
    else
        # Add new key
        echo "" >> .env
        echo "# OAuth JWT Private Key (base64 encoded)" >> .env
        echo "OAUTH_JWT_PRIVATE_KEY_B64=${key_b64}" >> .env
        echo "Added OAUTH_JWT_PRIVATE_KEY_B64 to .env"
    fi
    
    echo "OAuth key generation complete!"

# Setup OAuth routes for the auth domain
oauth-routes-setup domain token="":
    #!/usr/bin/env bash
    set -euo pipefail
    
    # Default to ADMIN_TOKEN if no token specified
    if [ -z "{{token}}" ]; then
        token_value="${ADMIN_TOKEN:-}"
        if [ -z "$token_value" ]; then
            echo "Error: ADMIN_TOKEN not set in environment" >&2
            exit 1
        fi
    elif [ "{{token}}" = "ADMIN" ]; then
        token_value="${ADMIN_TOKEN:-}"
        if [ -z "$token_value" ]; then
            echo "Error: ADMIN_TOKEN not set in environment" >&2
            exit 1
        fi
    else
        token_value="{{token}}"
    fi
    
    docker exec {{container_name}} pixi run python scripts/oauth_routes_setup.py "{{domain}}" "$token_value"

# OAuth Client Testing Commands
# Register a new OAuth client for testing
oauth-client-register name redirect-uri="http://localhost:8080/callback" scope="mcp:read mcp:write":
    #!/usr/bin/env bash
    set -euo pipefail
    
    echo "Registering OAuth client '{{name}}'..."
    
    # Load BASE_DOMAIN from .env
    BASE_DOMAIN=$(grep "^BASE_DOMAIN=" .env | cut -d= -f2)
    
    response=$(curl -k -s -X POST "https://auth.${BASE_DOMAIN}/register" \
        -H "Content-Type: application/json" \
        -d '{
            "client_name": "{{name}}",
            "redirect_uris": ["{{redirect-uri}}"],
            "grant_types": ["authorization_code", "refresh_token"],
            "response_types": ["code"],
            "scope": "{{scope}}",
            "software_id": "mcp-test-client",
            "software_version": "1.0.0"
        }')
    
    client_id=$(echo "$response" | jq -r '.client_id')
    client_secret=$(echo "$response" | jq -r '.client_secret')
    registration_token=$(echo "$response" | jq -r '.registration_access_token')
    registration_uri=$(echo "$response" | jq -r '.registration_client_uri')
    
    if [ "$client_id" = "null" ]; then
        echo "Error registering client:"
        echo "$response" | jq .
        exit 1
    fi
    
    echo "✅ Client registered successfully!"
    echo ""
    echo "Client ID: $client_id"
    echo "Client Secret: $client_secret"
    echo "Registration Token: $registration_token"
    echo "Registration URI: $registration_uri"
    echo ""
    echo "Add these to your .env file:"
    echo "MCP_CLIENT_ID=$client_id"
    echo "MCP_CLIENT_SECRET=$client_secret"
    echo "MCP_CLIENT_REGISTRATION_TOKEN=$registration_token"
    echo "MCP_CLIENT_REGISTRATION_URI=$registration_uri"

# Generate test OAuth tokens for MCP client
oauth-test-tokens server-url:
    #!/usr/bin/env bash
    set -euo pipefail
    
    echo "Setting up OAuth test tokens for {{server-url}}..."
    
    # Check if we have credentials
    if [ -z "${MCP_CLIENT_ID:-}" ] || [ -z "${MCP_CLIENT_SECRET:-}" ]; then
        echo "No OAuth client found. Creating one..."
        just oauth-client-register "mcp-test-$(date +%s)" "http://localhost:8080/callback"
        echo ""
        echo "Please add the credentials to .env and run this command again."
        exit 1
    fi
    
    # Write server URL to .env if not present
    if ! grep -q "^MCP_SERVER_URL=" .env 2>/dev/null; then
        echo "" >> .env
        echo "# MCP Server Configuration" >> .env
        echo "MCP_SERVER_URL={{server-url}}" >> .env
        echo "Added MCP_SERVER_URL to .env"
    else
        sed -i.bak "s|^MCP_SERVER_URL=.*|MCP_SERVER_URL={{server-url}}|" .env
        echo "Updated MCP_SERVER_URL in .env"
    fi
    
    echo ""
    echo "OAuth client configured. Use the following to get tokens:"
    echo "cd mcp-streamablehttp-client"
    echo "pixi run mcp-streamablehttp-client --token"

# Test MCP client authentication
mcp-test-auth:
    @echo "Testing MCP client authentication..."
    docker exec {{container_name}} pixi run pytest tests/test_mcp_client.py::TestMCPClient::test_oauth_client_registration -v

# List tools available on MCP server
mcp-list-tools:
    #!/usr/bin/env bash
    set -euo pipefail
    cd mcp-streamablehttp-client
    
    echo "Listing available MCP tools..."
    pixi run mcp-streamablehttp-client --list-tools

# Execute MCP command
mcp-exec command:
    #!/usr/bin/env bash
    set -euo pipefail
    cd mcp-streamablehttp-client
    
    echo "Executing MCP command: {{command}}"
    pixi run mcp-streamablehttp-client -c "{{command}}"

# Test echo servers with MCP client
mcp-test-echo type="stateful":
    #!/usr/bin/env bash
    set -euo pipefail
    
    if [ "{{type}}" = "stateful" ]; then
        server_url="https://echo-stateful.${BASE_DOMAIN}/mcp"
    else
        server_url="https://echo-stateless.${BASE_DOMAIN}/mcp"
    fi
    
    echo "Testing {{type}} echo server at $server_url"
    
    # Configure server URL
    just oauth-test-tokens "$server_url"
    
    # Get tokens
    cd mcp-streamablehttp-client
    echo ""
    echo "Authenticating with OAuth server..."
    pixi run mcp-streamablehttp-client --token
    
    echo ""
    echo "Testing echo functionality..."
    pixi run mcp-streamablehttp-client -c 'echo message="Hello from MCP client!"'
    
    if [ "{{type}}" = "stateful" ]; then
        echo ""
        echo "Testing stateful functionality..."
        pixi run mcp-streamablehttp-client -c 'echo message="First message"'
        pixi run mcp-streamablehttp-client -c 'echo message="Second message"'
        pixi run mcp-streamablehttp-client -c 'get_history'
    fi

# Run full MCP client test suite
mcp-test-all:
    @echo "Running full MCP client test suite..."
    docker exec {{container_name}} pixi run pytest tests/test_mcp_client.py -v -m integration

# Instance Management Commands
# List all registered instances
instance-list:
    #!/usr/bin/env bash
    BASE_URL="${BASE_URL:-{{default_base_url}}}"
    echo "=== Named Instances ==="
    curl -s "${BASE_URL}/instances" | \
        jq -r '.[] | [.name, .target_url, .description, .created_by] | @tsv' | \
        column -t -s $'\t' -N "Name,Target URL,Description,Created By"

# Show instance details
instance-show name:
    #!/usr/bin/env bash
    BASE_URL="${BASE_URL:-{{default_base_url}}}"
    curl -s "${BASE_URL}/instances/{{name}}" | jq '.'

# Register a new named instance
instance-register name target-url token="" description="":
    #!/usr/bin/env bash
    BASE_URL="${BASE_URL:-{{default_base_url}}}"
    TOKEN="{{token}}"
    if [ -z "$TOKEN" ]; then
        TOKEN="$ADMIN_TOKEN"
    fi
    if [ -z "$TOKEN" ]; then
        echo "Error: No token provided and ADMIN_TOKEN not set" >&2
        exit 1
    fi
    
    RESPONSE=$(curl -sL -w "\n%{http_code}" -X POST "${BASE_URL}/instances" \
        -H "Authorization: Bearer $TOKEN" \
        -H "Content-Type: application/json" \
        -d '{
            "name": "{{name}}",
            "target_url": "{{target-url}}",
            "description": "{{description}}"
        }')
    
    HTTP_CODE=$(echo "$RESPONSE" | tail -1)
    BODY=$(echo "$RESPONSE" | head -n -1)
    
    if [ "$HTTP_CODE" = "200" ]; then
        echo "$BODY" | jq '.'
        echo "✓ Instance '{{name}}' registered successfully"
    else
        echo "$BODY" | jq '.' || echo "$BODY"
        exit 1
    fi

# Update an existing instance
instance-update name target-url token="" description="":
    #!/usr/bin/env bash
    BASE_URL="${BASE_URL:-{{default_base_url}}}"
    TOKEN="{{token}}"
    if [ -z "$TOKEN" ]; then
        TOKEN="$ADMIN_TOKEN"
    fi
    if [ -z "$TOKEN" ]; then
        echo "Error: No token provided and ADMIN_TOKEN not set" >&2
        exit 1
    fi
    
    RESPONSE=$(curl -s -w "\n%{http_code}" -X PUT "${BASE_URL}/instances/{{name}}" \
        -H "Authorization: Bearer $TOKEN" \
        -H "Content-Type: application/json" \
        -d '{
            "name": "{{name}}",
            "target_url": "{{target-url}}",
            "description": "{{description}}"
        }')
    
    HTTP_CODE=$(echo "$RESPONSE" | tail -1)
    BODY=$(echo "$RESPONSE" | head -n -1)
    
    if [ "$HTTP_CODE" = "200" ]; then
        echo "$BODY" | jq '.'
        echo "✓ Instance '{{name}}' updated successfully"
    else
        echo "$BODY" | jq '.' || echo "$BODY"
        exit 1
    fi

# Delete a named instance
instance-delete name token="":
    #!/usr/bin/env bash
    BASE_URL="${BASE_URL:-{{default_base_url}}}"
    TOKEN="{{token}}"
    if [ -z "$TOKEN" ]; then
        TOKEN="$ADMIN_TOKEN"
    fi
    if [ -z "$TOKEN" ]; then
        echo "Error: No token provided and ADMIN_TOKEN not set" >&2
        exit 1
    fi
    
    RESPONSE=$(curl -s -w "\n%{http_code}" -X DELETE "${BASE_URL}/instances/{{name}}" \
        -H "Authorization: Bearer $TOKEN")
    
    HTTP_CODE=$(echo "$RESPONSE" | tail -1)
    BODY=$(echo "$RESPONSE" | head -n -1)
    
    if [ "$HTTP_CODE" = "204" ]; then
        echo "✓ Instance '{{name}}' deleted successfully"
    else
        echo "$BODY" | jq '.' || echo "$BODY"
        exit 1
    fi

# Register OAuth server instance (convenience command)
instance-register-oauth token="":
    just instance-register "auth" "http://auth:8000" "{{token}}" "OAuth 2.0 Authorization Server"

# Route Management Commands
# List all routes
route-list:
    docker exec {{container_name}} pixi run python scripts/route_list.py

# Show route details
route-show route-id:
    docker exec {{container_name}} pixi run python scripts/route_show.py --route-id {{route-id}}

# Create a new route
route-create path target-type target-value token="" priority="50" methods="*" is-regex="false" description="":
    #!/usr/bin/env bash
    set -euo pipefail
    
    # Default to ADMIN_TOKEN if no token specified
    if [ -z "{{token}}" ]; then
        token_value="${ADMIN_TOKEN:-}"
        if [ -z "$token_value" ]; then
            echo "Error: ADMIN_TOKEN not set in environment" >&2
            exit 1
        fi
    elif [ "{{token}}" = "ADMIN" ]; then
        token_value="${ADMIN_TOKEN:-}"
        if [ -z "$token_value" ]; then
            echo "Error: ADMIN_TOKEN not set in environment" >&2
            exit 1
        fi
    else
        token_value="{{token}}"
    fi
    
    docker exec {{container_name}} pixi run python scripts/route_create.py \
        "{{path}}" \
        "{{target-type}}" \
        "{{target-value}}" \
        "$token_value" \
        "{{priority}}" \
        "{{methods}}" \
        "{{is-regex}}" \
        "{{description}}"

# Delete a route
route-delete route-id token="":
    #!/usr/bin/env bash
    set -euo pipefail
    
    # Default to ADMIN_TOKEN if no token specified
    if [ -z "{{token}}" ]; then
        token_value="${ADMIN_TOKEN:-}"
        if [ -z "$token_value" ]; then
            echo "Error: ADMIN_TOKEN not set in environment" >&2
            exit 1
        fi
    elif [ "{{token}}" = "ADMIN" ]; then
        token_value="${ADMIN_TOKEN:-}"
        if [ -z "$token_value" ]; then
            echo "Error: ADMIN_TOKEN not set in environment" >&2
            exit 1
        fi
    else
        token_value="{{token}}"
    fi
    
    docker exec {{container_name}} pixi run python scripts/route_delete.py \
        "{{route-id}}" \
        "$token_value"

# Setup MCP client development environment
mcp-setup:
    #!/usr/bin/env bash
    set -euo pipefail
    
    echo "Setting up MCP client development environment..."
    
    # Ensure OAuth service is running
    if ! docker-compose ps auth | grep -q "Up"; then
        echo "Starting OAuth service..."
        docker-compose up -d auth
        sleep 5
    fi
    
    # Ensure echo servers are running
    if ! docker-compose ps echo-stateful | grep -q "Up"; then
        echo "Starting echo servers..."
        docker-compose up -d echo-stateful
        docker-compose up -d echo-stateless
        sleep 3
    fi
    
    # Setup OAuth routes if needed
    if ! just route-list | grep -q "/authorize"; then
        echo "Setting up OAuth routes..."
        just oauth-routes-setup "auth.${BASE_DOMAIN}" ADMIN
    fi
    
    # Install MCP client dependencies
    cd mcp-streamablehttp-client
    if [ ! -d ".pixi" ]; then
        echo "Installing MCP client dependencies..."
        pixi install
    fi
    
    echo ""
    echo "✅ MCP client environment ready!"
    echo ""
    echo "Next steps:"
    echo "1. Register an OAuth client: just oauth-client-register test-client"
    echo "2. Add credentials to .env"
    echo "3. Test authentication: just mcp-test-auth"
    echo "4. Run tests: just mcp-test-all"

# ============================================================================
# SERVICE NAME MIGRATION
# ============================================================================

# Migrate to new service names (run this after updating docker-compose.yml)
@migrate-service-names token="${ADMIN_TOKEN}":
    #!/usr/bin/env bash
    set -euo pipefail
    
    echo "🔄 Migrating to new service names..."
    echo "=================================="
    
    # 1. Start services with new names
    echo "1️⃣ Starting services with new names..."
    just up
    
    # 2. Wait for services to be healthy
    echo ""
    echo "2️⃣ Waiting for services to be healthy..."
    sleep 15
    
    # 3. Update proxy targets
    echo ""
    echo "3️⃣ Updating proxy targets..."
    
    # Update auth proxy
    if just proxy-list | grep -q "auth.${BASE_DOMAIN}"; then
        echo "   Updating auth.${BASE_DOMAIN}..."
        curl -X PUT -H "Authorization: Bearer {{token}}" \
            -H "Content-Type: application/json" \
            -d '{"target_url": "http://auth:8000"}' \
            http://localhost/proxy/targets/auth.${BASE_DOMAIN} > /dev/null 2>&1 || true
    fi
    
    # Update echo-stateful proxy
    if just proxy-list | grep -q "echo-stateful.${BASE_DOMAIN}"; then
        echo "   Updating echo-stateful.${BASE_DOMAIN}..."
        curl -X PUT -H "Authorization: Bearer {{token}}" \
            -H "Content-Type: application/json" \
            -d '{"target_url": "http://echo-stateful:3000"}' \
            http://localhost/proxy/targets/echo-stateful.${BASE_DOMAIN} > /dev/null 2>&1 || true
    fi
    
    # Update echo-stateless proxy
    if just proxy-list | grep -q "echo-stateless.${BASE_DOMAIN}"; then
        echo "   Updating echo-stateless.${BASE_DOMAIN}..."
        curl -X PUT -H "Authorization: Bearer {{token}}" \
            -H "Content-Type: application/json" \
            -d '{"target_url": "http://echo-stateless:3000"}' \
            http://localhost/proxy/targets/echo-stateless.${BASE_DOMAIN} > /dev/null 2>&1 || true
    fi
    
    # Update fetcher proxy
    if just proxy-list | grep -q "fetcher.${BASE_DOMAIN}"; then
        echo "   Updating fetcher.${BASE_DOMAIN}..."
        curl -X PUT -H "Authorization: Bearer {{token}}" \
            -H "Content-Type: application/json" \
            -d '{"target_url": "http://fetcher:3000"}' \
            http://localhost/proxy/targets/fetcher.${BASE_DOMAIN} > /dev/null 2>&1 || true
    fi
    
    # 4. Verify services
    echo ""
    echo "4️⃣ Verifying services..."
    docker compose ps
    
    echo ""
    echo "5️⃣ Updated proxy targets:"
    just proxy-list | grep -E "auth|echo|fetcher" || true
    
    echo ""
    echo "✅ Migration complete!"
    echo ""
    echo "Service name changes:"
    echo "  - acme-certmanager → proxy"
    echo "  - mcp-proxy-gateway → proxy"
    echo "  - mcp-oauth-dynamicclient → auth"
    echo "  - mcp-oauth-server → auth"
    echo "  - mcp-echo-streamablehttp-server-stateful → echo-stateful"
    echo "  - mcp-echo-stateful → echo-stateful"
    echo "  - mcp-echo-streamablehttp-server-stateless → echo-stateless"
    echo "  - mcp-echo-stateless → echo-stateless"
    echo "  - fetcher-mcp → fetcher"
    echo "  - mcp-fetcher → fetcher"

# ============================================================================
# MCP ECHO SERVER MANAGEMENT  
# ============================================================================

# Start MCP echo servers
@mcp-echo-start:
    #!/usr/bin/env bash
    set -euo pipefail
    
    echo "Starting MCP echo servers..."
    docker compose up -d echo-stateful echo-stateless
    
    # Wait for services to be healthy
    echo "Waiting for services to be healthy..."
    for i in {1..10}; do
        echo -n "."
        sleep 1
    done
    echo ""
    
    echo "✓ Echo servers started"

# Complete setup for MCP echo servers (one command to rule them all!)
@mcp-echo-setup token="${ADMIN_TOKEN}":
    #!/usr/bin/env bash
    set -euo pipefail
    
    echo "🚀 Setting up MCP Echo Servers..."
    echo "================================"
    
    # 1. Ensure echo services are running
    echo "1️⃣ Starting echo services..."
    just mcp-echo-start || true
    
    # Wait a bit more for services to fully initialize
    sleep 5
    
    # 2. Create proxy entries for both echo servers
    echo ""
    echo "2️⃣ Creating proxy entries..."
    
    # Stateless echo server
    if ! just proxy-list | grep -q "echo-stateless.${BASE_DOMAIN}"; then
        echo "   Creating echo-stateless proxy..."
        just proxy-create "echo-stateless.${BASE_DOMAIN}" "http://echo-stateless:3000" "{{token}}" "${ADMIN_EMAIL}" "false" "true" "true" "true"
    else
        echo "   ✓ echo-stateless proxy already exists"
    fi
    
    # Stateful echo server  
    if ! just proxy-list | grep -q "echo-stateful.${BASE_DOMAIN}"; then
        echo "   Creating echo-stateful proxy..."
        just proxy-create "echo-stateful.${BASE_DOMAIN}" "http://echo-stateful:3000" "{{token}}" "${ADMIN_EMAIL}" "false" "true" "true" "true"
    else
        echo "   ✓ echo-stateful proxy already exists"
    fi
    
    # 3. Disable auth on both echo servers for easy testing
    echo ""
    echo "3️⃣ Configuring authentication..."
    
    # Disable auth on stateless
    echo "   Disabling auth on echo-stateless..."
    curl -s -X DELETE -H "Authorization: Bearer {{token}}" http://localhost/proxy/targets/echo-stateless.${BASE_DOMAIN}/auth > /dev/null 2>&1 || true
    echo "   ✓ Auth disabled on echo-stateless"
    
    # Disable auth on stateful
    echo "   Disabling auth on echo-stateful..."
    curl -s -X DELETE -H "Authorization: Bearer {{token}}" http://localhost/proxy/targets/echo-stateful.${BASE_DOMAIN}/auth > /dev/null 2>&1 || true
    echo "   ✓ Auth disabled on echo-stateful"
    
    # 4. Verify everything is working
    echo ""
    echo "4️⃣ Verifying setup..."
    
    # Test stateless
    if curl -s https://echo-stateless.${BASE_DOMAIN}/.well-known/oauth-protected-resource | grep -q "mcp_server_info"; then
        echo "   ✅ echo-stateless is accessible"
    else
        echo "   ❌ echo-stateless check failed"
    fi
    
    # Test stateful
    if curl -s https://echo-stateful.${BASE_DOMAIN}/.well-known/oauth-protected-resource | grep -q "mcp_server_info"; then
        echo "   ✅ echo-stateful is accessible"
    else
        echo "   ❌ echo-stateful check failed"
    fi
    
    # 5. Show the URLs
    echo ""
    echo "✨ MCP Echo Servers Ready!"
    echo "=========================="
    echo ""
    echo "Stateless server: https://echo-stateless.${BASE_DOMAIN}/mcp"
    echo "Stateful server:  https://echo-stateful.${BASE_DOMAIN}/mcp"
    echo ""
    echo "Both servers are configured WITHOUT authentication for easy testing."
    echo "You can now use these URLs in claude.ai or any MCP client!"
    echo ""
    echo "To test with the MCP client:"
    echo "  just mcp-client-tokens-all    # Generate tokens for both servers"
    echo "  just mcp-client-run           # List available tools"

# ============================================================================
# MCP STREAMABLEHTTP CLIENT TOKEN GENERATION
# ============================================================================

# Generate OAuth tokens for MCP client testing (uses env vars from parent .env)
@mcp-client-token-generate server-url="${MCP_SERVER_URL}":
    #!/usr/bin/env bash
    set -euo pipefail
    cd mcp-streamablehttp-client
    just token-generate {{server-url}}

# Quick setup for MCP client with echo server
@mcp-client-test-setup:
    #!/usr/bin/env bash
    set -euo pipefail
    
    # Ensure echo servers are running
    echo "Ensuring echo servers are running..."
    just mcp-echo-start
    
    # Setup OAuth if needed
    if ! just route-list | grep -q "/authorize"; then
        echo "Setting up OAuth routes..."
        just oauth-routes-setup "auth.${BASE_DOMAIN}" ADMIN
    fi
    
    # Generate token for stateless echo server
    echo "Generating token for stateless echo server..."
    cd mcp-streamablehttp-client
    just token-generate "https://echo-stateless.${BASE_DOMAIN}/mcp"
    
    # Test the connection
    echo "Testing connection..."
    just token-test

# Show available echo server URLs
@mcp-client-servers:
    #!/usr/bin/env bash
    set -euo pipefail
    
    echo "Available MCP test servers:"
    echo ""
    echo "1. Stateless echo server:"
    echo "   URL: https://echo-stateless.${BASE_DOMAIN}/mcp"
    echo "   Command: just mcp-client-token-generate \"https://echo-stateless.${BASE_DOMAIN}/mcp\""
    echo ""
    echo "2. Stateful echo server:"
    echo "   URL: https://echo-stateful.${BASE_DOMAIN}/mcp"
    echo "   Command: just mcp-client-token-generate \"https://echo-stateful.${BASE_DOMAIN}/mcp\""
    echo ""
    echo "To use a specific server:"
    echo "  MCP_SERVER_URL=<server-url> just mcp-client-run"

# Generate tokens for both echo servers
@mcp-client-tokens-all:
    #!/usr/bin/env bash
    set -euo pipefail
    
    echo "Generating tokens for all test servers..."
    
    # Stateless echo server
    echo ""
    echo "1. Stateless echo server (https://echo-stateless.${BASE_DOMAIN}/mcp):"
    echo "   Server URL: https://echo-stateless.${BASE_DOMAIN}/mcp"
    echo ""
    just mcp-client-token-generate "https://echo-stateless.${BASE_DOMAIN}/mcp"
    
    # Add a separator and wait to ensure output is complete
    echo ""
    echo "---"
    echo ""
    echo "2. Stateful echo server (https://echo-stateful.${BASE_DOMAIN}/mcp):"
    echo "   Server URL: https://echo-stateful.${BASE_DOMAIN}/mcp"
    echo ""
    echo "To test with stateful server, run:"
    echo "  MCP_SERVER_URL=https://echo-stateful.${BASE_DOMAIN}/mcp just mcp-client-run"

# Test MCP client with current token
@mcp-client-test:
    cd mcp-streamablehttp-client && just token-test

# Show MCP client token status
@mcp-client-status:
    cd mcp-streamablehttp-client && just token-status

# Reset MCP client tokens
@mcp-client-reset:
    cd mcp-streamablehttp-client && just token-reset

# Show available MCP tools
@mcp-client-run:
    #!/usr/bin/env bash
    set -euo pipefail
    
    echo "Fetching available MCP tools from ${MCP_SERVER_URL:-configured server}..."
    echo ""
    
    # Just use the built-in list-tools command
    cd mcp-streamablehttp-client && pixi run mcp-streamablehttp-client --list-tools

# Execute command via MCP client
@mcp-client-exec command:
    cd mcp-streamablehttp-client && just exec "{{command}}"

# Run comprehensive MCP client tests
@mcp-client-test-all:
    ./scripts/test-mcp-client.sh

# Save OAuth client credentials to .env from MCP client registration
mcp-client-save-credentials client-id client-secret registration-token="" registration-uri="":
    #!/usr/bin/env bash
    set -euo pipefail
    echo "Saving OAuth client credentials to .env..."
    
    # Update or add client credentials
    if grep -q "^MCP_CLIENT_ID=" .env; then
        sed -i "s|^MCP_CLIENT_ID=.*|MCP_CLIENT_ID={{client-id}}|" .env
    else
        echo "MCP_CLIENT_ID={{client-id}}" >> .env
    fi
    
    if grep -q "^MCP_CLIENT_SECRET=" .env; then
        sed -i "s|^MCP_CLIENT_SECRET=.*|MCP_CLIENT_SECRET={{client-secret}}|" .env
    else
        echo "MCP_CLIENT_SECRET={{client-secret}}" >> .env
    fi
    
    if [ -n "{{registration-token}}" ]; then
        if grep -q "^MCP_CLIENT_REGISTRATION_TOKEN=" .env; then
            sed -i "s|^MCP_CLIENT_REGISTRATION_TOKEN=.*|MCP_CLIENT_REGISTRATION_TOKEN={{registration-token}}|" .env
        else
            echo "MCP_CLIENT_REGISTRATION_TOKEN={{registration-token}}" >> .env
        fi
    fi
    
    if [ -n "{{registration-uri}}" ]; then
        if grep -q "^MCP_CLIENT_REGISTRATION_URI=" .env; then
            sed -i "s|^MCP_CLIENT_REGISTRATION_URI=.*|MCP_CLIENT_REGISTRATION_URI={{registration-uri}}|" .env
        else
            echo "MCP_CLIENT_REGISTRATION_URI={{registration-uri}}" >> .env
        fi
    fi
    
    echo "✓ OAuth client credentials saved to .env"

# Register OAuth client for MCP testing (auto-saves to .env)
mcp-client-register-auto server-url="${MCP_SERVER_URL}":
    #!/usr/bin/env bash
    set -euo pipefail
    
    echo "Registering OAuth client for {{server-url}}..."
    
    # Extract base domain from server URL
    DOMAIN=$(echo "{{server-url}}" | sed -E 's|https?://([^/]+).*|\1|')
    
    # Discover OAuth configuration
    echo "Discovering OAuth configuration from $DOMAIN..."
    OAUTH_METADATA=$(curl -sf "https://$DOMAIN/.well-known/oauth-authorization-server" || echo "")
    if [ -z "$OAUTH_METADATA" ]; then
        echo "Error: Failed to discover OAuth configuration from $DOMAIN"
        exit 1
    fi
    
    # Extract registration endpoint
    REG_ENDPOINT=$(echo "$OAUTH_METADATA" | jq -r '.registration_endpoint // empty')
    if [ -z "$REG_ENDPOINT" ]; then
        echo "Error: No registration endpoint found in OAuth metadata"
        exit 1
    fi
    
    # Register client
    echo "Registering client at $REG_ENDPOINT..."
    RESPONSE=$(curl -sf -X POST "$REG_ENDPOINT" \
        -H "Content-Type: application/json" \
        -d '{
            "software_id": "mcp-streamablehttp-client",
            "software_version": "1.0.0",
            "client_name": "MCP StreamableHTTP Client",
            "redirect_uris": ["urn:ietf:wg:oauth:2.0:oob"],
            "grant_types": ["authorization_code", "refresh_token", "urn:ietf:params:oauth:grant-type:device_code"],
            "response_types": ["code"],
            "scope": "read write"
        }')
    
    if [ -z "$RESPONSE" ]; then
        echo "Error: Failed to register client"
        exit 1
    fi
    
    # Extract credentials
    CLIENT_ID=$(echo "$RESPONSE" | jq -r '.client_id')
    CLIENT_SECRET=$(echo "$RESPONSE" | jq -r '.client_secret')
    REG_TOKEN=$(echo "$RESPONSE" | jq -r '.registration_access_token // empty')
    REG_URI=$(echo "$RESPONSE" | jq -r '.registration_client_uri // empty')
    
    echo "Client registered successfully!"
    echo "Client ID: $CLIENT_ID"
    echo "Client Secret: ${CLIENT_SECRET:0:12}..."
    
    # Save to .env
    just mcp-client-save-credentials "$CLIENT_ID" "$CLIENT_SECRET" "$REG_TOKEN" "$REG_URI"
