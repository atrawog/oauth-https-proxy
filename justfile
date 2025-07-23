# MCP HTTP Proxy - Refactored Modular Justfile
# This is a refactored version with modular approach and API-first design

# Variables
container_name := "mcp-http-proxy-acme-certmanager-1"
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
rebuild service="acme-certmanager":
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
    
    # Use provided email or prompt
    if [ -n "{{email}}" ]; then
        cert_email="{{email}}"
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
        response=$(curl -s -H "Authorization: Bearer $token_value" "${BASE_URL}/tokens/info")
        cert_email=$(echo "$response" | jq -r '.cert_email // empty')
        if [ -z "$cert_email" ]; then
            echo "Error: No email provided and token has no default email"
            exit 1
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
            domains: [$domain],
            email: $email,
            acme_directory_url: (if $staging == "true" then env.ACME_STAGING_URL else null end)
        }')
    
    # Create certificate
    response=$(curl -s -w '\n%{http_code}' -X POST "${BASE_URL}/certificates" \
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
    response=$(curl -sL "${BASE_URL}/certificates" -H "Authorization: Bearer $token_value")
    
    # Format as table
    echo "=== Certificates ==="
    echo "$response" | jq -r '.[] | [.cert_name, (.domains | join(",")), .status, .expires_at[0:10]] | @tsv' | \
        column -t -s $'\t' -N "Name,Domains,Status,Expires"

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
proxy-create hostname target-url token="" staging="false" preserve-host="true" enable-http="true" enable-https="true":
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
    
    # Get certificate email
    response=$(curl -s -H "Authorization: Bearer $token_value" "${BASE_URL}/tokens/info")
    cert_email=$(echo "$response" | jq -r '.cert_email // empty')
    if [ -z "$cert_email" ]; then
        echo "Error: Token has no certificate email set"
        exit 1
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
            acme_directory_url: (if $staging == "true" then env.ACME_STAGING_URL else null end)
        }')
    
    # Create proxy
    response=$(curl -s -w '\n%{http_code}' -X POST "${BASE_URL}/proxy/targets" \
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

# Run basic tests
test:
    @echo "Running basic API tests..."
    @just health

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
    #!/usr/bin/env bash
    set -euo pipefail
    cd mcp-streamablehttp-client
    
    echo "Testing MCP client authentication..."
    pixi run mcp-streamablehttp-client --test-auth

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
    #!/usr/bin/env bash
    set -euo pipefail
    
    echo "Running full MCP client test suite..."
    echo ""
    
    # Test stateful echo server
    echo "1. Testing stateful echo server..."
    just mcp-test-echo stateful
    
    echo ""
    echo "2. Testing stateless echo server..."
    just mcp-test-echo stateless
    
    echo ""
    echo "✅ All MCP client tests completed!"

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
    just instance-register "oauth-server" "http://mcp-oauth-dynamicclient:8000" "{{token}}" "OAuth 2.0 Authorization Server"

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
    if ! docker-compose ps mcp-oauth-dynamicclient | grep -q "Up"; then
        echo "Starting OAuth service..."
        docker-compose up -d mcp-oauth-dynamicclient
        sleep 5
    fi
    
    # Ensure echo servers are running
    if ! docker-compose ps mcp-echo-streamablehttp-server-stateful | grep -q "Up"; then
        echo "Starting echo servers..."
        docker-compose up -d mcp-echo-streamablehttp-server-stateful
        docker-compose up -d mcp-echo-streamablehttp-server-stateless
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

# Generate tokens for both echo servers
@mcp-client-tokens-all:
    #!/usr/bin/env bash
    set -euo pipefail
    
    echo "Generating tokens for all test servers..."
    
    # Stateless echo server
    echo ""
    echo "1. Stateless echo server (https://echo-stateless.${BASE_DOMAIN}/mcp):"
    just mcp-client-token-generate "https://echo-stateless.${BASE_DOMAIN}/mcp"
    
    echo ""
    echo "2. Stateful echo server (https://echo-stateful.${BASE_DOMAIN}/mcp):"
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

# Run MCP client in proxy mode
@mcp-client-run:
    cd mcp-streamablehttp-client && just run

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
