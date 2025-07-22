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
