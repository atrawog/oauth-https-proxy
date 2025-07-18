set dotenv-load := true
set dotenv-required
set positional-arguments := true
set allow-duplicate-recipes
set export := true
set quiet

# Enable Docker Compose Bake for better performance
export COMPOSE_BAKE := "true"

@default:
    just --list

# Initialize project
setup:
    pixi install

# Run tests locally
test:
    pixi run pytest tests/ -v

# Run tests against Docker services
test-docker:
    #!/usr/bin/env bash
    set -euo pipefail
    echo "Starting services..."
    docker-compose up -d redis acme-certmanager
    echo "Waiting for services to be healthy..."
    max_wait=120
    waited=0
    while [ $waited -lt $max_wait ]; do
        if docker-compose ps | grep -q "healthy.*redis" && docker-compose ps | grep -q "healthy.*acme-certmanager"; then
            echo "Services are healthy!"
            break
        fi
        if [ $waited -eq 0 ]; then
            echo -n "Waiting for services"
        fi
        echo -n "."
        sleep 2
        waited=$((waited + 2))
    done
    echo
    if [ $waited -ge $max_wait ]; then
        echo "Services did not become healthy in time"
        docker-compose ps
        docker-compose logs --tail=50
        exit 1
    fi
    echo "Running tests..."
    TEST_BASE_URL=http://localhost:80 pixi run pytest tests/ -v --tb=short

# Run tests inside Docker
test-integration:
    docker-compose --profile test run --rm test-runner

# Run complete test suite with Docker
test-all:
    just test-docker
    just test-integration

# Run tests with verbose output
test-verbose:
    pixi run pytest tests/ -vvv

# Run REAL ACME tests with actual domains
test-acme:
    #!/usr/bin/env bash
    set -euo pipefail
    echo "Starting REAL ACME tests with domain: $TEST_DOMAIN"
    docker-compose up -d redis acme-certmanager
    echo "Waiting for services..."
    sleep 10
    echo "Running REAL tests..."
    pixi run python scripts/run_real_acme_tests.py

# Run linting and formatting
lint:
    pixi run ruff check .
    pixi run ruff format .

# Start development environment
dev:
    pixi run uvicorn acme_certmanager.server:app --reload --host 0.0.0.0 --port 8000

# Build Jupyter Book documentation
docs-build:
    pixi run jupyter-book build docs

# Start all services
up:
    docker-compose up -d

# Stop all services
down:
    docker-compose down

# Rebuild specific service
rebuild service:
    docker-compose build {{service}}
    docker-compose up -d {{service}}

# Restart specific service
restart service:
    docker-compose restart {{service}}

# View service logs
logs:
    docker-compose logs -f

# View service logs with tail
logs-tail service n="50":
    docker-compose logs {{service}} --tail {{n}}

# Run the ACME certificate manager server
run-server:
    pixi run python scripts/run_server.py

# Build package for PyPi
build:
    pixi run python -m build

# Upload to PyPi (test)
upload-test:
    pixi run twine upload --repository testpypi dist/*

# Upload to PyPi (production)
upload:
    pixi run twine upload dist/*

# Clean build artifacts
clean:
    rm -rf dist/ build/ *.egg-info
    find . -type d -name __pycache__ -exec rm -rf {} +
    find . -type f -name "*.pyc" -delete

# Test environment loading
test-env:
    pixi run python scripts/test_env_loading.py

# Quick certificate generation test
test-cert-quick:
    pixi run python scripts/test_cert_quick.py

# Test challenge timing
test-timing:
    pixi run python scripts/test_challenge_timing.py

# Test external access
test-external:
    pixi run python scripts/test_external_access.py

# Generate a new API token (defaults to ADMIN_EMAIL)
token-generate name cert-email="":
    #!/usr/bin/env bash
    set -euo pipefail
    echo "Generating API token: {{name}}"
    
    # Use ADMIN_EMAIL as default if no email provided
    email="{{cert-email}}"
    if [ -z "$email" ] && [ -n "${ADMIN_EMAIL:-}" ]; then
        email="${ADMIN_EMAIL}"
        echo "Using default email: $email"
    fi
    
    if [ -n "$email" ]; then
        docker exec mcp-http-proxy-acme-certmanager-1 pixi run python scripts/generate_token.py "{{name}}" "$email"
    else
        docker exec mcp-http-proxy-acme-certmanager-1 pixi run python scripts/generate_token.py "{{name}}"
    fi

# List all tokens
token-list:
    #!/usr/bin/env bash
    set -euo pipefail
    echo "Listing all API tokens..."
    docker exec mcp-http-proxy-acme-certmanager-1 pixi run python scripts/list_tokens.py

# Delete a token (and all its certificates)
token-delete name force="":
    #!/usr/bin/env bash
    set -euo pipefail
    echo "Deleting token: {{name}}"
    if [ -n "{{force}}" ]; then
        echo "yes" | docker exec -i mcp-http-proxy-acme-certmanager-1 pixi run python scripts/delete_token.py "{{name}}"
    else
        docker exec -it mcp-http-proxy-acme-certmanager-1 pixi run python scripts/delete_token.py "{{name}}"
    fi

# Show certificates owned by a token (or all if no token specified)
token-show-certs token="":
    #!/usr/bin/env bash
    set -euo pipefail
    if [ -z "{{token}}" ]; then
        echo "Showing all certificates by token..."
    else
        echo "Showing certificates for token: {{token}}"
    fi
    docker exec mcp-http-proxy-acme-certmanager-1 pixi run python scripts/show_token_certs.py "{{token}}"

# Generate admin token and save to .env
token-generate-admin cert-email="admin@example.com" force="false":
    #!/usr/bin/env bash
    set -euo pipefail
    
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "Generating Admin Token"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    
    # Check if admin token already exists in .env
    if grep -q "^ADMIN_TOKEN=" .env 2>/dev/null && [ "{{force}}" != "true" ]; then
        echo "⚠️  Admin token already exists in .env"
        echo ""
        echo "To regenerate, run: just token-generate-admin {{cert-email}} true"
        exit 0
    fi
    
    # Check if admin token exists in Redis and delete it if force is true
    if docker exec mcp-http-proxy-acme-certmanager-1 pixi run python scripts/show_token.py "admin" 2>/dev/null | grep -q "^Token: "; then
        if [ "{{force}}" = "true" ]; then
            echo "Removing existing admin token from system..."
            docker exec mcp-http-proxy-acme-certmanager-1 pixi run python scripts/delete_admin_token.py
        else
            echo "⚠️  Admin token already exists in system"
            echo ""
            echo "To regenerate, run: just token-generate-admin {{cert-email}} true"
            exit 0
        fi
    fi
    
    # Generate new admin token
    echo "Generating new admin token..."
    output=$(docker exec mcp-http-proxy-acme-certmanager-1 pixi run python scripts/generate_token.py "admin" "{{cert-email}}")
    
    # Extract token from output
    token=$(echo "$output" | grep "^Token: " | cut -d' ' -f2)
    
    if [ -z "$token" ]; then
        echo "Error: Failed to generate admin token"
        echo "Debug output:"
        echo "$output"
        exit 1
    fi
    
    # Update or add ADMIN_TOKEN in .env
    if grep -q "^ADMIN_TOKEN=" .env 2>/dev/null; then
        # Replace existing token
        sed -i.bak "s/^ADMIN_TOKEN=.*/ADMIN_TOKEN=$token/" .env
        echo "✓ Updated ADMIN_TOKEN in .env"
    else
        # Add new token
        echo "" >> .env
        echo "# Admin token for internal use" >> .env
        echo "ADMIN_TOKEN=$token" >> .env
        echo "✓ Added ADMIN_TOKEN to .env"
    fi
    
    # Update or add ADMIN_EMAIL in .env
    if grep -q "^ADMIN_EMAIL=" .env 2>/dev/null; then
        # Replace existing email
        sed -i.bak "s/^ADMIN_EMAIL=.*/ADMIN_EMAIL={{cert-email}}/" .env
        echo "✓ Updated ADMIN_EMAIL in .env"
    else
        # Add new email
        echo "ADMIN_EMAIL={{cert-email}}" >> .env
        echo "✓ Added ADMIN_EMAIL to .env"
    fi
    
    echo ""
    echo "Admin token generated successfully!"
    echo "Token Name: admin"
    echo "Email: {{cert-email}}"
    echo ""
    echo "This token is now available as ADMIN_TOKEN in .env"
    echo "and will be used for internal operations."
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# Show detailed info about a specific token
token-info name:
    #!/usr/bin/env bash
    set -euo pipefail
    echo "Token details for: {{name}}"
    docker exec mcp-http-proxy-acme-certmanager-1 pixi run python scripts/show_token_certs.py "{{name}}"

# Show full token by name
token-show name:
    #!/usr/bin/env bash
    set -euo pipefail
    docker exec mcp-http-proxy-acme-certmanager-1 pixi run python scripts/show_token.py "{{name}}"

# Create a new certificate (defaults to ADMIN_TOKEN and ADMIN_EMAIL)
cert-create name domain email="" token-name="" staging="false":
    #!/usr/bin/env bash
    set -euo pipefail
    echo "Creating certificate: {{name}}"
    
    # Use ADMIN_EMAIL as default if no email provided
    cert_email="{{email}}"
    if [ -z "$cert_email" ]; then
        cert_email="${ADMIN_EMAIL:-}"
        if [ -z "$cert_email" ]; then
            echo "Error: No email provided and ADMIN_EMAIL not set"
            exit 1
        fi
        echo "Using default email: $cert_email"
    fi
    
    # Use ADMIN_TOKEN as default if no token provided
    token="{{token-name}}"
    if [ -z "$token" ]; then
        token="${ADMIN_TOKEN:-}"
        if [ -z "$token" ]; then
            echo "Error: No token provided and ADMIN_TOKEN not set"
            exit 1
        fi
        echo "Using admin token"
    elif [[ ! "$token" =~ ^acm_ ]]; then
        echo "Looking up token: {{token-name}}"
        token=$(docker exec mcp-http-proxy-acme-certmanager-1 pixi run python scripts/show_token.py "{{token-name}}" | grep "^Token: " | cut -d' ' -f2)
        if [ -z "$token" ]; then
            echo "Error: Could not find token '{{token-name}}'"
            exit 1
        fi
    fi
    # Handle staging parameter
    if [ "{{staging}}" = "true" ]; then
        docker exec mcp-http-proxy-acme-certmanager-1 pixi run python scripts/cert_create.py "{{name}}" "{{domain}}" "$cert_email" "$token" "true"
    else
        docker exec mcp-http-proxy-acme-certmanager-1 pixi run python scripts/cert_create.py "{{name}}" "{{domain}}" "$cert_email" "$token"
    fi

# Show certificate details (token optional for public certs, can use token name)
cert-show name token="" pem="":
    #!/usr/bin/env bash
    set -euo pipefail
    # Get the actual token if a name was provided
    actual_token="{{token}}"
    if [ -n "{{token}}" ] && [[ ! "{{token}}" =~ ^acm_ ]]; then
        echo "Looking up token: {{token}}"
        actual_token=$(docker exec mcp-http-proxy-acme-certmanager-1 pixi run python scripts/show_token.py "{{token}}" | grep "^Token: " | cut -d' ' -f2)
        if [ -z "$actual_token" ]; then
            echo "Error: Could not find token '{{token}}'"
            exit 1
        fi
    fi
    
    if [ -n "{{pem}}" ] && [ -n "$actual_token" ]; then
        docker exec mcp-http-proxy-acme-certmanager-1 pixi run python scripts/cert_show.py "{{name}}" "$actual_token" --pem
    elif [ -n "{{pem}}" ]; then
        docker exec mcp-http-proxy-acme-certmanager-1 pixi run python scripts/cert_show.py "{{name}}" --pem
    elif [ -n "$actual_token" ]; then
        docker exec mcp-http-proxy-acme-certmanager-1 pixi run python scripts/cert_show.py "{{name}}" "$actual_token"
    else
        docker exec mcp-http-proxy-acme-certmanager-1 pixi run python scripts/cert_show.py "{{name}}"
    fi

# List all certificates (defaults to ADMIN_TOKEN to see all)
cert-list token-name="":
    #!/usr/bin/env bash
    set -euo pipefail
    if [ -z "{{token-name}}" ]; then
        # Use ADMIN_TOKEN by default to list all certificates
        if [ -n "${ADMIN_TOKEN:-}" ]; then
            echo "Listing all certificates (using admin token)..."
            docker exec mcp-http-proxy-acme-certmanager-1 pixi run python scripts/cert_list.py "${ADMIN_TOKEN}"
        else
            echo "Error: No token provided and ADMIN_TOKEN not set"
            exit 1
        fi
    else
        echo "Listing certificates for token..."
        # Get the actual token if a name was provided
        token="{{token-name}}"
        if [[ ! "$token" =~ ^acm_ ]]; then
            echo "Looking up token: {{token-name}}"
            token=$(docker exec mcp-http-proxy-acme-certmanager-1 pixi run python scripts/show_token.py "{{token-name}}" | grep "^Token: " | cut -d' ' -f2)
            if [ -z "$token" ]; then
                echo "Error: Could not find token '{{token-name}}'"
                exit 1
            fi
        fi
        docker exec mcp-http-proxy-acme-certmanager-1 pixi run python scripts/cert_list.py "$token"
    fi

# Delete a certificate (defaults to ADMIN_TOKEN)
cert-delete name token-name="" force="":
    #!/usr/bin/env bash
    set -euo pipefail
    echo "Deleting certificate: {{name}}"
    
    # Use ADMIN_TOKEN as default if no token provided
    token="{{token-name}}"
    if [ -z "$token" ]; then
        token="${ADMIN_TOKEN:-}"
        if [ -z "$token" ]; then
            echo "Error: No token provided and ADMIN_TOKEN not set"
            exit 1
        fi
        echo "Using admin token"
    elif [[ ! "$token" =~ ^acm_ ]]; then
        echo "Looking up token: {{token-name}}"
        token=$(docker exec mcp-http-proxy-acme-certmanager-1 pixi run python scripts/show_token.py "{{token-name}}" | grep "^Token: " | cut -d' ' -f2)
        if [ -z "$token" ]; then
            echo "Error: Could not find token '{{token-name}}'"
            exit 1
        fi
    fi
    if [ -n "{{force}}" ]; then
        docker exec mcp-http-proxy-acme-certmanager-1 pixi run python scripts/cert_delete.py "{{name}}" "$token" --force
    else
        docker exec -it mcp-http-proxy-acme-certmanager-1 pixi run python scripts/cert_delete.py "{{name}}" "$token"
    fi

# Renew a certificate (defaults to ADMIN_TOKEN)
cert-renew name token-name="" force="":
    #!/usr/bin/env bash
    set -euo pipefail
    echo "Renewing certificate: {{name}}"
    
    # Use ADMIN_TOKEN as default if no token provided
    token="{{token-name}}"
    if [ -z "$token" ]; then
        token="${ADMIN_TOKEN:-}"
        if [ -z "$token" ]; then
            echo "Error: No token provided and ADMIN_TOKEN not set"
            exit 1
        fi
        echo "Using admin token"
    elif [[ ! "$token" =~ ^acm_ ]]; then
        echo "Looking up token: {{token-name}}"
        token=$(docker exec mcp-http-proxy-acme-certmanager-1 pixi run python scripts/show_token.py "{{token-name}}" | grep "^Token: " | cut -d' ' -f2)
        if [ -z "$token" ]; then
            echo "Error: Could not find token '{{token-name}}'"
            exit 1
        fi
    fi
    if [ -n "{{force}}" ]; then
        docker exec mcp-http-proxy-acme-certmanager-1 pixi run python scripts/cert_renew.py "{{name}}" "$token" --force
    else
        docker exec mcp-http-proxy-acme-certmanager-1 pixi run python scripts/cert_renew.py "{{name}}" "$token"
    fi

# Check certificate generation status
cert-status name token="" wait="":
    #!/usr/bin/env bash
    set -euo pipefail
    if [ -n "{{wait}}" ] && [ -n "{{token}}" ]; then
        docker exec mcp-http-proxy-acme-certmanager-1 pixi run python scripts/cert_status.py "{{name}}" "{{token}}" --wait
    elif [ -n "{{wait}}" ]; then
        docker exec mcp-http-proxy-acme-certmanager-1 pixi run python scripts/cert_status.py "{{name}}" --wait
    elif [ -n "{{token}}" ]; then
        docker exec mcp-http-proxy-acme-certmanager-1 pixi run python scripts/cert_status.py "{{name}}" "{{token}}"
    else
        docker exec mcp-http-proxy-acme-certmanager-1 pixi run python scripts/cert_status.py "{{name}}"
    fi

# Create multi-domain certificate
cert-create-multi name domains email token-name="" staging="false":
    #!/usr/bin/env bash
    set -euo pipefail
    echo "Creating multi-domain certificate: {{name}}"
    
    # Use ADMIN_TOKEN as default if no token provided
    token="{{token-name}}"
    if [ -z "$token" ]; then
        token="${ADMIN_TOKEN:-}"
        if [ -z "$token" ]; then
            echo "Error: No token provided and ADMIN_TOKEN not set"
            exit 1
        fi
        echo "Using admin token"
    else
        echo "Looking up token: {{token-name}}"
        token=$(docker exec mcp-http-proxy-acme-certmanager-1 pixi run python scripts/show_token.py "{{token-name}}" | grep "^Token: " | cut -d' ' -f2)
        if [ -z "$token" ] || [ "$token" = "None" ]; then
            echo "Error: Token '{{token-name}}' not found"
            exit 1
        fi
    fi
    
    docker exec mcp-http-proxy-acme-certmanager-1 pixi run python scripts/cert_create_multi.py \
        "{{name}}" \
        "{{domains}}" \
        "{{email}}" \
        "$token" \
        "{{staging}}"

# Create wildcard certificate
cert-create-wildcard name base-domain email token-name="" staging="false":
    #!/usr/bin/env bash
    set -euo pipefail
    echo "Creating wildcard certificate: {{name}}"
    echo "  Base domain: {{base-domain}}"
    echo "  Will cover: *.{{base-domain}} and {{base-domain}}"
    
    # Use ADMIN_TOKEN as default if no token provided
    token="{{token-name}}"
    if [ -z "$token" ]; then
        token="${ADMIN_TOKEN:-}"
        if [ -z "$token" ]; then
            echo "Error: No token provided and ADMIN_TOKEN not set"
            exit 1
        fi
        echo "Using admin token"
    else
        echo "Looking up token: {{token-name}}"
        token=$(docker exec mcp-http-proxy-acme-certmanager-1 pixi run python scripts/show_token.py "{{token-name}}" | grep "^Token: " | cut -d' ' -f2)
        if [ -z "$token" ] || [ "$token" = "None" ]; then
            echo "Error: Token '{{token-name}}' not found"
            exit 1
        fi
    fi
    
    docker exec mcp-http-proxy-acme-certmanager-1 pixi run python scripts/cert_create_wildcard.py \
        "{{name}}" \
        "{{base-domain}}" \
        "{{email}}" \
        "$token" \
        "{{staging}}"

# Show which proxy targets can use a certificate
cert-coverage name token-name="":
    #!/usr/bin/env bash
    set -euo pipefail
    
    # Use ADMIN_TOKEN as default if no token provided
    token="{{token-name}}"
    if [ -z "$token" ]; then
        token="${ADMIN_TOKEN:-}"
    elif [[ ! "$token" =~ ^acm_ ]]; then
        echo "Looking up token: {{token-name}}"
        token=$(docker exec mcp-http-proxy-acme-certmanager-1 pixi run python scripts/show_token.py "{{token-name}}" | grep "^Token: " | cut -d' ' -f2)
        if [ -z "$token" ] || [ "$token" = "None" ]; then
            # Try without token for public read access
            token=""
        fi
    fi
    
    if [ -z "$token" ]; then
        docker exec mcp-http-proxy-acme-certmanager-1 pixi run python scripts/cert_coverage.py "{{name}}"
    else
        docker exec mcp-http-proxy-acme-certmanager-1 pixi run python scripts/cert_coverage.py "{{name}}" "$token"
    fi

# Convert certificate from staging to production
cert-to-production name token-name="":
    #!/usr/bin/env bash
    set -euo pipefail
    
    # Use ADMIN_TOKEN as default if no token provided
    token="{{token-name}}"
    if [ -z "$token" ]; then
        token="${ADMIN_TOKEN:-}"
        if [ -z "$token" ]; then
            echo "Error: No token provided and ADMIN_TOKEN not set"
            exit 1
        fi
    elif [[ ! "$token" =~ ^acm_ ]]; then
        echo "Looking up token: {{token-name}}"
        token=$(docker exec mcp-http-proxy-acme-certmanager-1 pixi run python scripts/show_token.py "{{token-name}}" | grep "^Token: " | cut -d' ' -f2)
        if [ -z "$token" ]; then
            echo "Error: Could not find token '{{token-name}}'"
            exit 1
        fi
    fi
    
    # Use the improved conversion script that preserves proxy associations
    docker exec mcp-http-proxy-acme-certmanager-1 pixi run python scripts/cert_to_production.py "{{name}}" "$token"

# Test authorization system (defaults to ADMIN_TOKEN)
test-auth token="":
    #!/usr/bin/env bash
    set -euo pipefail
    # Use ADMIN_TOKEN as default if no token provided
    auth_token="{{token}}"
    if [ -z "$auth_token" ]; then
        auth_token="${ADMIN_TOKEN:-}"
        if [ -z "$auth_token" ]; then
            echo "Error: No token provided and ADMIN_TOKEN not set"
            exit 1
        fi
        echo "Using admin token"
    fi
    pixi run python scripts/test_auth.py "$auth_token"

# Test web GUI (optionally with token)
test-webgui token="":
    pixi run python scripts/test_webgui.py "{{token}}"

# Test public certificate access without authentication
test-public-access:
    pixi run python scripts/test_public_cert_access.py

# Demo public certificate access
demo-public-access:
    pixi run python scripts/demo_public_access.py

# Test all certificate commands comprehensively
test-cert-commands:
    pixi run python scripts/test_all_cert_commands.py

# Test all token and cert commands
test-all-commands:
    pixi run python scripts/test_all_commands.py

# Test all commands with authentication defaults
test-commands-auth:
    pixi run python scripts/test_commands_auth.py

# Clean up all tokens and certificates
cleanup-all:
    docker exec mcp-http-proxy-acme-certmanager-1 pixi run python scripts/cleanup_all.py

# Show status of all services
status:
    docker-compose ps

# Show logs from services
logs *args='':
    docker-compose logs {{args}}

# Test basic proxy functionality
test-proxy-basic:
    pixi run python scripts/test_proxy_basic.py

# Test proxy request forwarding
test-proxy-requests:
    pixi run python scripts/test_proxy_requests.py

# Test WebSocket proxy functionality
test-websocket-proxy:
    pixi run python scripts/test_websocket_proxy.py

# Test streaming and SSE proxy functionality
test-streaming-proxy:
    pixi run python scripts/test_streaming_proxy.py

# Run all proxy tests
test-proxy-all:
    pixi run python scripts/test_proxy_all.py

# Clean up proxy targets (bypasses auth for admin cleanup)
proxy-cleanup hostname="":
    #!/usr/bin/env bash
    set -euo pipefail
    if [ -z "{{hostname}}" ]; then
        echo "Cleaning up all proxy targets..."
        docker exec mcp-http-proxy-acme-certmanager-1 pixi run python scripts/proxy_cleanup.py
    else
        echo "Cleaning up proxy target: {{hostname}}"
        docker exec mcp-http-proxy-acme-certmanager-1 pixi run python scripts/proxy_cleanup.py "{{hostname}}"
    fi

# Create a new proxy target (defaults to ADMIN_TOKEN)
proxy-create hostname target-url token-name="" staging="false" preserve-host="true" enable-http="true" enable-https="true":
    #!/usr/bin/env bash
    set -euo pipefail
    echo "Creating proxy target: {{hostname}} -> {{target-url}}"
    echo "  HTTP: {{enable-http}}, HTTPS: {{enable-https}}"
    
    # Use ADMIN_TOKEN as default if no token provided
    token="{{token-name}}"
    if [ -z "$token" ]; then
        token="${ADMIN_TOKEN:-}"
        if [ -z "$token" ]; then
            echo "Error: No token provided and ADMIN_TOKEN not set"
            exit 1
        fi
        echo "Using admin token"
    elif [[ ! "$token" =~ ^acm_ ]]; then
        echo "Looking up token: {{token-name}}"
        token=$(docker exec mcp-http-proxy-acme-certmanager-1 pixi run python scripts/show_token.py "{{token-name}}" | grep "^Token: " | cut -d' ' -f2)
        if [ -z "$token" ]; then
            echo "Error: Could not find token '{{token-name}}'"
            exit 1
        fi
    fi
    docker exec mcp-http-proxy-acme-certmanager-1 pixi run python scripts/proxy_create.py "{{hostname}}" "{{target-url}}" "$token" "{{staging}}" "{{preserve-host}}" "{{enable-http}}" "{{enable-https}}"

# List all proxy targets (defaults to ADMIN_TOKEN to see all)
proxy-list token-name="":
    #!/usr/bin/env bash
    set -euo pipefail
    if [ -z "{{token-name}}" ]; then
        # Use ADMIN_TOKEN by default to list all proxy targets
        if [ -n "${ADMIN_TOKEN:-}" ]; then
            echo "Listing all proxy targets (using admin token)..."
            docker exec mcp-http-proxy-acme-certmanager-1 pixi run python scripts/proxy_list.py "${ADMIN_TOKEN}"
        else
            echo "Error: No token provided and ADMIN_TOKEN not set"
            exit 1
        fi
    else
        echo "Listing proxy targets for token..."
        # Get the actual token if a name was provided
        token="{{token-name}}"
        if [[ ! "$token" =~ ^acm_ ]]; then
            echo "Looking up token: {{token-name}}"
            token=$(docker exec mcp-http-proxy-acme-certmanager-1 pixi run python scripts/show_token.py "{{token-name}}" | grep "^Token: " | cut -d' ' -f2)
            if [ -z "$token" ]; then
                echo "Error: Could not find token '{{token-name}}'"
                exit 1
            fi
        fi
        docker exec mcp-http-proxy-acme-certmanager-1 pixi run python scripts/proxy_list.py "$token"
    fi

# Show proxy target details
proxy-show hostname:
    #!/usr/bin/env bash
    set -euo pipefail
    echo "Showing proxy target: {{hostname}}"
    docker exec mcp-http-proxy-acme-certmanager-1 pixi run python scripts/proxy_show.py "{{hostname}}"

# Update proxy target (defaults to ADMIN_TOKEN)
proxy-update hostname token-name="" target-url="" preserve-host="" custom-headers="":
    #!/usr/bin/env bash
    set -euo pipefail
    echo "Updating proxy target: {{hostname}}"
    
    # Use ADMIN_TOKEN as default if no token provided
    token="{{token-name}}"
    if [ -z "$token" ]; then
        token="${ADMIN_TOKEN:-}"
        if [ -z "$token" ]; then
            echo "Error: No token provided and ADMIN_TOKEN not set"
            exit 1
        fi
        echo "Using admin token"
    elif [[ ! "$token" =~ ^acm_ ]]; then
        echo "Looking up token: {{token-name}}"
        token=$(docker exec mcp-http-proxy-acme-certmanager-1 pixi run python scripts/show_token.py "{{token-name}}" | grep "^Token: " | cut -d' ' -f2)
        if [ -z "$token" ]; then
            echo "Error: Could not find token '{{token-name}}'"
            exit 1
        fi
    fi
    args=()
    if [ -n "{{target-url}}" ]; then
        args+=("--target-url" "{{target-url}}")
    fi
    if [ -n "{{preserve-host}}" ]; then
        args+=("--preserve-host" "{{preserve-host}}")
    fi
    if [ -n "{{custom-headers}}" ]; then
        args+=("--custom-headers" "{{custom-headers}}")
    fi
    if [ ${#args[@]} -eq 0 ]; then
        docker exec mcp-http-proxy-acme-certmanager-1 pixi run python scripts/proxy_update.py "{{hostname}}" "$token"
    else
        docker exec mcp-http-proxy-acme-certmanager-1 pixi run python scripts/proxy_update.py "{{hostname}}" "$token" "${args[@]}"
    fi

# Delete a proxy target (defaults to ADMIN_TOKEN)
proxy-delete hostname token-name="" delete-cert="false" force="":
    #!/usr/bin/env bash
    set -euo pipefail
    echo "Deleting proxy target: {{hostname}}"
    
    # Use ADMIN_TOKEN as default if no token provided
    token="{{token-name}}"
    if [ -z "$token" ]; then
        token="${ADMIN_TOKEN:-}"
        if [ -z "$token" ]; then
            echo "Error: No token provided and ADMIN_TOKEN not set"
            exit 1
        fi
        echo "Using admin token"
    elif [[ ! "$token" =~ ^acm_ ]]; then
        echo "Looking up token: {{token-name}}"
        token=$(docker exec mcp-http-proxy-acme-certmanager-1 pixi run python scripts/show_token.py "{{token-name}}" | grep "^Token: " | cut -d' ' -f2)
        if [ -z "$token" ]; then
            echo "Error: Could not find token '{{token-name}}'"
            exit 1
        fi
    fi
    args=()
    if [ "{{delete-cert}}" = "true" ]; then
        args+=("--delete-certificate")
    fi
    if [ -n "{{force}}" ]; then
        args+=("--force")
    fi
    if [ -n "{{force}}" ]; then
        if [ ${#args[@]} -eq 0 ]; then
            docker exec mcp-http-proxy-acme-certmanager-1 pixi run python scripts/proxy_delete.py "{{hostname}}" "$token"
        else
            docker exec mcp-http-proxy-acme-certmanager-1 pixi run python scripts/proxy_delete.py "{{hostname}}" "$token" "${args[@]}"
        fi
    else
        if [ ${#args[@]} -eq 0 ]; then
            docker exec -it mcp-http-proxy-acme-certmanager-1 pixi run python scripts/proxy_delete.py "{{hostname}}" "$token"
        else
            docker exec -it mcp-http-proxy-acme-certmanager-1 pixi run python scripts/proxy_delete.py "{{hostname}}" "$token" "${args[@]}"
        fi
    fi

# Enable a proxy target (defaults to ADMIN_TOKEN)
proxy-enable hostname token-name="":
    #!/usr/bin/env bash
    set -euo pipefail
    echo "Enabling proxy target: {{hostname}}"
    
    # Use ADMIN_TOKEN as default if no token provided
    token="{{token-name}}"
    if [ -z "$token" ]; then
        token="${ADMIN_TOKEN:-}"
        if [ -z "$token" ]; then
            echo "Error: No token provided and ADMIN_TOKEN not set"
            exit 1
        fi
        echo "Using admin token"
    elif [[ ! "$token" =~ ^acm_ ]]; then
        echo "Looking up token: {{token-name}}"
        token=$(docker exec mcp-http-proxy-acme-certmanager-1 pixi run python scripts/show_token.py "{{token-name}}" | grep "^Token: " | cut -d' ' -f2)
        if [ -z "$token" ]; then
            echo "Error: Could not find token '{{token-name}}'"
            exit 1
        fi
    fi
    docker exec mcp-http-proxy-acme-certmanager-1 pixi run python scripts/proxy_enable.py "{{hostname}}" "$token"

# Disable a proxy target (defaults to ADMIN_TOKEN)
proxy-disable hostname token-name="":
    #!/usr/bin/env bash
    set -euo pipefail
    echo "Disabling proxy target: {{hostname}}"
    
    # Use ADMIN_TOKEN as default if no token provided
    token="{{token-name}}"
    if [ -z "$token" ]; then
        token="${ADMIN_TOKEN:-}"
        if [ -z "$token" ]; then
            echo "Error: No token provided and ADMIN_TOKEN not set"
            exit 1
        fi
        echo "Using admin token"
    elif [[ ! "$token" =~ ^acm_ ]]; then
        echo "Looking up token: {{token-name}}"
        token=$(docker exec mcp-http-proxy-acme-certmanager-1 pixi run python scripts/show_token.py "{{token-name}}" | grep "^Token: " | cut -d' ' -f2)
        if [ -z "$token" ]; then
            echo "Error: Could not find token '{{token-name}}'"
            exit 1
        fi
    fi
    docker exec mcp-http-proxy-acme-certmanager-1 pixi run python scripts/proxy_disable.py "{{hostname}}" "$token"

# Generate a new certificate for an existing proxy
proxy-cert-generate hostname token-name="" staging="false":
    #!/usr/bin/env bash
    set -euo pipefail
    echo "Generating certificate for proxy: {{hostname}}"
    
    # Use ADMIN_TOKEN as default if no token provided
    token="{{token-name}}"
    if [ -z "$token" ]; then
        token="${ADMIN_TOKEN:-}"
        if [ -z "$token" ]; then
            echo "Error: No token provided and ADMIN_TOKEN not set"
            exit 1
        fi
        echo "Using admin token"
    else
        echo "Looking up token: {{token-name}}"
        token=$(docker exec mcp-http-proxy-acme-certmanager-1 pixi run python scripts/show_token.py "{{token-name}}" | grep "^Token: " | cut -d' ' -f2)
        if [ -z "$token" ] || [ "$token" = "None" ]; then
            echo "Error: Token '{{token-name}}' not found"
            exit 1
        fi
    fi
    
    docker exec mcp-http-proxy-acme-certmanager-1 pixi run python scripts/proxy_cert_generate.py "{{hostname}}" "$token" "{{staging}}"

# Create a group of proxy targets sharing a single multi-domain certificate
proxy-create-group group-name hostnames target-url token-name="" staging="false" preserve-host="true":
    #!/usr/bin/env bash
    set -euo pipefail
    echo "Creating proxy group: {{group-name}}"
    
    # Use ADMIN_TOKEN as default if no token provided
    token="{{token-name}}"
    if [ -z "$token" ]; then
        token="${ADMIN_TOKEN:-}"
        if [ -z "$token" ]; then
            echo "Error: No token provided and ADMIN_TOKEN not set"
            exit 1
        fi
        echo "Using admin token"
    else
        echo "Looking up token: {{token-name}}"
        token=$(docker exec mcp-http-proxy-acme-certmanager-1 pixi run python scripts/show_token.py "{{token-name}}" | grep "^Token: " | cut -d' ' -f2)
        if [ -z "$token" ] || [ "$token" = "None" ]; then
            echo "Error: Token '{{token-name}}' not found"
            exit 1
        fi
    fi
    
    docker exec mcp-http-proxy-acme-certmanager-1 pixi run python scripts/proxy_create_group.py \
        "{{group-name}}" \
        "{{hostnames}}" \
        "{{target-url}}" \
        "$token" \
        "{{staging}}" \
        "{{preserve-host}}"

# Attach an existing certificate to a proxy
proxy-cert-attach hostname cert-name token-name="":
    #!/usr/bin/env bash
    set -euo pipefail
    echo "Attaching certificate '{{cert-name}}' to proxy: {{hostname}}"
    
    # Use ADMIN_TOKEN as default if no token provided
    token="{{token-name}}"
    if [ -z "$token" ]; then
        token="${ADMIN_TOKEN:-}"
        if [ -z "$token" ]; then
            echo "Error: No token provided and ADMIN_TOKEN not set"
            exit 1
        fi
        echo "Using admin token"
    else
        echo "Looking up token: {{token-name}}"
        token=$(docker exec mcp-http-proxy-acme-certmanager-1 pixi run python scripts/show_token.py "{{token-name}}" | grep "^Token: " | cut -d' ' -f2)
        if [ -z "$token" ] || [ "$token" = "None" ]; then
            echo "Error: Token '{{token-name}}' not found"
            exit 1
        fi
    fi
    
    docker exec mcp-http-proxy-acme-certmanager-1 pixi run python scripts/proxy_cert_attach.py "{{hostname}}" "{{cert-name}}" "$token"

# Test all proxy management commands
test-proxy-commands:
    pixi run python scripts/test_proxy_commands.py

# Show proxy targets owned by a token (or all if no token specified)
proxy-show-targets token="":
    #!/usr/bin/env bash
    set -euo pipefail
    if [ -z "{{token}}" ]; then
        echo "Showing all proxy targets by token..."
    else
        echo "Showing proxy targets for token: {{token}}"
    fi
    docker exec mcp-http-proxy-acme-certmanager-1 pixi run python scripts/show_token_proxies.py "{{token}}"

# Test proxy with example.com
test-proxy-example:
    pixi run python scripts/test_proxy_example.py

# Test certificate email configuration
test-cert-email:
    pixi run python scripts/test_cert_email.py

# ============================================================================
# Route Management
# ============================================================================

# List all routes (uses ADMIN_TOKEN for authentication)
route-list:
    #!/usr/bin/env bash
    set -euo pipefail
    # Routes require authentication now
    if [ -n "${ADMIN_TOKEN:-}" ]; then
        echo "Listing all routes (using admin token)..."
        docker exec mcp-http-proxy-acme-certmanager-1 pixi run python scripts/route_list.py "${ADMIN_TOKEN}"
    else
        echo "Error: ADMIN_TOKEN not set"
        exit 1
    fi

# Show route details
route-show route-id:
    #!/usr/bin/env bash
    set -euo pipefail
    echo "Showing route: {{route-id}}"
    docker exec mcp-http-proxy-acme-certmanager-1 pixi run python scripts/route_show.py "{{route-id}}"

# Create a new route (defaults to ADMIN_TOKEN)
route-create path target-type target-value token-name="" priority="50" methods="" is-regex="false" description="":
    #!/usr/bin/env bash
    set -euo pipefail
    echo "Creating route: {{path}} -> {{target-type}}:{{target-value}} (priority: {{priority}})"
    
    # Use ADMIN_TOKEN as default if no token provided
    token="{{token-name}}"
    if [ -z "$token" ]; then
        token="${ADMIN_TOKEN:-}"
        if [ -z "$token" ]; then
            echo "Error: No token provided and ADMIN_TOKEN not set"
            exit 1
        fi
        echo "Using admin token"
    elif [[ ! "$token" =~ ^acm_ ]]; then
        echo "Looking up token: {{token-name}}"
        token=$(docker exec mcp-http-proxy-acme-certmanager-1 pixi run python scripts/show_token.py "{{token-name}}" | grep "^Token: " | cut -d' ' -f2)
        if [ -z "$token" ]; then
            echo "Error: Could not find token '{{token-name}}'"
            exit 1
        fi
    fi
    docker exec mcp-http-proxy-acme-certmanager-1 pixi run python scripts/route_create.py "{{path}}" "{{target-type}}" "{{target-value}}" "$token" "{{priority}}" "{{methods}}" "{{is-regex}}" "{{description}}"

# Update a route (defaults to ADMIN_TOKEN)
route-update route-id token-name="" path="" target-type="" target-value="" priority="" methods="" is-regex="" description="" enabled="":
    #!/usr/bin/env bash
    set -euo pipefail
    echo "Updating route: {{route-id}}"
    
    # Use ADMIN_TOKEN as default if no token provided
    token="{{token-name}}"
    if [ -z "$token" ]; then
        token="${ADMIN_TOKEN:-}"
        if [ -z "$token" ]; then
            echo "Error: No token provided and ADMIN_TOKEN not set"
            exit 1
        fi
        echo "Using admin token"
    elif [[ ! "$token" =~ ^acm_ ]]; then
        echo "Looking up token: {{token-name}}"
        token=$(docker exec mcp-http-proxy-acme-certmanager-1 pixi run python scripts/show_token.py "{{token-name}}" | grep "^Token: " | cut -d' ' -f2)
        if [ -z "$token" ]; then
            echo "Error: Could not find token '{{token-name}}'"
            exit 1
        fi
    fi
    args=""
    [ -n "{{path}}" ] && args="$args --path '{{path}}'"
    [ -n "{{target-type}}" ] && args="$args --target-type '{{target-type}}'"
    [ -n "{{target-value}}" ] && args="$args --target-value '{{target-value}}'"
    [ -n "{{priority}}" ] && args="$args --priority '{{priority}}'"
    [ -n "{{methods}}" ] && args="$args --methods '{{methods}}'"
    [ -n "{{is-regex}}" ] && args="$args --is-regex '{{is-regex}}'"
    [ -n "{{description}}" ] && args="$args --description '{{description}}'"
    [ -n "{{enabled}}" ] && args="$args --enabled '{{enabled}}'"
    eval docker exec mcp-http-proxy-acme-certmanager-1 pixi run python scripts/route_update.py "{{route-id}}" "$token" $args

# Delete a route (defaults to ADMIN_TOKEN)
route-delete route-id token-name="":
    #!/usr/bin/env bash
    set -euo pipefail
    echo "Deleting route: {{route-id}}"
    
    # Use ADMIN_TOKEN as default if no token provided
    token="{{token-name}}"
    if [ -z "$token" ]; then
        token="${ADMIN_TOKEN:-}"
        if [ -z "$token" ]; then
            echo "Error: No token provided and ADMIN_TOKEN not set"
            exit 1
        fi
        echo "Using admin token"
    elif [[ ! "$token" =~ ^acm_ ]]; then
        echo "Looking up token: {{token-name}}"
        token=$(docker exec mcp-http-proxy-acme-certmanager-1 pixi run python scripts/show_token.py "{{token-name}}" | grep "^Token: " | cut -d' ' -f2)
        if [ -z "$token" ]; then
            echo "Error: Could not find token '{{token-name}}'"
            exit 1
        fi
    fi
    docker exec mcp-http-proxy-acme-certmanager-1 pixi run python scripts/route_delete.py "{{route-id}}" "$token"

# Enable a route (defaults to ADMIN_TOKEN)
route-enable route-id token-name="":
    #!/usr/bin/env bash
    set -euo pipefail
    just route-update "{{route-id}}" "{{token-name}}" enabled="true"

# Disable a route (defaults to ADMIN_TOKEN)
route-disable route-id token-name="":
    #!/usr/bin/env bash
    set -euo pipefail
    just route-update "{{route-id}}" "{{token-name}}" enabled="false"

# Test route functionality
test-routes:
    pixi run python scripts/test_routes.py

# Create example routes (defaults to ADMIN_TOKEN)
route-examples token-name="":
    #!/usr/bin/env bash
    set -euo pipefail
    echo "Creating example routes..."
    just route-create "/.well-known/" instance localhost "{{token-name}}" 100 "" false "Well-known paths"
    just route-create "/api/v1/" instance api "{{token-name}}" 95 "" false "API v1 endpoints"
    just route-create "/ws/" instance localhost "{{token-name}}" 90 "GET" false "WebSocket endpoints"
    just route-create "^/user/[0-9]+/profile$" instance api "{{token-name}}" 85 "GET,PUT" true "User profile regex"
    echo "Example routes created!"

# ============================================================================

# Update JavaScript for web GUI
update-js:
    pixi run python scripts/update_app_js.py

# Test email settings functionality
test-email-settings token-name:
    docker exec mcp-http-proxy-acme-certmanager-1 pixi run python scripts/test_email_settings.py "{{token-name}}"

# Verify web GUI updates
verify-webgui:
    pixi run python scripts/verify_webgui.py

# Test full implementation end-to-end
test-full-implementation:
    docker exec mcp-http-proxy-acme-certmanager-1 pixi run python scripts/test_full_implementation.py

# Show demo workflow
demo-workflow:
    @bash scripts/demo_workflow.sh

# Debug token info endpoint
debug-token-info token:
    pixi run python scripts/debug_token_info.py "{{token}}"

# Add JavaScript debug logging
add-js-debug:
    pixi run python scripts/add_js_debug.py

# Browser console debugging guide
browser-debug:
    @pixi run python scripts/check_browser_console.py

# Test settings tab flow
test-settings-flow:
    pixi run python scripts/test_settings_flow.py

# Fix loadTokenInfo function
fix-loadtokeninfo:
    pixi run python scripts/fix_loadtokeninfo.py

# Remove JavaScript debug logging
remove-js-debug:
    pixi run python scripts/remove_js_debug.py

# Test settings for ALL tokens
test-all-tokens-settings:
    docker exec mcp-http-proxy-acme-certmanager-1 pixi run python scripts/test_all_tokens_settings.py

# Create test tokens for testing
create-test-tokens:
    docker exec mcp-http-proxy-acme-certmanager-1 pixi run python scripts/create_test_tokens.py

# Cleanup test tokens
cleanup-test-tokens:
    docker exec mcp-http-proxy-acme-certmanager-1 pixi run python scripts/cleanup_test_tokens.py

# Test individual token email update
test-token-email-update token:
    pixi run python scripts/test_individual_email_update.py "{{token}}"

# Debug certificate ownership
debug-cert-ownership:
    docker exec mcp-http-proxy-acme-certmanager-1 pixi run python scripts/debug_cert_ownership.py

# Cleanup orphaned certificates
cleanup-orphaned-certs delete="":
    #!/usr/bin/env bash
    set -euo pipefail
    if [ -n "{{delete}}" ]; then
        echo "Cleaning up orphaned certificates (DELETE MODE)..."
        docker exec mcp-http-proxy-acme-certmanager-1 pixi run python scripts/cleanup_orphaned_certs.py --delete
    else
        echo "Checking for orphaned certificates (DRY RUN)..."
        docker exec mcp-http-proxy-acme-certmanager-1 pixi run python scripts/cleanup_orphaned_certs.py
    fi

# Check for orphaned resources (certificates and proxy targets)
check-orphaned-resources:
    docker exec mcp-http-proxy-acme-certmanager-1 pixi run python scripts/check_orphaned_resources.py

# Test merged tabs in web GUI
test-merged-tabs:
    pixi run python scripts/test_merged_tabs.py

# Demo merged tabs functionality
demo-merged-tabs:
    pixi run python scripts/demo_merged_tabs.py

# Setup GUI access with HTTPS and custom domain
gui-setup hostname cert-email="" staging="false":
    #!/usr/bin/env bash
    set -euo pipefail
    
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "MCP HTTP Proxy - Web GUI HTTPS Setup"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo ""
    
    # Validate hostname format - must contain at least one dot
    if ! echo "{{hostname}}" | grep -qE '^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)+$'; then
        echo "✗ Error: Invalid hostname format: {{hostname}}"
        echo ""
        echo "A valid hostname must be a fully qualified domain name (FQDN)."
        echo "Examples:"
        echo "  ✓ gui.example.com"
        echo "  ✓ admin.mysite.org"
        echo "  ✓ portal.company.io"
        echo "  ✗ gui (too short - needs domain)"
        echo "  ✗ localhost (use actual domain)"
        echo ""
        echo "The hostname must:"
        echo "  - Contain at least one dot (.)"
        echo "  - Use only letters, numbers, hyphens, and dots"
        echo "  - Not start or end with a hyphen"
        echo ""
        exit 1
    fi
    
    echo "Setting up HTTPS access for: {{hostname}}"
    echo ""
    
    # Step 1: Check for admin token
    echo "▶ Step 1: Checking admin token..."
    
    # Check if ADMIN_TOKEN environment variable is set (loaded from .env by just)
    if [ -z "${ADMIN_TOKEN:-}" ]; then
        echo "  ✗ Error: ADMIN_TOKEN not found"
        echo ""
        echo "Please run 'just token-generate-admin' first to create an admin token."
        exit 1
    fi
    
    # Use the admin token from environment
    token="${ADMIN_TOKEN}"
    
    # Verify token is valid by checking if admin token exists
    if docker exec mcp-http-proxy-acme-certmanager-1 pixi run python scripts/show_token.py "admin" 2>/dev/null | grep -q "^Token: "; then
        echo "  ✓ Admin token verified"
        existing_email=$(docker exec mcp-http-proxy-acme-certmanager-1 pixi run python scripts/show_token.py "admin" | grep "^Certificate Email: " | cut -d' ' -f3- || echo "")
        if [ -n "$existing_email" ] && [ "$existing_email" != "None" ]; then
            echo "  ✓ Using admin token email: $existing_email"
        fi
    else
        echo "  ✗ Error: Admin token not found in system"
        echo ""
        echo "Please run 'just token-generate-admin' to create the admin token."
        exit 1
    fi
    
    echo ""
    
    # Step 2: Check if proxy target already exists
    echo "▶ Step 2: Checking proxy configuration..."
    
    if docker exec mcp-http-proxy-acme-certmanager-1 pixi run python scripts/proxy_show.py "{{hostname}}" 2>/dev/null | grep -q "Hostname:"; then
        echo "  ⚠ Proxy target for {{hostname}} already exists"
        echo "  ℹ To reconfigure, first run: just proxy-delete {{hostname}} admin"
        exit 1
    fi
    
    # Step 3: Create proxy target
    echo "  → Creating proxy target: {{hostname}} -> GUI (localhost:80)"
    
    staging_flag=""
    if [ "{{staging}}" = "true" ]; then
        staging_flag="staging"
        echo "  ℹ Using Let's Encrypt STAGING environment"
    fi
    
    docker exec mcp-http-proxy-acme-certmanager-1 pixi run python scripts/proxy_create.py \
        "{{hostname}}" \
        "http://localhost:80" \
        "$token" \
        "$staging_flag" \
        "false" \
        "true" \
        "true"
    
    echo ""
    
    # Step 4: Get certificate name and wait for generation
    echo "▶ Step 3: SSL Certificate Generation..."
    
    # Certificate name follows the pattern proxy-<hostname with dots replaced by dashes>
    cert_name="proxy-$(echo {{hostname}} | tr '.' '-')"
    echo "  → Certificate name: $cert_name"
    echo "  → Waiting for certificate generation..."
    echo ""
    
    # Wait for certificate with progress indication
    docker exec mcp-http-proxy-acme-certmanager-1 pixi run python scripts/cert_status.py "$cert_name" --wait
    
    echo ""
    
    # Step 5: Show DNS configuration requirements
    echo "▶ Step 4: DNS Configuration Required"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    
    # Get server's public IP (try multiple methods)
    public_ip=$(curl -s https://ipinfo.io/ip 2>/dev/null || \
                curl -s https://api.ipify.org 2>/dev/null || \
                curl -s https://checkip.amazonaws.com 2>/dev/null || \
                echo "<YOUR-SERVER-IP>")
    
    echo ""
    echo "Add the following DNS record:"
    echo ""
    echo "  Type:  A"
    echo "  Name:  {{hostname}}"
    echo "  Value: $public_ip"
    echo "  TTL:   300 (5 minutes)"
    echo ""
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    
    # Step 6: Show access information
    echo ""
    echo "✅ Setup Complete!"
    echo ""
    echo "Once DNS propagates, access your GUI at:"
    echo ""
    echo "  🔒 https://{{hostname}}"
    echo ""
    echo "Login with admin token from .env"
    echo "(Use 'just token-show admin' to see full token)"
    echo ""
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# Check GUI HTTPS setup status
gui-status:
    #!/usr/bin/env bash
    set -euo pipefail
    
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "MCP HTTP Proxy - Web GUI Status"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo ""
    
    # Find all proxy targets pointing to localhost:80 (GUI)
    echo "▶ GUI Proxy Configurations:"
    echo ""
    
    found_gui=false
    
    # Get all proxy targets and filter for GUI ones
    # Look for lines containing both hostname and localhost:80 target
    gui_proxies=$(docker exec mcp-http-proxy-acme-certmanager-1 pixi run python scripts/proxy_list.py 2>/dev/null | grep -E "^\|.*http://localhost:80.*\|" || echo "")
    
    if [ -n "$gui_proxies" ]; then
        while IFS= read -r line; do
            # Extract hostname from the table row
            hostname=$(echo "$line" | awk -F'|' '{print $2}' | tr -d ' ')
            if [ -n "$hostname" ] && [ "$hostname" != "Hostname" ]; then
                found_gui=true
                echo "  🌐 Domain: $hostname"
                
                # Get certificate status
                cert_name="proxy-$(echo $hostname | tr '.' '-')"
                cert_status=$(docker exec mcp-http-proxy-acme-certmanager-1 pixi run python scripts/cert_status.py "$cert_name" 2>/dev/null | grep "Status:" | awk '{print $2}' || echo "unknown")
                
                echo "  📜 Certificate: $cert_name ($cert_status)"
                
                # Check if domain is accessible
                if command -v dig >/dev/null 2>&1; then
                    dns_result=$(dig +short "$hostname" 2>/dev/null | head -n1)
                    if [ -n "$dns_result" ]; then
                        echo "  ✓ DNS: Resolves to $dns_result"
                    else
                        echo "  ⚠ DNS: Not configured or not propagated"
                    fi
                fi
                
                echo "  🔗 Access URL: https://$hostname"
                echo ""
            fi
        done <<< "$gui_proxies"
    fi
    
    if [ "$found_gui" = false ]; then
        echo "  ⚠ No GUI proxy configurations found"
        echo ""
        echo "  To set up GUI access, run:"
        echo "  just gui-setup <hostname> <cert-email>"
        echo ""
    fi
    
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# Remove GUI HTTPS setup
gui-remove hostname force="":
    #!/usr/bin/env bash
    set -euo pipefail
    
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "MCP HTTP Proxy - Remove GUI Setup"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo ""
    
    # Check if proxy exists
    if ! docker exec mcp-http-proxy-acme-certmanager-1 pixi run python scripts/proxy_show.py "{{hostname}}" 2>/dev/null | grep -q "Target URL: http://localhost:80"; then
        echo "⚠ No GUI proxy configuration found for: {{hostname}}"
        echo ""
        echo "Use 'just gui-status' to see existing GUI configurations"
        exit 1
    fi
    
    echo "This will remove GUI access for: {{hostname}}"
    echo ""
    
    # Confirm if not forced
    if [ -z "{{force}}" ]; then
        read -p "Are you sure? (y/N) " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            echo "Cancelled."
            exit 0
        fi
    fi
    
    # Get admin token from environment
    if [ -z "${ADMIN_TOKEN:-}" ]; then
        echo "⚠ Warning: ADMIN_TOKEN not found"
        echo ""
        echo "Please run 'just token-generate-admin' first to create an admin token."
        echo "Attempting cleanup without token..."
        docker exec mcp-http-proxy-acme-certmanager-1 pixi run python scripts/proxy_cleanup.py "{{hostname}}"
        exit 0
    fi
    
    token="${ADMIN_TOKEN}"
    
    # Delete proxy target and certificate
    echo "▶ Removing proxy configuration..."
    docker exec mcp-http-proxy-acme-certmanager-1 pixi run python scripts/proxy_delete.py "{{hostname}}" "$token" --delete-certificate
    
    echo ""
    echo "✅ GUI setup removed for: {{hostname}}"
    echo ""
    echo "To set up again, run:"
    echo "just gui-setup {{hostname}}"
    echo ""
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# Setup fetcher-mcp with proper domain
fetcher-setup hostname staging="false":
    #!/usr/bin/env bash
    set -euo pipefail
    
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "MCP HTTP Proxy - Fetcher MCP Setup"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo ""
    
    # Validate hostname is FQDN
    if ! echo "{{hostname}}" | grep -qE '^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)+$'; then
        echo "✗ Error: Invalid hostname format: {{hostname}}"
        echo ""
        echo "A valid hostname must be a fully qualified domain name (FQDN)."
        echo "Examples:"
        echo "  ✓ fetcher.example.com"
        echo "  ✓ mcp.yourdomain.com"
        echo "  ✓ scraper.company.io"
        echo ""
        exit 1
    fi
    
    # Check admin token
    if [ -z "${ADMIN_TOKEN:-}" ]; then
        echo "✗ Error: ADMIN_TOKEN not found"
        echo ""
        echo "Please run 'just token-generate-admin' first to create an admin token."
        exit 1
    fi
    
    # Check if fetcher-mcp is running
    if ! docker-compose ps fetcher-mcp 2>/dev/null | grep -q "Up"; then
        echo "⚠ Warning: fetcher-mcp container is not running"
        echo ""
        echo "Starting fetcher-mcp..."
        docker-compose up -d fetcher-mcp
        echo "Waiting for fetcher-mcp to be ready..."
        sleep 10
    fi
    
    # Create proxy
    echo "▶ Creating proxy: {{hostname}} → fetcher-mcp:3000"
    output=$(docker exec mcp-http-proxy-acme-certmanager-1 pixi run python scripts/proxy_create.py \
        "{{hostname}}" \
        "http://fetcher-mcp:3000" \
        "${ADMIN_TOKEN}" \
        "" "{{staging}}" 2>&1)
    
    echo "$output"
    
    echo ""
    echo "✅ Fetcher MCP configured!"
    echo ""
    echo "Access via:"
    echo "  🔗 HTTP:  http://{{hostname}}/"
    echo "  🔒 HTTPS: https://{{hostname}}/"
    echo ""
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# Remove fetcher proxy
fetcher-remove hostname:
    #!/usr/bin/env bash
    set -euo pipefail
    
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "MCP HTTP Proxy - Remove Fetcher Setup"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo ""
    
    # Check if proxy exists
    if ! docker exec mcp-http-proxy-acme-certmanager-1 pixi run python scripts/proxy_show.py "{{hostname}}" 2>/dev/null | grep -q "fetcher-mcp:3000"; then
        echo "⚠ No fetcher proxy configuration found for: {{hostname}}"
        exit 1
    fi
    
    # Get admin token
    if [ -z "${ADMIN_TOKEN:-}" ]; then
        echo "✗ Error: ADMIN_TOKEN not found"
        echo ""
        echo "Please run 'just token-generate-admin' first"
        exit 1
    fi
    
    # Delete proxy
    echo "▶ Removing proxy configuration..."
    docker exec mcp-http-proxy-acme-certmanager-1 pixi run python scripts/proxy_delete.py \
        "{{hostname}}" "${ADMIN_TOKEN}" --delete-certificate
    
    echo ""
    echo "✅ Fetcher proxy removed: {{hostname}}"
    echo ""
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# Check fetcher status
fetcher-status:
    #!/usr/bin/env bash
    set -euo pipefail
    
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "MCP HTTP Proxy - Fetcher MCP Status"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo ""
    
    echo "▶ Container Status:"
    docker-compose ps fetcher-mcp 2>/dev/null || echo "  fetcher-mcp container not found"
    
    echo ""
    echo "▶ Proxy Configurations:"
    proxies=$(docker exec mcp-http-proxy-acme-certmanager-1 pixi run python scripts/proxy_list.py 2>/dev/null | grep "fetcher-mcp:3000" || echo "")
    
    if [ -n "$proxies" ]; then
        echo "$proxies" | while IFS= read -r line; do
            hostname=$(echo "$line" | awk '{print $1}')
            echo "  • $hostname → fetcher-mcp:3000"
        done
    else
        echo "  No fetcher proxies configured"
        echo ""
        echo "  To set up fetcher access, run:"
        echo "  just fetcher-setup <hostname>"
    fi
    
    echo ""
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# View fetcher logs
fetcher-logs:
    docker-compose logs -f fetcher-mcp

# ============================================================================
# Echo Server Management
# ============================================================================

# Setup echo-stateful with proper domain
echo-stateful-setup hostname staging="false":
    #!/usr/bin/env bash
    set -euo pipefail
    
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "MCP HTTP Proxy - Echo Stateful Setup"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo ""
    
    # Validate hostname is FQDN
    if ! echo "{{hostname}}" | grep -qE '^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)+$'; then
        echo "✗ Error: Invalid hostname format: {{hostname}}"
        echo ""
        echo "A valid hostname must be a fully qualified domain name (FQDN)."
        echo "Examples:"
        echo "  ✓ echo-stateful.example.com"
        echo "  ✓ mcp-stateful.yourdomain.com"
        echo ""
        exit 1
    fi
    
    # Check admin token
    if [ -z "${ADMIN_TOKEN:-}" ]; then
        echo "✗ Error: ADMIN_TOKEN not found"
        echo ""
        echo "Please run 'just token-generate-admin' first to create an admin token."
        exit 1
    fi
    
    # Check if echo-stateful is running
    if ! docker-compose ps echo-stateful 2>/dev/null | grep -q "Up"; then
        echo "⚠ Warning: echo-stateful container is not running"
        echo ""
        echo "Starting echo-stateful..."
        docker-compose up -d echo-stateful
        echo "Waiting for echo-stateful to be ready..."
        sleep 10
    fi
    
    # Create proxy
    echo "▶ Creating proxy: {{hostname}} → echo-stateful:3000"
    output=$(docker exec mcp-http-proxy-acme-certmanager-1 pixi run python scripts/proxy_create.py \
        "{{hostname}}" \
        "http://echo-stateful:3000" \
        "${ADMIN_TOKEN}" \
        "" "{{staging}}" 2>&1)
    
    echo "$output"
    
    echo ""
    echo "✅ Echo Stateful configured!"
    echo ""
    echo "Access via:"
    echo "  🔗 HTTP:  http://{{hostname}}/"
    echo "  🔒 HTTPS: https://{{hostname}}/"
    echo ""
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# Setup echo-stateless with proper domain
echo-stateless-setup hostname staging="false":
    #!/usr/bin/env bash
    set -euo pipefail
    
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "MCP HTTP Proxy - Echo Stateless Setup"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo ""
    
    # Validate hostname is FQDN
    if ! echo "{{hostname}}" | grep -qE '^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)+$'; then
        echo "✗ Error: Invalid hostname format: {{hostname}}"
        echo ""
        echo "A valid hostname must be a fully qualified domain name (FQDN)."
        echo "Examples:"
        echo "  ✓ echo-stateless.example.com"
        echo "  ✓ mcp-stateless.yourdomain.com"
        echo ""
        exit 1
    fi
    
    # Check admin token
    if [ -z "${ADMIN_TOKEN:-}" ]; then
        echo "✗ Error: ADMIN_TOKEN not found"
        echo ""
        echo "Please run 'just token-generate-admin' first to create an admin token."
        exit 1
    fi
    
    # Check if echo-stateless is running
    if ! docker-compose ps echo-stateless 2>/dev/null | grep -q "Up"; then
        echo "⚠ Warning: echo-stateless container is not running"
        echo ""
        echo "Starting echo-stateless..."
        docker-compose up -d echo-stateless
        echo "Waiting for echo-stateless to be ready..."
        sleep 10
    fi
    
    # Create proxy
    echo "▶ Creating proxy: {{hostname}} → echo-stateless:3000"
    output=$(docker exec mcp-http-proxy-acme-certmanager-1 pixi run python scripts/proxy_create.py \
        "{{hostname}}" \
        "http://echo-stateless:3000" \
        "${ADMIN_TOKEN}" \
        "" "{{staging}}" 2>&1)
    
    echo "$output"
    
    echo ""
    echo "✅ Echo Stateless configured!"
    echo ""
    echo "Access via:"
    echo "  🔗 HTTP:  http://{{hostname}}/"
    echo "  🔒 HTTPS: https://{{hostname}}/"
    echo ""
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# Remove echo-stateful proxy
echo-stateful-remove hostname:
    #!/usr/bin/env bash
    set -euo pipefail
    
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "MCP HTTP Proxy - Remove Echo Stateful Setup"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo ""
    
    # Check if proxy exists
    if ! docker exec mcp-http-proxy-acme-certmanager-1 pixi run python scripts/proxy_show.py "{{hostname}}" 2>/dev/null | grep -q "echo-stateful:3000"; then
        echo "⚠ No echo-stateful proxy configuration found for: {{hostname}}"
        exit 1
    fi
    
    # Get admin token
    if [ -z "${ADMIN_TOKEN:-}" ]; then
        echo "✗ Error: ADMIN_TOKEN not found"
        echo ""
        echo "Please run 'just token-generate-admin' first"
        exit 1
    fi
    
    # Delete proxy
    echo "▶ Removing proxy configuration..."
    docker exec mcp-http-proxy-acme-certmanager-1 pixi run python scripts/proxy_delete.py \
        "{{hostname}}" "${ADMIN_TOKEN}" --delete-certificate
    
    echo ""
    echo "✅ Echo stateful proxy removed: {{hostname}}"
    echo ""
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# Remove echo-stateless proxy
echo-stateless-remove hostname:
    #!/usr/bin/env bash
    set -euo pipefail
    
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "MCP HTTP Proxy - Remove Echo Stateless Setup"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo ""
    
    # Check if proxy exists
    if ! docker exec mcp-http-proxy-acme-certmanager-1 pixi run python scripts/proxy_show.py "{{hostname}}" 2>/dev/null | grep -q "echo-stateless:3000"; then
        echo "⚠ No echo-stateless proxy configuration found for: {{hostname}}"
        exit 1
    fi
    
    # Get admin token
    if [ -z "${ADMIN_TOKEN:-}" ]; then
        echo "✗ Error: ADMIN_TOKEN not found"
        echo ""
        echo "Please run 'just token-generate-admin' first"
        exit 1
    fi
    
    # Delete proxy
    echo "▶ Removing proxy configuration..."
    docker exec mcp-http-proxy-acme-certmanager-1 pixi run python scripts/proxy_delete.py \
        "{{hostname}}" "${ADMIN_TOKEN}" --delete-certificate
    
    echo ""
    echo "✅ Echo stateless proxy removed: {{hostname}}"
    echo ""
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# Check echo server status
echo-status:
    #!/usr/bin/env bash
    set -euo pipefail
    
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "MCP HTTP Proxy - Echo Servers Status"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo ""
    
    echo "▶ Container Status:"
    echo ""
    echo "Echo Stateful:"
    docker-compose ps echo-stateful 2>/dev/null || echo "  echo-stateful container not found"
    echo ""
    echo "Echo Stateless:"
    docker-compose ps echo-stateless 2>/dev/null || echo "  echo-stateless container not found"
    
    echo ""
    echo "▶ Proxy Configurations:"
    
    # Check for echo-stateful proxies
    echo ""
    echo "Echo Stateful Proxies:"
    stateful_proxies=$(docker exec mcp-http-proxy-acme-certmanager-1 pixi run python scripts/proxy_list.py 2>/dev/null | grep "echo-stateful:3000" || echo "")
    
    if [ -n "$stateful_proxies" ]; then
        echo "$stateful_proxies" | while IFS= read -r line; do
            hostname=$(echo "$line" | awk '{print $1}')
            echo "  • $hostname → echo-stateful:3000"
        done
    else
        echo "  No echo-stateful proxies configured"
    fi
    
    # Check for echo-stateless proxies
    echo ""
    echo "Echo Stateless Proxies:"
    stateless_proxies=$(docker exec mcp-http-proxy-acme-certmanager-1 pixi run python scripts/proxy_list.py 2>/dev/null | grep "echo-stateless:3000" || echo "")
    
    if [ -n "$stateless_proxies" ]; then
        echo "$stateless_proxies" | while IFS= read -r line; do
            hostname=$(echo "$line" | awk '{print $1}')
            echo "  • $hostname → echo-stateless:3000"
        done
    else
        echo "  No echo-stateless proxies configured"
    fi
    
    echo ""
    echo "To set up echo server access, run:"
    echo "  just echo-stateful-setup <hostname>"
    echo "  just echo-stateless-setup <hostname>"
    echo ""
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# View echo-stateful logs
echo-stateful-logs:
    docker-compose logs -f echo-stateful

# View echo-stateless logs
echo-stateless-logs:
    docker-compose logs -f echo-stateless