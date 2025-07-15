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
    TEST_BASE_URL=http://localhost:80 TEST_REDIS_URL=redis://localhost:6379/1 pixi run pytest tests/ -v --tb=short

# Run tests inside Docker
test-integration:
    docker-compose -f docker-compose.yml -f docker-compose.test.yml run --rm test-runner

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

# Generate a new API token
token-generate name:
    #!/usr/bin/env bash
    set -euo pipefail
    echo "Generating API token: {{name}}"
    docker exec mcp-http-proxy-acme-certmanager-1 pixi run python scripts/generate_token.py "{{name}}"

# List all tokens
token-list:
    #!/usr/bin/env bash
    set -euo pipefail
    echo "Listing all API tokens..."
    docker exec mcp-http-proxy-acme-certmanager-1 pixi run python scripts/list_tokens.py

# Delete a token (and all its certificates)
token-delete name:
    #!/usr/bin/env bash
    set -euo pipefail
    echo "Deleting token: {{name}}"
    docker exec -it mcp-http-proxy-acme-certmanager-1 pixi run python scripts/delete_token.py "{{name}}"

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

# Create a new certificate (can use token name instead of full token)
cert-create name domain email token-name staging="false":
    #!/usr/bin/env bash
    set -euo pipefail
    echo "Creating certificate: {{name}}"
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
    docker exec mcp-http-proxy-acme-certmanager-1 pixi run python scripts/cert_create.py "{{name}}" "{{domain}}" "{{email}}" "$token" "{{staging}}"

# Show certificate details (token optional for public certs)
cert-show name token="" pem="":
    #!/usr/bin/env bash
    set -euo pipefail
    if [ -n "{{pem}}" ] && [ -n "{{token}}" ]; then
        docker exec mcp-http-proxy-acme-certmanager-1 pixi run python scripts/cert_show.py "{{name}}" "{{token}}" --pem
    elif [ -n "{{pem}}" ]; then
        docker exec mcp-http-proxy-acme-certmanager-1 pixi run python scripts/cert_show.py "{{name}}" --pem
    elif [ -n "{{token}}" ]; then
        docker exec mcp-http-proxy-acme-certmanager-1 pixi run python scripts/cert_show.py "{{name}}" "{{token}}"
    else
        docker exec mcp-http-proxy-acme-certmanager-1 pixi run python scripts/cert_show.py "{{name}}"
    fi

# List all certificates (optionally filtered by token)
cert-list token-name="":
    #!/usr/bin/env bash
    set -euo pipefail
    if [ -z "{{token-name}}" ]; then
        echo "Listing all certificates..."
        docker exec mcp-http-proxy-acme-certmanager-1 pixi run python scripts/cert_list.py
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

# Delete a certificate
cert-delete name token force="":
    #!/usr/bin/env bash
    set -euo pipefail
    echo "Deleting certificate: {{name}}"
    if [ -n "{{force}}" ]; then
        docker exec mcp-http-proxy-acme-certmanager-1 pixi run python scripts/cert_delete.py "{{name}}" "{{token}}" --force
    else
        docker exec -it mcp-http-proxy-acme-certmanager-1 pixi run python scripts/cert_delete.py "{{name}}" "{{token}}"
    fi

# Renew a certificate
cert-renew name token force="":
    #!/usr/bin/env bash
    set -euo pipefail
    echo "Renewing certificate: {{name}}"
    if [ -n "{{force}}" ]; then
        docker exec mcp-http-proxy-acme-certmanager-1 pixi run python scripts/cert_renew.py "{{name}}" "{{token}}" --force
    else
        docker exec mcp-http-proxy-acme-certmanager-1 pixi run python scripts/cert_renew.py "{{name}}" "{{token}}"
    fi

# Check certificate generation status
cert-status name token="" wait="":
    #!/usr/bin/env bash
    set -euo pipefail
    if [ -n "{{wait}}" ]; then
        docker exec mcp-http-proxy-acme-certmanager-1 pixi run python scripts/cert_status.py "{{name}}" "{{token}}" --wait
    else
        docker exec mcp-http-proxy-acme-certmanager-1 pixi run python scripts/cert_status.py "{{name}}" "{{token}}"
    fi

# Test authorization system
test-auth token:
    pixi run python scripts/test_auth.py "{{token}}"

# Test web GUI (optionally with token)
test-webgui token="":
    pixi run python scripts/test_webgui.py "{{token}}"

# Test public certificate access without authentication
test-public-access:
    pixi run python scripts/test_public_cert_access.py

# Demo public certificate access
demo-public-access:
    pixi run python scripts/demo_public_access.py