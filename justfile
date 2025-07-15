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
    docker-compose up -d redis certmanager
    echo "Waiting for services to be healthy..."
    max_wait=120
    waited=0
    while [ $waited -lt $max_wait ]; do
        if docker-compose ps | grep -q "healthy.*redis" && docker-compose ps | grep -q "healthy.*certmanager"; then
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

# View service logs
logs:
    docker-compose logs -f

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