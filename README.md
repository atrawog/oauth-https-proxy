# ACME Certificate Manager

Pure Python HTTPS server with automatic ACME certificate management. Obtains and renews TLS certificates via ACME protocol, stores all data in Redis, supports multiple domains per certificate, and hot-reloads certificates without downtime.

## Features

- **Automatic Certificate Management**: Obtains and renews certificates via ACME protocol
- **Redis Storage**: All data stored in Redis - no filesystem persistence
- **Multi-Domain Support**: Single certificate for multiple domains
- **Hot Reload**: Update certificates without restarting the server
- **Auto-Renewal**: Scheduled certificate renewal before expiry
- **SNI Support**: Serve different certificates based on requested domain
- **FastAPI Integration**: RESTful API for certificate management
- **Health Checks**: Built-in health monitoring
- **Docker Ready**: Includes Docker Compose configuration

## Installation

```bash
pip install acme-certmanager
```

## Quick Start

### Using Docker Compose (Recommended)

```bash
# Clone the repository
git clone https://github.com/acme-certmanager/acme-certmanager
cd acme-certmanager

# Configure environment
cp .env.example .env
# Edit .env with your settings

# Start services
docker-compose up -d
```

### Manual Setup

1. Start Redis:
```bash
docker run -d -p 6379:6379 redis:7-alpine
```

2. Set environment variables:
```bash
export REDIS_URL=redis://localhost:6379/0
export HTTP_PORT=80
export HTTPS_PORT=443
```

3. Run the server:
```bash
acme-certmanager
```

## API Usage

### Create Certificate

```bash
curl -X POST http://localhost/certificates \
  -H "Content-Type: application/json" \
  -d '{
    "domain": "example.com",
    "email": "admin@example.com",
    "cert_name": "production",
    "acme_directory_url": "https://acme-v02.api.letsencrypt.org/directory"
  }'
```

### List Certificates

```bash
curl http://localhost/certificates
```

### Renew Certificate

```bash
curl -X POST http://localhost/certificates/production/renew
```

### Health Check

```bash
curl http://localhost/health
```

## Configuration

Environment variables:

- `REDIS_URL`: Redis connection string (default: `redis://localhost:6379/0`)
- `HTTP_PORT`: HTTP port (default: `80`)
- `HTTPS_PORT`: HTTPS port (default: `443`)
- `LOG_LEVEL`: Logging level (default: `INFO`)
- `RENEWAL_CHECK_INTERVAL`: How often to check for renewals in seconds (default: `86400`)
- `RENEWAL_THRESHOLD_DAYS`: Days before expiry to renew (default: `30`)

## Development

### Setup Development Environment

```bash
# Install pixi (Python environment manager)
curl -fsSL https://pixi.sh/install.sh | bash

# Install dependencies
just setup

# Run tests
just test-docker

# Run development server
just dev
```

### Testing

Tests run against real services (no mocks):

```bash
# Run all tests against Docker services
just test-all

# Run specific tests
just test

# Run with verbose output
just test-verbose
```

## Architecture

- **Certificate Manager**: Core ACME protocol implementation
- **HTTPS Server**: FastAPI server with dynamic SSL context loading  
- **Redis Storage**: Exclusive data persistence layer
- **Scheduler**: Automatic certificate renewal
- **Health Monitoring**: Service health checks

## License

MIT License - see LICENSE file for details 
