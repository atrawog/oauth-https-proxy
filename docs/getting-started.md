# Getting Started

This guide will help you get ACME Certificate Manager up and running quickly.

## Prerequisites

- Python 3.10 or higher
- Redis server
- Domain name(s) pointing to your server
- Ports 80 and 443 available

## Installation Methods

### Method 1: Docker Compose (Recommended)

The easiest way to get started is with Docker Compose:

```bash
# Clone the repository
git clone https://github.com/acme-certmanager/acme-certmanager
cd acme-certmanager

# Copy and configure environment
cp .env.example .env
nano .env  # Edit with your settings

# Start services
docker-compose up -d

# Check logs
docker-compose logs -f
```

### Method 2: PyPI Installation

Install from PyPI:

```bash
pip install acme-certmanager
```

### Method 3: Development Setup

For development with pixi:

```bash
# Install pixi
curl -fsSL https://pixi.sh/install.sh | bash

# Clone and setup
git clone https://github.com/acme-certmanager/acme-certmanager
cd acme-certmanager
just setup

# Run development server
just dev
```

## Configuration

### Environment Variables

Create a `.env` file with these settings:

```env
# Redis connection
REDIS_URL=redis://localhost:6379/0

# Server ports
HTTP_PORT=80
HTTPS_PORT=443

# ACME provider
ACME_DIRECTORY_URL=https://acme-v02.api.letsencrypt.org/directory

# Logging
LOG_LEVEL=INFO

# Renewal settings
RENEWAL_CHECK_INTERVAL=86400
RENEWAL_THRESHOLD_DAYS=30
```

### ACME Providers

| Provider | Directory URL |
|----------|--------------|
| Let's Encrypt Production | `https://acme-v02.api.letsencrypt.org/directory` |
| Let's Encrypt Staging | `https://acme-staging-v02.api.letsencrypt.org/directory` |
| ZeroSSL | `https://acme.zerossl.com/v2/DV90` |
| Buypass | `https://api.buypass.com/acme/directory` |

:::{warning}
Always test with staging environments first to avoid rate limits!
:::

## First Certificate

### Step 1: Verify Domain

Ensure your domain points to your server:

```bash
# Check DNS
dig +short yourdomain.com

# Verify connectivity
curl http://yourdomain.com
```

### Step 2: Create Certificate

Request a certificate via API:

```bash
curl -X POST http://localhost/certificates \
  -H "Content-Type: application/json" \
  -d '{
    "domain": "yourdomain.com",
    "email": "admin@yourdomain.com",
    "cert_name": "production",
    "acme_directory_url": "https://acme-staging-v02.api.letsencrypt.org/directory"
  }'
```

### Step 3: Verify Certificate

Check certificate status:

```bash
# List all certificates
curl http://localhost/certificates

# Get specific certificate
curl http://localhost/certificates/production
```

### Step 4: Test HTTPS

Once certificate is active:

```bash
# Test HTTPS
curl https://yourdomain.com

# Check certificate
openssl s_client -connect yourdomain.com:443 -servername yourdomain.com
```

## Common Tasks

### Add Multiple Domains

Currently, create separate certificates for each domain:

```bash
# Certificate for www subdomain
curl -X POST http://localhost/certificates \
  -H "Content-Type: application/json" \
  -d '{
    "domain": "www.yourdomain.com",
    "email": "admin@yourdomain.com",
    "cert_name": "www-production",
    "acme_directory_url": "https://acme-v02.api.letsencrypt.org/directory"
  }'
```

### Manual Renewal

Trigger manual renewal:

```bash
curl -X POST http://localhost/certificates/production/renew
```

### Health Monitoring

Check system health:

```bash
curl http://localhost/health
```

Response:
```json
{
  "status": "healthy",
  "scheduler": true,
  "redis": "healthy",
  "certificates_loaded": 2,
  "https_enabled": true
}
```

## Troubleshooting

### Certificate Generation Fails

1. **Check domain DNS**: Ensure domain points to your server
2. **Verify ports**: Ports 80 and 443 must be accessible
3. **Check logs**: `docker-compose logs certmanager`
4. **Use staging first**: Avoid production rate limits

### Redis Connection Issues

```bash
# Test Redis connection
redis-cli -u $REDIS_URL ping
```

### Permission Errors

Run with appropriate permissions for ports 80/443:

```bash
# Using sudo (not recommended)
sudo acme-certmanager

# Better: Use authbind
authbind --deep acme-certmanager

# Best: Use reverse proxy on high port
HTTP_PORT=8080 HTTPS_PORT=8443 acme-certmanager
```

## Next Steps

- Review [API Reference](api-reference) for all endpoints
- Understand [Architecture](architecture) for customization
- Follow [Deployment Guide](deployment) for production setup