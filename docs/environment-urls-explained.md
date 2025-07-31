# Environment URL and Domain Variables Explained

## Overview
The project uses multiple URL and domain environment variables that serve different purposes. This document clarifies their usage to prevent confusion.

## URL Variables

### BASE_URL
- **Value**: `http://localhost:80`
- **Purpose**: Local API endpoint for host-to-container communication
- **Used by**: Just commands running on the host machine
- **Example**: `curl http://localhost:80/api/v1/tokens`
- **Note**: This is for LOCAL development only

### TEST_BASE_URL  
- **Value**: `https://test.atradev.org`
- **Purpose**: Real domain for testing HTTPS, certificates, and production-like scenarios
- **Used by**: Integration tests that need real SSL/TLS
- **When to use**: Testing certificate generation, OAuth flows with real domains

### TEST_BASE_URL_INTERNAL
- **Value**: `http://proxy` (set in docker-compose.yml)
- **Purpose**: Internal Docker network communication between containers
- **Used by**: Containers talking to the proxy service
- **Note**: Only works within Docker network

### TEST_PROXY_TARGET_URL
- **Value**: `https://example.com`
- **Purpose**: Default target for proxy testing
- **Used by**: Test scripts creating proxy configurations

### MCP_SERVER_URL
- **Value**: `https://echo-stateless.atradev.org/mcp`
- **Purpose**: Specific MCP server endpoint for testing
- **Used by**: MCP client tests

## Domain Variables

### BASE_DOMAIN
- **Value**: `atradev.org`
- **Purpose**: Primary domain for OAuth and production services
- **Used by**: OAuth configuration, production deployments
- **Example**: Creates `auth.atradev.org` for OAuth

### TEST_DOMAIN
- **Value**: `test.atradev.org`
- **Purpose**: Specific subdomain for testing
- **Used by**: Certificate tests, proxy tests
- **Note**: Must have DNS pointing to test server

### TEST_DOMAIN_BASE
- **Value**: `atradev.org`
- **Purpose**: Base domain for creating test subdomains dynamically
- **Used by**: Scripts that create multiple test subdomains
- **Example**: Can create `test1.atradev.org`, `test2.atradev.org`, etc.

## Common Confusion Points

1. **BASE_URL vs TEST_BASE_URL**
   - BASE_URL = localhost (development)
   - TEST_BASE_URL = real domain (testing)

2. **BASE_DOMAIN vs TEST_DOMAIN_BASE**
   - BASE_DOMAIN = production domain configuration
   - TEST_DOMAIN_BASE = for creating test subdomains

3. **Internal vs External URLs**
   - External: BASE_URL, TEST_BASE_URL (from host/internet)
   - Internal: TEST_BASE_URL_INTERNAL (between containers)

## Usage Guidelines

### For Local Development
```bash
# Use BASE_URL
curl http://localhost:80/health
just token-list  # Uses BASE_URL internally
```

### For Testing with Real Domains
```bash
# Use TEST_BASE_URL and TEST_DOMAIN
export CERT_DOMAIN=test.atradev.org
just cert-create test-cert $CERT_DOMAIN admin@example.com token
```

### For Container-to-Container
```yaml
# In docker-compose.yml
environment:
  - TEST_BASE_URL_INTERNAL=http://proxy
```

### For OAuth Setup
```bash
# Uses BASE_DOMAIN to create auth.atradev.org
just oauth-routes-setup atradev.org token
```

## Best Practices

1. **Always use BASE_URL for local development commands**
2. **Use TEST_* variables only for testing scenarios**
3. **Never hardcode URLs in scripts - use environment variables**
4. **Document which URL variable your script/service expects**
5. **Set TEST_BASE_URL_INTERNAL in docker-compose for internal communication**

## Variable Dependency Chart

```
BASE_URL (localhost)
  └── Used by: Just commands, local API calls

TEST_BASE_URL (https://test.atradev.org)
  └── Used by: Integration tests, certificate tests
  
BASE_DOMAIN (atradev.org)
  ├── Creates: auth.{BASE_DOMAIN} for OAuth
  └── Used by: Production configuration

TEST_DOMAIN (test.atradev.org)
  └── Used by: Specific test scenarios

TEST_DOMAIN_BASE (atradev.org)
  └── Used by: Dynamic subdomain creation
```

## Troubleshooting

### "BASE_URL not set"
- Check if .env file is loaded: `just --evaluate BASE_URL`
- Ensure `set dotenv-load := true` in justfile
- Export manually: `export BASE_URL=http://localhost:80`

### "Connection refused"
- Wrong URL for context (using external URL internally)
- Service not running on expected port
- Check with: `docker-compose ps`

### "SSL certificate errors"
- Using http:// URL where https:// is expected
- Certificate not generated for domain
- Check with: `just cert-list`