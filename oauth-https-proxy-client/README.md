# OAuth HTTPS Proxy Client

A comprehensive command-line interface for managing OAuth HTTPS proxy infrastructure with TLS/ACME certificate support.

## Features

- **Complete API Coverage**: Full implementation of all OAuth HTTPS Proxy REST endpoints
- **Certificate Management**: ACME/Let's Encrypt integration with multi-domain support
- **OAuth Integration**: GitHub OAuth authentication and authorization
- **Service Orchestration**: Docker container management and external service registration
- **Advanced Routing**: Priority-based path routing with scope control
- **MCP Protocol Support**: Model Context Protocol compliance
- **Real-time Monitoring**: Log streaming and metrics collection
- **Multiple Output Formats**: JSON, Table, YAML, and CSV output

## Installation

### From PyPI

```bash
pip install oauth-https-proxy-client
```

### From Source

```bash
git clone https://github.com/yourusername/oauth-https-proxy-client.git
cd oauth-https-proxy-client
pip install -e .
```

### Development Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/oauth-https-proxy-client.git
cd oauth-https-proxy-client

# Install with development dependencies
pip install -e ".[dev]"

# Install pre-commit hooks
pre-commit install
```

## Configuration

### Environment Variables

The client uses the same environment variables as the OAuth HTTPS Proxy server's `justfile`:

```bash
# Core Configuration
export BASE_URL=http://localhost:80
export ADMIN_TOKEN=your_admin_token_here

# Optional Configuration
export LOG_LEVEL=INFO
export PROXY_REQUEST_TIMEOUT=120
export PROXY_CONNECT_TIMEOUT=30

# For testing
export TEST_TOKEN=test_token_here
export TEST_BASE_URL=https://test.yourdomain.org
```

### Configuration File

Create `~/.oauth-proxy-client.yml`:

```yaml
profiles:
  default:
    base_url: http://localhost:80
    token: ${ADMIN_TOKEN}
    output_format: table
    
  production:
    base_url: https://api.proxy.example.com
    token: ${PROD_TOKEN}
    output_format: json
    
  dev:
    base_url: http://localhost:9000
    token: dev_token_here
    log_level: DEBUG

defaults:
  timeout: 30
  retries: 3
```

## Usage

### Basic Commands

```bash
# Use with environment variables
proxy-client token list

# Specify base URL and token explicitly
proxy-client --base-url http://localhost:9000 --token your_token token list

# Use a specific profile
proxy-client --profile production proxy list

# Output in different formats
proxy-client --format json token list
proxy-client --format yaml cert list
```

### Token Management

```bash
# List all tokens
proxy-client token list

# Create a new token
proxy-client token create my-token --cert-email admin@example.com

# Show token details
proxy-client token show my-token

# Reveal token value
proxy-client token reveal my-token

# Update token email
proxy-client token update-email my-token new@example.com

# Delete token
proxy-client token delete my-token
```

### Certificate Management

```bash
# List certificates
proxy-client cert list

# Create single-domain certificate
proxy-client cert create my-cert example.com --email admin@example.com

# Create multi-domain certificate
proxy-client cert create-multi my-cert example.com,www.example.com,api.example.com

# Check certificate status
proxy-client cert status my-cert

# Renew certificate
proxy-client cert renew my-cert

# Export certificate to files
proxy-client cert export my-cert --output-dir ./certs
```

### Proxy Management

```bash
# List all proxies
proxy-client proxy list

# Create a proxy
proxy-client proxy create api.example.com http://backend:8080

# Enable OAuth authentication
proxy-client proxy auth enable api.example.com auth.example.com forward

# Configure allowed users
proxy-client proxy auth config api.example.com --users alice,bob

# Set MCP metadata
proxy-client proxy resource set api.example.com --endpoint /mcp --scopes mcp:read,mcp:write

# Attach certificate
proxy-client proxy cert attach api.example.com my-cert

# Delete proxy
proxy-client proxy delete api.example.com
```

### Service Management

```bash
# List Docker services
proxy-client service list

# Create a service
proxy-client service create my-app nginx:latest --port 8080

# Control services
proxy-client service start my-app
proxy-client service stop my-app
proxy-client service restart my-app

# View logs
proxy-client service logs my-app --lines 100

# Add port to service
proxy-client service port add my-app 8081 --bind 0.0.0.0

# Register external service
proxy-client service external register api-gateway https://gateway.example.com
```

### Route Management

```bash
# List routes
proxy-client route list

# Create a route
proxy-client route create /api/v1/ service auth --priority 100

# Create proxy-specific route
proxy-client route create-proxy /admin/ port 8080 api.example.com --priority 90

# Delete route
proxy-client route delete route-id-123
```

### Log Queries

```bash
# Search logs
proxy-client log search --query "status:404" --hours 24

# Query by IP
proxy-client log by-ip 192.168.1.100 --hours 1

# Show errors
proxy-client log errors --hours 6 --limit 50

# Follow logs in real-time
proxy-client log follow --interval 2

# Get event statistics
proxy-client log events --hours 24
```

### OAuth Administration

```bash
# List OAuth clients
proxy-client oauth client list

# Show OAuth sessions
proxy-client oauth session list

# Revoke session
proxy-client oauth session revoke session-id-123

# Check OAuth health
proxy-client oauth health

# View OAuth metrics
proxy-client oauth metrics
```

## Advanced Usage

### Pipeline Operations

```bash
# Export proxy list as JSON and process with jq
proxy-client --format json proxy list | jq '.[] | .hostname'

# Create multiple proxies from file
cat proxies.txt | while read hostname target; do
  proxy-client proxy create "$hostname" "$target"
done

# Export all certificates
proxy-client cert list --format json | jq -r '.[] | .cert_name' | \
  xargs -I {} proxy-client cert export {} --output-dir ./certs/{}
```

### Batch Operations

```bash
# Create multiple tokens
for name in alice bob charlie; do
  proxy-client token create "$name" --cert-email "$name@example.com"
done

# Update all proxy certificates to production
proxy-client proxy list --format json | jq -r '.[] | .hostname' | \
  xargs -I {} proxy-client proxy cert generate {} --production
```

## Error Handling

The client provides detailed error messages and exit codes:

- `0`: Success
- `1`: General error
- `2`: Configuration error
- `3`: Authentication error
- `4`: Resource not found
- `5`: Validation error
- `6`: Connection error
- `7`: Timeout error

## Development

### Running Tests

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=oauth_proxy_client

# Run specific test file
pytest tests/test_tokens.py

# Run integration tests only
pytest -m integration
```

### Code Quality

```bash
# Format code
black src tests

# Lint code
ruff check src tests

# Type checking
mypy src
```

### Building Documentation

```bash
# Build Sphinx documentation
sphinx-build -b html docs docs/_build/html

# Serve documentation locally
python -m http.server -d docs/_build/html 8000
```

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

MIT License - see [LICENSE](LICENSE) file for details.

## Support

- Documentation: https://oauth-https-proxy-client.readthedocs.io
- Issues: https://github.com/yourusername/oauth-https-proxy-client/issues
- Discussions: https://github.com/yourusername/oauth-https-proxy-client/discussions