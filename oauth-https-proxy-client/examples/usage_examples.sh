#!/bin/bash
# OAuth HTTPS Proxy Client - Usage Examples

# Set up environment (copy .env.example to .env and update)
export API_URL=http://localhost:80
export ADMIN_TOKEN=your_token_here

# Or use configuration file
# cp examples/config.example.yml ~/.oauth-proxy-client.yml

echo "=== OAuth HTTPS Proxy Client Examples ==="
echo

# ============================================
# Token Management
# ============================================
echo "# Token Management Examples"
echo

# List all tokens
proxy-client token list

# Create a new token with certificate email
proxy-client token create dev-token --cert-email dev@example.com

# Show token information
proxy-client token show dev-token

# Reveal full token value (be careful!)
proxy-client token reveal dev-token

# Get current token info
proxy-client token info

# Update certificate email for current token
proxy-client token update-email admin@newdomain.com

# Delete a token (and owned resources)
proxy-client token delete old-token --force

# ============================================
# Certificate Management
# ============================================
echo "# Certificate Management Examples"
echo

# List all certificates
proxy-client cert list

# Create single-domain certificate (staging)
proxy-client cert create test-cert test.example.com \
  --email admin@example.com \
  --staging

# Create multi-domain certificate (production)
proxy-client cert create-multi prod-cert \
  example.com www.example.com api.example.com \
  --email admin@example.com

# Check certificate status
proxy-client cert status test-cert

# Renew a certificate
proxy-client cert renew prod-cert

# Export certificate to files
proxy-client cert export prod-cert --output-dir ./certs

# Convert staging to production
proxy-client cert to-production test-cert

# ============================================
# Proxy Management
# ============================================
echo "# Proxy Management Examples"
echo

# List all proxies
proxy-client proxy list

# Create a basic proxy
proxy-client proxy create api.example.com http://backend:8080

# Create proxy with certificate
proxy-client proxy create secure.example.com https://backend:443 \
  --cert-name prod-cert \
  --preserve-host

# Enable OAuth authentication
proxy-client proxy auth enable api.example.com auth.example.com forward \
  --users alice,bob,charlie \
  --scopes mcp:read,mcp:write

# Configure per-proxy user allowlist
proxy-client proxy auth config api.example.com \
  --users alice,bob  # Only these GitHub users can access

# Disable authentication
proxy-client proxy auth disable api.example.com

# Delete proxy
proxy-client proxy delete old.example.com --force

# ============================================
# Route Management
# ============================================
echo "# Route Management Examples"
echo

# List all routes
proxy-client route list

# List routes with formatting
proxy-client route list --formatted

# Create global route to service
proxy-client route create /api/v1/ service auth \
  --priority 100 \
  --methods GET,POST

# Create proxy-specific route
proxy-client route create /admin/ port 8080 \
  --scope proxy \
  --proxies admin.example.com \
  --priority 90

# Delete route
proxy-client route delete route-123

# ============================================
# Service Management
# ============================================
echo "# Service Management Examples"
echo

# List all services
proxy-client service list --type all

# Create Docker service
proxy-client service create my-app nginx:latest \
  --port 8080 \
  --memory 512m \
  --cpu 1.0 \
  --env NODE_ENV=production

# Control services
proxy-client service start my-app
proxy-client service stop my-app
proxy-client service restart my-app

# View service logs
proxy-client service logs my-app --lines 100

# Get service stats
proxy-client service stats my-app

# ============================================
# OAuth Administration
# ============================================
echo "# OAuth Administration Examples"
echo

# List OAuth clients
proxy-client oauth client list --active-only

# Show client details
proxy-client oauth client show client_abc123

# List active sessions
proxy-client oauth session list

# Revoke a session
proxy-client oauth session revoke session-xyz --force

# Check OAuth health
proxy-client oauth health

# View OAuth metrics
proxy-client oauth metrics

# Register new OAuth client
proxy-client oauth register my-mcp-client \
  --redirect-uri https://client.example.com/callback \
  --scope "mcp:read mcp:write"

# ============================================
# MCP Resource Management
# ============================================
echo "# MCP Resource Examples"
echo

# List protected resources
proxy-client resource list

# Register protected resource
proxy-client resource register \
  https://mcp.example.com \
  mcp.example.com \
  "Example Protected Resource" \
  --scopes mcp:read,mcp:write

# Validate token for resource
proxy-client resource validate-token \
  https://mcp.example.com \
  eyJhbGciOiJSUzI1NiIs...

# Auto-register resources from proxies
proxy-client resource auto-register

# ============================================
# Log Queries
# ============================================
echo "# Log Query Examples"
echo

# Search logs
proxy-client log search \
  --query "status:404" \
  --hours 24 \
  --limit 50

# Query by IP address
proxy-client log by-ip 192.168.1.100 --hours 1

# Query by OAuth client
proxy-client log by-client client_abc123 --hours 24

# Show recent errors
proxy-client log errors --hours 6 --include-warnings

# Follow logs in real-time
proxy-client log follow --interval 2 --hostname api.example.com

# Get event statistics
proxy-client log events --hours 24

# ============================================
# System Commands
# ============================================
echo "# System Command Examples"
echo

# Check system health
proxy-client system health

# Show system information
proxy-client system info

# Display statistics
proxy-client system stats

# Validate configuration
proxy-client system validate

# Show versions
proxy-client system version

# ============================================
# Output Format Examples
# ============================================
echo "# Output Format Examples"
echo

# JSON output (for scripting)
proxy-client --format json token list

# Table output (default for terminal)
proxy-client --format table proxy list

# YAML output (for configuration)
proxy-client --format yaml cert show prod-cert

# CSV output (for data analysis)
proxy-client --format csv log search --hours 24

# ============================================
# Pipeline Examples
# ============================================
echo "# Pipeline and Scripting Examples"
echo

# Get all proxy hostnames
proxy-client --format json proxy list | jq -r '.[] | .hostname'

# Delete all tokens with "test" in name
proxy-client --format json token list | \
  jq -r '.[] | select(.name | contains("test")) | .name' | \
  xargs -I {} proxy-client token delete {} --force

# Export all certificates
proxy-client --format json cert list | \
  jq -r '.[] | .cert_name' | \
  xargs -I {} proxy-client cert export {} --output-dir ./certs/{}

# Create proxies from file
while IFS=',' read -r hostname target; do
  proxy-client proxy create "$hostname" "$target"
done < proxies.csv

# Monitor proxy health
watch -n 10 'proxy-client --format json proxy list | \
  jq -r ".[] | [.hostname, .enabled] | @tsv"'

# ============================================
# Profile Usage
# ============================================
echo "# Profile Usage Examples"
echo

# Use production profile
proxy-client --profile production proxy list

# Use dev profile with custom config file
proxy-client --profile dev --config ~/my-config.yml token list

# Override profile settings
proxy-client --profile production --base-url https://staging.example.com proxy list

echo
echo "=== End of Examples ===="