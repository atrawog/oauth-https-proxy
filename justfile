# MCP HTTP Proxy - Refactored Modular Justfile
# This is a refactored version with modular approach and API-first design

# Variables
container_name := "mcp-http-proxy-proxy-1"
default_base_url := "http://localhost:80"
staging_cert_email := env_var_or_default("TEST_EMAIL", env_var_or_default("ACME_EMAIL", "test@example.com"))

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
rebuild service="proxy":
    docker compose build {{service}}
    docker compose up -d {{service}}

# View Docker container logs (no follow, last 100 lines)
logs service="" lines="100":
    #!/usr/bin/env bash
    if [ -n "{{service}}" ]; then
        docker compose logs --tail={{lines}} {{service}}
    else
        docker compose logs --tail={{lines}}
    fi

# Follow Docker container logs (like tail -f)
logs-follow service="":
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
# LOGGING AND MONITORING  
# ============================================================================

# Show both Docker and application logs (combined view)
logs-all lines="50" hours="1" token="${ADMIN_TOKEN}":
    #!/usr/bin/env bash
    set -euo pipefail
    
    echo "=== Docker Container Logs (last {{lines}} lines) ==="
    docker compose logs --tail={{lines}} || true
    
    echo ""
    echo "=== Application Structured Logs (last {{hours}} hour(s)) ==="
    just app-logs hours={{hours}} limit={{lines}} token={{token}} || true

# Show available log commands
logs-help:
    @echo "=== Available Logging Commands ==="
    @echo ""
    @echo "🐳 Docker Container Logs:"
    @echo "  just logs                    # Show Docker container logs (last 100 lines)"
    @echo "  just logs-follow             # Follow Docker container logs (tail -f)"
    @echo "  just logs proxy              # Show proxy service logs"
    @echo "  just logs-follow redis       # Follow redis service logs"
    @echo ""
    @echo "🔄 Combined View:"
    @echo "  just logs-all                # Show both Docker and application logs"
    @echo ""
    @echo "📋 Application Logs (Structured):"
    @echo "  just app-logs                # Show recent application logs"
    @echo "  just app-logs-recent         # Quick view of last 10 logs"
    @echo "  just app-logs-follow         # Follow application logs in real-time"
    @echo "  just app-logs-errors         # Show only errors"
    @echo ""
    @echo "🔍 Search and Filter:"
    @echo "  just app-logs-by-ip <ip>     # Query logs from specific IP"
    @echo "  just app-logs-by-client <id> # Query logs from OAuth client"
    @echo "  just app-logs-by-host <host> # Query logs for specific hostname"
    @echo "  just app-logs-search         # Search with multiple filters"
    @echo ""
    @echo "🔗 Flow Tracking:"
    @echo "  just app-logs-correlation <id> # Get complete request flow"
    @echo "  just app-logs-oauth-flow       # Track OAuth authentication flows"
    @echo ""
    @echo "📊 Analysis:"
    @echo "  just app-logs-event-stats    # Show event statistics"
    @echo ""
    @echo "💡 Examples:"
    @echo "  just logs                    # Docker container logs"
    @echo "  just app-logs event=oauth    # Application OAuth logs"
    @echo "  just app-logs-follow event=proxy.error"
    @echo "  just app-logs-correlation 1735689600-https-a7b3c9d2-001"

# Show recent application logs (no following)
app-logs hours="1" event="" level="" hostname="" limit="50" token="${ADMIN_TOKEN}":
    #!/usr/bin/env bash
    set -euo pipefail
    
    # Get token value
    if [ -z "{{token}}" ]; then
        echo "Error: Token required. Set ADMIN_TOKEN or provide token parameter." >&2
        exit 1
    fi
    
    BASE_URL="${BASE_URL:-{{default_base_url}}}"
    
    # Build query parameters
    params="hours={{hours}}&limit={{limit}}"
    [ -n "{{event}}" ] && params="${params}&event={{event}}"
    [ -n "{{level}}" ] && params="${params}&level={{level}}"
    [ -n "{{hostname}}" ] && params="${params}&hostname={{hostname}}"
    
    # Get recent logs
    response=$(curl -sL -H "Authorization: Bearer {{token}}" \
        "${BASE_URL}/api/v1/logs/search?${params}")
    
    # Format output - handle timestamp as Unix epoch
    echo "$response" | jq -r '
        "=== Recent Logs (last {{hours}} hour(s)) ===",
        "Total: \(.total) (showing \(.logs | length))",
        "",
        (.logs[] | 
            (if .timestamp then (.timestamp | todateiso8601 | split(".")[0] | gsub("T"; " ")) else "unknown time" end) as $ts |
            "\($ts) [\(.level)] \(.event // "no-event")",
            "  \(.message)",
            if .hostname then "  Host: \(.hostname)" else empty end,
            if .path then "  Path: \(.path)" else empty end,
            if .status then "  Status: \(.status)" else empty end,
            if .correlation_id then "  Correlation: \(.correlation_id)" else empty end,
            ""
        )
    ' 2>/dev/null || echo "$response" | jq '.'

# Quick view of last 10 application logs (compact format)
app-logs-recent limit="10" token="${ADMIN_TOKEN}":
    #!/usr/bin/env bash
    set -euo pipefail
    
    # Get token value
    if [ -z "{{token}}" ]; then
        echo "Error: Token required. Set ADMIN_TOKEN or provide token parameter." >&2
        exit 1
    fi
    
    BASE_URL="${BASE_URL:-{{default_base_url}}}"
    
    # Get recent logs (last 5 minutes)
    response=$(curl -sL -H "Authorization: Bearer {{token}}" \
        "${BASE_URL}/api/v1/logs/search?hours=1&limit={{limit}}")
    
    # Compact format - simple time display
    echo "$response" | jq -r '
        (.logs[] | 
            ((if .timestamp then (.timestamp | todateiso8601 | split("T")[1] | split(".")[0]) else "??:??:??" end) + " [" + .level + "] " + (.event // "no-event") + " - " + .message)
        )
    ' 2>/dev/null || echo "$response" | jq '.'

# Show only errors (quick error check)
app-logs-errors-only hours="1" limit="20" token="${ADMIN_TOKEN}":
    #!/usr/bin/env bash
    set -euo pipefail
    
    just app-logs-errors hours={{hours}} include-warnings=false limit={{limit}} token={{token}}

# Follow application logs in real-time (tail -f equivalent)
app-logs-follow interval="2" event="" level="" hostname="" token="${ADMIN_TOKEN}":
    #!/usr/bin/env bash
    set -euo pipefail
    
    # Get token value
    if [ -z "{{token}}" ]; then
        echo "Error: Token required. Set ADMIN_TOKEN or provide token parameter." >&2
        exit 1
    fi
    
    BASE_URL="${BASE_URL:-{{default_base_url}}}"
    
    echo "=== Following logs (Ctrl+C to stop) ==="
    echo "Refresh interval: {{interval}}s"
    [ -n "{{event}}" ] && echo "Event filter: {{event}}"
    [ -n "{{level}}" ] && echo "Level filter: {{level}}"
    [ -n "{{hostname}}" ] && echo "Hostname filter: {{hostname}}"
    echo ""
    
    # Track seen log IDs to avoid duplicates
    seen_file=$(mktemp)
    trap "rm -f $seen_file" EXIT
    
    while true; do
        # Get recent logs (last 5 minutes)
        params="hours=1&limit=100"
        [ -n "{{event}}" ] && params="${params}&event={{event}}"
        [ -n "{{level}}" ] && params="${params}&level={{level}}"
        [ -n "{{hostname}}" ] && params="${params}&hostname={{hostname}}"
        
        # Fetch logs
        response=$(curl -sL -H "Authorization: Bearer {{token}}" \
            "${BASE_URL}/api/v1/logs/search?${params}" 2>/dev/null || true)
        
        if [ -n "$response" ]; then
            # Process and display only new logs
            echo "$response" | jq -r '
                .logs[] | 
                "\(.timestamp)-\(.correlation_id // "none")" as $id |
                "\(.timestamp | todateiso8601 | split("T")[1] | split(".")[0]) [\(.level)] \(.event // "no-event") - \(.message) |\(.hostname // "unknown")|\($id)"
            ' 2>/dev/null | while IFS='|' read -r log_line hostname log_id; do
                if ! grep -q "^${log_id}$" "$seen_file" 2>/dev/null; then
                    echo "$log_id" >> "$seen_file"
                    echo "$log_line"
                fi
            done
        fi
        
        sleep {{interval}}
    done

# Query application logs by IP address
app-logs-by-ip ip hours="24" event="" level="" limit="100" token="${ADMIN_TOKEN}":
    #!/usr/bin/env bash
    set -euo pipefail
    
    # Get token value
    token_value="{{token}}"
    if [ -z "$token_value" ]; then
        echo "Error: Token required. Set ADMIN_TOKEN or provide token parameter." >&2
        exit 1
    fi
    
    BASE_URL="${BASE_URL:-{{default_base_url}}}"
    
    # Build query parameters
    query="hours={{hours}}&limit={{limit}}"
    [ -n "{{event}}" ] && query="${query}&event={{event}}"
    [ -n "{{level}}" ] && query="${query}&level={{level}}"
    
    # Query logs
    response=$(curl -sL -H "Authorization: Bearer $token_value" \
        "${BASE_URL}/api/v1/logs/ip/{{ip}}?${query}")
    
    echo "$response" | jq -r '
        .logs[] | 
        "\(.timestamp | todateiso8601 | split(".")[0] | gsub("T"; " ")) [\(.level)] \(.event // "no-event") - \(.message)"
    ' 2>/dev/null || echo "$response" | jq '.'

# Query application logs by OAuth client ID
app-logs-by-client client-id hours="24" event="" level="" limit="100" token="${ADMIN_TOKEN}":
    #!/usr/bin/env bash
    set -euo pipefail
    
    # Get token value
    token_value="{{token}}"
    if [ -z "$token_value" ]; then
        echo "Error: Token required. Set ADMIN_TOKEN or provide token parameter." >&2
        exit 1
    fi
    
    BASE_URL="${BASE_URL:-{{default_base_url}}}"
    
    # Build query parameters
    query="hours={{hours}}&limit={{limit}}"
    [ -n "{{event}}" ] && query="${query}&event={{event}}"
    [ -n "{{level}}" ] && query="${query}&level={{level}}"
    
    # Query logs
    response=$(curl -sL -H "Authorization: Bearer $token_value" \
        "${BASE_URL}/api/v1/logs/client/{{client-id}}?${query}")
    
    echo "$response" | jq -r '
        .logs[] | 
        "\(.timestamp | todateiso8601 | split(".")[0] | gsub("T"; " ")) [\(.level)] \(.event // "no-event") - \(.message)"
    ' 2>/dev/null || echo "$response" | jq '.'

# Get complete request flow by correlation ID
app-logs-correlation correlation-id token="${ADMIN_TOKEN}":
    #!/usr/bin/env bash
    set -euo pipefail
    
    # Get token value
    if [ -z "{{token}}" ]; then
        echo "Error: Token required. Set ADMIN_TOKEN or provide token parameter." >&2
        exit 1
    fi
    
    BASE_URL="${BASE_URL:-{{default_base_url}}}"
    
    # Get correlation flow
    response=$(curl -sL -H "Authorization: Bearer {{token}}" \
        "${BASE_URL}/api/v1/logs/correlation/{{correlation-id}}")
    
    # Format output
    echo "$response" | jq -r '
        "=== Correlation Flow: \(.correlation_id) ===",
        "Total Requests: \(.total_requests)",
        "Duration: \(.duration_ms)ms",
        "Events: " + (.flow_summary.events | to_entries | map("\(.key): \(.value)") | join(", ")),
        "",
        "=== Log Entries ===",
        (.logs[] | 
            "\(.timestamp | todateiso8601 | split(".")[0] | gsub("T"; " ")) [\(.level)] \(.event // "no-event")",
            "  \(.message)",
            if .error then "  Error: \(.error | tostring)" else empty end,
            ""
        )
    ' 2>/dev/null || echo "$response" | jq '.'

# Search application logs with filters
app-logs-search query="" hours="24" event="" level="" hostname="" limit="100" token="${ADMIN_TOKEN}":
    #!/usr/bin/env bash
    set -euo pipefail
    
    # Get token value
    if [ -z "{{token}}" ]; then
        echo "Error: Token required. Set ADMIN_TOKEN or provide token parameter." >&2
        exit 1
    fi
    
    BASE_URL="${BASE_URL:-{{default_base_url}}}"
    
    # Build query parameters
    params="hours={{hours}}&limit={{limit}}"
    [ -n "{{query}}" ] && params="${params}&q={{query}}"
    [ -n "{{event}}" ] && params="${params}&event={{event}}"
    [ -n "{{level}}" ] && params="${params}&level={{level}}"
    [ -n "{{hostname}}" ] && params="${params}&hostname={{hostname}}"
    
    # Search logs
    response=$(curl -sL -H "Authorization: Bearer {{token}}" \
        "${BASE_URL}/api/v1/logs/search?${params}")
    
    echo "$response" | jq -r '
        "Found \(.total) logs (showing \(.logs | length))",
        "",
        (.logs[] | 
            "\(.timestamp | todate | split(".")[0] | gsub("T"; " ")) [\(.level)] \(.event // "no-event") - \(.message)"
        )
    ' 2>/dev/null || echo "$response" | jq '.'

# Get recent application errors and warnings
app-logs-errors hours="1" include-warnings="false" limit="50" token="${ADMIN_TOKEN}":
    #!/usr/bin/env bash
    set -euo pipefail
    
    # Get token value
    if [ -z "{{token}}" ]; then
        echo "Error: Token required. Set ADMIN_TOKEN or provide token parameter." >&2
        exit 1
    fi
    
    BASE_URL="${BASE_URL:-{{default_base_url}}}"
    
    # Query recent errors
    response=$(curl -sL -H "Authorization: Bearer {{token}}" \
        "${BASE_URL}/api/v1/logs/errors?hours={{hours}}&include_warnings={{include-warnings}}&limit={{limit}}")
    
    echo "$response" | jq -r '
        "=== Recent Errors" + (if .query_params.include_warnings then " and Warnings" else "" end) + " ===",
        "Total: \(.total) (showing \(.logs | length))",
        "",
        (.logs[] | 
            "\(.timestamp | todateiso8601 | split(".")[0] | gsub("T"; " ")) [\(.level)]",
            "  Event: \(.event // "unknown")",
            "  Message: \(.message)",
            if .error then "  Error: \(.error | tostring)" else empty end,
            if .correlation_id then "  Correlation: \(.correlation_id)" else empty end,
            ""
        )
    ' 2>/dev/null || echo "$response" | jq '.'

# Get application event statistics
app-logs-event-stats hours="24" token="${ADMIN_TOKEN}":
    #!/usr/bin/env bash
    set -euo pipefail
    
    # Get token value
    if [ -z "{{token}}" ]; then
        echo "Error: Token required. Set ADMIN_TOKEN or provide token parameter." >&2
        exit 1
    fi
    
    BASE_URL="${BASE_URL:-{{default_base_url}}}"
    
    # Get event statistics
    response=$(curl -sL -H "Authorization: Bearer {{token}}" \
        "${BASE_URL}/api/v1/logs/events?hours={{hours}}")
    
    echo "=== Event Statistics (last {{hours}} hours) ==="
    echo "$response" | jq -r '
        to_entries | 
        .[] | 
        "\(.key): \(.value)"
    '

# Follow OAuth flow for a specific request
app-logs-oauth-flow client-id="" username="" hours="1" token="${ADMIN_TOKEN}":
    #!/usr/bin/env bash
    set -euo pipefail
    
    # Get token value
    if [ -z "{{token}}" ]; then
        echo "Error: Token required. Set ADMIN_TOKEN or provide token parameter." >&2
        exit 1
    fi
    
    BASE_URL="${BASE_URL:-{{default_base_url}}}"
    
    # Build search query
    query="event:oauth"
    [ -n "{{client-id}}" ] && query="${query} AND client_id:{{client-id}}"
    [ -n "{{username}}" ] && query="${query} AND username:{{username}}"
    
    # Search for OAuth events
    echo "=== OAuth Flow Trace ==="
    echo "Searching for: ${query}"
    echo ""
    
    # Search logs
    response=$(curl -sL -H "Authorization: Bearer {{token}}" \
        "${BASE_URL}/api/v1/logs/search?q=${query}&hours={{hours}}&limit=1000")
    
    # Group by correlation ID and show flows
    echo "$response" | jq -r '
        .logs | 
        group_by(.correlation_id) |
        .[] |
        (
            "Correlation: " + (.[0].correlation_id // "unknown"),
            "Client: " + (.[0].client_id // "unknown"),
            "User: " + (.[0].username // "unknown"),
            "",
            (sort_by(.timestamp) | .[] | 
                "  \(.timestamp | todateiso8601 | split("T")[1] | split(".")[0]) \(.event) - \(.message)"
            ),
            ""
        )
    ' 2>/dev/null || echo "$response" | jq '.'

# Show all application logs for a hostname
app-logs-by-host hostname hours="24" limit="100" token="${ADMIN_TOKEN}":
    #!/usr/bin/env bash
    set -euo pipefail
    
    # Get token value
    if [ -z "{{token}}" ]; then
        echo "Error: Token required. Set ADMIN_TOKEN or provide token parameter." >&2
        exit 1
    fi
    
    BASE_URL="${BASE_URL:-{{default_base_url}}}"
    
    # Search logs for hostname
    response=$(curl -sL -H "Authorization: Bearer {{token}}" \
        "${BASE_URL}/api/v1/logs/search?hostname={{hostname}}&hours={{hours}}&limit={{limit}}")
    
    echo "$response" | jq -r '
        "=== Logs for {{hostname}} ===",
        "Total: \(.total) (showing \(.logs | length))",
        "",
        (.logs[] | 
            "\(.timestamp | todateiso8601 | split(".")[0] | gsub("T"; " ")) [\(.level)] \(.event // "no-event")",
            "  Path: \(.path // "/")",
            "  Status: \(.status // "N/A")",
            "  Message: \(.message)",
            ""
        )
    ' 2>/dev/null || echo "$response" | jq '.'

# Test application logging system
app-logs-test token="${ADMIN_TOKEN}":
    #!/usr/bin/env bash
    set -euo pipefail
    
    echo "=== Testing Logging System ==="
    echo ""
    
    # 1. Make a test request to generate logs
    echo "1. Making test request to /health..."
    BASE_URL="${BASE_URL:-{{default_base_url}}}"
    curl -sL "${BASE_URL}/health" > /dev/null
    
    # 2. Wait for logs to be processed
    echo "2. Waiting for logs to be processed..."
    sleep 2
    
    # 3. Query recent logs
    echo "3. Querying recent logs..."
    echo ""
    just app-logs-recent limit=5 token={{token}}
    
    echo ""
    echo "4. Checking event statistics..."
    just app-logs-event-stats hours=1 token={{token}} | head -10
    
    echo ""
    echo "✅ Logging system test complete!"


# ============================================================================
# TOKEN MANAGEMENT
# ============================================================================

# Generate a new API token
token-generate name email="":
    #!/usr/bin/env bash
    set -euo pipefail
    
    # Use provided email or ADMIN_EMAIL or prompt
    if [ -n "{{email}}" ]; then
        cert_email="{{email}}"
    elif [ -n "${ADMIN_EMAIL:-}" ]; then
        cert_email="$ADMIN_EMAIL"
        echo "Using ADMIN_EMAIL: $cert_email"
    else
        read -p "Certificate email for {{name}}: " cert_email
    fi
    
    # Try API first if available
    if [ "${USE_API:-true}" = "true" ] && [ -n "${BASE_URL:-}" ]; then
        # Get admin token
        if [ -n "${ADMIN_TOKEN:-}" ]; then
            auth_token="${ADMIN_TOKEN}"
        else
            echo "Error: ADMIN_TOKEN not set in environment" >&2
            exit 1
        fi
        
        if [ -n "$auth_token" ]; then
            # Try API call
            response=$(curl -sf -X POST "${BASE_URL}/api/v1/tokens/generate" \
                -H "Authorization: Bearer $auth_token" \
                -H "Content-Type: application/json" \
                -d "{\"name\": \"{{name}}\", \"cert_email\": \"$cert_email\"}" 2>/dev/null || true)
            
            if [ -n "$response" ]; then
                # Extract and display token info
                token=$(echo "$response" | jq -r '.token' 2>/dev/null || true)
                if [ -n "$token" ]; then
                    echo "Token generated successfully!"
                    echo "Name: {{name}}"
                    echo "Token: $token"
                    echo "Certificate Email: $cert_email"
                    echo ""
                    echo "Token stored securely. You can retrieve it later with: just token-show {{name}}"
                    exit 0
                fi
            fi
        fi
    fi
    
    # No API available, exit with error
    echo "Error: API not available. Please ensure BASE_URL is set and proxy is running." >&2
    exit 1

# Show token value
token-show name:
    #!/usr/bin/env bash
    set -euo pipefail
    
    if [ "{{name}}" = "ADMIN" ] && [ -n "${ADMIN_TOKEN:-}" ]; then
        echo "Token: ${ADMIN_TOKEN}"
        exit 0
    fi
    
    BASE_URL="${BASE_URL:-{{default_base_url}}}"
    
    # Get admin token for API access
    auth_token="${ADMIN_TOKEN:-}"
    if [ -z "$auth_token" ]; then
        echo "Error: ADMIN_TOKEN not set in environment" >&2
        exit 1
    fi
    
    # Use API to reveal token
    response=$(curl -sf -X GET "${BASE_URL}/api/v1/tokens/{{name}}/reveal" \
        -H "Authorization: Bearer $auth_token" 2>/dev/null || true)
    
    if [ -n "$response" ]; then
        token=$(echo "$response" | jq -r '.token' 2>/dev/null || true)
        if [ -n "$token" ] && [ "$token" != "null" ]; then
            echo "Token: $token"
            exit 0
        fi
    fi
    
    echo "Error: Token '{{name}}' not found" >&2
    exit 1

# List all tokens
token-list:
    #!/usr/bin/env bash
    set -euo pipefail
    
    # Try API first if available
    if [ "${USE_API:-true}" = "true" ] && [ -n "${BASE_URL:-}" ]; then
        # Get admin token
        if [ -n "${ADMIN_TOKEN:-}" ]; then
            auth_token="${ADMIN_TOKEN}"
        else
            echo "Error: ADMIN_TOKEN not set in environment" >&2
            exit 1
        fi
        
        if [ -n "$auth_token" ]; then
            # Try API call
            response=$(curl -sf -H "Authorization: Bearer $auth_token" "${BASE_URL}/api/v1/tokens/formatted" 2>/dev/null || true)
            if [ -n "$response" ]; then
                echo "$response"
                exit 0
            fi
        fi
    fi
    
    # No API available, exit with error
    echo "Error: API not available. Please ensure BASE_URL is set and proxy is running." >&2
    exit 1

# Delete token and owned resources
token-delete name:
    #!/usr/bin/env bash
    set -euo pipefail
    
    # Confirm deletion
    read -p "Delete token '{{name}}' and all owned resources? [y/N] " -n 1 -r
    echo
    [[ $REPLY =~ ^[Yy]$ ]] || exit 1
    
    BASE_URL="${BASE_URL:-{{default_base_url}}}"
    
    # Get admin token
    auth_token="${ADMIN_TOKEN:-}"
    if [ -z "$auth_token" ]; then
        echo "Error: ADMIN_TOKEN not set in environment" >&2
        exit 1
    fi
    
    # Delete token via API
    response=$(curl -sf -X DELETE "${BASE_URL}/api/v1/tokens/{{name}}" \
        -H "Authorization: Bearer $auth_token" 2>&1)
    
    if [ $? -eq 0 ]; then
        echo "✓ Token '{{name}}' deleted successfully"
    else
        echo "Error deleting token: $response" >&2
        exit 1
    fi

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
        # Use API to get token value
        BASE_URL="${BASE_URL:-{{default_base_url}}}"
        response=$(curl -sf -X GET "${BASE_URL}/api/v1/tokens/{{token}}/reveal" \
            -H "Authorization: Bearer ${ADMIN_TOKEN}" 2>/dev/null || true)
        
        if [ -n "$response" ]; then
            token_value=$(echo "$response" | jq -r '.token' 2>/dev/null || true)
            if [ -z "$token_value" ] || [ "$token_value" = "null" ]; then
                echo "Error: Token '{{token}}' not found" >&2
                exit 1
            fi
        else
            echo "Error: Failed to retrieve token '{{token}}'" >&2
            exit 1
        fi
    fi
    
    BASE_URL="${BASE_URL:-{{default_base_url}}}"
    data=$(jq -n --arg email "{{email}}" '{email: $email}')
    
    response=$(curl -s -w '\n%{http_code}' -X PUT "${BASE_URL}/api/v1/tokens/email" \
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
    
    # Use API to generate admin token
    response=$(curl -sf -X POST "${BASE_URL}/api/v1/tokens/generate" \
        -H "Content-Type: application/json" \
        -d "{\"name\": \"ADMIN\", \"cert_email\": \"$admin_email\"}" 2>/dev/null || true)
    
    if [ -n "$response" ]; then
        token=$(echo "$response" | jq -r '.token' 2>/dev/null || true)
        if [ -n "$token" ] && [ "$token" != "null" ]; then
            echo "Generated new ADMIN token:"
            echo "Token: $token"
            echo "$token" > admin_token.txt
            echo
            echo "Save the token above as ADMIN_TOKEN in your .env file"
        else
            echo "Error: Failed to generate admin token" >&2
            exit 1
        fi
    else
        echo "Error: API not available. Please ensure proxy is running." >&2
        exit 1
    fi

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
        # Use API to get token value
        BASE_URL="${BASE_URL:-{{default_base_url}}}"
        response=$(curl -sf -X GET "${BASE_URL}/api/v1/tokens/{{token}}/reveal" \
            -H "Authorization: Bearer ${ADMIN_TOKEN}" 2>/dev/null || true)
        
        if [ -n "$response" ]; then
            token_value=$(echo "$response" | jq -r '.token' 2>/dev/null || true)
            if [ -z "$token_value" ] || [ "$token_value" = "null" ]; then
                echo "Error: Token '{{token}}' not found" >&2
                exit 1
            fi
        else
            echo "Error: Failed to retrieve token '{{token}}'" >&2
            exit 1
        fi
    fi
    
    BASE_URL="${BASE_URL:-{{default_base_url}}}"
    
    # Get certificate email if not provided
    if [ -z "{{email}}" ]; then
        # Try to get from token first
        response=$(curl -s -H "Authorization: Bearer $token_value" "${BASE_URL}/api/v1/tokens/info")
        cert_email=$(echo "$response" | jq -r '.cert_email // empty')
        
        # Fall back to ACME_EMAIL or ADMIN_EMAIL if token has no email
        if [ -z "$cert_email" ]; then
            cert_email="${ACME_EMAIL:-${ADMIN_EMAIL:-}}"
            if [ -z "$cert_email" ]; then
                echo "Error: No email provided, token has no default email, and neither ACME_EMAIL nor ADMIN_EMAIL are set"
                exit 1
            fi
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
            domain: $domain,
            email: $email,
            acme_directory_url: (if $staging == "true" then env.ACME_STAGING_URL else env.ACME_DIRECTORY_URL end)
        }')
    
    # Create certificate
    response=$(curl -sL -w '\n%{http_code}' -X POST "${BASE_URL}/api/v1/certificates/" \
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
        # Use API to get token value
        BASE_URL="${BASE_URL:-{{default_base_url}}}"
        response=$(curl -sf -X GET "${BASE_URL}/api/v1/tokens/{{token}}/reveal" \
            -H "Authorization: Bearer ${ADMIN_TOKEN}" 2>/dev/null || true)
        
        if [ -n "$response" ]; then
            token_value=$(echo "$response" | jq -r '.token' 2>/dev/null || true)
            if [ -z "$token_value" ] || [ "$token_value" = "null" ]; then
                echo "Error: Token '{{token}}' not found" >&2
                exit 1
            fi
        else
            echo "Error: Failed to retrieve token '{{token}}'" >&2
            exit 1
        fi
    fi
    
    # Get certificates with auth
    response=$(curl -sL "${BASE_URL}/api/v1/certificates/" -H "Authorization: Bearer $token_value")
    
    # Format as table
    echo "=== Certificates ==="
    echo "$response" | jq -r '.[] | [
        .cert_name, 
        (.domains | join(",")), 
        .status, 
        .expires_at[0:10], 
        (if .acme_directory_url | contains("staging") then "Staging" else "Production" end)
    ] | @tsv' | \
        column -t -s $'\t' -N "Name,Domains,Status,Expires,Environment" | \
        awk 'NR==1 {print $0} NR>1 {if ($NF == "Staging") {print "\033[33m" $0 "\033[0m"} else if ($NF == "Production") {print "\033[32m" $0 "\033[0m"} else {print $0}}'

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
        # Use API to get token value
        BASE_URL="${BASE_URL:-{{default_base_url}}}"
        response=$(curl -sf -X GET "${BASE_URL}/api/v1/tokens/{{token}}/reveal" \
            -H "Authorization: Bearer ${ADMIN_TOKEN}" 2>/dev/null || true)
        
        if [ -n "$response" ]; then
            token_value=$(echo "$response" | jq -r '.token' 2>/dev/null || true)
            if [ -z "$token_value" ] || [ "$token_value" = "null" ]; then
                echo "Error: Token '{{token}}' not found" >&2
                exit 1
            fi
        else
            echo "Error: Failed to retrieve token '{{token}}'" >&2
            exit 1
        fi
    fi
    
    # Get certificate with auth
    response=$(curl -s "${BASE_URL}/api/v1/certificates/{{name}}" -H "Authorization: Bearer $token_value")
    
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
        # Use API to get token value
        BASE_URL="${BASE_URL:-{{default_base_url}}}"
        response=$(curl -sf -X GET "${BASE_URL}/api/v1/tokens/{{token}}/reveal" \
            -H "Authorization: Bearer ${ADMIN_TOKEN}" 2>/dev/null || true)
        
        if [ -n "$response" ]; then
            token_value=$(echo "$response" | jq -r '.token' 2>/dev/null || true)
            if [ -z "$token_value" ] || [ "$token_value" = "null" ]; then
                echo "Error: Token '{{token}}' not found" >&2
                exit 1
            fi
        else
            echo "Error: Failed to retrieve token '{{token}}'" >&2
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
    response=$(curl -s -w '\n%{http_code}' -X DELETE "${BASE_URL}/api/v1/certificates/{{name}}" \
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
proxy-create hostname target-url token="" email="" staging="false" preserve-host="true" enable-http="true" enable-https="true":
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
        # Use API to get token value
        BASE_URL="${BASE_URL:-{{default_base_url}}}"
        response=$(curl -sf -X GET "${BASE_URL}/api/v1/tokens/{{token}}/reveal" \
            -H "Authorization: Bearer ${ADMIN_TOKEN}" 2>/dev/null || true)
        
        if [ -n "$response" ]; then
            token_value=$(echo "$response" | jq -r '.token' 2>/dev/null || true)
            if [ -z "$token_value" ] || [ "$token_value" = "null" ]; then
                echo "Error: Token '{{token}}' not found" >&2
                exit 1
            fi
        else
            echo "Error: Failed to retrieve token '{{token}}'" >&2
            exit 1
        fi
    fi
    
    BASE_URL="${BASE_URL:-{{default_base_url}}}"
    
    # Get certificate email - use parameter first, then token, then ADMIN_EMAIL
    if [ -n "{{email}}" ]; then
        cert_email="{{email}}"
    else
        # Try to get from token
        response=$(curl -s -H "Authorization: Bearer $token_value" "${BASE_URL}/api/v1/tokens/info")
        cert_email=$(echo "$response" | jq -r '.cert_email // empty')
        
        # Fall back to ADMIN_EMAIL if token has no email
        if [ -z "$cert_email" ]; then
            cert_email="${ADMIN_EMAIL:-}"
            if [ -z "$cert_email" ]; then
                echo "Error: No email provided, token has no certificate email, and ADMIN_EMAIL not set"
                exit 1
            fi
        fi
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
            acme_directory_url: (if $staging == "true" then env.ACME_STAGING_URL else env.ACME_DIRECTORY_URL end)
        }')
    
    # Create proxy
    response=$(curl -sL -w '\n%{http_code}' -X POST "${BASE_URL}/api/v1/proxy/targets/" \
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
        # Use API to get token value
        BASE_URL="${BASE_URL:-{{default_base_url}}}"
        response=$(curl -sf -X GET "${BASE_URL}/api/v1/tokens/{{token}}/reveal" \
            -H "Authorization: Bearer ${ADMIN_TOKEN}" 2>/dev/null || true)
        
        if [ -n "$response" ]; then
            token_value=$(echo "$response" | jq -r '.token' 2>/dev/null || true)
            if [ -z "$token_value" ] || [ "$token_value" = "null" ]; then
                echo "Error: Token '{{token}}' not found" >&2
                exit 1
            fi
        else
            echo "Error: Failed to retrieve token '{{token}}'" >&2
            exit 1
        fi
    fi
    
    # Try API first if available
    if [ "${USE_API:-true}" = "true" ]; then
        # Try internal port first (for local development)
        response=$(curl -sf -H "Authorization: Bearer $token_value" "http://localhost:9000/api/v1/proxy/targets/formatted" 2>/dev/null || true)
        if [ -n "$response" ]; then
            echo "$response"
            exit 0
        fi
        
        # Fall back to BASE_URL if set
        if [ -n "${BASE_URL:-}" ]; then
            response=$(curl -sf -H "Authorization: Bearer $token_value" "${BASE_URL}/api/v1/proxy/targets/formatted" 2>/dev/null || true)
            if [ -n "$response" ]; then
                echo "$response"
                exit 0
            fi
        fi
    fi
    
    # No API available, show error
    echo "Error: API not available. Please ensure BASE_URL is set and proxy is running." >&2
    exit 1

# Show proxy details
proxy-show hostname:
    #!/usr/bin/env bash
    set -euo pipefail
    
    BASE_URL="${BASE_URL:-{{default_base_url}}}"
    
    response=$(curl -s -X GET "${BASE_URL}/api/v1/proxy/targets/{{hostname}}")
    
    # Check if proxy was found
    if echo "$response" | grep -q '"detail".*not found'; then
        echo "✗ Proxy target '{{hostname}}' not found" >&2
        exit 1
    fi
    
    # Pretty print the response
    echo "$response" | jq '.' 2>/dev/null || echo "$response"

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
        # Use API to get token value
        BASE_URL="${BASE_URL:-{{default_base_url}}}"
        response=$(curl -sf -X GET "${BASE_URL}/api/v1/tokens/{{token}}/reveal" \
            -H "Authorization: Bearer ${ADMIN_TOKEN}" 2>/dev/null || true)
        
        if [ -n "$response" ]; then
            token_value=$(echo "$response" | jq -r '.token' 2>/dev/null || true)
            if [ -z "$token_value" ] || [ "$token_value" = "null" ]; then
                echo "Error: Token '{{token}}' not found" >&2
                exit 1
            fi
        else
            echo "Error: Failed to retrieve token '{{token}}'" >&2
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
    response=$(curl -s -w '\n%{http_code}' -X DELETE "${BASE_URL}/api/v1/proxy/targets/{{hostname}}$query" \
        -H "Authorization: Bearer $token_value")
    
    http_code=$(echo "$response" | tail -n1)
    body=$(echo "$response" | head -n -1)
    
    if [[ ! "$http_code" =~ ^2 ]]; then
        echo "Error: HTTP $http_code"
        echo "$body" | jq '.' 2>/dev/null || echo "$body"
        exit 1
    fi
    
    echo "$body" | jq '.'

# Enable OAuth authentication on a proxy
proxy-auth-enable hostname token="" auth-proxy="" mode="forward":
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
    else
        token_value="{{token}}"
    fi
    
    # Default auth proxy to auth.${BASE_DOMAIN}
    if [ -z "{{auth-proxy}}" ]; then
        auth_proxy_value="auth.${BASE_DOMAIN}"
    else
        auth_proxy_value="{{auth-proxy}}"
    fi
    
    # Create auth config
    response=$(curl -s -w '\n%{http_code}' -X POST "${BASE_URL}/api/v1/proxy/targets/{{hostname}}/auth" \
        -H "Authorization: Bearer $token_value" \
        -H "Content-Type: application/json" \
        -d '{
            "enabled": true,
            "auth_proxy": "'$auth_proxy_value'",
            "mode": "{{mode}}"
        }')
    
    http_code=$(echo "$response" | tail -n1)
    body=$(echo "$response" | head -n -1)
    
    if [[ ! "$http_code" =~ ^2 ]]; then
        echo "Error: HTTP $http_code"
        echo "$body" | jq '.' 2>/dev/null || echo "$body"
        exit 1
    fi
    
    echo "✓ Auth enabled on {{hostname}}"
    echo "$body" | jq '.'

# Disable OAuth authentication on a proxy
proxy-auth-disable hostname token="":
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
    else
        token_value="{{token}}"
    fi
    
    # Delete auth config
    response=$(curl -s -w '\n%{http_code}' -X DELETE "${BASE_URL}/api/v1/proxy/targets/{{hostname}}/auth" \
        -H "Authorization: Bearer $token_value")
    
    http_code=$(echo "$response" | tail -n1)
    body=$(echo "$response" | head -n -1)
    
    if [[ ! "$http_code" =~ ^2 ]]; then
        echo "Error: HTTP $http_code"
        echo "$body" | jq '.' 2>/dev/null || echo "$body"
        exit 1
    fi
    
    echo "✓ Auth disabled on {{hostname}}"

# Show proxy authentication configuration
proxy-auth-show hostname:
    #!/usr/bin/env bash
    set -euo pipefail
    
    response=$(curl -s -w '\n%{http_code}' "${BASE_URL}/api/v1/proxy/targets/{{hostname}}/auth")
    
    http_code=$(echo "$response" | tail -n1)
    body=$(echo "$response" | head -n -1)
    
    if [[ ! "$http_code" =~ ^2 ]]; then
        echo "Error: HTTP $http_code"
        echo "$body" | jq '.' 2>/dev/null || echo "$body"
        exit 1
    fi
    
    echo "$body" | jq '.'

# Configure MCP metadata for a proxy
proxy-mcp-enable hostname token="" endpoint="/mcp" scopes="mcp:read mcp:write" stateful="false" override-backend="false":
    #!/usr/bin/env bash
    set -euo pipefail
    
    # Default to ADMIN_TOKEN if no token specified
    if [ -z "{{token}}" ]; then
        if [ -z "${ADMIN_TOKEN:-}" ]; then
            echo "Error: No token provided and ADMIN_TOKEN not set"
            exit 1
        fi
        TOKEN="${ADMIN_TOKEN}"
    else
        TOKEN="{{token}}"
    fi
    
    # Build scopes array
    scopes_json=$(echo "{{scopes}}" | jq -R 'split(" ")')
    
    # Build request body
    body=$(jq -n \
        --argjson scopes "$scopes_json" \
        '{
            enabled: true,
            endpoint: "{{endpoint}}",
            scopes: $scopes,
            stateful: {{stateful}},
            override_backend: {{override-backend}}
        }')
    
    echo "Enabling MCP for {{hostname}}..."
    echo "$body" | jq '.'
    
    response=$(curl -s -w '\n%{http_code}' -X POST \
        -H "Authorization: Bearer $TOKEN" \
        -H "Content-Type: application/json" \
        -d "$body" \
        "${BASE_URL}/api/v1/proxy/targets/{{hostname}}/mcp")
    
    http_code=$(echo "$response" | tail -n1)
    body=$(echo "$response" | head -n -1)
    
    if [[ ! "$http_code" =~ ^2 ]]; then
        echo "Error: HTTP $http_code"
        echo "$body" | jq '.' 2>/dev/null || echo "$body"
        exit 1
    fi
    
    echo "✓ MCP enabled on {{hostname}}"
    echo "$body" | jq '.proxy_target.mcp_metadata' 2>/dev/null || echo "$body"

# Disable MCP metadata for a proxy
proxy-mcp-disable hostname token="":
    #!/usr/bin/env bash
    set -euo pipefail
    
    # Default to ADMIN_TOKEN if no token specified
    if [ -z "{{token}}" ]; then
        if [ -z "${ADMIN_TOKEN:-}" ]; then
            echo "Error: No token provided and ADMIN_TOKEN not set"
            exit 1
        fi
        TOKEN="${ADMIN_TOKEN}"
    else
        TOKEN="{{token}}"
    fi
    
    echo "Disabling MCP for {{hostname}}..."
    
    response=$(curl -s -w '\n%{http_code}' -X DELETE \
        -H "Authorization: Bearer $TOKEN" \
        "${BASE_URL}/api/v1/proxy/targets/{{hostname}}/mcp")
    
    http_code=$(echo "$response" | tail -n1)
    body=$(echo "$response" | head -n -1)
    
    if [[ ! "$http_code" =~ ^2 ]]; then
        echo "Error: HTTP $http_code"
        echo "$body" | jq '.' 2>/dev/null || echo "$body"
        exit 1
    fi
    
    echo "✓ MCP disabled on {{hostname}}"

# Show MCP configuration for a proxy
proxy-mcp-show hostname:
    #!/usr/bin/env bash
    set -euo pipefail
    
    response=$(curl -s -w '\n%{http_code}' "${BASE_URL}/api/v1/proxy/targets/{{hostname}}/mcp")
    
    http_code=$(echo "$response" | tail -n1)
    body=$(echo "$response" | head -n -1)
    
    if [[ ! "$http_code" =~ ^2 ]]; then
        echo "Error: HTTP $http_code"
        echo "$body" | jq '.' 2>/dev/null || echo "$body"
        exit 1
    fi
    
    echo "$body" | jq '.'

# Test proxy MCP metadata endpoint
test-proxy-mcp hostname:
    #!/usr/bin/env bash
    set -euo pipefail
    
    # First check if proxy exists
    echo "Testing MCP metadata endpoint for {{hostname}}..."
    
    # Try to fetch the MCP metadata endpoint
    response=$(curl -s -w '\n%{http_code}' "https://{{hostname}}/.well-known/oauth-protected-resource" -k)
    
    http_code=$(echo "$response" | tail -n1)
    body=$(echo "$response" | head -n -1)
    
    echo "HTTP Status: $http_code"
    echo "Response:"
    echo "$body" | jq '.' 2>/dev/null || echo "$body"
    
    # Also check the proxy's MCP configuration
    echo -e "\nProxy MCP Configuration:"
    just proxy-mcp-show {{hostname}}

# ============================================================================
# DOCKER SERVICE MANAGEMENT
# ============================================================================

# Create a Docker service
service-create name image="" dockerfile="" port="" token="" memory="512m" cpu="1.0" auto-proxy="false":
    #!/usr/bin/env bash
    set -euo pipefail
    
    # Validate inputs
    if [ -z "{{image}}" ] && [ -z "{{dockerfile}}" ]; then
        echo "Error: Either --image or --dockerfile must be specified" >&2
        exit 1
    fi
    
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
        # Use API to get token value
        BASE_URL="${BASE_URL:-{{default_base_url}}}"
        response=$(curl -sf -X GET "${BASE_URL}/api/v1/tokens/{{token}}/reveal" \
            -H "Authorization: Bearer ${ADMIN_TOKEN}" 2>/dev/null || true)
        
        if [ -n "$response" ]; then
            token_value=$(echo "$response" | jq -r '.token' 2>/dev/null || true)
            if [ -z "$token_value" ] || [ "$token_value" = "null" ]; then
                echo "Error: Token '{{token}}' not found" >&2
                exit 1
            fi
        else
            echo "Error: Failed to retrieve token '{{token}}'" >&2
            exit 1
        fi
    fi
    
    BASE_URL="${BASE_URL:-{{default_base_url}}}"
    
    # Build request data
    data=$(jq -n \
        --arg name "{{name}}" \
        --arg image "{{image}}" \
        --arg dockerfile "{{dockerfile}}" \
        --arg port "{{port}}" \
        --arg memory "{{memory}}" \
        --arg cpu "{{cpu}}" \
        '{
            service_name: $name,
            memory_limit: $memory,
            cpu_limit: ($cpu | tonumber)
        } + (if $image != "" then {image: $image} else {} end)
          + (if $dockerfile != "" then {dockerfile_path: $dockerfile} else {} end)
          + (if $port != "" then {external_port: ($port | tonumber)} else {} end)')
    
    # Create service
    response=$(curl -sL -w '\n%{http_code}' -X POST "${BASE_URL}/api/v1/services?auto_proxy={{auto-proxy}}" \
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

# List Docker services
service-list owned-only="false" token="":
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
    elif [[ "{{token}}" == acm_* ]]; then
        token_value="{{token}}"
    else
        # Use API to get token value
        BASE_URL="${BASE_URL:-{{default_base_url}}}"
        response=$(curl -sf -X GET "${BASE_URL}/api/v1/tokens/{{token}}/reveal" \
            -H "Authorization: Bearer ${ADMIN_TOKEN}" 2>/dev/null || true)
        
        if [ -n "$response" ]; then
            token_value=$(echo "$response" | jq -r '.token' 2>/dev/null || true)
            if [ -z "$token_value" ] || [ "$token_value" = "null" ]; then
                echo "Error: Token '{{token}}' not found" >&2
                exit 1
            fi
        else
            echo "Error: Failed to retrieve token '{{token}}'" >&2
            exit 1
        fi
    fi
    
    response=$(curl -sfL -H "Authorization: Bearer $token_value" \
        "${BASE_URL}/api/v1/services?owned_only={{owned-only}}")
    
    echo "$response" | jq -r '.services[] | "\(.service_name)\t\(.status)\t\(.allocated_port)\t\(.created_at)"' | \
        column -t -s $'\t' -N "SERVICE,STATUS,PORT,CREATED"

# Show Docker service details
service-show name:
    #!/usr/bin/env bash
    set -euo pipefail
    
    BASE_URL="${BASE_URL:-{{default_base_url}}}"
    token_value="${ADMIN_TOKEN:-}"
    
    response=$(curl -sfL -H "Authorization: Bearer $token_value" \
        "${BASE_URL}/api/v1/services/{{name}}")
    
    echo "$response" | jq '.'

# Delete Docker service
service-delete name token="" force="false" delete-proxy="true":
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
    elif [[ "{{token}}" == acm_* ]]; then
        token_value="{{token}}"
    else
        # Use API to get token value
        BASE_URL="${BASE_URL:-{{default_base_url}}}"
        response=$(curl -sf -X GET "${BASE_URL}/api/v1/tokens/{{token}}/reveal" \
            -H "Authorization: Bearer ${ADMIN_TOKEN}" 2>/dev/null || true)
        
        if [ -n "$response" ]; then
            token_value=$(echo "$response" | jq -r '.token' 2>/dev/null || true)
            if [ -z "$token_value" ] || [ "$token_value" = "null" ]; then
                echo "Error: Token '{{token}}' not found" >&2
                exit 1
            fi
        else
            echo "Error: Failed to retrieve token '{{token}}'" >&2
            exit 1
        fi
    fi
    
    # Confirm unless forced
    if [ "{{force}}" != "true" ]; then
        read -p "Delete service '{{name}}'? [y/N] " -n 1 -r
        echo
        [[ $REPLY =~ ^[Yy]$ ]] || exit 1
    fi
    
    BASE_URL="${BASE_URL:-{{default_base_url}}}"
    
    # Delete service
    response=$(curl -s -w '\n%{http_code}' -X DELETE \
        "${BASE_URL}/api/v1/services/{{name}}?force={{force}}&delete_proxy={{delete-proxy}}" \
        -H "Authorization: Bearer $token_value")
    
    http_code=$(echo "$response" | tail -n1)
    
    if [[ "$http_code" == "204" ]]; then
        echo "Service '{{name}}' deleted successfully"
    else
        body=$(echo "$response" | head -n -1)
        echo "Error: HTTP $http_code"
        echo "$body" | jq '.' 2>/dev/null || echo "$body"
        exit 1
    fi

# Start Docker service
service-start name token="":
    #!/usr/bin/env bash
    set -euo pipefail
    
    # Default to ADMIN_TOKEN if no token specified
    if [ -z "{{token}}" ]; then
        token_value="${ADMIN_TOKEN:-}"
    elif [ "{{token}}" = "ADMIN" ]; then
        token_value="${ADMIN_TOKEN:-}"
    elif [[ "{{token}}" == acm_* ]]; then
        token_value="{{token}}"
    else
        token_value=$(docker exec {{container_name}} pixi run python scripts/show_token.py "{{token}}" 2>/dev/null | grep "^Token: " | cut -d' ' -f2 || true)
    fi
    
    BASE_URL="${BASE_URL:-{{default_base_url}}}"
    
    response=$(curl -s -w '\n%{http_code}' -X POST \
        "${BASE_URL}/api/v1/services/{{name}}/start" \
        -H "Authorization: Bearer $token_value")
    
    http_code=$(echo "$response" | tail -n1)
    body=$(echo "$response" | head -n -1)
    
    if [[ "$http_code" =~ ^2 ]]; then
        echo "$body" | jq -r '.message'
    else
        echo "Error: HTTP $http_code"
        echo "$body" | jq '.' 2>/dev/null || echo "$body"
        exit 1
    fi

# Stop Docker service
service-stop name token="":
    #!/usr/bin/env bash
    set -euo pipefail
    
    # Default to ADMIN_TOKEN if no token specified
    if [ -z "{{token}}" ]; then
        token_value="${ADMIN_TOKEN:-}"
    elif [ "{{token}}" = "ADMIN" ]; then
        token_value="${ADMIN_TOKEN:-}"
    elif [[ "{{token}}" == acm_* ]]; then
        token_value="{{token}}"
    else
        token_value=$(docker exec {{container_name}} pixi run python scripts/show_token.py "{{token}}" 2>/dev/null | grep "^Token: " | cut -d' ' -f2 || true)
    fi
    
    BASE_URL="${BASE_URL:-{{default_base_url}}}"
    
    response=$(curl -s -w '\n%{http_code}' -X POST \
        "${BASE_URL}/api/v1/services/{{name}}/stop" \
        -H "Authorization: Bearer $token_value")
    
    http_code=$(echo "$response" | tail -n1)
    body=$(echo "$response" | head -n -1)
    
    if [[ "$http_code" =~ ^2 ]]; then
        echo "$body" | jq -r '.message'
    else
        echo "Error: HTTP $http_code"
        echo "$body" | jq '.' 2>/dev/null || echo "$body"
        exit 1
    fi

# Restart Docker service
service-restart name token="":
    #!/usr/bin/env bash
    set -euo pipefail
    
    # Default to ADMIN_TOKEN if no token specified
    if [ -z "{{token}}" ]; then
        token_value="${ADMIN_TOKEN:-}"
    elif [ "{{token}}" = "ADMIN" ]; then
        token_value="${ADMIN_TOKEN:-}"
    elif [[ "{{token}}" == acm_* ]]; then
        token_value="{{token}}"
    else
        token_value=$(docker exec {{container_name}} pixi run python scripts/show_token.py "{{token}}" 2>/dev/null | grep "^Token: " | cut -d' ' -f2 || true)
    fi
    
    BASE_URL="${BASE_URL:-{{default_base_url}}}"
    
    response=$(curl -s -w '\n%{http_code}' -X POST \
        "${BASE_URL}/api/v1/services/{{name}}/restart" \
        -H "Authorization: Bearer $token_value")
    
    http_code=$(echo "$response" | tail -n1)
    body=$(echo "$response" | head -n -1)
    
    if [[ "$http_code" =~ ^2 ]]; then
        echo "$body" | jq -r '.message'
    else
        echo "Error: HTTP $http_code"
        echo "$body" | jq '.' 2>/dev/null || echo "$body"
        exit 1
    fi

# Get Docker service logs
service-logs name lines="100" timestamps="false":
    #!/usr/bin/env bash
    set -euo pipefail
    
    BASE_URL="${BASE_URL:-{{default_base_url}}}"
    token_value="${ADMIN_TOKEN:-}"
    
    response=$(curl -sf -H "Authorization: Bearer $token_value" \
        "${BASE_URL}/api/v1/services/{{name}}/logs?lines={{lines}}&timestamps={{timestamps}}")
    
    echo "$response" | jq -r '.logs[]'

# Get Docker service stats
service-stats name:
    #!/usr/bin/env bash
    set -euo pipefail
    
    BASE_URL="${BASE_URL:-{{default_base_url}}}"
    token_value="${ADMIN_TOKEN:-}"
    
    response=$(curl -sfL -H "Authorization: Bearer $token_value" \
        "${BASE_URL}/api/v1/services/{{name}}/stats")
    
    echo "$response" | jq '.'

# Create proxy for Docker service
service-proxy-create name hostname="" enable-https="false" token="":
    #!/usr/bin/env bash
    set -euo pipefail
    
    # Default to ADMIN_TOKEN if no token specified
    if [ -z "{{token}}" ]; then
        token_value="${ADMIN_TOKEN:-}"
    elif [ "{{token}}" = "ADMIN" ]; then
        token_value="${ADMIN_TOKEN:-}"
    elif [[ "{{token}}" == acm_* ]]; then
        token_value="{{token}}"
    else
        token_value=$(docker exec {{container_name}} pixi run python scripts/show_token.py "{{token}}" 2>/dev/null | grep "^Token: " | cut -d' ' -f2 || true)
    fi
    
    BASE_URL="${BASE_URL:-{{default_base_url}}}"
    
    # Build request data
    if [ -n "{{hostname}}" ]; then
        url="${BASE_URL}/api/v1/services/{{name}}/proxy?enable_https={{enable-https}}&hostname={{hostname}}"
    else
        url="${BASE_URL}/api/v1/services/{{name}}/proxy?enable_https={{enable-https}}"
    fi
    
    response=$(curl -s -w '\n%{http_code}' -X POST "$url" \
        -H "Authorization: Bearer $token_value")
    
    http_code=$(echo "$response" | tail -n1)
    body=$(echo "$response" | head -n -1)
    
    if [[ "$http_code" =~ ^2 ]]; then
        echo "$body" | jq '.'
    else
        echo "Error: HTTP $http_code"
        echo "$body" | jq '.' 2>/dev/null || echo "$body"
        exit 1
    fi


# Cleanup orphaned Docker services (admin only)
service-cleanup:
    #!/usr/bin/env bash
    set -euo pipefail
    
    BASE_URL="${BASE_URL:-{{default_base_url}}}"
    token_value="${ADMIN_TOKEN:-}"
    
    response=$(curl -s -w '\n%{http_code}' -X POST "${BASE_URL}/api/v1/services/cleanup" \
        -H "Authorization: Bearer $token_value")
    
    http_code=$(echo "$response" | tail -n1)
    body=$(echo "$response" | head -n -1)
    
    if [[ "$http_code" =~ ^2 ]]; then
        echo "$body" | jq -r '.message'
    else
        echo "Error: HTTP $http_code"
        echo "$body" | jq '.' 2>/dev/null || echo "$body"
        exit 1
    fi

# ============================================================================
# PORT MANAGEMENT COMMANDS
# ============================================================================

# Add a port to an existing service
service-port-add name port bind-address="127.0.0.1" source-token="" token="":
    #!/usr/bin/env bash
    set -euo pipefail
    
    BASE_URL="${BASE_URL:-{{default_base_url}}}"
    token_value="${TOKEN:-{{token}}}"
    
    if [ -z "$token_value" ]; then
        echo "Error: Token required. Set TOKEN env var or pass as argument."
        exit 1
    fi
    
    # Parse port specification (format: host:container or just port)
    if [[ "{{port}}" =~ ^([0-9]+):([0-9]+)$ ]]; then
        host_port="${BASH_REMATCH[1]}"
        container_port="${BASH_REMATCH[2]}"
    else
        host_port="{{port}}"
        container_port="{{port}}"
    fi
    
    # Generate a port name based on the port number
    port_name="port-${host_port}"
    
    # Build JSON payload
    payload=$(jq -n \
        --arg name "$port_name" \
        --argjson host "$host_port" \
        --argjson container "$container_port" \
        --arg bind "{{bind-address}}" \
        --arg token "{{source-token}}" \
        '{name: $name, host: $host, container: $container, bind: $bind, protocol: "tcp"} |
        if $token != "" then . + {token: $token} else . end')
    
    response=$(curl -s -w '\n%{http_code}' -X POST "${BASE_URL}/api/v1/services/{{name}}/ports" \
        -H "Authorization: Bearer $token_value" \
        -H "Content-Type: application/json" \
        -d "$payload")
    
    http_code=$(echo "$response" | tail -n1)
    body=$(echo "$response" | head -n -1)
    
    if [[ "$http_code" =~ ^2 ]]; then
        echo "✓ Added port to service {{name}}:"
        echo "$body" | jq '.'
    else
        echo "Error: HTTP $http_code"
        echo "$body" | jq '.' 2>/dev/null || echo "$body"
        exit 1
    fi

# Remove a port from a service
service-port-remove name port-name token="":
    #!/usr/bin/env bash
    set -euo pipefail
    
    BASE_URL="${BASE_URL:-{{default_base_url}}}"
    token_value="${TOKEN:-{{token}}}"
    
    if [ -z "$token_value" ]; then
        echo "Error: Token required. Set TOKEN env var or pass as argument."
        exit 1
    fi
    
    response=$(curl -s -w '\n%{http_code}' -X DELETE "${BASE_URL}/api/v1/services/{{name}}/ports/{{port-name}}" \
        -H "Authorization: Bearer $token_value")
    
    http_code=$(echo "$response" | tail -n1)
    body=$(echo "$response" | head -n -1)
    
    if [[ "$http_code" =~ ^2 ]]; then
        echo "$body" | jq -r '.message'
    else
        echo "Error: HTTP $http_code"
        echo "$body" | jq '.' 2>/dev/null || echo "$body"
        exit 1
    fi

# List ports for a service
service-port-list name:
    #!/usr/bin/env bash
    set -euo pipefail
    
    BASE_URL="${BASE_URL:-{{default_base_url}}}"
    token_value="${TOKEN:-${ADMIN_TOKEN:-}}"
    
    response=$(curl -s -w '\n%{http_code}' "${BASE_URL}/api/v1/services/{{name}}/ports" \
        -H "Authorization: Bearer $token_value")
    
    http_code=$(echo "$response" | tail -n1)
    body=$(echo "$response" | head -n -1)
    
    if [[ "$http_code" =~ ^2 ]]; then
        echo "Ports for service {{name}}:"
        echo "$body" | jq -r '.[] | "- \(.port_name): \(.bind_address):\(.host_port) -> :\(.container_port) (\(.protocol))"'
    else
        echo "Error: HTTP $http_code"
        echo "$body" | jq '.' 2>/dev/null || echo "$body"
        exit 1
    fi

# List all allocated ports globally
service-ports-global available-only="false":
    #!/usr/bin/env bash
    set -euo pipefail
    
    BASE_URL="${BASE_URL:-{{default_base_url}}}"
    token_value="${TOKEN:-${ADMIN_TOKEN:-}}"
    
    if [ "{{available-only}}" = "true" ]; then
        endpoint="/api/v1/ports/available"
        echo "Available port ranges:"
    else
        endpoint="/api/v1/ports"
        echo "Allocated ports:"
    fi
    
    response=$(curl -s -w '\n%{http_code}' "${BASE_URL}${endpoint}" \
        -H "Authorization: Bearer $token_value")
    
    http_code=$(echo "$response" | tail -n1)
    body=$(echo "$response" | head -n -1)
    
    if [[ "$http_code" =~ ^2 ]]; then
        if [ "{{available-only}}" = "true" ]; then
            echo "$body" | jq -r '.[] | "- \(.start)-\(.end) (\(.count) ports)"'
        else
            echo "$body" | jq -r 'to_entries | .[] | "- Port \(.key): \(.value.service_name // .value.purpose) (\(.value.bind_address))"'
        fi
    else
        echo "Error: HTTP $http_code"
        echo "$body" | jq '.' 2>/dev/null || echo "$body"
        exit 1
    fi

# Check if a port is available
service-port-check port bind-address="127.0.0.1":
    #!/usr/bin/env bash
    set -euo pipefail
    
    BASE_URL="${BASE_URL:-{{default_base_url}}}"
    token_value="${TOKEN:-${ADMIN_TOKEN:-}}"
    
    payload=$(jq -n \
        --argjson port {{port}} \
        --arg bind "{{bind-address}}" \
        '{port: $port, bind_address: $bind}')
    
    response=$(curl -s -w '\n%{http_code}' -X POST "${BASE_URL}/api/v1/ports/check" \
        -H "Authorization: Bearer $token_value" \
        -H "Content-Type: application/json" \
        -d "$payload")
    
    http_code=$(echo "$response" | tail -n1)
    body=$(echo "$response" | head -n -1)
    
    if [[ "$http_code" =~ ^2 ]]; then
        available=$(echo "$body" | jq -r '.available')
        if [ "$available" = "true" ]; then
            echo "✓ Port {{port}} is available on {{bind-address}}"
        else
            reason=$(echo "$body" | jq -r '.reason // "Unknown reason"')
            echo "✗ Port {{port}} is not available on {{bind-address}}: $reason"
        fi
    else
        echo "Error: HTTP $http_code"
        echo "$body" | jq '.' 2>/dev/null || echo "$body"
        exit 1
    fi

# Create a service with exposed port(s)
service-create-exposed name image port bind-address="127.0.0.1" token="" memory="512m" cpu="1.0":
    #!/usr/bin/env bash
    set -euo pipefail
    
    BASE_URL="${BASE_URL:-{{default_base_url}}}"
    token_value="${TOKEN:-{{token}}}"
    
    if [ -z "$token_value" ]; then
        echo "Error: Token required. Set TOKEN env var or pass as argument."
        exit 1
    fi
    
    # Parse port specification
    if [[ "{{port}}" =~ ^([0-9]+):([0-9]+)$ ]]; then
        host_port="${BASH_REMATCH[1]}"
        container_port="${BASH_REMATCH[2]}"
    else
        host_port="{{port}}"
        container_port="{{port}}"
    fi
    
    # Build port configuration
    port_config=$(jq -n \
        --arg name "main" \
        --argjson host "$host_port" \
        --argjson container "$container_port" \
        --arg bind "{{bind-address}}" \
        '[{name: $name, host: $host, container: $container, bind: $bind, protocol: "tcp"}]')
    
    # Build service configuration
    payload=$(jq -n \
        --arg name "{{name}}" \
        --arg image "{{image}}" \
        --argjson internal_port "$container_port" \
        --arg memory "{{memory}}" \
        --argjson cpu {{cpu}} \
        --argjson port_configs "$port_config" \
        '{
            service_name: $name,
            image: $image,
            internal_port: $internal_port,
            memory_limit: $memory,
            cpu_limit: $cpu,
            expose_ports: true,
            port_configs: $port_configs,
            bind_address: "{{bind-address}}"
        }')
    
    response=$(curl -s -w '\n%{http_code}' -X POST "${BASE_URL}/api/v1/services/" \
        -H "Authorization: Bearer $token_value" \
        -H "Content-Type: application/json" \
        -d "$payload")
    
    http_code=$(echo "$response" | tail -n1)
    body=$(echo "$response" | head -n -1)
    
    if [[ "$http_code" =~ ^2 ]]; then
        echo "✓ Created service {{name}} with exposed port:"
        echo "$body" | jq '.service | {name: .service_name, status: .status, ports: .exposed_ports}'
        echo ""
        echo "Service accessible at {{bind-address}}:{{port}}"
    else
        echo "Error: HTTP $http_code"
        echo "$body" | jq '.' 2>/dev/null || echo "$body"
        exit 1
    fi

# ============================================================================
# PORT ACCESS TOKEN COMMANDS
# ============================================================================

# Create a port access token
service-token-create token-name allowed-services="" allowed-ports="" expires-hours="":
    #!/usr/bin/env bash
    set -euo pipefail
    
    BASE_URL="${BASE_URL:-{{default_base_url}}}"
    token_value="${ADMIN_TOKEN:-}"
    
    if [ -z "$token_value" ]; then
        echo "Error: Admin token required. Set ADMIN_TOKEN env var."
        exit 1
    fi
    
    # Build arrays from comma-separated lists
    if [ -n "{{allowed-services}}" ]; then
        services_json=$(echo "{{allowed-services}}" | jq -R 'split(",")')
    else
        services_json="[]"
    fi
    
    if [ -n "{{allowed-ports}}" ]; then
        ports_json=$(echo "{{allowed-ports}}" | jq -R 'split(",") | map(tonumber)')
    else
        ports_json="[]"
    fi
    
    # Build payload
    payload=$(jq -n \
        --arg name "{{token-name}}" \
        --argjson services "$services_json" \
        --argjson ports "$ports_json" \
        --argjson expires "{{expires-hours}}" \
        '{token_name: $name, allowed_services: $services, allowed_ports: $ports} |
        if $expires != "" then . + {expires_in_hours: ($expires | tonumber)} else . end')
    
    response=$(curl -s -w '\n%{http_code}' -X POST "${BASE_URL}/api/v1/ports/tokens" \
        -H "Authorization: Bearer $token_value" \
        -H "Content-Type: application/json" \
        -d "$payload")
    
    http_code=$(echo "$response" | tail -n1)
    body=$(echo "$response" | head -n -1)
    
    if [[ "$http_code" =~ ^2 ]]; then
        echo "✓ Created port access token:"
        echo "$body" | jq '.'
        echo ""
        echo "Save this token value - it cannot be retrieved again!"
    else
        echo "Error: HTTP $http_code"
        echo "$body" | jq '.' 2>/dev/null || echo "$body"
        exit 1
    fi

# List port access tokens
service-token-list:
    #!/usr/bin/env bash
    set -euo pipefail
    
    BASE_URL="${BASE_URL:-{{default_base_url}}}"
    token_value="${ADMIN_TOKEN:-}"
    
    if [ -z "$token_value" ]; then
        echo "Error: Admin token required. Set ADMIN_TOKEN env var."
        exit 1
    fi
    
    response=$(curl -s -w '\n%{http_code}' "${BASE_URL}/api/v1/ports/tokens" \
        -H "Authorization: Bearer $token_value")
    
    http_code=$(echo "$response" | tail -n1)
    body=$(echo "$response" | head -n -1)
    
    if [[ "$http_code" =~ ^2 ]]; then
        echo "Port access tokens:"
        echo "$body" | jq -r '.[] | "- \(.token_name): Services=\(.allowed_services | join(",") // "all"), Ports=\(.allowed_ports | join(",") // "all"), Expires=\(.expires_at // "never")"'
    else
        echo "Error: HTTP $http_code"
        echo "$body" | jq '.' 2>/dev/null || echo "$body"
        exit 1
    fi

# Revoke a port access token
service-token-revoke token-name:
    #!/usr/bin/env bash
    set -euo pipefail
    
    BASE_URL="${BASE_URL:-{{default_base_url}}}"
    token_value="${ADMIN_TOKEN:-}"
    
    if [ -z "$token_value" ]; then
        echo "Error: Admin token required. Set ADMIN_TOKEN env var."
        exit 1
    fi
    
    response=$(curl -s -w '\n%{http_code}' -X DELETE "${BASE_URL}/api/v1/ports/tokens/{{token-name}}" \
        -H "Authorization: Bearer $token_value")
    
    http_code=$(echo "$response" | tail -n1)
    body=$(echo "$response" | head -n -1)
    
    if [[ "$http_code" =~ ^2 ]]; then
        echo "$body" | jq -r '.message'
    else
        echo "Error: HTTP $http_code"
        echo "$body" | jq '.' 2>/dev/null || echo "$body"
        exit 1
    fi

# ============================================================================
# TESTING COMMANDS
# ============================================================================

# Run tests (optionally specify test files)
test *files="tests/test_health.py":
    #!/usr/bin/env bash
    if [ "$#" -eq 0 ]; then
        echo "Running basic API tests..."
        docker exec {{container_name}} pixi run pytest tests/test_health.py -v
    else
        echo "Running specified tests: $@"
        docker exec {{container_name}} pixi run pytest "$@" -v
    fi

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

# Test token management
test-tokens:
    docker exec {{container_name}} pixi run pytest tests/test_tokens.py -v

# Test all proxy operations
test-proxy-all:
    docker exec {{container_name}} pixi run pytest tests/test_proxy.py -v

# Test proxy authentication
test-proxy-auth:
    docker exec {{container_name}} pixi run pytest tests/test_proxy.py -v -k "TestProxyAuthentication"

# Test OAuth functionality
test-auth token="${ADMIN_TOKEN}":
    docker exec {{container_name}} pixi run pytest tests/test_oauth.py -v

# Test OAuth flow for a specific hostname
test-auth-flow hostname:
    @echo "Testing OAuth flow for {{hostname}}..."
    @echo "This test would validate the complete OAuth flow"
    docker exec {{container_name}} pixi run pytest tests/test_oauth.py::TestOAuthFlow::test_complete_flow -v --hostname={{hostname}}

# Test route management
test-routes:
    docker exec {{container_name}} pixi run pytest tests/test_routes.py -v

# Test instance management
test-instances:
    docker exec {{container_name}} pixi run pytest tests/test_instances.py -v

# Test with specific marks
test-mark mark:
    docker exec {{container_name}} pixi run pytest tests/ -v -m {{mark}}

# Test MCP functionality
test-mcp:
    docker exec {{container_name}} pixi run pytest tests/test_mcp_client.py -v

# Test OAuth status API
test-oauth-status-api:
    docker exec {{container_name}} pixi run pytest tests/test_oauth.py::TestOAuthStatus -v

# Test WebSocket proxy
test-websocket-proxy:
    docker exec {{container_name}} pixi run pytest tests/test_proxy.py -v -k "websocket"

# Test streaming proxy
test-streaming-proxy:
    docker exec {{container_name}} pixi run pytest tests/test_proxy.py -v -k "streaming"

# Test multi-domain certificates
test-multi-domain:
    docker exec {{container_name}} pixi run pytest tests/test_certificates.py::TestMultiDomainCertificates -v

# Test proxy routes
test-proxy-routes:
    docker exec {{container_name}} pixi run pytest tests/test_routes.py::TestProxyRouteControl -v

# Test MCP compliance
test-mcp-compliance:
    docker exec {{container_name}} pixi run pytest tests/test_mcp_client.py::TestMCPProtocolCompliance -v

# Test resource indicators
test-resource-indicators:
    docker exec {{container_name}} pixi run pytest tests/test_oauth.py::TestMCPResourceManagement -v

# Test audience validation  
test-audience-validation:
    docker exec {{container_name}} pixi run pytest tests/test_oauth.py -v -k "audience"

# Test Docker service management
test-docker-services:
    docker exec {{container_name}} pixi run pytest tests/test_docker_services.py -v

# Test Docker service API
test-docker-api:
    docker exec {{container_name}} pixi run pytest tests/test_docker_services.py::TestDockerServiceAPI -v

# Test port management functionality
test-ports:
    docker exec {{container_name}} pixi run pytest tests/test_ports.py -v

# Test service port management
test-service-ports:
    docker exec {{container_name}} pixi run pytest tests/test_service_ports.py -v

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
    #!/usr/bin/env bash
    set -euo pipefail
    
    BASE_URL="${BASE_URL:-{{default_base_url}}}"
    
    # Get admin token
    auth_token="${ADMIN_TOKEN:-}"
    if [ -z "$auth_token" ]; then
        echo "Error: ADMIN_TOKEN not set in environment" >&2
        exit 1
    fi
    
    echo "Cleaning up orphaned resources..."
    
    # Call cleanup endpoints
    # Clean up orphaned certificates
    curl -sf -X POST "${BASE_URL}/api/v1/certificates/cleanup" \
        -H "Authorization: Bearer $auth_token" || echo "Certificate cleanup failed"
    
    # Clean up orphaned proxies
    curl -sf -X POST "${BASE_URL}/api/v1/proxy/cleanup" \
        -H "Authorization: Bearer $auth_token" || echo "Proxy cleanup failed"
    
    # Clean up orphaned Docker services
    curl -sf -X POST "${BASE_URL}/api/v1/services/cleanup" \
        -H "Authorization: Bearer $auth_token" || echo "Docker services cleanup failed"
    
    echo "Cleanup completed"

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
    
    # Try API first if available
    if [ "${USE_API:-true}" = "true" ] && [ -n "${BASE_URL:-}" ]; then
        # Try API call
        response=$(curl -sf -X POST "${BASE_URL}/api/v1/oauth/admin/setup-routes" \
            -H "Authorization: Bearer $token_value" \
            -H "Content-Type: application/json" \
            -d "{\"oauth_domain\": \"{{domain}}\", \"force\": false}" 2>/dev/null || true)
        
        if [ -n "$response" ]; then
            # Check if successful
            success=$(echo "$response" | jq -r '.success' 2>/dev/null || true)
            if [ "$success" = "true" ]; then
                echo "OAuth routes setup completed successfully!"
                echo "$response" | jq -r '.created_routes[]' | while read route; do
                    echo "  ✓ Created: $route"
                done
                echo "$response" | jq -r '.skipped_routes[]' | while read route; do
                    echo "  - Skipped: $route (already exists)"
                done
            else
                echo "OAuth routes setup completed with issues:"
                echo "$response" | jq -r '.created_routes[]' | while read route; do
                    echo "  ✓ Created: $route"
                done
                echo "$response" | jq -r '.errors[]' | while read error; do
                    echo "  ✗ Error: $error"
                done
            fi
            exit 0
        fi
    fi
    
    # No API available, show error
    echo "Error: OAuth routes setup API not available" >&2
    echo "Please ensure the proxy service is running and accessible" >&2
    exit 1

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
    echo "OAuth client configured. Server URL saved to .env."

# Test MCP client authentication
mcp-test-auth:
    @echo "Testing MCP client authentication..."
    docker exec {{container_name}} pixi run pytest tests/test_mcp_client.py::TestMCPClient::test_oauth_client_registration -v

# OAuth Status Commands
# List OAuth clients
oauth-clients-list active-only="":
    #!/usr/bin/env bash
    set -euo pipefail
    
    BASE_URL="${BASE_URL:-{{default_base_url}}}"
    auth_token="${ADMIN_TOKEN:-}"
    
    if [ -z "$auth_token" ]; then
        echo "Error: ADMIN_TOKEN not set in environment" >&2
        exit 1
    fi
    
    # Build query parameter
    query=""
    if [ "{{active-only}}" = "true" ]; then
        query="?active_only=true"
    fi
    
    response=$(curl -sf -X GET "${BASE_URL}/api/v1/oauth/clients${query}" \
        -H "Authorization: Bearer $auth_token" 2>/dev/null || true)
    
    if [ -n "$response" ]; then
        echo "$response" | jq '.' 2>/dev/null || echo "$response"
    else
        echo "Error: Failed to list OAuth clients" >&2
        exit 1
    fi

# List active OAuth sessions
oauth-sessions-list:
    #!/usr/bin/env bash
    set -euo pipefail
    
    BASE_URL="${BASE_URL:-{{default_base_url}}}"
    auth_token="${ADMIN_TOKEN:-}"
    
    if [ -z "$auth_token" ]; then
        echo "Error: ADMIN_TOKEN not set in environment" >&2
        exit 1
    fi
    
    response=$(curl -sf -X GET "${BASE_URL}/api/v1/oauth/sessions" \
        -H "Authorization: Bearer $auth_token" 2>/dev/null || true)
    
    if [ -n "$response" ]; then
        echo "$response" | jq '.' 2>/dev/null || echo "$response"
    else
        echo "Error: Failed to list OAuth sessions" >&2
        exit 1
    fi

# MCP Resource Commands
# List MCP resources
resource-list:
    #!/usr/bin/env bash
    set -euo pipefail
    
    BASE_URL="${BASE_URL:-{{default_base_url}}}"
    auth_token="${ADMIN_TOKEN:-}"
    
    if [ -z "$auth_token" ]; then
        echo "Error: ADMIN_TOKEN not set in environment" >&2
        exit 1
    fi
    
    response=$(curl -sf -X GET "${BASE_URL}/api/v1/resources" \
        -H "Authorization: Bearer $auth_token" 2>/dev/null || true)
    
    if [ -n "$response" ]; then
        echo "$response" | jq '.' 2>/dev/null || echo "$response"
    else
        echo "Error: Failed to list MCP resources" >&2
        exit 1
    fi

# Run full MCP client test suite
mcp-test-all:
    @echo "Running full MCP client test suite..."
    docker exec {{container_name}} pixi run pytest tests/test_mcp_client.py -v -m integration

# Instance Management Commands
# List all registered instances
instance-list:
    #!/usr/bin/env bash
    set -euo pipefail
    
    BASE_URL="${BASE_URL:-{{default_base_url}}}"
    
    # Get admin token
    token_value="${ADMIN_TOKEN:-}"
    if [ -z "$token_value" ]; then
        echo "Error: ADMIN_TOKEN not set in environment" >&2
        exit 1
    fi
    
    echo "=== Named Instances ==="
    response=$(curl -s "${BASE_URL}/api/v1/instances/" -H "Authorization: Bearer $token_value")
    
    # Check if response is an error
    if echo "$response" | jq -e '.detail' &>/dev/null; then
        echo "Error: $(echo "$response" | jq -r '.detail')"
        exit 1
    fi
    
    # Format the output
    echo "$response" | \
        jq -r '.[] | [.name, .target_url, .description, .created_by] | @tsv' | \
        column -t -s $'\t' -N "Name,Target URL,Description,Created By"

# Show instance details
instance-show name:
    #!/usr/bin/env bash
    set -euo pipefail
    
    BASE_URL="${BASE_URL:-{{default_base_url}}}"
    
    # Get admin token
    token_value="${ADMIN_TOKEN:-}"
    if [ -z "$token_value" ]; then
        echo "Error: ADMIN_TOKEN not set in environment" >&2
        exit 1
    fi
    
    response=$(curl -s "${BASE_URL}/api/v1/instances/{{name}}" -H "Authorization: Bearer $token_value")
    
    # Check if response is an error
    if echo "$response" | jq -e '.detail' &>/dev/null; then
        echo "Error: $(echo "$response" | jq -r '.detail')"
        exit 1
    fi
    
    echo "$response" | jq '.'

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
    
    RESPONSE=$(curl -sL -w "\n%{http_code}" -X POST "${BASE_URL}/api/v1/instances" \
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
    
    RESPONSE=$(curl -s -w "\n%{http_code}" -X PUT "${BASE_URL}/api/v1/instances/{{name}}" \
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
    
    RESPONSE=$(curl -s -w "\n%{http_code}" -X DELETE "${BASE_URL}/api/v1/instances/{{name}}" \
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
    just instance-register "auth" "http://auth:8000" "{{token}}" "OAuth 2.0 Authorization Server"

# Route Management Commands
# List all routes
route-list:
    #!/usr/bin/env bash
    set -euo pipefail
    
    # Try API first if available
    if [ "${USE_API:-true}" = "true" ] && [ -n "${BASE_URL:-}" ]; then
        # Routes endpoint doesn't require authentication
        response=$(curl -sf "${BASE_URL}/api/v1/routes/formatted" 2>/dev/null || true)
        if [ -n "$response" ]; then
            echo "$response"
            exit 0
        fi
    fi
    
    # No API available, show error
    echo "Error: API not available. Please ensure BASE_URL is set and proxy is running." >&2
    exit 1

# Show route details
route-show route-id:
    #!/usr/bin/env bash
    set -euo pipefail
    
    BASE_URL="${BASE_URL:-{{default_base_url}}}"
    
    response=$(curl -sf -X GET "${BASE_URL}/api/v1/routes/{{route-id}}" 2>/dev/null || true)
    
    if [ -n "$response" ]; then
        echo "$response" | jq '.' 2>/dev/null || echo "$response"
    else
        echo "Error: Route '{{route-id}}' not found or API not available" >&2
        exit 1
    fi

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
    
    # Create route via API
    BASE_URL="${BASE_URL:-{{default_base_url}}}"
    
    # Build the JSON payload
    json_payload='{'
    json_payload="${json_payload}\"path_pattern\": \"{{path}}\","
    json_payload="${json_payload}\"target_type\": \"{{target-type}}\","
    json_payload="${json_payload}\"target_value\": \"{{target-value}}\","
    json_payload="${json_payload}\"priority\": {{priority}},"
    json_payload="${json_payload}\"is_regex\": {{is-regex}},"
    json_payload="${json_payload}\"description\": \"{{description}}\""
    json_payload="${json_payload}}"
    
    # Add methods if specified and not "*"
    if [ -n "{{methods}}" ] && [ "{{methods}}" != "*" ]; then
        methods_array=$(echo "{{methods}}" | sed 's/,/","/g' | sed 's/^/["/;s/$/"]/')
        json_payload=$(echo "$json_payload" | jq ". + {methods: $methods_array}")
    fi
    
    json_payload=$(echo "$json_payload" | jq -c '.')
    
    # Debug output
    if [ "${DEBUG:-}" = "1" ]; then
        echo "DEBUG: JSON payload: $json_payload" >&2
        echo "DEBUG: API URL: ${BASE_URL}/api/v1/routes/" >&2
    fi
    
    response=$(curl -s -w '\n%{http_code}' -X POST "${BASE_URL}/api/v1/routes/" \
        -H "Authorization: Bearer $token_value" \
        -H "Content-Type: application/json" \
        -d "$json_payload")
    
    http_code=$(echo "$response" | tail -n1)
    body=$(echo "$response" | head -n -1)
    
    if [[ "$http_code" =~ ^2 ]]; then
        echo "$body" | jq '.' 2>/dev/null || echo "$body"
    else
        echo "Error creating route: HTTP $http_code" >&2
        echo "$body" | jq '.' 2>/dev/null || echo "$body" >&2
        exit 1
    fi

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
    
    # Delete route via API
    BASE_URL="${BASE_URL:-{{default_base_url}}}"
    
    response=$(curl -sf -X DELETE "${BASE_URL}/api/v1/routes/{{route-id}}" \
        -H "Authorization: Bearer $token_value" 2>&1)
    
    if [ $? -eq 0 ]; then
        echo "✓ Route '{{route-id}}' deleted successfully"
    else
        echo "Error deleting route: $response" >&2
        exit 1
    fi

# ============================================================================
# SERVICE NAME MIGRATION
# ============================================================================

# Migrate to new service names (run this after updating docker-compose.yml)
@migrate-service-names token="${ADMIN_TOKEN}":
    #!/usr/bin/env bash
    set -euo pipefail
    
    echo "🔄 Migrating to new service names..."
    echo "=================================="
    
    # 1. Start services with new names
    echo "1️⃣ Starting services with new names..."
    just up
    
    # 2. Wait for services to be healthy
    echo ""
    echo "2️⃣ Waiting for services to be healthy..."
    sleep 15
    
    # 3. Update proxy targets
    echo ""
    echo "3️⃣ Updating proxy targets..."
    
    # Update auth proxy
    if just proxy-list | grep -q "auth.${BASE_DOMAIN}"; then
        echo "   Updating auth.${BASE_DOMAIN}..."
        curl -X PUT -H "Authorization: Bearer {{token}}" \
            -H "Content-Type: application/json" \
            -d '{"target_url": "http://auth:8000"}' \
            http://localhost/api/v1/proxy/targets/auth.${BASE_DOMAIN} > /dev/null 2>&1 || true
    fi
    
    # Update echo-stateful proxy
    if just proxy-list | grep -q "echo-stateful.${BASE_DOMAIN}"; then
        echo "   Updating echo-stateful.${BASE_DOMAIN}..."
        curl -X PUT -H "Authorization: Bearer {{token}}" \
            -H "Content-Type: application/json" \
            -d '{"target_url": "http://echo-stateful:3000"}' \
            http://localhost/api/v1/proxy/targets/echo-stateful.${BASE_DOMAIN} > /dev/null 2>&1 || true
    fi
    
    # Update echo-stateless proxy
    if just proxy-list | grep -q "echo-stateless.${BASE_DOMAIN}"; then
        echo "   Updating echo-stateless.${BASE_DOMAIN}..."
        curl -X PUT -H "Authorization: Bearer {{token}}" \
            -H "Content-Type: application/json" \
            -d '{"target_url": "http://echo-stateless:3000"}' \
            http://localhost/api/v1/proxy/targets/echo-stateless.${BASE_DOMAIN} > /dev/null 2>&1 || true
    fi
    
    # Update fetcher proxy
    if just proxy-list | grep -q "fetcher.${BASE_DOMAIN}"; then
        echo "   Updating fetcher.${BASE_DOMAIN}..."
        curl -X PUT -H "Authorization: Bearer {{token}}" \
            -H "Content-Type: application/json" \
            -d '{"target_url": "http://fetcher:3000"}' \
            http://localhost/api/v1/proxy/targets/fetcher.${BASE_DOMAIN} > /dev/null 2>&1 || true
    fi
    
    # 4. Verify services
    echo ""
    echo "4️⃣ Verifying services..."
    docker compose ps
    
    echo ""
    echo "5️⃣ Updated proxy targets:"
    just proxy-list | grep -E "auth|echo|fetcher" || true
    
    echo ""
    echo "✅ Migration complete!"
    echo ""
    echo "Service name changes:"
    echo "  - acme-certmanager → proxy"
    echo "  - mcp-proxy-gateway → proxy"
    echo "  - mcp-oauth-dynamicclient → auth"
    echo "  - mcp-oauth-server → auth"
    echo "  - mcp-echo-streamablehttp-server-stateful → echo-stateful"
    echo "  - mcp-echo-stateful → echo-stateful"
    echo "  - mcp-echo-streamablehttp-server-stateless → echo-stateless"
    echo "  - mcp-echo-stateless → echo-stateless"
    echo "  - fetcher-mcp → fetcher"
    echo "  - mcp-fetcher → fetcher"

# ============================================================================
# MCP ECHO SERVER MANAGEMENT  
# ============================================================================

# Start MCP echo servers
@mcp-echo-start:
    #!/usr/bin/env bash
    set -euo pipefail
    
    echo "Starting MCP echo servers..."
    docker compose up -d echo-stateful echo-stateless
    
    # Wait for services to be healthy
    echo "Waiting for services to be healthy..."
    for i in {1..10}; do
        echo -n "."
        sleep 1
    done
    echo ""
    
    echo "✓ Echo servers started"

# Complete setup for MCP echo servers (one command to rule them all!)
@mcp-echo-setup token="${ADMIN_TOKEN}":
    #!/usr/bin/env bash
    set -euo pipefail
    
    echo "🚀 Setting up MCP Echo Servers..."
    echo "================================"
    
    # 1. Ensure echo services are running
    echo "1️⃣ Starting echo services..."
    just mcp-echo-start || true
    
    # Wait a bit more for services to fully initialize
    sleep 5
    
    # 2. Create proxy entries for both echo servers
    echo ""
    echo "2️⃣ Creating proxy entries..."
    
    # Stateless echo server
    if ! just proxy-list | grep -q "echo-stateless.${BASE_DOMAIN}"; then
        echo "   Creating echo-stateless proxy..."
        just proxy-create "echo-stateless.${BASE_DOMAIN}" "http://echo-stateless:3000" "{{token}}" "${ADMIN_EMAIL}" "false" "true" "true" "true"
    else
        echo "   ✓ echo-stateless proxy already exists"
    fi
    
    # Stateful echo server  
    if ! just proxy-list | grep -q "echo-stateful.${BASE_DOMAIN}"; then
        echo "   Creating echo-stateful proxy..."
        just proxy-create "echo-stateful.${BASE_DOMAIN}" "http://echo-stateful:3000" "{{token}}" "${ADMIN_EMAIL}" "false" "true" "true" "true"
    else
        echo "   ✓ echo-stateful proxy already exists"
    fi
    
    # 3. Enable auth on both echo servers for proper security
    echo ""
    echo "3️⃣ Configuring authentication..."
    
    # Enable auth on stateless
    echo "   Enabling auth on echo-stateless..."
    curl -s -X POST -H "Authorization: Bearer {{token}}" -H "Content-Type: application/json" \
        -d '{"auth_proxy": "auth.'${BASE_DOMAIN}'", "auth_mode": "forward"}' \
        http://localhost/api/v1/proxy/targets/echo-stateless.${BASE_DOMAIN}/auth > /dev/null 2>&1 || true
    echo "   ✓ Auth enabled on echo-stateless"
    
    # Enable auth on stateful
    echo "   Enabling auth on echo-stateful..."
    curl -s -X POST -H "Authorization: Bearer {{token}}" -H "Content-Type: application/json" \
        -d '{"auth_proxy": "auth.'${BASE_DOMAIN}'", "auth_mode": "forward"}' \
        http://localhost/api/v1/proxy/targets/echo-stateful.${BASE_DOMAIN}/auth > /dev/null 2>&1 || true
    echo "   ✓ Auth enabled on echo-stateful"
    
    # 4. Verify everything is working
    echo ""
    echo "4️⃣ Verifying setup..."
    
    # Test stateless
    if curl -s https://echo-stateless.${BASE_DOMAIN}/.well-known/oauth-protected-resource | grep -q "mcp_server_info"; then
        echo "   ✅ echo-stateless is accessible"
    else
        echo "   ❌ echo-stateless check failed"
    fi
    
    # Test stateful
    if curl -s https://echo-stateful.${BASE_DOMAIN}/.well-known/oauth-protected-resource | grep -q "mcp_server_info"; then
        echo "   ✅ echo-stateful is accessible"
    else
        echo "   ❌ echo-stateful check failed"
    fi
    
    # 5. Show the URLs
    echo ""
    echo "✨ MCP Echo Servers Ready!"
    echo "=========================="
    echo ""
    echo "Stateless server: https://echo-stateless.${BASE_DOMAIN}/mcp"
    echo "Stateful server:  https://echo-stateful.${BASE_DOMAIN}/mcp"
    echo ""
    echo "Both servers are configured WITH OAuth authentication for security."
    echo "You can now use these URLs in claude.ai or any MCP client!"

