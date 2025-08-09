# HTTP Proxy with Protected Resources - Refactored Modular Justfile
# This is a refactored version with modular approach and API-first design

# Variables
container_name := "mcp-http-proxy-api-1"
default_api_url := "http://localhost:80"
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

# Rebuild a specific service (defaults to api)
rebuild service="api":
    docker compose build {{service}}
    docker compose up -d {{service}}

# View Docker container logs (no follow, last 100 lines)
logs-service service="" lines="100":
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
    
    API_URL="${API_URL:-{{default_api_url}}}"
    
    response=$(curl -sL "${API_URL}/health")
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
    just logs hours={{hours}} limit={{lines}} token={{token}} || true

# Show available log commands
logs-help:
    @echo "=== Available Logging Commands ==="
    @echo ""
    @echo "🐳 Docker Container Logs:"
    @echo "  just logs-service            # Show Docker container logs (last 100 lines)"
    @echo "  just logs-follow             # Follow Docker container logs (tail -f)"
    @echo "  just logs-service api        # Show api service logs"
    @echo "  just logs-follow redis       # Follow redis service logs"
    @echo ""
    @echo "🔄 Combined View:"
    @echo "  just logs-all                # Show both Docker and application logs"
    @echo ""
    @echo "📋 Application Logs:"
    @echo "  just logs                    # Show recent application logs (default)"
    @echo "  just logs-follow             # Follow application logs in real-time"
    @echo "  just logs-errors             # Show only errors"
    @echo "  just logs-errors-debug       # Detailed errors with debugging info"
    @echo ""
    @echo "🔍 Search and Filter:"
    @echo "  just logs-ip <ip>            # Query logs from specific IP"
    @echo "  just logs-client <id>        # Query logs from OAuth client"
    @echo "  just logs-host <host>        # Query logs for specific hostname"
    @echo "  just logs-search             # Search with multiple filters"
    @echo ""
    @echo "🔐 OAuth Debugging:"
    @echo "  just logs-oauth <ip>         # OAuth activity summary for IP"
    @echo "  just logs-oauth-debug <ip>   # Full OAuth flow debug for IP"
    @echo "  just logs-oauth-flow         # Track OAuth authentication flows"
    @echo ""
    @echo "📊 Analysis:"
    @echo "  just logs-stats              # Show event statistics"
    @echo ""
    @echo "🗑️  Maintenance:"
    @echo "  just logs-clear              # Clear all logs from Redis (requires token)"
    @echo "  just logs-test               # Test logging system"
    @echo ""
    @echo "💡 Examples:"
    @echo "  just logs                    # Show recent application logs"
    @echo "  just logs-service            # Docker container logs"
    @echo "  just logs event=oauth        # Application OAuth logs"
    @echo "  just logs-follow event=proxy.error"
    @echo "  just logs-ip 192.168.1.100"

# Show recent application logs (default command)
logs hours="1" event="" level="" hostname="" limit="50" token="${ADMIN_TOKEN}":
    #!/usr/bin/env bash
    set -euo pipefail
    
    # Get token value
    if [ -z "{{token}}" ]; then
        echo "Error: Token required. Set ADMIN_TOKEN or provide token parameter." >&2
        exit 1
    fi
    
    API_URL="${API_URL:-{{default_api_url}}}"
    
    # Build query parameters
    params="hours={{hours}}&limit={{limit}}"
    [ -n "{{event}}" ] && params="${params}&event={{event}}"
    [ -n "{{level}}" ] && params="${params}&level={{level}}"
    [ -n "{{hostname}}" ] && params="${params}&hostname={{hostname}}"
    
    # Get recent logs
    response=$(curl -sL -H "Authorization: Bearer {{token}}" \
        "${API_URL}/api/v1/logs/search?${params}")
    
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
            if .request_id then "  Request ID: \(.request_id)" else empty end,
            ""
        )
    ' 2>/dev/null || echo "$response" | jq '.'


# Show only errors (quick error check)
logs-errors hours="1" limit="20" token="${ADMIN_TOKEN}":
    #!/usr/bin/env bash
    set -euo pipefail
    
    just logs-errors-debug hours={{hours}} include-warnings=false limit={{limit}} token={{token}}

# Follow application logs in real-time (tail -f equivalent)
logs-follow interval="2" event="" level="" hostname="" token="${ADMIN_TOKEN}":
    #!/usr/bin/env bash
    set -euo pipefail
    
    # Get token value
    if [ -z "{{token}}" ]; then
        echo "Error: Token required. Set ADMIN_TOKEN or provide token parameter." >&2
        exit 1
    fi
    
    API_URL="${API_URL:-{{default_api_url}}}"
    
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
            "${API_URL}/api/v1/logs/search?${params}" 2>/dev/null || true)
        
        if [ -n "$response" ]; then
            # Process and display only new logs
            echo "$response" | jq -r '
                .logs[] | 
                "\(.timestamp)-\(.ip // "none")" as $id |
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
logs-ip ip hours="24" event="" level="" limit="100" token="${ADMIN_TOKEN}":
    #!/usr/bin/env bash
    set -euo pipefail
    
    # Get token value
    token_value="{{token}}"
    if [ -z "$token_value" ]; then
        echo "Error: Token required. Set ADMIN_TOKEN or provide token parameter." >&2
        exit 1
    fi
    
    API_URL="${API_URL:-{{default_api_url}}}"
    
    # Build query parameters
    query="hours={{hours}}&limit={{limit}}"
    [ -n "{{event}}" ] && query="${query}&event={{event}}"
    [ -n "{{level}}" ] && query="${query}&level={{level}}"
    
    # Query logs
    response=$(curl -sL -H "Authorization: Bearer $token_value" \
        "${API_URL}/api/v1/logs/ip/{{ip}}?${query}")
    
    # Format logs in single-line format with enhanced OAuth debugging
    echo "$response" | jq -r '
        if .logs then
            .logs | reverse | .[] | 
            ((.timestamp | todateiso8601 | split(".")[0] | gsub("T"; " ")) + 
             " [" + .level + "] " + .hostname + " " + .ip + 
             (if .method then 
                " - " + .method + " " + .path + 
                (if .context.oauth_action then " [OAuth:" + .context.oauth_action + 
                    (if .context.oauth_state then " state=" + .context.oauth_state else "" end) + "]" 
                 elif (.path | test("^/(authorize|callback|token|mcp)$")) then " [OAuth:" + .path[1:] + "]" 
                 else "" end) +
                (if .query and (.query | length) > 0 then 
                    " q=" + (.query | split("&") | map(select(test("(client_id|state|code|scope|redirect_uri|resource)=")) | .[0:60]) | join(" ")) 
                 else "" end) +
                # Show critical endpoint flag
                (if .is_critical_endpoint then " [CRITICAL]" else "" end) +
                # Show request body for OAuth endpoints
                (if .request_body and (.request_body | length) > 0 and (.request_body | length) < 200 then 
                    " body=" + .request_body 
                 else "" end) +
                # Show form data for token endpoint
                (if .request_form_data and (.request_form_data | length) > 0 then 
                    " form_data=" + (.request_form_data | tojson | .[0:100])
                 else "" end) +
                # Show critical headers
                (if .critical_headers and (.critical_headers | length) > 0 then
                    " headers=" + (.critical_headers | to_entries | map(.key + ":" + (.value | .[0:20])) | join(","))
                 else "" end) +
                (if .referer and .referer != "" then " referer=" + .referer else "" end) +
                (if .user_agent and .user_agent != "" then " UA=\"" + (.user_agent | split(" ")[0]) + "\"" else "" end)
              else
                " -> " + (.status | tostring) + " (" + (.duration_ms | tostring) + "ms)" +
                # Show response body for errors
                (if .response_body and .status >= 400 and (.response_body | length) < 300 then 
                    " response=" + .response_body 
                 else "" end) +
                # Show OAuth failure analysis
                (if .oauth_failure_analysis then 
                    " oauth_fail=" + (.oauth_failure_analysis | tojson | .[0:100])
                 else "" end) +
                # Show error details
                (if .error and .error.message then 
                    " error=" + .error.message
                 else "" end) +
                (if .context.oauth_redirect_to then " redirect_to=" + (.context.oauth_redirect_to | split("?")[0]) else "" end) +
                (if .context.oauth_authorization_granted then " auth=" + .context.oauth_authorization_granted else "" end) +
                (if .context.oauth_rejection_reason then " rejection=" + .context.oauth_rejection_reason else "" end) +
                (if .context.oauth_github_username then " github_user=" + .context.oauth_github_username else "" end)
              end))
        else
            .
        end
    '

# Query application logs by OAuth client ID
logs-client client-id hours="24" event="" level="" limit="100" token="${ADMIN_TOKEN}":
    #!/usr/bin/env bash
    set -euo pipefail
    
    # Get token value
    token_value="{{token}}"
    if [ -z "$token_value" ]; then
        echo "Error: Token required. Set ADMIN_TOKEN or provide token parameter." >&2
        exit 1
    fi
    
    API_URL="${API_URL:-{{default_api_url}}}"
    
    # Build query parameters
    query="hours={{hours}}&limit={{limit}}"
    [ -n "{{event}}" ] && query="${query}&event={{event}}"
    [ -n "{{level}}" ] && query="${query}&level={{level}}"
    
    # Query logs
    response=$(curl -sL -H "Authorization: Bearer $token_value" \
        "${API_URL}/api/v1/logs/client/{{client-id}}?${query}")
    
    echo "$response" | jq -r '
        .logs[] | 
        "\(.timestamp | todateiso8601 | split(".")[0] | gsub("T"; " ")) [\(.level)] \(.event // "no-event") - \(.message)"
    ' 2>/dev/null || echo "$response" | jq '.'

# Query application logs by IP with full OAuth flow debug details
logs-oauth-debug ip hours="24" limit="100" token="${ADMIN_TOKEN}":
    #!/usr/bin/env bash
    set -euo pipefail
    
    # Get token value
    token_value="{{token}}"
    if [ -z "$token_value" ]; then
        echo "Error: Token required. Set ADMIN_TOKEN or provide token parameter." >&2
        exit 1
    fi
    
    API_URL="${API_URL:-{{default_api_url}}}"
    
    # Query logs
    response=$(curl -sL -H "Authorization: Bearer $token_value" \
        "${API_URL}/api/v1/logs/ip/{{ip}}?hours={{hours}}&limit={{limit}}")
    
    # Format logs with full OAuth debug details
    echo "$response" | jq -r '
        if .logs then
            .logs | reverse | .[] | 
            # Header line with timestamp, level, hostname, IP, method, path, status
            "\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" +
            "\n\((.timestamp | todateiso8601 | split(".")[0] | gsub("T"; " "))+"Z") [\(.level)] \(.hostname) \(.ip)" +
            (if .method then " - \(.method) \(.path)" else "" end) +
            (if .status then " → \(.status)" else "" end) +
            (if .duration_ms then " (\(.duration_ms)ms)" else "" end) +
            
            # OAuth endpoint detection
            (if (.path // "" | test("^/(authorize|callback|token|verify|mcp|register)$")) or (.context.oauth_action) then
                "\n📌 OAuth Flow: " + (.context.oauth_action // .path[1:]) +
                (if .context.oauth_state then " [state: \(.context.oauth_state)]" else "" end)
            else "" end) +
            
            # Request details
            (if .method then
                "\n\n📥 REQUEST:" +
                (if .context.query then "\n  Query: \(.context.query)" else "" end) +
                (if .context.request_headers then "\n  Headers: \(.context.request_headers | to_entries | map("\(.key): \(.value)") | join(", "))" else "" end) +
                (if .context.critical_headers then "\n  Critical Headers: \(.context.critical_headers | to_entries | map("\(.key): \(.value)") | join(", "))" else "" end) +
                (if .context.request_body then "\n  Body: \(.context.request_body)" else "" end) +
                (if .context.request_form_data then "\n  Form Data: \(.context.request_form_data | tostring)" else "" end) +
                (if .context.oauth_resources then "\n  Resources: \(.context.oauth_resources | tostring)" else "" end)
            else "" end) +
            
            # OAuth-specific details
            (if .context.oauth_client_id then "\n\n🔐 OAuth Details:\n  Client ID: \(.context.oauth_client_id)" else "" end) +
            (if .context.oauth_grant_type then "\n  Grant Type: \(.context.oauth_grant_type)" else "" end) +
            (if .context.oauth_scope then "\n  Scope: \(.context.oauth_scope)" else "" end) +
            (if .context.oauth_user_id then "\n  User ID: \(.context.oauth_user_id)" else "" end) +
            (if .context.oauth_username then "\n  Username: \(.context.oauth_username)" else "" end) +
            (if .context.oauth_email then "\n  Email: \(.context.oauth_email)" else "" end) +
            (if .context.oauth_github_username then "\n  GitHub User: \(.context.oauth_github_username)" else "" end) +
            
            # Token details
            (if .context.oauth_token_jti then "\n\n🎫 Token Details:\n  JTI: \(.context.oauth_token_jti)" else "" end) +
            (if .context.oauth_token_aud then "\n  Audience: \(.context.oauth_token_aud | tostring)" else "" end) +
            (if .context.oauth_token_exp then "\n  Expires: \(.context.oauth_token_exp)" else "" end) +
            (if .context.oauth_token_iat then "\n  Issued: \(.context.oauth_token_iat)" else "" end) +
            (if .context.oauth_resources then "\n  Resources: \(.context.oauth_resources | tostring)" else "" end) +
            (if .context.authorized_resources then "\n  Authorized Resources: \(.context.authorized_resources | tostring)" else "" end) +
            (if .context.requested_resources then "\n  Requested Resources: \(.context.requested_resources | tostring)" else "" end) +
            (if .context.token_resources then "\n  Token Resources: \(.context.token_resources | tostring)" else "" end) +
            (if .context.token_audience then "\n  Token Audience: \(.context.token_audience | tostring)" else "" end) +
            (if .context.complete_claims then "\n  Complete Claims: \(.context.complete_claims | tostring)" else "" end) +
            
            # Response details
            (if .status then
                "\n\n📤 RESPONSE:" +
                "\n  Status: \(.status)" +
                (if .context.response_headers then "\n  Headers: \(.context.response_headers | to_entries | map("\(.key): \(.value)") | join(", "))" else "" end) +
                (if .context.critical_response_headers then "\n  Critical Headers: \(.context.critical_response_headers | to_entries | map("\(.key): \(.value)") | join(", "))" else "" end) +
                (if .context.response_body then "\n  Body: \(.context.response_body)" else "" end) +
                (if .context.response_json then "\n  JSON: \(.context.response_json | tostring)" else "" end) +
                (if .context.response_json_masked then "\n  JSON (masked): \(.context.response_json_masked | tostring)" else "" end)
            else "" end) +
            
            # Error details
            (if .error or (.status >= 400) then
                "\n\n❌ ERROR DETAILS:" +
                (if .error then "\n  Error: \(.error | tostring)" else "" end) +
                (if .context.error_detail then "\n  Detail: \(.context.error_detail)" else "" end) +
                (if .context.parsed_error_data then "\n  Parsed Error: \(.context.parsed_error_data | tostring)" else "" end) +
                (if .context.oauth_failure_analysis then "\n  Failure Analysis: \(.context.oauth_failure_analysis | tostring)" else "" end) +
                (if .context.debug_context then "\n  Debug Context: \(.context.debug_context | tostring)" else "" end) +
                (if .context.debugging_hints then "\n  Debugging Hints:\n    - \(.context.debugging_hints | join("\n    - "))" else "" end)
            else "" end) +
            
            # Authentication details
            (if .context.auth_enabled then
                "\n\n🔑 Authentication:" +
                "\n  Auth Enabled: \(.context.auth_enabled)" +
                (if .context.auth_proxy then "\n  Auth Proxy: \(.context.auth_proxy)" else "" end) +
                (if .context.auth_mode then "\n  Auth Mode: \(.context.auth_mode)" else "" end) +
                (if .context.auth_url then "\n  Auth URL: \(.context.auth_url)" else "" end) +
                (if .context.auth_failure then "\n  Auth Failure: \(.context.auth_failure)" else "" end) +
                (if .context.failure_type then "\n  Failure Type: \(.context.failure_type)" else "" end)
            else "" end) +
            
            # MCP details
            (if .context.mcp_enabled then
                "\n\n🔌 MCP Configuration:" +
                "\n  MCP Enabled: \(.context.mcp_enabled)" +
                (if .context.mcp_metadata_enabled then "\n  Metadata Enabled: \(.context.mcp_metadata_enabled)" else "" end) +
                (if .context.mcp_endpoint then "\n  Endpoint: \(.context.mcp_endpoint)" else "" end)
            else "" end) +
            
            # Additional context
            (if .context then
                (if (.context | keys | map(select(test("^(ip|hostname|method|path|status|duration_ms|level|timestamp|query|user_agent|referer|error|oauth_.*|request_.*|response_.*|auth_.*|mcp_.*|critical_.*|debug.*|token.*|authorized.*|requested.*|complete_claims|parsed_error_data)$") | not))) | length > 0 then
                    "\n\n📎 Additional Context:" +
                    (.context | to_entries | map(select(.key | test("^(ip|hostname|method|path|status|duration_ms|level|timestamp|query|user_agent|referer|error|oauth_.*|request_.*|response_.*|auth_.*|mcp_.*|critical_.*|debug.*|token.*|authorized.*|requested.*|complete_claims|parsed_error_data)$") | not)) | map("\n  \(.key): \(.value | tostring)") | join(""))
                else "" end)
            else "" end)
        else
            .
        end
    '

# OAuth activity summary for an IP
logs-oauth ip hours="24" limit="100" token="${ADMIN_TOKEN}":
    #!/usr/bin/env bash
    set -euo pipefail
    
    # Get token value
    token_value="{{token}}"
    if [ -z "$token_value" ]; then
        echo "Error: Token required. Set ADMIN_TOKEN or provide token parameter." >&2
        exit 1
    fi
    
    API_URL="${API_URL:-{{default_api_url}}}"
    
    # Query logs
    response=$(curl -sL -H "Authorization: Bearer $token_value" \
        "${API_URL}/api/v1/logs/ip/{{ip}}?hours={{hours}}&limit={{limit}}")
    
    # Format logs showing OAuth flow summary
    echo "$response" | jq -r '
        if .logs then
            # Filter only OAuth-related requests
            (.logs | reverse | map(select(
                (.path // "" | test("^/(authorize|callback|token|verify|mcp|register)$")) or
                (.context.oauth_action) or
                (.context.is_critical_endpoint == true)
            ))) | .[] | 
            "\((.timestamp | todateiso8601 | split(".")[0] | gsub("T"; " "))) [\(.level)] \(.hostname) \(.ip) - \(.method) \(.path)" +
            (if .status then " → \(.status) (\(.duration_ms)ms)" else "" end) +
            
            # OAuth flow stage
            (if .path == "/authorize" then " 🔐 AUTHORIZATION" 
             elif .path == "/callback" then " 🔄 CALLBACK" 
             elif .path == "/token" then " 🎫 TOKEN EXCHANGE"
             elif .path == "/verify" then " ✅ VERIFICATION"
             elif .path == "/mcp" then " 🔌 MCP ACCESS"
             elif .path == "/register" then " 📝 REGISTRATION"
             else "" end) +
            
            # Key details on same line
            (if .context.oauth_client_id then " [client: \(.context.oauth_client_id)]" else "" end) +
            (if .context.oauth_username then " [user: \(.context.oauth_username)]" else "" end) +
            (if .context.oauth_github_username then " [github: \(.context.oauth_github_username)]" else "" end) +
            (if .context.oauth_token_jti then " [token: \(.context.oauth_token_jti)]" else "" end) +
            
            # Critical info for debugging
            (if .path == "/authorize" and .context.query then
                "\n    → Query: " + (.context.query | split("&") | map(select(test("(client_id|resource|scope|redirect_uri)="))) | join(" "))
            else "" end) +
            
            (if .path == "/token" then
                (if .context.oauth_resources or .context.requested_resources then 
                    "\n    → Resources requested: \(.context.oauth_resources // .context.requested_resources | tostring)"
                else "\n    → No resources requested" end) +
                (if .context.token_audience or .context.oauth_token_aud then 
                    "\n    → Token audience: \(.context.token_audience // .context.oauth_token_aud | tostring)"
                else "" end)
            else "" end) +
            
            (if .status >= 400 then
                "\n    ❌ ERROR: " +
                (if .context.error_detail then .context.error_detail
                 elif .context.parsed_error_data then (.context.parsed_error_data | tostring)
                 elif .error then (.error | tostring)
                 elif .context.response_body then .context.response_body
                 else "Status \(.status)" end) +
                (if .context.debugging_hints then 
                    "\n    💡 Hints: " + (.context.debugging_hints | join("; "))
                else "" end)
            else "" end) +
            "\n"
        else
            .
        end
    '

# Search application logs with filters
logs-search query="" hours="24" event="" level="" hostname="" limit="100" token="${ADMIN_TOKEN}":
    #!/usr/bin/env bash
    set -euo pipefail
    
    # Get token value
    if [ -z "{{token}}" ]; then
        echo "Error: Token required. Set ADMIN_TOKEN or provide token parameter." >&2
        exit 1
    fi
    
    API_URL="${API_URL:-{{default_api_url}}}"
    
    # Build query parameters
    params="hours={{hours}}&limit={{limit}}"
    [ -n "{{query}}" ] && params="${params}&q={{query}}"
    [ -n "{{event}}" ] && params="${params}&event={{event}}"
    [ -n "{{level}}" ] && params="${params}&level={{level}}"
    [ -n "{{hostname}}" ] && params="${params}&hostname={{hostname}}"
    
    # Search logs
    response=$(curl -sL -H "Authorization: Bearer {{token}}" \
        "${API_URL}/api/v1/logs/search?${params}")
    
    echo "$response" | jq -r '
        "Found \(.total) logs (showing \(.logs | length))",
        "",
        (.logs[] | 
            "\(.timestamp | todate | split(".")[0] | gsub("T"; " ")) [\(.level)] \(.event // "no-event") - \(.message)"
        )
    ' 2>/dev/null || echo "$response" | jq '.'

# Get detailed application errors with debugging info
logs-errors-debug hours="1" include-warnings="false" limit="50" token="${ADMIN_TOKEN}":
    #!/usr/bin/env bash
    set -euo pipefail
    
    # Get token value
    if [ -z "{{token}}" ]; then
        echo "Error: Token required. Set ADMIN_TOKEN or provide token parameter." >&2
        exit 1
    fi
    
    API_URL="${API_URL:-{{default_api_url}}}"
    
    # Query recent errors
    response=$(curl -sL -H "Authorization: Bearer {{token}}" \
        "${API_URL}/api/v1/logs/errors?hours={{hours}}&include_warnings={{include-warnings}}&limit={{limit}}")
    
    echo "$response" | jq -r '
        "=== Recent Errors" + (if .query_params.include_warnings then " and Warnings" else "" end) + " ===",
        "Total: \(.total) (showing \(.logs | length))",
        "",
        (.logs[] | 
            "\(.timestamp | todateiso8601 | split(".")[0] | gsub("T"; " ")) [\(.level)]",
            "  Event: \(.event // "unknown")",
            "  Message: \(.message)",
            if .error then "  Error: \(.error | tostring)" else empty end,
            if .request_id then "  Request ID: \(.request_id)" else empty end,
            ""
        )
    ' 2>/dev/null || echo "$response" | jq '.'

# Get application event statistics
logs-stats hours="24" token="${ADMIN_TOKEN}":
    #!/usr/bin/env bash
    set -euo pipefail
    
    # Get token value
    if [ -z "{{token}}" ]; then
        echo "Error: Token required. Set ADMIN_TOKEN or provide token parameter." >&2
        exit 1
    fi
    
    API_URL="${API_URL:-{{default_api_url}}}"
    
    # Get event statistics
    response=$(curl -sL -H "Authorization: Bearer {{token}}" \
        "${API_URL}/api/v1/logs/events?hours={{hours}}")
    
    echo "=== Event Statistics (last {{hours}} hours) ==="
    echo "$response" | jq -r '
        to_entries | 
        .[] | 
        "\(.key): \(.value)"
    '

# Follow OAuth flow for a specific request
logs-oauth-flow client-id="" username="" hours="1" token="${ADMIN_TOKEN}":
    #!/usr/bin/env bash
    set -euo pipefail
    
    # Get token value
    if [ -z "{{token}}" ]; then
        echo "Error: Token required. Set ADMIN_TOKEN or provide token parameter." >&2
        exit 1
    fi
    
    API_URL="${API_URL:-{{default_api_url}}}"
    
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
        "${API_URL}/api/v1/logs/search?q=${query}&hours={{hours}}&limit=1000")
    
    # Group by correlation ID and show flows
    echo "$response" | jq -r '
        .logs | 
        group_by(.ip) |
        .[] |
        (
            "IP: " + (.[0].ip // "unknown"),
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
logs-host hostname hours="24" limit="100" token="${ADMIN_TOKEN}":
    #!/usr/bin/env bash
    set -euo pipefail
    
    # Get token value
    if [ -z "{{token}}" ]; then
        echo "Error: Token required. Set ADMIN_TOKEN or provide token parameter." >&2
        exit 1
    fi
    
    API_URL="${API_URL:-{{default_api_url}}}"
    
    # Search logs for hostname
    response=$(curl -sL -H "Authorization: Bearer {{token}}" \
        "${API_URL}/api/v1/logs/search?hostname={{hostname}}&hours={{hours}}&limit={{limit}}")
    
    echo "$response" | jq -r '
        "=== Logs for {{hostname}} ===",
        "Total: \(.total) (showing \(.logs | length))",
        "",
        (.logs | reverse | .[] | 
            "\(.timestamp | todateiso8601 | split(".")[0] | gsub("T"; " ")) [\(.level)] \(.hostname) \(.ip) - \(.method) \(.path) -> \(.status) (\(.duration_ms // 0)ms) - UA: \(.context.user_agent // "none")"
        )
    ' 2>/dev/null || echo "$response" | jq '.'

# Test application logging system
logs-test token="${ADMIN_TOKEN}":
    #!/usr/bin/env bash
    set -euo pipefail
    
    echo "=== Testing Logging System ==="
    echo ""
    
    # 1. Make a test request to generate logs
    echo "1. Making test request to /health..."
    API_URL="${API_URL:-{{default_api_url}}}"
    curl -sL "${API_URL}/health" > /dev/null
    
    # 2. Wait for logs to be processed
    echo "2. Waiting for logs to be processed..."
    sleep 2
    
    # 3. Query recent logs
    echo "3. Querying recent logs..."
    echo ""
    just logs limit=5 token={{token}}
    
    echo ""
    echo "4. Checking event statistics..."
    just logs-stats hours=1 token={{token}} | head -10
    
    echo ""
    echo "✅ Logging system test complete!"

# Clear all application logs from Redis
logs-clear token="${ADMIN_TOKEN}":
    #!/usr/bin/env bash
    set -euo pipefail
    
    echo "=== Clearing All Application Logs ==="
    echo ""
    
    # Check token
    auth_token="${token:-${ADMIN_TOKEN:-}}"
    if [ -z "$auth_token" ]; then
        echo "❌ Error: No authentication token provided"
        echo "Use: just logs-clear <token> or set ADMIN_TOKEN"
        exit 1
    fi
    
    echo "⚠️  WARNING: This will delete ALL logs from Redis!"
    echo "Press Ctrl+C to cancel, or wait 5 seconds to continue..."
    sleep 5
    
    echo ""
    echo "Clearing logs..."
    
    # Use redis-cli to delete log keys using patterns
    # We need to delete all keys matching the patterns from RequestLogger
    
    # Get Redis password from environment or .env file
    if [ -z "${REDIS_PASSWORD:-}" ] && [ -f .env ]; then
        export $(grep REDIS_PASSWORD .env | xargs)
    fi
    
    # 1. Delete request data keys: req:*
    echo "- Clearing request data..."
    docker compose exec -T redis redis-cli -a "${REDIS_PASSWORD}" --no-auth-warning --scan --pattern "req:*" | xargs -r docker compose exec -T redis redis-cli -a "${REDIS_PASSWORD}" --no-auth-warning DEL 2>/dev/null || true
    
    # 2. Delete all index keys: idx:req:*
    echo "- Clearing request indexes..."
    docker compose exec -T redis redis-cli -a "${REDIS_PASSWORD}" --no-auth-warning --scan --pattern "idx:req:*" | xargs -r docker compose exec -T redis redis-cli -a "${REDIS_PASSWORD}" --no-auth-warning DEL 2>/dev/null || true
    
    # 3. Delete stream data: stream:requests
    echo "- Clearing request stream..."
    docker compose exec -T redis redis-cli -a "${REDIS_PASSWORD}" --no-auth-warning DEL "stream:requests" 2>/dev/null || true
    
    # 4. Delete statistics keys: stats:*
    echo "- Clearing statistics..."
    docker compose exec -T redis redis-cli -a "${REDIS_PASSWORD}" --no-auth-warning --scan --pattern "stats:requests:*" | xargs -r docker compose exec -T redis redis-cli -a "${REDIS_PASSWORD}" --no-auth-warning DEL 2>/dev/null || true
    docker compose exec -T redis redis-cli -a "${REDIS_PASSWORD}" --no-auth-warning --scan --pattern "stats:unique_ips:*" | xargs -r docker compose exec -T redis redis-cli -a "${REDIS_PASSWORD}" --no-auth-warning DEL 2>/dev/null || true
    docker compose exec -T redis redis-cli -a "${REDIS_PASSWORD}" --no-auth-warning --scan --pattern "stats:errors:*" | xargs -r docker compose exec -T redis redis-cli -a "${REDIS_PASSWORD}" --no-auth-warning DEL 2>/dev/null || true
    docker compose exec -T redis redis-cli -a "${REDIS_PASSWORD}" --no-auth-warning --scan --pattern "stats:error_types:*" | xargs -r docker compose exec -T redis redis-cli -a "${REDIS_PASSWORD}" --no-auth-warning DEL 2>/dev/null || true
    docker compose exec -T redis redis-cli -a "${REDIS_PASSWORD}" --no-auth-warning --scan --pattern "stats:response_times:*" | xargs -r docker compose exec -T redis redis-cli -a "${REDIS_PASSWORD}" --no-auth-warning DEL 2>/dev/null || true
    
    # 5. Delete structured logs (from Python logging system)
    echo "- Clearing structured logs..."
    docker compose exec -T redis redis-cli -a "${REDIS_PASSWORD}" --no-auth-warning DEL "logs:stream" 2>/dev/null || true
    docker compose exec -T redis redis-cli -a "${REDIS_PASSWORD}" --no-auth-warning --scan --pattern "logs:entry:*" | xargs -r docker compose exec -T redis redis-cli -a "${REDIS_PASSWORD}" --no-auth-warning DEL 2>/dev/null || true
    docker compose exec -T redis redis-cli -a "${REDIS_PASSWORD}" --no-auth-warning --scan --pattern "logs:index:*" | xargs -r docker compose exec -T redis redis-cli -a "${REDIS_PASSWORD}" --no-auth-warning DEL 2>/dev/null || true
    
    echo ""
    echo "✅ All logs cleared successfully!"
    echo ""
    echo "Note: New requests will start generating logs immediately."


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
    if [ "${USE_API:-true}" = "true" ] && [ -n "${API_URL:-}" ]; then
        # Get admin token
        if [ -n "${ADMIN_TOKEN:-}" ]; then
            auth_token="${ADMIN_TOKEN}"
        else
            echo "Error: ADMIN_TOKEN not set in environment" >&2
            exit 1
        fi
        
        if [ -n "$auth_token" ]; then
            # Try API call
            response=$(curl -sf -X POST "${API_URL}/api/v1/tokens/generate" \
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
    echo "Error: API not available. Please ensure API_URL is set and proxy is running." >&2
    exit 1

# Show token value
token-show name:
    #!/usr/bin/env bash
    set -euo pipefail
    
    if [ "{{name}}" = "ADMIN" ] && [ -n "${ADMIN_TOKEN:-}" ]; then
        echo "Token: ${ADMIN_TOKEN}"
        exit 0
    fi
    
    API_URL="${API_URL:-{{default_api_url}}}"
    
    # Get admin token for API access
    auth_token="${ADMIN_TOKEN:-}"
    if [ -z "$auth_token" ]; then
        echo "Error: ADMIN_TOKEN not set in environment" >&2
        exit 1
    fi
    
    # Use API to reveal token
    response=$(curl -sf -X GET "${API_URL}/api/v1/tokens/{{name}}/reveal" \
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
    if [ "${USE_API:-true}" = "true" ] && [ -n "${API_URL:-}" ]; then
        # Get admin token
        if [ -n "${ADMIN_TOKEN:-}" ]; then
            auth_token="${ADMIN_TOKEN}"
        else
            echo "Error: ADMIN_TOKEN not set in environment" >&2
            exit 1
        fi
        
        if [ -n "$auth_token" ]; then
            # Try API call
            response=$(curl -sf -H "Authorization: Bearer $auth_token" "${API_URL}/api/v1/tokens/formatted" 2>/dev/null || true)
            if [ -n "$response" ]; then
                echo "$response"
                exit 0
            fi
        fi
    fi
    
    # No API available, exit with error
    echo "Error: API not available. Please ensure API_URL is set and proxy is running." >&2
    exit 1

# Delete token and owned resources
token-delete name:
    #!/usr/bin/env bash
    set -euo pipefail
    
    # Confirm deletion
    read -p "Delete token '{{name}}' and all owned resources? [y/N] " -n 1 -r
    echo
    [[ $REPLY =~ ^[Yy]$ ]] || exit 1
    
    API_URL="${API_URL:-{{default_api_url}}}"
    
    # Get admin token
    auth_token="${ADMIN_TOKEN:-}"
    if [ -z "$auth_token" ]; then
        echo "Error: ADMIN_TOKEN not set in environment" >&2
        exit 1
    fi
    
    # Delete token via API
    response=$(curl -sf -X DELETE "${API_URL}/api/v1/tokens/{{name}}" \
        -H "Authorization: Bearer $auth_token" 2>&1)
    
    if [ $? -eq 0 ]; then
        echo "✓ Token '{{name}}' deleted successfully"
    else
        echo "Error deleting token: $response" >&2
        exit 1
    fi

# Update certificate email for token
token-email name email token="":
    #!/usr/bin/env bash
    set -euo pipefail
    
    # Default to ADMIN_TOKEN if no token specified
    if [ -z "{{token}}" ]; then
        # For token-email, we need to get the token for the specified name
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
        API_URL="${API_URL:-{{default_api_url}}}"
        response=$(curl -sf -X GET "${API_URL}/api/v1/tokens/{{token}}/reveal" \
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
    
    API_URL="${API_URL:-{{default_api_url}}}"
    data=$(jq -n --arg email "{{email}}" '{email: $email}')
    
    response=$(curl -s -w '\n%{http_code}' -X PUT "${API_URL}/api/v1/tokens/email" \
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
token-admin:
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
    response=$(curl -sf -X POST "${API_URL}/api/v1/tokens/generate" \
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
        API_URL="${API_URL:-{{default_api_url}}}"
        response=$(curl -sf -X GET "${API_URL}/api/v1/tokens/{{token}}/reveal" \
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
    
    API_URL="${API_URL:-{{default_api_url}}}"
    
    # Get certificate email if not provided
    if [ -z "{{email}}" ]; then
        # Try to get from token first
        response=$(curl -s -H "Authorization: Bearer $token_value" "${API_URL}/api/v1/tokens/info")
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
    response=$(curl -sL -w '\n%{http_code}' -X POST "${API_URL}/api/v1/certificates/" \
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
    
    API_URL="${API_URL:-{{default_api_url}}}"
    
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
        API_URL="${API_URL:-{{default_api_url}}}"
        response=$(curl -sf -X GET "${API_URL}/api/v1/tokens/{{token}}/reveal" \
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
    response=$(curl -sL "${API_URL}/api/v1/certificates/" -H "Authorization: Bearer $token_value")
    
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
    
    API_URL="${API_URL:-{{default_api_url}}}"
    
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
        API_URL="${API_URL:-{{default_api_url}}}"
        response=$(curl -sf -X GET "${API_URL}/api/v1/tokens/{{token}}/reveal" \
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
    response=$(curl -s "${API_URL}/api/v1/certificates/{{name}}" -H "Authorization: Bearer $token_value")
    
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
        API_URL="${API_URL:-{{default_api_url}}}"
        response=$(curl -sf -X GET "${API_URL}/api/v1/tokens/{{token}}/reveal" \
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
    
    API_URL="${API_URL:-{{default_api_url}}}"
    
    # Delete certificate
    response=$(curl -s -w '\n%{http_code}' -X DELETE "${API_URL}/api/v1/certificates/{{name}}" \
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
        API_URL="${API_URL:-{{default_api_url}}}"
        response=$(curl -sf -X GET "${API_URL}/api/v1/tokens/{{token}}/reveal" \
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
    
    API_URL="${API_URL:-{{default_api_url}}}"
    
    # Get certificate email - use parameter first, then token, then ADMIN_EMAIL
    if [ -n "{{email}}" ]; then
        cert_email="{{email}}"
    else
        # Try to get from token
        response=$(curl -s -H "Authorization: Bearer $token_value" "${API_URL}/api/v1/tokens/info")
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
    response=$(curl -sL -w '\n%{http_code}' -X POST "${API_URL}/api/v1/proxy/targets/" \
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
    
    API_URL="${API_URL:-{{default_api_url}}}"
    
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
        API_URL="${API_URL:-{{default_api_url}}}"
        response=$(curl -sf -X GET "${API_URL}/api/v1/tokens/{{token}}/reveal" \
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
        
        # Fall back to API_URL if set
        if [ -n "${API_URL:-}" ]; then
            response=$(curl -sf -H "Authorization: Bearer $token_value" "${API_URL}/api/v1/proxy/targets/formatted" 2>/dev/null || true)
            if [ -n "$response" ]; then
                echo "$response"
                exit 0
            fi
        fi
    fi
    
    # No API available, show error
    echo "Error: API not available. Please ensure API_URL is set and proxy is running." >&2
    exit 1

# Show proxy details
proxy-show hostname:
    #!/usr/bin/env bash
    set -euo pipefail
    
    API_URL="${API_URL:-{{default_api_url}}}"
    
    response=$(curl -s -X GET "${API_URL}/api/v1/proxy/targets/{{hostname}}")
    
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
        API_URL="${API_URL:-{{default_api_url}}}"
        response=$(curl -sf -X GET "${API_URL}/api/v1/tokens/{{token}}/reveal" \
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
    
    API_URL="${API_URL:-{{default_api_url}}}"
    
    # Build query params
    query=""
    if [ "{{delete-cert}}" = "true" ]; then
        query="?delete_certificate=true"
    fi
    
    # Delete proxy
    response=$(curl -s -w '\n%{http_code}' -X DELETE "${API_URL}/api/v1/proxy/targets/{{hostname}}$query" \
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
proxy-auth-enable hostname token="" auth-proxy="" mode="forward" allowed-scopes="" allowed-audiences="":
    #!/usr/bin/env bash
    set -euo pipefail
    
    API_URL="${API_URL:-{{default_api_url}}}"
    
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
    
    # Build the JSON payload
    json_payload=$(jq -n \
        --arg auth_proxy "$auth_proxy_value" \
        --arg mode "{{mode}}" \
        '{
            "enabled": true,
            "auth_proxy": $auth_proxy,
            "mode": $mode
        }')
    
    # Add allowed_scopes if provided
    if [ -n "{{allowed-scopes}}" ]; then
        # Convert comma-separated string to JSON array
        scopes_array=$(echo "{{allowed-scopes}}" | jq -R 'split(",") | map(gsub("^\\s+|\\s+$"; ""))')
        json_payload=$(echo "$json_payload" | jq --argjson scopes "$scopes_array" '. + {allowed_scopes: $scopes}')
    fi
    
    # Add allowed_audiences if provided
    if [ -n "{{allowed-audiences}}" ]; then
        # Convert comma-separated string to JSON array
        audiences_array=$(echo "{{allowed-audiences}}" | jq -R 'split(",") | map(gsub("^\\s+|\\s+$"; ""))')
        json_payload=$(echo "$json_payload" | jq --argjson audiences "$audiences_array" '. + {allowed_audiences: $audiences}')
    fi
    
    # Create auth config
    response=$(curl -s -w '\n%{http_code}' -X POST "${API_URL}/api/v1/proxy/targets/{{hostname}}/auth" \
        -H "Authorization: Bearer $token_value" \
        -H "Content-Type: application/json" \
        -d "$json_payload")
    
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
    
    API_URL="${API_URL:-{{default_api_url}}}"
    
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
    response=$(curl -s -w '\n%{http_code}' -X DELETE "${API_URL}/api/v1/proxy/targets/{{hostname}}/auth" \
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
    
    response=$(curl -s -w '\n%{http_code}' "${API_URL}/api/v1/proxy/targets/{{hostname}}/auth")
    
    http_code=$(echo "$response" | tail -n1)
    body=$(echo "$response" | head -n -1)
    
    if [[ ! "$http_code" =~ ^2 ]]; then
        echo "Error: HTTP $http_code"
        echo "$body" | jq '.' 2>/dev/null || echo "$body"
        exit 1
    fi
    
    echo "$body" | jq '.'

# Configure auth settings for a proxy (users, emails, groups, scopes, audiences)
proxy-auth-config hostname token="" users="" emails="" groups="" allowed-scopes="" allowed-audiences="":
    #!/usr/bin/env bash
    set -euo pipefail
    
    API_URL="${API_URL:-{{default_api_url}}}"
    
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
    
    # Get current auth configuration
    response=$(curl -s -w '\n%{http_code}' "${API_URL}/api/v1/proxy/targets/{{hostname}}/auth")
    http_code=$(echo "$response" | tail -n1)
    body=$(echo "$response" | head -n -1)
    
    if [[ ! "$http_code" =~ ^2 ]]; then
        echo "Error: Failed to get current auth config - HTTP $http_code"
        echo "$body" | jq '.' 2>/dev/null || echo "$body"
        exit 1
    fi
    
    # Extract current config
    current_config=$(echo "$body" | jq '{
        enabled: .auth_enabled,
        auth_proxy: .auth_proxy,
        mode: .auth_mode,
        pass_headers: .auth_pass_headers,
        cookie_name: .auth_cookie_name,
        header_prefix: .auth_header_prefix,
        excluded_paths: .auth_excluded_paths
    }')
    
    # Build the JSON payload starting with current config
    json_payload="$current_config"
    
    # Add required_users if provided
    if [ -n "{{users}}" ]; then
        users_array=$(echo "{{users}}" | jq -R 'split(",") | map(gsub("^\\s+|\\s+$"; ""))')
        json_payload=$(echo "$json_payload" | jq --argjson users "$users_array" '. + {required_users: $users}')
    fi
    
    # Add required_emails if provided
    if [ -n "{{emails}}" ]; then
        emails_array=$(echo "{{emails}}" | jq -R 'split(",") | map(gsub("^\\s+|\\s+$"; ""))')
        json_payload=$(echo "$json_payload" | jq --argjson emails "$emails_array" '. + {required_emails: $emails}')
    fi
    
    # Add required_groups if provided
    if [ -n "{{groups}}" ]; then
        groups_array=$(echo "{{groups}}" | jq -R 'split(",") | map(gsub("^\\s+|\\s+$"; ""))')
        json_payload=$(echo "$json_payload" | jq --argjson groups "$groups_array" '. + {required_groups: $groups}')
    fi
    
    # Add allowed_scopes if provided
    if [ -n "{{allowed-scopes}}" ]; then
        scopes_array=$(echo "{{allowed-scopes}}" | jq -R 'split(",") | map(gsub("^\\s+|\\s+$"; ""))')
        json_payload=$(echo "$json_payload" | jq --argjson scopes "$scopes_array" '. + {allowed_scopes: $scopes}')
    fi
    
    # Add allowed_audiences if provided
    if [ -n "{{allowed-audiences}}" ]; then
        audiences_array=$(echo "{{allowed-audiences}}" | jq -R 'split(",") | map(gsub("^\\s+|\\s+$"; ""))')
        json_payload=$(echo "$json_payload" | jq --argjson audiences "$audiences_array" '. + {allowed_audiences: $audiences}')
    fi
    
    # Update auth config
    response=$(curl -s -w '\n%{http_code}' -X POST "${API_URL}/api/v1/proxy/targets/{{hostname}}/auth" \
        -H "Authorization: Bearer $token_value" \
        -H "Content-Type: application/json" \
        -d "$json_payload")
    
    http_code=$(echo "$response" | tail -n1)
    body=$(echo "$response" | head -n -1)
    
    if [[ ! "$http_code" =~ ^2 ]]; then
        echo "Error: HTTP $http_code"
        echo "$body" | jq '.' 2>/dev/null || echo "$body"
        exit 1
    fi
    
    echo "✓ Auth configuration updated for {{hostname}}"
    echo "$body" | jq '.'

# Set protected resource metadata for a proxy
proxy-resource-set hostname token="" endpoint="/mcp" scopes="mcp:read mcp:write" stateful="false" override-backend="false" bearer-methods="header" doc-suffix="/docs" server-info="{}" custom-metadata="{}" hacker-one-research="":
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
    
    # Build bearer methods array
    bearer_methods_json=$(echo "{{bearer-methods}}" | jq -R 'split(" ")')
    
    # Parse server-info and custom-metadata as JSON
    server_info_json=$(echo '{{server-info}}' | jq '.')
    custom_metadata_json=$(echo '{{custom-metadata}}' | jq '.')
    
    # Build request body
    body=$(jq -n \
        --argjson scopes "$scopes_json" \
        --argjson bearer_methods "$bearer_methods_json" \
        --argjson server_info "$server_info_json" \
        --argjson custom_metadata "$custom_metadata_json" \
        --arg hacker_one_research "{{hacker-one-research}}" \
        '{
            endpoint: "{{endpoint}}",
            scopes: $scopes,
            stateful: {{stateful}},
            versions: ["2025-06-18"],
            override_backend: {{override-backend}},
            bearer_methods: $bearer_methods,
            documentation_suffix: "{{doc-suffix}}",
            server_info: (if $server_info == {} then null else $server_info end),
            custom_metadata: (if $custom_metadata == {} then null else $custom_metadata end),
            hacker_one_research_header: (if $hacker_one_research == "" then null else $hacker_one_research end)
        }')
    
    echo "Configuring protected resource metadata for {{hostname}}..."
    echo "$body" | jq '.'
    
    response=$(curl -s -w '\n%{http_code}' -X POST \
        -H "Authorization: Bearer $TOKEN" \
        -H "Content-Type: application/json" \
        -d "$body" \
        "${API_URL}/api/v1/proxy/targets/{{hostname}}/resource")
    
    http_code=$(echo "$response" | tail -n1)
    body=$(echo "$response" | head -n -1)
    
    if [[ ! "$http_code" =~ ^2 ]]; then
        echo "Error: HTTP $http_code"
        echo "$body" | jq '.' 2>/dev/null || echo "$body"
        exit 1
    fi
    
    echo "✓ Protected resource metadata configured on {{hostname}}"
    echo "$body" | jq '.proxy_target | {resource_endpoint, resource_scopes, resource_stateful, resource_bearer_methods, resource_documentation_suffix}' 2>/dev/null || echo "$body"

# Clear protected resource metadata for a proxy
proxy-resource-clear hostname token="":
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
    
    echo "Removing protected resource metadata for {{hostname}}..."
    
    response=$(curl -s -w '\n%{http_code}' -X DELETE \
        -H "Authorization: Bearer $TOKEN" \
        "${API_URL}/api/v1/proxy/targets/{{hostname}}/resource")
    
    http_code=$(echo "$response" | tail -n1)
    body=$(echo "$response" | head -n -1)
    
    if [[ ! "$http_code" =~ ^2 ]]; then
        echo "Error: HTTP $http_code"
        echo "$body" | jq '.' 2>/dev/null || echo "$body"
        exit 1
    fi
    
    echo "✓ Protected resource metadata removed from {{hostname}}"

# Show protected resource metadata configuration for a proxy
proxy-resource-show hostname:
    #!/usr/bin/env bash
    set -euo pipefail
    
    response=$(curl -s -w '\n%{http_code}' "${API_URL}/api/v1/proxy/targets/{{hostname}}/resource")
    
    http_code=$(echo "$response" | tail -n1)
    body=$(echo "$response" | head -n -1)
    
    if [[ ! "$http_code" =~ ^2 ]]; then
        echo "Error: HTTP $http_code"
        echo "$body" | jq '.' 2>/dev/null || echo "$body"
        exit 1
    fi
    
    echo "$body" | jq '.'

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
        API_URL="${API_URL:-{{default_api_url}}}"
        response=$(curl -sf -X GET "${API_URL}/api/v1/tokens/{{token}}/reveal" \
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
    
    API_URL="${API_URL:-{{default_api_url}}}"
    
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
    response=$(curl -sL -w '\n%{http_code}' -X POST "${API_URL}/api/v1/services?auto_proxy={{auto-proxy}}" \
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
    
    API_URL="${API_URL:-{{default_api_url}}}"
    
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
        API_URL="${API_URL:-{{default_api_url}}}"
        response=$(curl -sf -X GET "${API_URL}/api/v1/tokens/{{token}}/reveal" \
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
        "${API_URL}/api/v1/services?owned_only={{owned-only}}")
    
    echo "$response" | jq -r '.services[] | "\(.service_name)\t\(.status)\t\(.allocated_port)\t\(.created_at)"' | \
        column -t -s $'\t' -N "SERVICE,STATUS,PORT,CREATED"

# Show Docker service details
service-show name:
    #!/usr/bin/env bash
    set -euo pipefail
    
    API_URL="${API_URL:-{{default_api_url}}}"
    token_value="${ADMIN_TOKEN:-}"
    
    response=$(curl -sfL -H "Authorization: Bearer $token_value" \
        "${API_URL}/api/v1/services/{{name}}")
    
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
        API_URL="${API_URL:-{{default_api_url}}}"
        response=$(curl -sf -X GET "${API_URL}/api/v1/tokens/{{token}}/reveal" \
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
    
    API_URL="${API_URL:-{{default_api_url}}}"
    
    # Delete service
    response=$(curl -s -w '\n%{http_code}' -X DELETE \
        "${API_URL}/api/v1/services/{{name}}?force={{force}}&delete_proxy={{delete-proxy}}" \
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
    
    API_URL="${API_URL:-{{default_api_url}}}"
    
    response=$(curl -s -w '\n%{http_code}' -X POST \
        "${API_URL}/api/v1/services/{{name}}/start" \
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
    
    API_URL="${API_URL:-{{default_api_url}}}"
    
    response=$(curl -s -w '\n%{http_code}' -X POST \
        "${API_URL}/api/v1/services/{{name}}/stop" \
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
    
    API_URL="${API_URL:-{{default_api_url}}}"
    
    response=$(curl -s -w '\n%{http_code}' -X POST \
        "${API_URL}/api/v1/services/{{name}}/restart" \
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
    
    API_URL="${API_URL:-{{default_api_url}}}"
    token_value="${ADMIN_TOKEN:-}"
    
    response=$(curl -sf -H "Authorization: Bearer $token_value" \
        "${API_URL}/api/v1/services/{{name}}/logs?lines={{lines}}&timestamps={{timestamps}}")
    
    echo "$response" | jq -r '.logs[]'

# Get Docker service stats
service-stats name:
    #!/usr/bin/env bash
    set -euo pipefail
    
    API_URL="${API_URL:-{{default_api_url}}}"
    token_value="${ADMIN_TOKEN:-}"
    
    response=$(curl -sfL -H "Authorization: Bearer $token_value" \
        "${API_URL}/api/v1/services/{{name}}/stats")
    
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
    
    API_URL="${API_URL:-{{default_api_url}}}"
    
    # Build request data
    if [ -n "{{hostname}}" ]; then
        url="${API_URL}/api/v1/services/{{name}}/proxy?enable_https={{enable-https}}&hostname={{hostname}}"
    else
        url="${API_URL}/api/v1/services/{{name}}/proxy?enable_https={{enable-https}}"
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
    
    API_URL="${API_URL:-{{default_api_url}}}"
    token_value="${ADMIN_TOKEN:-}"
    
    response=$(curl -s -w '\n%{http_code}' -X POST "${API_URL}/api/v1/services/cleanup" \
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
    
    API_URL="${API_URL:-{{default_api_url}}}"
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
    
    response=$(curl -s -w '\n%{http_code}' -X POST "${API_URL}/api/v1/services/{{name}}/ports" \
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
    
    API_URL="${API_URL:-{{default_api_url}}}"
    token_value="${TOKEN:-{{token}}}"
    
    if [ -z "$token_value" ]; then
        echo "Error: Token required. Set TOKEN env var or pass as argument."
        exit 1
    fi
    
    response=$(curl -s -w '\n%{http_code}' -X DELETE "${API_URL}/api/v1/services/{{name}}/ports/{{port-name}}" \
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
    
    API_URL="${API_URL:-{{default_api_url}}}"
    token_value="${TOKEN:-${ADMIN_TOKEN:-}}"
    
    response=$(curl -s -w '\n%{http_code}' "${API_URL}/api/v1/services/{{name}}/ports" \
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
    
    API_URL="${API_URL:-{{default_api_url}}}"
    token_value="${TOKEN:-${ADMIN_TOKEN:-}}"
    
    if [ "{{available-only}}" = "true" ]; then
        endpoint="/api/v1/services/ports/available"
        echo "Available port ranges:"
    else
        endpoint="/api/v1/services/ports"
        echo "Allocated ports:"
    fi
    
    response=$(curl -s -w '\n%{http_code}' "${API_URL}${endpoint}" \
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
    
    API_URL="${API_URL:-{{default_api_url}}}"
    token_value="${TOKEN:-${ADMIN_TOKEN:-}}"
    
    response=$(curl -s -w '\n%{http_code}' -X POST "${API_URL}/api/v1/services/ports/check?port={{port}}&bind_address={{bind-address}}" \
        -H "Authorization: Bearer $token_value")
    
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
    
    API_URL="${API_URL:-{{default_api_url}}}"
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
    
    response=$(curl -s -w '\n%{http_code}' -X POST "${API_URL}/api/v1/services/" \
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
# TESTING COMMANDS
# ============================================================================

# Run tests - smart default (quick suite) or specific files
test *files="":
    #!/usr/bin/env bash
    if [ -z "{{files}}" ]; then
        # No arguments: run quick test suite
        echo "Running quick test suite..."
        echo "════════════════════════════════════════════════════════════════"
        echo "  Quick tests: health, basic tokens, certs, proxy, routes, oauth"
        echo "  Use 'just test-all' for comprehensive testing"
        echo "  Use 'just test <file>' to run specific test files"
        echo "════════════════════════════════════════════════════════════════"
        docker exec {{container_name}} pixi run pytest \
            tests/test_health.py \
            tests/test_tokens.py \
            tests/test_certificates.py \
            tests/test_proxy.py \
            tests/test_routes.py \
            tests/test_oauth.py \
            -v \
            -m "not slow and not integration" \
            --tb=short \
            --maxfail=5 \
            -x
    else
        # Arguments provided: run specified tests
        echo "Running specified tests: {{files}}"
        docker exec {{container_name}} pixi run pytest {{files}} -v
    fi

# Run all tests comprehensively
test-all:
    @echo "Running comprehensive test suite..."
    @echo "════════════════════════════════════════════════════════════════"
    @echo "  Running ALL tests including slow and integration tests"
    @echo "  This may take 5-10 minutes to complete"
    @echo "════════════════════════════════════════════════════════════════"
    docker exec {{container_name}} pixi run pytest tests/ -v --tb=short

# ============================================================================
# UTILITY COMMANDS
# ============================================================================

# Build documentation
docs-build:
    pixi run jupyter-book build docs

# Clean up orphaned resources
service-cleanup-orphaned:
    #!/usr/bin/env bash
    set -euo pipefail
    
    API_URL="${API_URL:-{{default_api_url}}}"
    
    # Get admin token
    auth_token="${ADMIN_TOKEN:-}"
    if [ -z "$auth_token" ]; then
        echo "Error: ADMIN_TOKEN not set in environment" >&2
        exit 1
    fi
    
    echo "Cleaning up orphaned resources..."
    
    # Call cleanup endpoints
    # Clean up orphaned certificates
    curl -sf -X POST "${API_URL}/api/v1/certificates/cleanup" \
        -H "Authorization: Bearer $auth_token" || echo "Certificate cleanup failed"
    
    # Clean up orphaned proxies
    curl -sf -X POST "${API_URL}/api/v1/proxy/cleanup" \
        -H "Authorization: Bearer $auth_token" || echo "Proxy cleanup failed"
    
    # Clean up orphaned Docker services
    curl -sf -X POST "${API_URL}/api/v1/services/cleanup" \
        -H "Authorization: Bearer $auth_token" || echo "Docker services cleanup failed"
    
    echo "Cleanup completed"

# Save full configuration including SSL certificates to YAML backup file
config-save filename="":
    #!/usr/bin/env bash
    set -euo pipefail
    
    # Ensure backup directory exists
    mkdir -p ./backup
    
    # Generate filename if not provided
    if [ -z "{{filename}}" ]; then
        filename="backup_$(date +%Y%m%d_%H%M%S).yaml"
    else
        filename="{{filename}}"
    fi
    
    # Run the save script in container
    docker exec {{container_name}} pixi run python scripts/config_save.py "$filename"
    
    # Copy the backup file to host
    docker cp {{container_name}}:/app/backup/"$filename" ./backup/
    
    echo "Backup saved to ./backup/$filename"

# Load configuration from YAML backup file
config-load filename force="":
    #!/usr/bin/env bash
    set -euo pipefail
    
    if [ -z "{{filename}}" ]; then
        echo "Error: filename is required"
        echo "Usage: just config-load <filename> [--force]"
        echo ""
        echo "Examples:"
        echo "  just config-load backup_20241215_120000.yaml"
        echo "  just config-load backup.yaml --force"
        echo ""
        echo "Available backups:"
        ls -la ./backup/*.yaml 2>/dev/null || echo "  No backup files found in ./backup/"
        exit 1
    fi
    
    # Copy backup file to container if it exists on host
    if [ -f "./backup/{{filename}}" ]; then
        docker cp "./backup/{{filename}}" {{container_name}}:/app/backup/
    elif [ -f "{{filename}}" ]; then
        # If full path provided
        docker cp "{{filename}}" {{container_name}}:/app/backup/
    fi
    
    # Run the load script
    if [ "{{force}}" = "--force" ]; then
        docker exec {{container_name}} pixi run python scripts/config_load.py "{{filename}}" --force
    else
        docker exec {{container_name}} pixi run python scripts/config_load.py "{{filename}}"
    fi

# OAuth Commands
# Generate RSA private key for OAuth JWT signing
oauth-key-generate:
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
    if [ "${USE_API:-true}" = "true" ] && [ -n "${API_URL:-}" ]; then
        # Try API call
        response=$(curl -sf -X POST "${API_URL}/api/v1/oauth/admin/setup-routes" \
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

# OAuth Status Commands
# List OAuth clients
oauth-clients-list active-only="":
    #!/usr/bin/env bash
    set -euo pipefail
    
    API_URL="${API_URL:-{{default_api_url}}}"
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
    
    response=$(curl -sf -X GET "${API_URL}/api/v1/oauth/clients${query}" \
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
    
    API_URL="${API_URL:-{{default_api_url}}}"
    auth_token="${ADMIN_TOKEN:-}"
    
    if [ -z "$auth_token" ]; then
        echo "Error: ADMIN_TOKEN not set in environment" >&2
        exit 1
    fi
    
    response=$(curl -sf -X GET "${API_URL}/api/v1/oauth/sessions" \
        -H "Authorization: Bearer $auth_token" 2>/dev/null || true)
    
    if [ -n "$response" ]; then
        echo "$response" | jq '.' 2>/dev/null || echo "$response"
    else
        echo "Error: Failed to list OAuth sessions" >&2
        exit 1
    fi

# Protected Resource Commands
# List protected resources
proxy-resource-list:
    #!/usr/bin/env bash
    set -euo pipefail
    
    API_URL="${API_URL:-{{default_api_url}}}"
    auth_token="${ADMIN_TOKEN:-}"
    
    if [ -z "$auth_token" ]; then
        echo "Error: ADMIN_TOKEN not set in environment" >&2
        exit 1
    fi
    
    response=$(curl -sf -X GET "${API_URL}/api/v1/resources/" \
        -H "Authorization: Bearer $auth_token" 2>/dev/null || true)
    
    if [ -n "$response" ]; then
        echo "$response" | jq '.' 2>/dev/null || echo "$response"
    else
        echo "Error: Failed to list protected resources" >&2
        exit 1
    fi

# External Service Management Commands (replaces instance management)
# List all external services (formerly instances)
service-list-external:
    #!/usr/bin/env bash
    set -euo pipefail
    
    API_URL="${API_URL:-{{default_api_url}}}"
    
    # Get admin token
    token_value="${ADMIN_TOKEN:-}"
    if [ -z "$token_value" ]; then
        echo "Error: ADMIN_TOKEN not set in environment" >&2
        exit 1
    fi
    
    echo "=== External Services ==="
    response=$(curl -s "${API_URL}/api/v1/services/external" -H "Authorization: Bearer $token_value")
    
    # Check if response is an error
    if echo "$response" | jq -e '.detail' &>/dev/null; then
        echo "Error: $(echo "$response" | jq -r '.detail')"
        exit 1
    fi
    
    # Format the output
    echo "$response" | \
        jq -r '.[] | [.service_name, .target_url, .description, .created_by] | @tsv' | \
        column -t -s $'\t' -N "Name,Target URL,Description,Created By"

# Show external service details
service-show-external name:
    #!/usr/bin/env bash
    set -euo pipefail
    
    API_URL="${API_URL:-{{default_api_url}}}"
    
    # Get admin token
    token_value="${ADMIN_TOKEN:-}"
    if [ -z "$token_value" ]; then
        echo "Error: ADMIN_TOKEN not set in environment" >&2
        exit 1
    fi
    
    # Try to find in external services
    response=$(curl -s "${API_URL}/api/v1/services/external" -H "Authorization: Bearer $token_value")
    
    # Check if response is an error
    if echo "$response" | jq -e '.detail' &>/dev/null; then
        echo "Error: $(echo "$response" | jq -r '.detail')"
        exit 1
    fi
    
    # Find the specific service
    service=$(echo "$response" | jq --arg name "{{name}}" '.[] | select(.service_name == $name)')
    if [ -z "$service" ]; then
        echo "Error: Service '{{name}}' not found"
        exit 1
    fi
    
    echo "$service" | jq '.'

# Register an external service (replaces instance-register)
service-register name target-url token="" description="":
    #!/usr/bin/env bash
    API_URL="${API_URL:-{{default_api_url}}}"
    TOKEN="{{token}}"
    if [ -z "$TOKEN" ]; then
        TOKEN="$ADMIN_TOKEN"
    fi
    if [ -z "$TOKEN" ]; then
        echo "Error: No token provided and ADMIN_TOKEN not set" >&2
        exit 1
    fi
    
    RESPONSE=$(curl -sL -w "\n%{http_code}" -X POST "${API_URL}/api/v1/services/external" \
        -H "Authorization: Bearer $TOKEN" \
        -H "Content-Type: application/json" \
        -d '{
            "service_name": "{{name}}",
            "target_url": "{{target-url}}",
            "description": "{{description}}"
        }')
    
    HTTP_CODE=$(echo "$RESPONSE" | tail -1)
    BODY=$(echo "$RESPONSE" | head -n -1)
    
    if [ "$HTTP_CODE" = "200" ]; then
        echo "$BODY" | jq '.'
        echo "✓ External service '{{name}}' registered successfully"
    else
        echo "$BODY" | jq '.' || echo "$BODY"
        exit 1
    fi

# Update an external service
service-update-external name target-url token="" description="":
    #!/usr/bin/env bash
    API_URL="${API_URL:-{{default_api_url}}}"
    TOKEN="{{token}}"
    if [ -z "$TOKEN" ]; then
        TOKEN="$ADMIN_TOKEN"
    fi
    if [ -z "$TOKEN" ]; then
        echo "Error: No token provided and ADMIN_TOKEN not set" >&2
        exit 1
    fi
    
    # Since external services are immutable, we need to delete and recreate
    # First delete the old one
    curl -s -X DELETE "${API_URL}/api/v1/services/external/{{name}}" \
        -H "Authorization: Bearer $TOKEN" || true
    
    # Now create the new one
    RESPONSE=$(curl -s -w "\n%{http_code}" -X POST "${API_URL}/api/v1/services/external" \
        -H "Authorization: Bearer $TOKEN" \
        -H "Content-Type: application/json" \
        -d '{
            "service_name": "{{name}}",
            "target_url": "{{target-url}}",
            "description": "{{description}}"
        }')
    
    HTTP_CODE=$(echo "$RESPONSE" | tail -1)
    BODY=$(echo "$RESPONSE" | head -n -1)
    
    if [ "$HTTP_CODE" = "200" ]; then
        echo "$BODY" | jq '.'
        echo "✓ External service '{{name}}' updated successfully"
    else
        echo "$BODY" | jq '.' || echo "$BODY"
        exit 1
    fi

# Delete an external service
service-unregister name token="":
    #!/usr/bin/env bash
    API_URL="${API_URL:-{{default_api_url}}}"
    TOKEN="{{token}}"
    if [ -z "$TOKEN" ]; then
        TOKEN="$ADMIN_TOKEN"
    fi
    if [ -z "$TOKEN" ]; then
        echo "Error: No token provided and ADMIN_TOKEN not set" >&2
        exit 1
    fi
    
    RESPONSE=$(curl -s -w "\n%{http_code}" -X DELETE "${API_URL}/api/v1/services/external/{{name}}" \
        -H "Authorization: Bearer $TOKEN")
    
    HTTP_CODE=$(echo "$RESPONSE" | tail -1)
    BODY=$(echo "$RESPONSE" | head -n -1)
    
    if [ "$HTTP_CODE" = "204" ]; then
        echo "✓ External service '{{name}}' deleted successfully"
    else
        echo "$BODY" | jq '.' || echo "$BODY"
        exit 1
    fi

# Register OAuth server as external service (convenience command)
service-register-oauth token="":
    just service-register "auth" "http://auth:8000" "{{token}}" "OAuth 2.0 Authorization Server"

# List all services (Docker and external)
service-list-all type="":
    #!/usr/bin/env bash
    set -euo pipefail
    
    API_URL="${API_URL:-{{default_api_url}}}"
    
    # Get admin token
    token_value="${ADMIN_TOKEN:-}"
    if [ -z "$token_value" ]; then
        echo "Error: ADMIN_TOKEN not set in environment" >&2
        exit 1
    fi
    
    # Build query parameter
    query=""
    if [ -n "{{type}}" ]; then
        query="?service_type={{type}}"
    fi
    
    echo "=== All Services ==="
    response=$(curl -s "${API_URL}/api/v1/services/unified${query}" -H "Authorization: Bearer $token_value")
    
    # Check if response is an error
    if echo "$response" | jq -e '.detail' &>/dev/null; then
        echo "Error: $(echo "$response" | jq -r '.detail')"
        exit 1
    fi
    
    # Display summary
    echo "$response" | jq -r '"Total: \(.total)"'
    echo "$response" | jq -r '.by_type | to_entries[] | "  \(.key): \(.value)"'
    echo ""
    
    # Format the service list
    echo "$response" | \
        jq -r '.services[] | [.service_name, .service_type, (.target_url // .docker_info.image // "N/A"), .description] | @tsv' | \
        column -t -s $'\t' -N "Name,Type,Target/Image,Description"

# Route Management Commands
# List all routes
route-list:
    #!/usr/bin/env bash
    set -euo pipefail
    
    # Try API first if available
    if [ "${USE_API:-true}" = "true" ] && [ -n "${API_URL:-}" ]; then
        # Routes endpoint doesn't require authentication
        response=$(curl -sf "${API_URL}/api/v1/routes/formatted" 2>/dev/null || true)
        if [ -n "$response" ]; then
            echo "$response"
            exit 0
        fi
    fi
    
    # No API available, show error
    echo "Error: API not available. Please ensure API_URL is set and proxy is running." >&2
    exit 1

# Show route details
route-show route-id:
    #!/usr/bin/env bash
    set -euo pipefail
    
    API_URL="${API_URL:-{{default_api_url}}}"
    
    response=$(curl -sf -X GET "${API_URL}/api/v1/routes/{{route-id}}" 2>/dev/null || true)
    
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
    API_URL="${API_URL:-{{default_api_url}}}"
    
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
        echo "DEBUG: API URL: ${API_URL}/api/v1/routes/" >&2
    fi
    
    response=$(curl -s -w '\n%{http_code}' -X POST "${API_URL}/api/v1/routes/" \
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
    API_URL="${API_URL:-{{default_api_url}}}"
    
    response=$(curl -sf -X DELETE "${API_URL}/api/v1/routes/{{route-id}}" \
        -H "Authorization: Bearer $token_value" 2>&1)
    
    if [ $? -eq 0 ]; then
        echo "✓ Route '{{route-id}}' deleted successfully"
    else
        echo "Error deleting route: $response" >&2
        exit 1
    fi

# Create a global route (applies to all proxies)
route-create-global path target-type target-value token="" priority="50" methods="*" is-regex="false" description="":
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
    API_URL="${API_URL:-{{default_api_url}}}"
    
    # Build the JSON payload with scope=global
    json_payload='{'
    json_payload="${json_payload}\"path_pattern\": \"{{path}}\","
    json_payload="${json_payload}\"target_type\": \"{{target-type}}\","
    json_payload="${json_payload}\"target_value\": \"{{target-value}}\","
    json_payload="${json_payload}\"priority\": {{priority}},"
    json_payload="${json_payload}\"is_regex\": {{is-regex}},"
    json_payload="${json_payload}\"scope\": \"global\","
    json_payload="${json_payload}\"proxy_hostnames\": [],"
    json_payload="${json_payload}\"description\": \"{{description}}\""
    json_payload="${json_payload}}"
    
    # Add methods if specified and not "*"
    if [ -n "{{methods}}" ] && [ "{{methods}}" != "*" ]; then
        methods_array=$(echo "{{methods}}" | sed 's/,/","/g' | sed 's/^/["/;s/$/"]/')
        json_payload=$(echo "$json_payload" | jq ". + {methods: $methods_array}")
    fi
    
    json_payload=$(echo "$json_payload" | jq -c '.')
    
    response=$(curl -s -w '\n%{http_code}' -X POST "${API_URL}/api/v1/routes/" \
        -H "Authorization: Bearer $token_value" \
        -H "Content-Type: application/json" \
        -d "$json_payload")
    
    http_code=$(echo "$response" | tail -n1)
    body=$(echo "$response" | head -n -1)
    
    if [[ "$http_code" =~ ^2 ]]; then
        echo "✓ Created global route"
        echo "$body" | jq '.' 2>/dev/null || echo "$body"
    else
        echo "Error creating global route: HTTP $http_code" >&2
        echo "$body" | jq '.' 2>/dev/null || echo "$body" >&2
        exit 1
    fi

# Create a proxy-specific route (only applies to specified proxies)
route-create-proxy path target-type target-value proxies token="" priority="500" methods="*" is-regex="false" description="":
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
    API_URL="${API_URL:-{{default_api_url}}}"
    
    # Convert comma-separated proxies to JSON array
    proxies_array=$(echo "{{proxies}}" | sed 's/,/","/g' | sed 's/^/["/;s/$/"]/')
    
    # Build the JSON payload with scope=proxy
    json_payload='{'
    json_payload="${json_payload}\"path_pattern\": \"{{path}}\","
    json_payload="${json_payload}\"target_type\": \"{{target-type}}\","
    json_payload="${json_payload}\"target_value\": \"{{target-value}}\","
    json_payload="${json_payload}\"priority\": {{priority}},"
    json_payload="${json_payload}\"is_regex\": {{is-regex}},"
    json_payload="${json_payload}\"scope\": \"proxy\","
    json_payload="${json_payload}\"proxy_hostnames\": $proxies_array,"
    json_payload="${json_payload}\"description\": \"{{description}}\""
    json_payload="${json_payload}}"
    
    # Add methods if specified and not "*"
    if [ -n "{{methods}}" ] && [ "{{methods}}" != "*" ]; then
        methods_array=$(echo "{{methods}}" | sed 's/,/","/g' | sed 's/^/["/;s/$/"]/')
        json_payload=$(echo "$json_payload" | jq ". + {methods: $methods_array}")
    fi
    
    json_payload=$(echo "$json_payload" | jq -c '.')
    
    response=$(curl -s -w '\n%{http_code}' -X POST "${API_URL}/api/v1/routes/" \
        -H "Authorization: Bearer $token_value" \
        -H "Content-Type: application/json" \
        -d "$json_payload")
    
    http_code=$(echo "$response" | tail -n1)
    body=$(echo "$response" | head -n -1)
    
    if [[ "$http_code" =~ ^2 ]]; then
        echo "✓ Created proxy-specific route for: {{proxies}}"
        echo "$body" | jq '.' 2>/dev/null || echo "$body"
    else
        echo "Error creating proxy-specific route: HTTP $http_code" >&2
        echo "$body" | jq '.' 2>/dev/null || echo "$body" >&2
        exit 1
    fi

# List routes filtered by scope
route-list-by-scope scope="all":
    #!/usr/bin/env bash
    set -euo pipefail
    
    API_URL="${API_URL:-{{default_api_url}}}"
    
    # Get all routes (with trailing slash to avoid redirect)
    response=$(curl -sf "${API_URL}/api/v1/routes/" 2>/dev/null || true)
    
    if [ -n "$response" ]; then
        if [ "{{scope}}" = "all" ]; then
            echo "$response" | jq '.'
        elif [ "{{scope}}" = "global" ]; then
            echo "$response" | jq '[.[] | select(.scope == "global")]'
        elif [ "{{scope}}" = "proxy" ]; then
            echo "$response" | jq '[.[] | select(.scope == "proxy")]'
        else
            echo "Error: Invalid scope '{{scope}}'. Use 'all', 'global', or 'proxy'" >&2
            exit 1
        fi
    else
        echo "Error: API not available" >&2
        exit 1
    fi

# ============================================================================
# SERVICE NAME MIGRATION
# ============================================================================

