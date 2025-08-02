#!/usr/bin/env bash
# Enhanced OAuth log viewer that shows full OAuth workflow details

set -euo pipefail

# Get parameters
IP="${1:-}"
HOURS="${2:-24}"
ADMIN_TOKEN="${ADMIN_TOKEN:-}"

if [ -z "$IP" ]; then
    echo "Usage: $0 <ip-address> [hours]"
    exit 1
fi

if [ -z "$ADMIN_TOKEN" ]; then
    echo "Error: ADMIN_TOKEN not set"
    exit 1
fi

BASE_URL="${BASE_URL:-http://localhost:9000}"

# Query logs
response=$(curl -sL -H "Authorization: Bearer $ADMIN_TOKEN" \
    "${BASE_URL}/api/v1/logs/ip/${IP}?hours=${HOURS}&limit=100")

# Enhanced formatter that shows OAuth details
echo "$response" | jq -r '
    .logs | reverse | .[] | 
    # Build base log line
    "\(.timestamp | todateiso8601 | split(".")[0] | gsub("T"; " ")) [\(.level)] \(.hostname) \(.ip) - \(.method) \(.path) -> \(.status) (\(.duration_ms // 0)ms)" +
    
    # Add OAuth action if present
    (if .context.oauth_action then "\n  OAuth Action: \(.context.oauth_action)" else "" end) +
    
    # Add OAuth client info
    (if .context.oauth_client_id then "\n  Client ID: \(.context.oauth_client_id)" else "" end) +
    
    # Add OAuth user info
    (if .context.oauth_username then "\n  Username: \(.context.oauth_username)" else "" end) +
    (if .context.oauth_user_id then "\n  User ID: \(.context.oauth_user_id)" else "" end) +
    (if .context.oauth_email then "\n  Email: \(.context.oauth_email)" else "" end) +
    
    # Add OAuth token info
    (if .context.oauth_token_jti then "\n  Token JTI: \(.context.oauth_token_jti)" else "" end) +
    (if .context.oauth_token_issued then "\n  Token Issued: true" else "" end) +
    (if .context.oauth_scope then "\n  Scope: \(.context.oauth_scope)" else "" end) +
    (if .context.oauth_resources then "\n  Resources: \(.context.oauth_resources | tostring)" else "" end) +
    
    # Add OAuth grant info
    (if .context.oauth_grant_type then "\n  Grant Type: \(.context.oauth_grant_type)" else "" end) +
    (if .context.oauth_state then "\n  State: \(.context.oauth_state)" else "" end) +
    
    # Add introspection result if present
    (if .context.oauth_introspection_result then "\n  Introspection Result: \(.context.oauth_introspection_result | tostring)" else "" end) +
    (if .context.oauth_token_active != null then "\n  Token Active: \(.context.oauth_token_active)" else "" end) +
    
    # Add GitHub info
    (if .context.oauth_github_username then "\n  GitHub Username: \(.context.oauth_github_username)" else "" end) +
    (if .context.oauth_github_email then "\n  GitHub Email: \(.context.oauth_github_email)" else "" end) +
    
    # Add separator
    "\n---"
' 2>/dev/null || echo "$response" | jq '.'