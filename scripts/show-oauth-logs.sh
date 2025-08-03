#!/bin/bash
# Show comprehensive OAuth logs for an IP address

IP="${1:-213.47.196.26}"
HOURS="${2:-1}"
LIMIT="${3:-20}"

# Use environment admin token or require it
ADMIN_TOKEN="${ADMIN_TOKEN:-${4:-}}"
if [ -z "$ADMIN_TOKEN" ]; then
    echo "Error: ADMIN_TOKEN not set. Set it or pass as 4th argument." >&2
    exit 1
fi

BASE_URL="${BASE_URL:-http://localhost:9000}"

echo "=== OAuth Flow Logs for IP: $IP (last $HOURS hour(s)) ==="
echo

# Query logs
response=$(curl -sL -H "Authorization: Bearer $ADMIN_TOKEN" \
    "${BASE_URL}/api/v1/logs/ip/${IP}?hours=${HOURS}&limit=${LIMIT}")

# Display with enhanced formatting
echo "$response" | jq -r '
    .logs | reverse | .[] | 
    # Base log line
    "\(.timestamp | todateiso8601 | split(".")[0] | gsub("T"; " ")) [\(.level)] \(.hostname) \(.ip) - \(.method // "N/A") \(.path // "N/A") -> \(.status // "N/A") (\(.duration_ms // 0)ms)" +
    "\n" +
    # OAuth Action Details
    (if .context.oauth_action then
        if .context.oauth_action == "authorize" then
            "  🔐 OAuth Authorization Request:\n" +
            "    Client ID: \(.context.oauth_client_id // "N/A")\n" +
            "    Redirect URI: \(.context.oauth_redirect_uri // "N/A")\n" +
            "    Response Type: \(.context.oauth_response_type // "N/A")\n" +
            "    Scope: \(.context.oauth_scope // "N/A")\n" +
            "    State: \(.context.oauth_state // "N/A")\n" +
            (if .context.oauth_code_challenge then "    PKCE Challenge: \(.context.oauth_code_challenge)\n" else "") +
            (if .context.oauth_resources then "    Resources: \(.context.oauth_resources | join(", "))\n" else "") +
            (if .context.oauth_resource_count then "    Resource Count: \(.context.oauth_resource_count)\n" else "")
        elif .context.oauth_action == "callback" then
            "  🔄 OAuth Callback:\n" +
            "    State: \(.context.oauth_state // "N/A")\n" +
            "    Code: \(.context.oauth_code // "N/A")\n" +
            (if .context.oauth_error then "    Error: \(.context.oauth_error)\n" else "") +
            (if .context.oauth_error_description then "    Error Desc: \(.context.oauth_error_description)\n" else "") +
            (if .context.oauth_github_username then "    GitHub User: \(.context.oauth_github_username)\n" else "") +
            (if .context.oauth_github_email then "    GitHub Email: \(.context.oauth_github_email)\n" else "")
        elif .context.oauth_action == "token_exchange" then
            "  🎫 OAuth Token Exchange:\n" +
            "    Client ID: \(.context.oauth_client_id // "N/A")\n" +
            "    Grant Type: \(.context.oauth_grant_type // "N/A")\n" +
            (if .context.oauth_token_issued then "    ✅ Token Issued Successfully\n" else "") +
            (if .context.oauth_token_jti then "    Token ID (jti): \(.context.oauth_token_jti)\n" else "") +
            (if .context.oauth_username then "    Username: \(.context.oauth_username)\n" else "") +
            (if .context.oauth_email then "    Email: \(.context.oauth_email)\n" else "") +
            (if .context.oauth_scope then "    Scope: \(.context.oauth_scope)\n" else "") +
            (if .context.oauth_resources then "    Resources: \(.context.oauth_resources | join(", "))\n" else "") +
            (if .context.oauth_token_exp then "    Expires: \(.context.oauth_token_exp | todateiso8601)\n" else "")
        elif .context.oauth_action == "introspect" then
            "  🔍 OAuth Token Introspection:\n" +
            "    Client ID: \(.context.oauth_client_id // "N/A")\n" +
            (if .context.oauth_token_type_hint then "    Token Type Hint: \(.context.oauth_token_type_hint)\n" else "") +
            (if .context.oauth_token_active then "    ✅ Token Active: \(.context.oauth_token_active)\n" else "    ❌ Token Active: false\n") +
            (if .context.oauth_token_sub then "    Subject: \(.context.oauth_token_sub)\n" else "") +
            (if .context.oauth_token_username then "    Username: \(.context.oauth_token_username)\n" else "") +
            (if .context.oauth_token_scope then "    Scope: \(.context.oauth_token_scope)\n" else "") +
            (if .context.oauth_token_jti then "    Token ID: \(.context.oauth_token_jti)\n" else "") +
            (if .context.oauth_token_exp then "    Expires: \(.context.oauth_token_exp | todateiso8601)\n" else "") +
            (if .context.oauth_introspection_result then "    Full Result: \(.context.oauth_introspection_result | tostring)\n" else "")
        else
            "  OAuth Action: \(.context.oauth_action)\n"
        end
    else "" end) +
    (if .context.query and (.context.query | length) > 0 then "  Query: \(.context.query)\n" else "" end) +
    (if .context.user_agent and .context.user_agent != "" then "  User-Agent: \(.context.user_agent)\n" else "" end) +
    "---"
' 2>/dev/null || echo "$response" | jq '.'

echo
echo "=== Total logs: $(echo "$response" | jq -r '.total') (showing $(echo "$response" | jq -r '.logs | length')) ==="