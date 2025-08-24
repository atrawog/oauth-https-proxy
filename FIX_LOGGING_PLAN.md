# Fix Comprehensive Logging Plan

## Critical Issues Identified

1. **Wrong Client IP**: Getting Docker network IP (172.20.0.1) instead of real client IP
2. **Missing Critical Info**: No proxy_hostname, request path, user agent, headers in logs
3. **No OAuth Flow Logging**: Zero logging for OAuth authorization, token exchange, validation
4. **No MCP Logging**: No specific logging for MCP protocol requests
5. **Useless Log Entries**: Current logs provide no debugging value

## Root Cause Analysis

1. **Why did it fail?** Client IP extraction looks for wrong headers
2. **Why did that condition exist?** Not checking X-Forwarded-For, X-Real-IP properly
3. **Why was it allowed?** Insufficient testing of logging output
4. **Why wasn't it caught?** No verification of log usefulness
5. **Why will it never happen again?** Comprehensive header checking and structured logging

## Implementation Plan

### 1. Fix Client IP Extraction

```python
def get_real_client_ip(request: Request) -> str:
    """Extract real client IP from headers, checking multiple sources."""
    # Priority order for IP extraction
    headers_to_check = [
        'x-forwarded-for',     # Standard proxy header (first IP in chain)
        'x-real-ip',           # Common nginx header
        'cf-connecting-ip',    # Cloudflare
        'true-client-ip',      # Cloudflare Enterprise
        'x-client-ip',         # General proxy
        'x-original-forwarded-for',  # Some proxies
    ]
    
    for header in headers_to_check:
        value = request.headers.get(header)
        if value:
            # X-Forwarded-For can have multiple IPs, take first
            ip = value.split(',')[0].strip()
            if ip and ip != 'unknown':
                return ip
    
    # Fallback to direct client
    if request.client:
        return request.client.host
    
    return 'unknown'
```

### 2. Enhance Logging Context

Every log entry MUST include:
- `proxy_hostname`: Which proxy is being accessed
- `client_ip`: Real client IP (not Docker IP)
- `client_hostname`: Resolved hostname
- `request_path`: Full path being accessed
- `request_method`: HTTP method
- `user_agent`: Client user agent
- `referer`: HTTP referer if present
- `request_id`: Unique request identifier
- `response_status`: HTTP response code
- `response_time_ms`: Request processing time
- `response_size`: Response body size

### 3. OAuth Flow Logging

Add detailed logging for:
- **Authorization Request**: Log all params, redirect URL, state, resource
- **Authorization Callback**: Log code, state validation, token exchange
- **Token Request**: Log grant type, client auth, scopes requested
- **Token Response**: Log issued scopes, expiry, refresh token presence
- **Token Validation**: Log validation result, user, scopes, audience
- **Token Refresh**: Log refresh attempts and results

### 4. MCP-Specific Logging

For MCP endpoints, additionally log:
- `mcp_version`: Protocol version from headers
- `mcp_method`: MCP method being called
- `mcp_session_id`: Session identifier
- `mcp_tool`: Tool being invoked
- `mcp_streaming`: Whether using SSE

### 5. Structured Logging Format

Use consistent structured format:
```python
log_info(
    "OAuth authorization request",
    component="oauth",
    action="authorize_request",
    proxy_hostname=proxy_hostname,
    client_ip=client_ip,
    client_hostname=client_hostname,
    request_path=request.url.path,
    request_method=request.method,
    user_agent=request.headers.get('user-agent'),
    referer=request.headers.get('referer'),
    response_type=response_type,
    client_id=client_id,
    redirect_uri=redirect_uri,
    scope=scope,
    state=state[:20] + "..." if state else None,  # Truncate for security
    resource=resource,
    pkce_challenge=code_challenge is not None,
)
```

## Files to Update

1. **src/proxy/unified_handler.py**
   - Fix client IP extraction
   - Add comprehensive logging context
   - Log all auth decisions
   - Log routing decisions with full context

2. **src/api/oauth/routes.py**
   - Add detailed logging for /authorize endpoint
   - Add detailed logging for /token endpoint
   - Add detailed logging for /introspect endpoint
   - Log token validation results

3. **src/api/routers/mcp/mcp_server.py**
   - Add MCP-specific logging
   - Log protocol version negotiation
   - Log tool invocations
   - Log session management

4. **src/shared/logger.py** (if needed)
   - Ensure TRACE level works properly
   - Add helper for client IP extraction

## Success Criteria

After implementation:
1. Every request shows real client IP (not Docker IP)
2. Every log entry includes proxy_hostname, path, method, user agent
3. OAuth flow is fully traceable through logs
4. MCP requests have protocol-specific logging
5. Can debug any issue from logs alone
6. Performance metrics (response time, size) in logs

## Testing Plan

1. Make request from external client, verify real IP in logs
2. Test OAuth flow, verify all steps logged
3. Test MCP endpoint, verify protocol logging
4. Test various proxy hostnames, verify in logs
5. Test error cases, verify detailed error logging