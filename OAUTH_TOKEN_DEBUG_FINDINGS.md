# OAuth Token and MCP Endpoint Debug Findings

## Summary

The root cause of the 401/503 errors from Claude IPs is that OAuth tokens are being issued with the wrong audience. The tokens have `aud: "https://auth.atradev.org"` but Claude needs to access `everything.atradev.org`, causing audience validation failures.

## Key Findings

### 1. Token Exchange Issue (IP: 34.162.102.82)

From the enhanced logging at 2025-08-03T17:54:02:

```json
{
  "resource": null,
  "resource_count": 0,
  "token_audience": "https://auth.atradev.org",
  "authorized_resources": [],
  "requested_resources": []
}
```

**Problem**: Claude is not including any `resource` parameter in the token request, so the OAuth server defaults to issuing tokens with `aud: "https://auth.atradev.org"`.

### 2. Recent 500 Errors on /token Endpoint

Multiple 500 errors were caused by:
- `TypeError: object of type 'async_generator' has no len()` - Fixed
- `AttributeError: 'MCPMetadata' object has no attribute 'get'` - Fixed

### 3. Service Connections

- 503 errors at 17:00:21 and 17:12:57 indicate the backend MCP service was unavailable
- 200 responses at 17:00:19 and 17:12:56 show successful token exchanges

## Enhanced Logging Implemented

### 1. OAuth Token Generation (src/api/oauth/routes.py)
- Complete token exchange request details including resources, form data, headers
- Full JWT token claims after generation
- Resource validation and audience tracking

### 2. Proxy Handler (src/proxy/handler.py)
- Detailed backend connection attempts with timeout configs
- Authorization header extraction with JWT preview
- Enhanced error logging with full context

### 3. Request/Response Logging (src/shared/logging.py)
- Automatic enhanced logging for critical endpoints (/token, /mcp, etc.)
- Request body parsing for OAuth form data
- Response body logging for error analysis
- Increased size limits for critical endpoints

## Fixes Applied

### 1. Fixed async_generator error
```python
content_length="async_generator" if hasattr(content, '__aiter__') else (len(content) if content else 0)
```

### 2. Fixed MCPMetadata attribute error
```python
mcp_enabled=getattr(target.mcp_metadata, 'enabled', False) if hasattr(target, 'mcp_metadata') and target.mcp_metadata else False
```

### 3. Fixed Redis boolean serialization
Changed all boolean values to strings in Redis operations to prevent serialization errors.

## Root Cause Analysis

1. **Why did it fail?** - OAuth tokens have wrong audience (`auth.atradev.org` instead of `everything.atradev.org`)
2. **Why did that condition exist?** - Claude clients are not including the `resource` parameter in token requests
3. **Why was it allowed?** - The OAuth server defaults to self-audience when no resource is specified
4. **Why wasn't it caught?** - Logging wasn't detailed enough to see token audience values
5. **Why will it never happen again?** - Enhanced logging now shows complete token details including audience

## Recommendations

1. **Client-side fix**: Claude clients need to include `resource=https://everything.atradev.org` in their token requests
2. **Server-side consideration**: Consider allowing cross-resource access or implementing an audience mapper
3. **Monitoring**: The enhanced logging now captures all necessary details for debugging OAuth issues

## Usage

To monitor OAuth issues:
```bash
# Check recent token exchanges
just logs api | grep "OAuth token issued"

# Check for audience validation failures  
just logs api | grep "invalid_audience"

# Check specific IP activity
just app-logs-by-ip <ip>
```