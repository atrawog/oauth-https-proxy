# CORRECTED: Actual Claude.ai HTTP Request Flow

## Important Correction

After deeper investigation, I need to correct my previous analysis. The well-known endpoints work differently than I initially reported.

## Actual Well-Known Endpoint Behavior

### Standard Endpoints (WORKING):
```bash
GET /.well-known/oauth-authorization-server
→ Returns 200 with OAuth metadata
{
  "issuer": "https://simple-oauth.atratest.org",
  "authorization_endpoint": "https://simple-oauth.atratest.org/authorize",
  "token_endpoint": "https://simple-oauth.atratest.org/token",
  "jwks_uri": "https://simple-oauth.atratest.org/jwks",
  ...
}

GET /.well-known/oauth-protected-resource
→ Returns 200 with protected resource metadata
{
  "resource": "https://simple-oauth.atratest.org/mcp",
  "authorization_servers": ["https://simple-oauth.atratest.org"],
  "scopes_supported": ["admin", "user", "mcp"],
  ...
}
```

### Non-Standard Endpoints (NOT WORKING):
```bash
GET /.well-known/oauth-authorization-server/mcp
→ Returns 404 Not Found

GET /.well-known/oauth-protected-resource/mcp
→ Returns 404 Not Found
```

## Confusing Log Entries Explained

The logs show requests to `/mcp` suffixed endpoints:
```
/.well-known/oauth-authorization-server/mcp
/.well-known/oauth-protected-resource/mcp
```

But these are **404 errors**! The confusion arose because:
1. The logs show these paths being requested
2. But they don't exist and return 404
3. Some log entries were from other IPs (88.99.211.11), not Claude.ai

## What Actually Happens

### Discovery Phase (Reality)

Claude.ai or related tools might be:
1. **Trying non-standard endpoints first** (with `/mcp` suffix) → Get 404
2. **Falling back to standard endpoints** → Get 200 with proper metadata
3. **Or** these `/mcp` requests are from different testing tools, not Claude.ai itself

### The Actual Successful Flow

Based on the working endpoints and successful connections:

```
1. Discovery (Standard Endpoints)
   GET /.well-known/oauth-authorization-server → 200
   GET /.well-known/oauth-protected-resource → 200

2. Authentication
   POST /token → 200 (using stored authorization code)

3. MCP Connection
   POST /mcp (with Bearer token) → 200
   GET /mcp (SSE stream) → 200
```

## Key Corrections

### WRONG (My Previous Analysis):
- ❌ "Claude.ai uses MCP-specific well-known endpoints with /mcp suffix"
- ❌ "The /mcp suffixed endpoints return 200"
- ❌ "This is how Claude expects it to work"

### RIGHT (Actual Behavior):
- ✅ Standard well-known endpoints work correctly
- ✅ The `/mcp` suffix endpoints don't exist (404)
- ✅ Claude.ai successfully connects using standard OAuth flow
- ✅ Some tools/clients may probe for non-standard endpoints

## Why the Confusion?

1. **Mixed Log Sources**: Logs contained requests from multiple IPs
2. **Failed Requests in Logs**: Presence in logs doesn't mean success
3. **Route Forwarding Logs**: Internal routing logs showed paths that weren't actually successful

## The Real Discovery Mechanism

Claude.ai (or the MCP client) likely:
1. Has the OAuth endpoints pre-configured or
2. Successfully uses the standard well-known discovery endpoints
3. The `/mcp` suffix attempts might be:
   - Probing for MCP-specific extensions (that don't exist)
   - From a different client/tool
   - Part of a fallback mechanism

## Verified Working Endpoints

```bash
# OAuth Metadata (WORKS)
curl https://simple-oauth.atratest.org/.well-known/oauth-authorization-server
→ 200 OK

# Protected Resource Metadata (WORKS)
curl https://simple-oauth.atratest.org/.well-known/oauth-protected-resource
→ 200 OK

# Token Exchange (WORKS)
POST https://simple-oauth.atratest.org/token
→ 200 OK

# MCP Endpoint (WORKS)
GET/POST https://simple-oauth.atratest.org/mcp
→ 200 OK (with valid Bearer token)
```

## Actual Request Sequence from Claude.ai

Based on successful connections observed:

1. **Token Exchange** (using existing authorization code):
   ```
   POST /token
   → Client: client_VSMC7orqn6WQoElOov-Zvw
   → Returns: JWT with scopes ["admin", "user", "mcp"]
   ```

2. **MCP Connections** (with Bearer token):
   ```
   POST /mcp → Tool invocations
   GET /mcp → SSE streaming
   ```

## Summary

The system works correctly with standard OAuth well-known endpoints. The `/mcp` suffix attempts seen in logs are failed requests (404) that don't affect the actual flow. Claude.ai successfully:
1. Obtains tokens via standard OAuth
2. Connects to MCP endpoints with proper authentication
3. Maintains SSE streams for real-time communication

The confusion came from misinterpreting failed request logs as successful ones. The standard OAuth discovery mechanism is what's actually working.