# Complete HTTP Request Flow from Claude.ai (Based on Actual Logs)

## Executive Summary

This document shows EVERY HTTP request Claude.ai makes when connecting to MCP endpoints, based on actual system logs. Claude.ai (IP: 34.162.102.82 from Google Cloud) follows a sophisticated discovery and authentication flow.

## Timeline of Requests (Chronological Order)

### Phase 1: MCP Discovery and Metadata Requests

#### 1.1 Initial Well-Known Discovery Requests

Claude.ai first tries to discover OAuth and MCP metadata:

```
[08:03:08.341] GET /.well-known/oauth-protected-resource
  → simple-oauth.atratest.org
  → Result: 404 Not Found

[08:03:08.715] GET /.well-known/oauth-protected-resource/mcp
  → simple-oauth.atratest.org
  → Forwarded to: http://api:9000/.well-known/oauth-protected-resource/mcp
  → Result: 200 OK (returns MCP resource metadata)

[08:03:08.720] GET /.well-known/oauth-authorization-server
  → simple-oauth.atratest.org
  → Result: 404 Not Found

[08:03:12.743] GET /.well-known/oauth-authorization-server/mcp
  → simple-oauth.atratest.org
  → Forwarded to: http://api:9000/.well-known/oauth-authorization-server/mcp
  → Result: 200 OK (returns OAuth server metadata)
```

**Key Insight**: Claude.ai appends `/mcp` to standard well-known endpoints to get MCP-specific metadata!

### Phase 2: OAuth Token Exchange

#### 2.1 Token Request (Using Previously Obtained Authorization Code)

```
[08:03:13.261] POST /token
  → simple-oauth.atratest.org
  → Path excluded from auth (matched /token in auth_excluded_paths)
  → Forwarded to: http://api:9000/token
  → Client: client_VSMC7orqn6WQoElOov-Zvw
  → Result: 200 OK (40ms)
  → Returns: JWT access token with scopes ["admin", "user", "mcp"]
```

### Phase 3: MCP Connection Attempts

#### 3.1 Initial MCP Connections (Multiple Parallel Requests)

Claude.ai connects to THREE different MCP servers simultaneously:

**To simple-oauth.atratest.org (WITH OAuth):**
```
[08:03:15.818] POST /mcp
  → Auth: Bearer token with User=atrawog, Scopes=["admin", "user", "mcp"]
  → Result: 200 OK

[08:03:16.397] POST /mcp
  → Multiple tool invocations
  → Result: 200 OK (197ms)
```

**To simple.atratest.org (NO OAuth):**
```
[08:03:16.524] GET /mcp
  → No authentication
  → Result: 200 OK (SSE stream established)

[08:03:16.537] POST /mcp
  → No authentication
  → Result: 202 Accepted
```

**To fast-echo.atratest.org (NO OAuth):**
```
[08:03:16.552] GET /mcp
  → No authentication
  → Result: 200 OK (SSE stream)

[08:03:16.561] POST /mcp
  → No authentication
  → Result: 202 Accepted
```

### Phase 4: MCP Protocol Communication

#### 4.1 Continuous MCP Requests

Claude.ai sends various MCP protocol messages:

```
[08:03:16-17] Multiple POST /mcp requests
  → JSON-RPC messages for:
    - Tool discovery
    - Session initialization
    - Capability negotiation
    - Tool invocations
  → Mix of 200 OK and 202 Accepted responses
```

#### 4.2 SSE Streaming

After initial setup, Claude maintains SSE connections:

```
[08:03:17.869] GET /mcp → SSE stream opened
[08:03:17-08:08:18] SSE chunks with ping messages every 15 seconds
[08:08:18.383] SSE stream ended after 20 chunks
```

## Complete Request Pattern Summary

### 1. Discovery Phase (Metadata Fetching)
```
GET /.well-known/oauth-protected-resource        → 404
GET /.well-known/oauth-protected-resource/mcp    → 200 (MCP metadata)
GET /.well-known/oauth-authorization-server      → 404
GET /.well-known/oauth-authorization-server/mcp  → 200 (OAuth metadata)
```

### 2. Authentication Phase
```
POST /token                                       → 200 (JWT token)
```

### 3. MCP Connection Phase
```
POST /mcp (with Bearer token)                    → 200 (authenticated)
GET /mcp  (SSE stream)                          → 200 (streaming)
POST /mcp (multiple tool calls)                  → 200/202
```

## Key Discoveries

### 1. MCP-Specific Well-Known Endpoints

Claude.ai tries BOTH standard and MCP-specific well-known URLs:
- Standard: `/.well-known/oauth-protected-resource` (404)
- MCP-specific: `/.well-known/oauth-protected-resource/mcp` (200)

This suggests Claude.ai expects MCP servers to use `/mcp` suffix for metadata!

### 2. Mixed Authentication Strategy

Claude.ai connects to:
- **OAuth-protected servers**: Uses Bearer token (simple-oauth.atratest.org)
- **Public servers**: No authentication (simple.atratest.org, fast-echo.atratest.org)

### 3. Parallel Connection Management

Claude.ai maintains multiple simultaneous connections:
- Request IDs show concurrent sessions (req-139849173551296, req-139849169286784, etc.)
- Different authentication states per connection
- Independent SSE streams

### 4. Token Exchange Without Prior Authorization Flow

The logs show Claude.ai directly POST to `/token` without going through `/authorize` first, suggesting:
- Claude.ai already had an authorization code stored
- Or using refresh token from previous session
- Client credentials: `client_VSMC7orqn6WQoElOov-Zvw`

### 5. Path Exclusions Working Correctly

The `/token` endpoint correctly bypassed authentication:
```
"Path /token excluded from auth (matched /token)"
```

This prevents the circular dependency (needing token to get token).

## HTTP Methods and Endpoints Used

### By Frequency:
```
25 POST /mcp       - MCP protocol messages
15 GET /mcp        - SSE streaming connections
 2 GET /.well-known/oauth-authorization-server/mcp
 2 GET /.well-known/oauth-protected-resource/mcp
 1 POST /token     - OAuth token exchange
 1 GET /.well-known/oauth-protected-resource
 1 GET /.well-known/oauth-authorization-server
```

### By Purpose:
- **Discovery**: `/.well-known/*` endpoints
- **Authentication**: `/token` endpoint
- **Protocol**: `/mcp` endpoint (both GET for SSE, POST for RPC)

## Authentication Headers Observed

### For OAuth-Protected Requests:
```
Authorization: Bearer <JWT>
→ Proxy extracts: User=atrawog, Scopes=["admin", "user", "mcp"]
→ Adds headers:
  X-Auth-User: atrawog
  X-Auth-Scopes: admin user mcp
  X-Auth-Email: <email>
  X-Auth-Client-Id: client_VSMC7orqn6WQoElOov-Zvw
```

### For Public Endpoints:
```
No Authorization header
→ Auth: (empty)
```

## Response Times

- **Metadata endpoints**: 10-28ms
- **Token exchange**: 40ms
- **MCP POST**: 5-302ms (varies by operation)
- **MCP GET (SSE)**: 2-16ms to establish stream

## Error Responses

### 404 Not Found:
- `/.well-known/oauth-protected-resource` (standard endpoint not implemented)
- `/.well-known/oauth-authorization-server` (standard endpoint not implemented)

### Successful Responses:
- All `/mcp` suffixed well-known endpoints return 200
- Token exchange successful
- MCP connections established

## Routing Decisions (From Logs)

```
simple-oauth.atratest.org/token
  → Route: token
  → Target: http://api:9000
  → Auth: Excluded

simple-oauth.atratest.org/.well-known/oauth-protected-resource/mcp
  → Route: oauth-protected-resource
  → Target: http://api:9000
  → Auth: Not required (public endpoint)

simple-oauth.atratest.org/mcp
  → Route: (default)
  → Target: http://simple:3000
  → Auth: Required (OAuth validation)
```

## Complete Flow Diagram

```
Claude.ai
    │
    ├─[1] Discovery Phase
    │     ├─ GET /.well-known/oauth-protected-resource → 404
    │     ├─ GET /.well-known/oauth-protected-resource/mcp → 200
    │     ├─ GET /.well-known/oauth-authorization-server → 404
    │     └─ GET /.well-known/oauth-authorization-server/mcp → 200
    │
    ├─[2] Authentication Phase
    │     └─ POST /token → 200 (JWT token received)
    │
    └─[3] MCP Connection Phase
          ├─ simple-oauth.atratest.org (WITH OAuth)
          │     ├─ POST /mcp (authenticated) → 200
          │     └─ GET /mcp (SSE stream) → 200
          │
          ├─ simple.atratest.org (NO OAuth)
          │     ├─ POST /mcp → 202
          │     └─ GET /mcp (SSE stream) → 200
          │
          └─ fast-echo.atratest.org (NO OAuth)
                ├─ POST /mcp → 202
                └─ GET /mcp (SSE stream) → 200
```

## Conclusions

1. **Claude.ai uses MCP-specific well-known endpoints** with `/mcp` suffix
2. **Mixed authentication model** - some servers require OAuth, others don't
3. **Efficient token reuse** - doesn't re-authorize for each connection
4. **Parallel connections** to multiple MCP servers simultaneously
5. **Smart discovery** - tries standard endpoints first, then MCP-specific
6. **Proper auth exclusion** - `/token` endpoint correctly bypasses auth
7. **SSE for real-time** - maintains persistent connections with ping/pong

This actual flow shows Claude.ai is more sophisticated than the theoretical documentation suggests, with intelligent discovery mechanisms and parallel connection management.