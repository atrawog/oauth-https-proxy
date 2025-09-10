# ACTUAL Claude.ai MCP Connection Flow (Based on Real Logs)

## Executive Summary

Based on actual system logs and Redis data, here's what REALLY happens when Claude.ai connects to MCP endpoints, versus what the theoretical documentation suggests.

## Key Discoveries from Logs

### 1. Claude.ai's OAuth Client Registration

**ACTUAL Client Details** (from Redis):
```json
{
  "client_id": "client_VSMC7orqn6WQoElOov-Zvw",
  "client_name": "Claude",
  "redirect_uris": ["https://claude.ai/api/mcp/auth_callback"],
  "grant_types": ["authorization_code", "refresh_token"],
  "client_secret": "r7N1HygHrYBNVPEiDbusyioDnJJDCJH4_9fA6500d90",
  "registration_client_uri": "https://simple-oauth.atratest.org/register/client_VSMC7orqn6WQoElOov-Zvw"
}
```

**Key Insights**:
- Claude.ai uses a DIFFERENT callback URL than assumed: `/api/mcp/auth_callback` (not just `/callback`)
- Registration happened on `simple-oauth.atratest.org` (not `auth.atratest.org`)
- Client has been used 3 times (usage_count: 3)
- Last token issued at timestamp 1756540993

### 2. ACTUAL Connection Patterns

Claude.ai (IP: 34.162.102.82 from Google Cloud) connects to THREE different MCP endpoints:

#### A. WITH OAuth Authentication
```
simple-oauth.atratest.org
  User: atrawog
  Scopes: ["admin", "user", "mcp"]
  Client: client_VSMC7orqn6WQoElOov-Zvw
  Result: SSE streaming with ping messages
```

#### B. WITHOUT OAuth Authentication
```
simple.atratest.org
  Auth: (empty)
  Result: SSE streaming with ping messages

fast-echo.atratest.org
  Auth: (empty)
  Result: SSE streaming with ping messages
```

### 3. The REAL OAuth Flow

#### 3.1 Client Registration (One-Time)

Claude.ai registered its client directly at the proxy domain:
```http
POST https://simple-oauth.atratest.org/register
{
  "client_name": "Claude",
  "redirect_uris": ["https://claude.ai/api/mcp/auth_callback"],
  "grant_types": ["authorization_code", "refresh_token"],
  "scope": "openid profile email"
}
```

#### 3.2 Authorization Flow (First Connection)

1. **Claude.ai initiates OAuth**:
```
GET https://simple-oauth.atratest.org/authorize?
  client_id=client_VSMC7orqn6WQoElOov-Zvw&
  redirect_uri=https://claude.ai/api/mcp/auth_callback&
  resource=https://simple-oauth.atratest.org
```

2. **System redirects to GitHub** (NOT to auth.atratest.org first):
   - The proxy at simple-oauth.atratest.org handles OAuth directly
   - Uses its configured GitHub OAuth App (or falls back to environment variables)

3. **GitHub callback returns to proxy**:
```
GET https://simple-oauth.atratest.org/callback?code=<github_code>&state=<state>
```

4. **Scope assignment based on configuration**:
```json
{
  "oauth_admin_users": ["atrawog"],     // atrawog gets admin scope
  "oauth_user_users": ["*"],             // all users get user scope
  "oauth_mcp_users": ["*"]               // all users get mcp scope
}
```
Result: atrawog receives ALL three scopes

5. **Redirect back to Claude.ai**:
```
Location: https://claude.ai/api/mcp/auth_callback?code=<auth_code>&state=<state>
```

#### 3.3 Token Exchange

Claude.ai exchanges the authorization code:
```http
POST https://simple-oauth.atratest.org/token
{
  "grant_type": "authorization_code",
  "code": "<auth_code>",
  "client_id": "client_VSMC7orqn6WQoElOov-Zvw",
  "client_secret": "r7N1HygHrYBNVPEiDbusyioDnJJDCJH4_9fA6500d90",
  "redirect_uri": "https://claude.ai/api/mcp/auth_callback"
}
```

Returns JWT with:
- sub: "atrawog"
- scope: "admin user mcp"
- aud: ["https://simple-oauth.atratest.org"]

### 4. MCP Connection (With Token)

**From logs**:
```
[2025-08-30 08:07:02.893Z] [proxy_handler] ● [INFO] SSE chunk 15: 45 bytes
  Client: 34.162.102.82 → Proxy: simple-oauth.atratest.org
  Auth: User=atrawog | Scopes=["admin", "user", "mcp"] | Client=client_VSMC7orqn6WQoElOov-Zvw
```

The connection:
1. Uses Bearer token in Authorization header
2. Proxy validates JWT and extracts user/scopes
3. Adds headers: X-Auth-User, X-Auth-Scopes, X-Auth-Email
4. Forwards to backend: http://simple:3000/mcp
5. Backend sends SSE ping messages every 15 seconds

### 5. Multiple Simultaneous Connections

Claude.ai maintains PARALLEL connections to different MCP servers:
- **Request IDs show concurrent sessions**:
  - req-139849173551296 → simple-oauth.atratest.org (WITH auth)
  - req-139849169286784 → simple.atratest.org (NO auth)
  - req-139849171292896 → fast-echo.atratest.org (NO auth)

## What's Different from Theory

### 1. OAuth Server Location
- **Theory**: OAuth server at auth.atratest.org handles everything
- **Reality**: Each proxy can handle OAuth directly (simple-oauth.atratest.org/register)

### 2. Registration Endpoint
- **Theory**: Register at auth domain first, then connect to resource
- **Reality**: Register directly at the resource domain

### 3. Callback URL
- **Theory**: Simple /callback endpoint
- **Reality**: Claude.ai uses `/api/mcp/auth_callback` specific endpoint

### 4. Multiple Connections
- **Theory**: Single authenticated connection to MCP
- **Reality**: Claude.ai connects to multiple MCP endpoints, some with auth, some without

### 5. SSE Streaming Pattern
- **Theory**: Complex MCP protocol messages
- **Reality**: Simple ping messages every 15 seconds in SSE format

## Authentication State from Logs

### For simple-oauth.atratest.org (OAuth-protected):
```
Auth: User=atrawog | Scopes=["admin", "user", "mcp"] | Client=client_VSMC7orqn6WQoElOov-Zvw
```

### For simple.atratest.org (No auth):
```
Auth: (empty)
```

This shows the proxy correctly enforces authentication based on configuration.

## Token Usage Pattern

From the logs showing "Access token invalid, attempting refresh":
- Tokens expire after 30 minutes (1800 seconds)
- Claude.ai automatically refreshes tokens
- Multiple active tokens exist in Redis simultaneously

## The ACTUAL Request Flow

```
Claude.ai (34.162.102.82) 
    ↓
[HTTPS Request with Bearer Token]
    ↓
Dispatcher (Port 443)
    ↓ [Extract hostname: simple-oauth.atratest.org]
    ↓ [Lookup port in Redis: 13xxx]
    ↓ [Add PROXY protocol header]
    ↓
HypercornInstance (Port 13xxx)
    ↓ [Parse PROXY protocol]
    ↓ [Terminate SSL]
    ↓
ProxyOnlyApp 
    ↓
UnifiedProxyHandler
    ↓ [Validate JWT token]
    ↓ [Check scopes: requires "mcp"]
    ↓ [User has ["admin", "user", "mcp"] ✓]
    ↓ [Add X-Auth-* headers]
    ↓
Backend (simple:3000)
    ↓ [Trust headers completely]
    ↓ [Send SSE response]
    ↓
SSE Stream: "ping - 2025-08-30 08:07:02.891615+00:00"
```

## Key Configuration Points

### simple-oauth.atratest.org Configuration:
```json
{
  "auth_enabled": true,
  "auth_required_users": ["*"],           // All GitHub users allowed
  "auth_allowed_scopes": ["admin", "user", "mcp"],
  "oauth_admin_users": ["atrawog"],       // atrawog gets admin
  "oauth_user_users": ["*"],              // everyone gets user
  "oauth_mcp_users": ["*"],               // everyone gets mcp
  "resource_endpoint": "/mcp",
  "resource_scopes": ["admin", "user", "mcp"]
}
```

## Debug Commands That Show Reality

```bash
# See Claude.ai's actual client registration
just redis "GET oauth:client:client_VSMC7orqn6WQoElOov-Zvw"

# Check active connections from Claude.ai
just log ip 34.162.102.82

# See OAuth-protected connections
just log hostname simple-oauth.atratest.org

# See non-OAuth connections
just log hostname simple.atratest.org

# Check active tokens
just redis "KEYS oauth:token:*"
```

## Summary of Actual vs Theoretical

| Aspect | Theoretical | Actual (from logs) |
|--------|------------|-------------------|
| OAuth Server | Centralized at auth.atratest.org | Each proxy can handle OAuth |
| Registration | Via /register on auth server | Direct on resource domain |
| Client Callback | Generic /callback | Specific /api/mcp/auth_callback |
| Authentication | All MCP connections authenticated | Mixed - some with, some without |
| Token Client | Generic MCP client | Specific client_VSMC7orqn6WQoElOov-Zvw |
| Connections | Single authenticated session | Multiple parallel connections |
| MCP Protocol | Complex JSON-RPC | Simple SSE with ping messages |
| User | Generic user | Specifically "atrawog" |
| Scopes | Requested scopes honored | Assigned by proxy configuration |

## Conclusion

The ACTUAL implementation is more flexible and distributed than the theoretical documentation suggests:
1. OAuth can be handled directly by resource proxies
2. Claude.ai maintains multiple connections with different auth states
3. The system supports both authenticated and non-authenticated MCP endpoints
4. Scope assignment is determined by proxy configuration, not client request
5. The implementation is working correctly as designed, just differently than initially documented