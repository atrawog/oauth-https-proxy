# How Claude.ai Connects to https://simple-oauth.atratest.org/mcp

## Executive Summary
Claude.ai connects to the MCP endpoint at `https://simple-oauth.atratest.org/mcp` through a sophisticated OAuth-protected reverse proxy system. The connection flows through multiple layers: Claude.ai → Dispatcher → HypercornInstance → ProxyOnlyApp → UnifiedProxyHandler → Backend MCP Server, with OAuth validation happening at the proxy layer.

## System Architecture Overview

```
Claude.ai Client
     ↓ HTTPS Request
[Port 443: Dispatcher] (Pure TCP Forwarder)
     ↓ Extract hostname via SNI
     ↓ Lookup port in Redis
     ↓ Add PROXY protocol header
     ↓ Forward raw TCP
[Port 13xxx: HypercornInstance] (SSL Termination)
     ↓ Parse PROXY protocol
     ↓ Terminate SSL/TLS
     ↓ Forward HTTP
[ProxyOnlyApp] (Minimal Starlette)
     ↓ Route all requests
[UnifiedProxyHandler] (OAuth + Routing)
     ↓ Validate OAuth JWT
     ↓ Check scopes & users
     ↓ Add auth headers
     ↓ Forward to backend
[Port 3000: MCP Server] (simple:3000)
     ↓ Process MCP request
     ↓ Return SSE or JSON
```

## Detailed Connection Flow

### 1. Initial Request from Claude.ai

Claude.ai initiates an HTTPS connection to `https://simple-oauth.atratest.org/mcp`:

```http
GET /mcp HTTP/1.1
Host: simple-oauth.atratest.org
Accept: text/event-stream
Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...
User-Agent: Claude/1.0
```

### 2. Dispatcher Reception (Port 443)

The Unified Dispatcher receives the TCP connection:

**File**: `src/dispatcher/unified_dispatcher.py`

```python
# Extract hostname from TLS SNI (Server Name Indication)
hostname = extract_hostname_from_sni(client_hello)  # "simple-oauth.atratest.org"

# Lookup target port in Redis
port = await redis.hget("proxy:ports:mappings", hostname)  # e.g., 13001 (HTTPS)

# Add PROXY protocol header to preserve client IP
proxy_header = f"PROXY TCP4 {client_ip} 127.0.0.1 {client_port} {port}\r\n"

# Forward raw TCP connection
await forward_tcp(client_socket, target_host="127.0.0.1", target_port=port)
```

**Key Points**:
- Dispatcher is a PURE TCP forwarder - no HTTP parsing
- Uses h11 library for safe hostname extraction from HTTP
- Uses SNI for HTTPS hostname extraction
- PROXY protocol preserves real client IP

### 3. HypercornInstance Processing (Port 13xxx)

The proxy instance for `simple-oauth.atratest.org` receives the connection:

**Configuration from Redis**:
```json
{
  "proxy_hostname": "simple-oauth.atratest.org",
  "target_url": "http://simple:3000",
  "cert_name": "simple-oauth.atratest.org",
  "enable_https": true,
  "auth_enabled": true,
  "auth_required_users": ["*"],
  "auth_allowed_scopes": ["admin", "user", "mcp"],
  "oauth_admin_users": ["atrawog"],
  "oauth_user_users": ["*"],
  "oauth_mcp_users": ["*"],
  "resource_endpoint": "/mcp",
  "resource_scopes": ["admin", "user", "mcp"]
}
```

**Processing Steps**:
1. Parse PROXY protocol header to get real client IP
2. Terminate SSL using certificate from Redis
3. Forward HTTP request to ProxyOnlyApp

### 4. ProxyOnlyApp Routing

**File**: `src/proxy/proxy_only_app.py`

The minimal Starlette application routes ALL requests to UnifiedProxyHandler:

```python
app = Starlette(routes=[
    Route("/{path:path}", UnifiedProxyHandler, methods=["GET", "POST", ...])
])
```

### 5. UnifiedProxyHandler OAuth Validation

**File**: `src/proxy/unified_handler.py` (912 lines of battle-tested logic)

#### 5.1 OAuth Token Validation

```python
# Extract JWT from Authorization header
auth_header = request.headers.get("Authorization")
token = auth_header.replace("Bearer ", "")

# Validate JWT signature (RS256)
payload = jwt.decode(
    token,
    public_key,
    algorithms=["RS256"],
    audience="https://simple-oauth.atratest.org"
)

# Extract user info
auth_user = payload.get("sub")  # GitHub username
auth_scopes = payload.get("scope", "").split()  # ["admin", "user", "mcp"]
auth_email = payload.get("email")
```

#### 5.2 Scope Requirements Check

For `/mcp` endpoint, the handler checks scope requirements:

```python
SCOPE_REQUIREMENTS = [
    (r".*", r"/mcp.*", ["mcp"]),  # MCP endpoints require 'mcp' scope
]

# Check if user has required scope
if "mcp" not in auth_scopes:
    return JSONResponse(
        status_code=401,
        headers={"WWW-Authenticate": build_www_authenticate_header(proxy_config)}
    )
```

#### 5.3 User Allowlist Validation

```python
# Check per-proxy user allowlist
auth_required_users = proxy_config.get("auth_required_users", [])

if auth_required_users and auth_required_users != ["*"]:
    if auth_user not in auth_required_users:
        return JSONResponse(status_code=403, content={"error": "User not allowed"})
```

#### 5.4 Add Authentication Headers

```python
# Add trusted headers for backend
custom_headers = {
    "X-Auth-User": auth_user,
    "X-Auth-Scopes": " ".join(auth_scopes),
    "X-Auth-Email": auth_email,
    "X-Real-IP": client_ip,  # From PROXY protocol
}
```

### 6. Backend Request Forwarding

#### 6.1 MCP SSE Detection

```python
# Special handling for MCP endpoint
is_mcp_request = request.url.path == '/mcp'
accept_header = headers.get('accept', '').lower()
expects_sse = 'text/event-stream' in accept_header

if is_mcp_request and request.method == "GET":
    # Use streaming for SSE responses
    return await stream_sse_response()
```

#### 6.2 Forward to Backend

```python
# Target URL from proxy config
target_url = "http://simple:3000/mcp"  # Docker service name

# Forward request with auth headers
async with httpx.AsyncClient() as client:
    response = await client.request(
        method=request.method,
        url=target_url,
        headers=custom_headers,
        content=await request.body()
    )
```

### 7. MCP Server Processing

The backend MCP server at `http://simple:3000` receives:

```http
GET /mcp HTTP/1.1
Host: simple-oauth.atratest.org
X-Auth-User: atrawog
X-Auth-Scopes: admin user mcp
X-Auth-Email: atrawog@example.com
X-Real-IP: 203.0.113.1
Accept: text/event-stream
```

The MCP server:
1. Trusts the `X-Auth-*` headers completely (proxy validated)
2. Processes the MCP request
3. Returns SSE stream or JSON response

### 8. Response Flow Back

The response flows back through the same path in reverse:

```
MCP Server → UnifiedProxyHandler → ProxyOnlyApp → HypercornInstance → Dispatcher → Claude.ai
```

For SSE responses, the system maintains:
- Keep-alive connections
- No buffering (`X-Accel-Buffering: no`)
- Proper `text/event-stream` content type
- Real-time streaming

## OAuth Authentication Details

### JWT Token Structure

Claude.ai presents a JWT token with:

```json
{
  "sub": "atrawog",                           // GitHub username
  "email": "atrawog@example.com",            // GitHub email
  "scope": "admin user mcp",                  // Assigned scopes
  "aud": "https://simple-oauth.atratest.org", // Resource URI
  "iss": "https://auth.atratest.org",        // OAuth issuer
  "exp": 1735650000,                         // Expiry time
  "iat": 1735648200                          // Issued at
}
```

### Scope Assignment

Scopes are assigned based on proxy configuration:

```python
# From proxy config in Redis
oauth_admin_users = ["atrawog"]  # Gets 'admin' scope
oauth_user_users = ["*"]         # All users get 'user' scope
oauth_mcp_users = ["*"]           # All users get 'mcp' scope
```

### WWW-Authenticate Header

On authentication failure, the system returns RFC 9728-compliant header:

```http
HTTP/1.1 401 Unauthorized
WWW-Authenticate: Bearer 
  realm="simple-oauth.atratest.org",
  as_uri="https://auth.atratest.org",
  resource_uri="https://simple-oauth.atratest.org",
  scope="mcp"
```

## Key Architecture Principles

### 1. Pure TCP Forwarding at Dispatcher
- Dispatcher ONLY extracts hostname and forwards TCP
- No HTTP parsing, routing, or modification
- Uses h11 for safe hostname extraction

### 2. OAuth at the Application Layer
- OAuth validation happens in UnifiedProxyHandler
- Full context available: routes, scopes, backends
- Complete validation: JWT, scopes, user allowlists

### 3. Trust Boundary
- Proxy validates OAuth completely
- Backend trusts `X-Auth-*` headers absolutely
- No dual validation overhead

### 4. PROXY Protocol for IP Preservation
- Internal use only (dispatcher → proxy instances)
- Preserves real client IP for logging/security
- Not exposed externally

### 5. Redis-Based Configuration
- All configuration in Redis
- Port mappings persist across restarts
- Dynamic updates without service restart

## Port Allocation

The system uses deterministic port allocation:

```python
# Port ranges
HTTP_PROXY_PORTS = 12000-12999
HTTPS_PROXY_PORTS = 13000-13999

# Hash-based preferred port for consistency
preferred_port = 13000 + (hash(hostname) % 1000)
```

For `simple-oauth.atratest.org`:
- Likely gets port 13xxx (HTTPS range)
- Mapping stored in Redis: `proxy:ports:mappings`
- Survives restarts due to persistence

## Debugging the Connection

### Check Proxy Configuration
```bash
just proxy show simple-oauth.atratest.org
```

### View Real-Time Logs
```bash
just log follow | grep simple-oauth
```

### Check OAuth Validation
```bash
just log oauth-debug | grep simple-oauth
```

### Monitor SSE Streaming
```bash
just log hostname simple-oauth.atratest.org | grep SSE
```

### Check Port Mapping
```bash
just redis "HGET proxy:ports:mappings simple-oauth.atratest.org"
```

## Common Issues and Solutions

### 1. 401 Unauthorized
- **Cause**: Invalid or expired JWT token
- **Solution**: Refresh token via OAuth flow
- **Debug**: Check `just log oauth-debug`

### 2. 403 Forbidden
- **Cause**: User not in allowlist or missing scope
- **Solution**: Update `oauth_mcp_users` configuration
- **Debug**: Check user in `just proxy show <hostname>`

### 3. SSE Not Streaming
- **Cause**: Buffering in proxy chain
- **Solution**: Ensure `X-Accel-Buffering: no` header
- **Debug**: Check `just log hostname <hostname> | grep chunk`

### 4. Connection Timeout
- **Cause**: Backend unreachable
- **Solution**: Verify Docker service running
- **Debug**: `docker ps | grep simple`

## Summary

The connection from Claude.ai to `https://simple-oauth.atratest.org/mcp` involves:

1. **Network Flow**: Claude.ai → Dispatcher (443) → Proxy (13xxx) → Backend (3000)
2. **OAuth Validation**: JWT validated at proxy layer with scope checking
3. **Trust Model**: Backend trusts proxy-provided headers completely
4. **Streaming Support**: SSE handled with proper keep-alive and no buffering
5. **Security**: Per-proxy user allowlists and scope requirements
6. **Performance**: Efficient TCP forwarding with minimal overhead

This architecture provides secure, scalable, and maintainable OAuth-protected access to MCP endpoints while maintaining clean separation of concerns and a simple trust model.