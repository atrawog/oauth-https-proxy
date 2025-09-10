# Complete OAuth and MCP Connection Flow

## Table of Contents
1. [Overview](#overview)
2. [Phase 1: OAuth Client Registration](#phase-1-oauth-client-registration)
3. [Phase 2: OAuth Authorization Flow](#phase-2-oauth-authorization-flow)
4. [Phase 3: Token Exchange](#phase-3-token-exchange)
5. [Phase 4: Authenticated MCP Connection](#phase-4-authenticated-mcp-connection)
6. [Token Refresh Flow](#token-refresh-flow)
7. [Device Flow Alternative](#device-flow-alternative)
8. [System Architecture](#system-architecture)
9. [Security Model](#security-model)

## Overview

This document provides the COMPLETE flow of how Claude.ai (or any OAuth client) connects to `https://simple-oauth.atratest.org/mcp`, starting from initial client registration through OAuth authentication to the final MCP connection.

### Key Components
- **OAuth Authorization Server**: `https://auth.atratest.org` (handles OAuth flows)
- **Protected Resource**: `https://simple-oauth.atratest.org/mcp` (MCP endpoint)
- **GitHub OAuth**: Used as the identity provider
- **JWT Tokens**: RS256 signed with resource-specific audiences

## Phase 1: OAuth Client Registration

### 1.1 Dynamic Client Registration (RFC 7591)

Claude.ai registers as an OAuth client:

```http
POST https://auth.atratest.org/register
Content-Type: application/json

{
  "software_id": "claude-ai-mcp-client",
  "software_version": "1.0.0",
  "client_name": "Claude AI MCP Client",
  "redirect_uris": ["https://claude.ai/callback"],
  "grant_types": ["authorization_code", "refresh_token"],
  "response_types": ["code"],
  "scope": "mcp",
  "client_uri": "https://claude.ai",
  "logo_uri": "https://claude.ai/logo.png"
}
```

### 1.2 Registration Response

```json
{
  "client_id": "mcp_claude_1735648200",
  "client_secret": "secret_abc123xyz...",
  "client_id_issued_at": 1735648200,
  "client_secret_expires_at": 0,
  "registration_access_token": "reg_token_xyz...",
  "registration_client_uri": "https://auth.atratest.org/register/mcp_claude_1735648200",
  "redirect_uris": ["https://claude.ai/callback"],
  "grant_types": ["authorization_code", "refresh_token"],
  "response_types": ["code"],
  "scope": "mcp",
  "token_endpoint_auth_method": "client_secret_basic"
}
```

### 1.3 Client Storage in Redis

```python
# Stored at key: oauth:client:mcp_claude_1735648200
{
  "client_id": "mcp_claude_1735648200",
  "client_secret_hash": "sha256:...",
  "redirect_uris": ["https://claude.ai/callback"],
  "grant_types": ["authorization_code", "refresh_token"],
  "created_at": "2025-01-01T10:00:00Z",
  "expires_at": "2025-04-01T10:00:00Z"
}
```

## Phase 2: OAuth Authorization Flow

### 2.1 Authorization Request

Claude.ai initiates OAuth flow with resource indicators (RFC 8707):

```http
GET https://auth.atratest.org/authorize?
  client_id=mcp_claude_1735648200&
  response_type=code&
  redirect_uri=https://claude.ai/callback&
  scope=mcp&
  state=random_state_123&
  resource=https://simple-oauth.atratest.org&
  code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM&
  code_challenge_method=S256
```

### 2.2 Proxy Detection and GitHub OAuth Setup

**File**: `src/api/oauth/routes.py:659-1000`

```python
@router.get("/authorize")
async def authorize(request, ...):
    # 1. Extract proxy hostname from headers
    proxy_hostname = request.headers.get("x-forwarded-host", "auth.atratest.org")
    
    # 2. Store authorization state
    auth_state = secrets.token_urlsafe(32)
    auth_data = {
        "client_id": "mcp_claude_1735648200",
        "redirect_uri": "https://claude.ai/callback",
        "scope": "mcp",
        "state": "random_state_123",
        "resources": ["https://simple-oauth.atratest.org"],
        "proxy_hostname": "simple-oauth.atratest.org",  # For per-proxy user checks
        "code_challenge": "E9Melhoa...",
        "code_challenge_method": "S256"
    }
    
    # 3. Store in Redis with 5-minute TTL
    await redis_client.setex(
        f"oauth:state:{auth_state}",
        300,
        json.dumps(auth_data)
    )
    
    # 4. Get GitHub OAuth credentials (per-proxy or global)
    if proxy_hostname:
        proxy = await storage.get_proxy_target(proxy_hostname)
        if proxy and proxy.github_client_id:
            github_client_id = proxy.github_client_id
            github_client_secret = proxy.github_client_secret
        else:
            github_client_id = settings.github_client_id  # From env
            github_client_secret = settings.github_client_secret
    
    # 5. Redirect to GitHub
    github_url = f"https://github.com/login/oauth/authorize?" + urlencode({
        "client_id": github_client_id,
        "redirect_uri": f"https://auth.atratest.org/callback",
        "scope": "read:user user:email",
        "state": auth_state
    })
    
    return RedirectResponse(github_url)
```

### 2.3 GitHub Authorization

User authenticates with GitHub and grants permissions:

```
Browser redirects to: https://github.com/login/oauth/authorize?
  client_id=<github_app_id>&
  redirect_uri=https://auth.atratest.org/callback&
  scope=read:user user:email&
  state=<auth_state>
```

### 2.4 OAuth Callback with Scope Assignment

**File**: `src/api/oauth/routes.py:1112-1500`

```python
@router.get("/callback")
async def oauth_callback(request, code, state, ...):
    # 1. Retrieve stored authorization state
    auth_data = await redis_client.get(f"oauth:state:{state}")
    proxy_hostname = auth_data.get("proxy_hostname")  # "simple-oauth.atratest.org"
    
    # 2. Exchange GitHub code for user info
    user_info = await auth_manager.exchange_github_code(
        code, 
        proxy_hostname,  # To get correct GitHub credentials
        "https://auth.atratest.org/callback"
    )
    # Returns: {"id": 123, "login": "atrawog", "email": "atrawog@example.com"}
    
    # 3. Check if user is allowed (auth_required_users)
    proxy = await storage.get_proxy_target(proxy_hostname)
    allowed_users = proxy.auth_required_users  # From simple-oauth.atratest.org config
    
    if allowed_users != ["*"] and user_info["login"] not in allowed_users:
        return RedirectResponse(
            f"{auth_data['redirect_uri']}?error=access_denied&state={auth_data['state']}"
        )
    
    # 4. Assign scopes based on proxy configuration
    github_user = user_info["login"]  # "atrawog"
    assigned_scopes = []
    
    # Check oauth_admin_users (from proxy config)
    if proxy.oauth_admin_users and github_user in proxy.oauth_admin_users:
        assigned_scopes.append("admin")  # atrawog is admin
    
    # Check oauth_user_users (["*"] = all users)
    if proxy.oauth_user_users and ("*" in proxy.oauth_user_users or github_user in proxy.oauth_user_users):
        assigned_scopes.append("user")
    
    # Check oauth_mcp_users (["*"] = all users)
    if proxy.oauth_mcp_users and ("*" in proxy.oauth_mcp_users or github_user in proxy.oauth_mcp_users):
        assigned_scopes.append("mcp")
    
    # Result: assigned_scopes = ["admin", "user", "mcp"] for atrawog
    
    # 5. Generate authorization code
    auth_code = secrets.token_urlsafe(32)
    
    # 6. Store code with user info and assigned scopes
    code_data = {
        **auth_data,
        "user_id": "123",
        "username": "atrawog",
        "email": "atrawog@example.com",
        "scope": " ".join(assigned_scopes)  # "admin user mcp"
    }
    
    await redis_client.setex(
        f"oauth:code:{auth_code}",
        600,  # 10 minutes
        json.dumps(code_data)
    )
    
    # 7. Redirect back to Claude.ai with authorization code
    return RedirectResponse(
        f"https://claude.ai/callback?code={auth_code}&state=random_state_123"
    )
```

## Phase 3: Token Exchange

### 3.1 Token Request

Claude.ai exchanges authorization code for tokens:

```http
POST https://auth.atratest.org/token
Content-Type: application/x-www-form-urlencoded

grant_type=authorization_code&
code=<auth_code>&
redirect_uri=https://claude.ai/callback&
client_id=mcp_claude_1735648200&
client_secret=secret_abc123xyz...&
code_verifier=<pkce_verifier>&
resource=https://simple-oauth.atratest.org
```

### 3.2 Token Generation

**File**: `src/api/oauth/routes.py:1526-1800`

```python
@router.post("/token")
async def token_exchange(request, grant_type, code, ...):
    # 1. Retrieve authorization code data
    code_data = await redis_client.get(f"oauth:code:{code}")
    
    # 2. Validate PKCE if present
    if code_data.get("code_challenge"):
        verify_pkce_challenge(code_verifier, code_data["code_challenge"])
    
    # 3. Validate resources match
    authorized_resources = code_data.get("resources", [])
    if resource and resource not in authorized_resources:
        raise HTTPException(400, "Resource not authorized")
    
    # 4. Generate JWT access token
    jti = secrets.token_urlsafe(32)
    now = datetime.utcnow()
    
    token_payload = {
        "iss": "https://auth.atratest.org",
        "sub": "atrawog",  # GitHub username
        "aud": ["https://simple-oauth.atratest.org"],  # Resource URIs
        "azp": "mcp_claude_1735648200",  # Authorized party
        "exp": int((now + timedelta(seconds=1800)).timestamp()),  # 30 min
        "iat": int(now.timestamp()),
        "jti": jti,
        "scope": "admin user mcp",  # From callback assignment
        "username": "atrawog",
        "email": "atrawog@example.com",
        "user_id": "123"
    }
    
    # 5. Sign with RS256
    access_token = jwt.encode(
        token_payload,
        private_key,  # RSA private key
        algorithm="RS256"
    )
    
    # 6. Generate refresh token
    refresh_token = await auth_manager.create_refresh_token({
        "user_id": "123",
        "username": "atrawog",
        "client_id": "mcp_claude_1735648200",
        "scope": "admin user mcp",
        "resources": ["https://simple-oauth.atratest.org"]
    })
    
    # 7. Store token metadata
    await redis_client.setex(
        f"oauth:token:{jti}",
        1800,
        json.dumps({
            "jti": jti,
            "user_id": "123",
            "username": "atrawog",
            "client_id": "mcp_claude_1735648200",
            "scope": "admin user mcp",
            "expires_at": (now + timedelta(seconds=1800)).isoformat()
        })
    )
    
    return {
        "access_token": access_token,
        "token_type": "Bearer",
        "expires_in": 1800,
        "refresh_token": refresh_token,
        "scope": "admin user mcp"
    }
```

### 3.3 Token Response

```json
{
  "access_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...",
  "token_type": "Bearer",
  "expires_in": 1800,
  "refresh_token": "refresh_xyz123...",
  "scope": "admin user mcp"
}
```

## Phase 4: Authenticated MCP Connection

### 4.1 MCP Request with Bearer Token

Claude.ai connects to MCP endpoint with the OAuth token:

```http
GET https://simple-oauth.atratest.org/mcp
Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...
Accept: text/event-stream
```

### 4.2 Request Flow Through System

```
[Claude.ai] --HTTPS--> [Dispatcher:443] --TCP+PROXY--> [HypercornInstance:13xxx]
                                                               |
                                                               v
                                                        [ProxyOnlyApp]
                                                               |
                                                               v
                                                      [UnifiedProxyHandler]
                                                               |
                                                               v
                                                   [OAuth Validation Process]
```

### 4.3 OAuth Validation in UnifiedProxyHandler

**File**: `src/proxy/unified_handler.py:564-650`

```python
async def _handle_auth(self, request, proxy_target):
    # 1. Extract JWT from Authorization header
    auth_header = request.headers.get("Authorization")
    if not auth_header or not auth_header.startswith("Bearer "):
        return self._auth_error_response(proxy_target, request)
    
    token = auth_header.replace("Bearer ", "")
    
    # 2. Decode and validate JWT
    try:
        # Get public key from OAuth server
        public_key = await self._get_oauth_public_key()
        
        payload = jwt.decode(
            token,
            public_key,
            algorithms=["RS256"],
            audience="https://simple-oauth.atratest.org",  # Validate audience
            issuer="https://auth.atratest.org"
        )
    except jwt.ExpiredSignatureError:
        return JSONResponse({"error": "Token expired"}, 401)
    except jwt.InvalidAudienceError:
        return JSONResponse({"error": "Invalid audience"}, 401)
    
    # 3. Extract user information
    auth_user = payload.get("username")  # "atrawog"
    auth_scopes = payload.get("scope", "").split()  # ["admin", "user", "mcp"]
    auth_email = payload.get("email")
    
    # 4. Check scope requirements for /mcp
    path = request.url.path  # "/mcp"
    required_scopes = self._get_required_scopes(path)  # ["mcp"]
    
    if not any(scope in auth_scopes for scope in required_scopes):
        return JSONResponse(
            {"error": "Insufficient scope"},
            status_code=403,
            headers={"WWW-Authenticate": self._build_www_authenticate(proxy_target)}
        )
    
    # 5. Check user allowlist (auth_required_users)
    if proxy_target.auth_required_users and proxy_target.auth_required_users != ["*"]:
        if auth_user not in proxy_target.auth_required_users:
            return JSONResponse({"error": "User not allowed"}, 403)
    
    # 6. Store auth info in request state
    request.state.auth_user = auth_user
    request.state.auth_scopes = auth_scopes
    request.state.auth_email = auth_email
    
    return None  # Auth successful
```

### 4.4 Forwarding to MCP Backend

```python
# Add authentication headers for backend
headers = {
    "X-Auth-User": "atrawog",
    "X-Auth-Scopes": "admin user mcp",
    "X-Auth-Email": "atrawog@example.com",
    "X-Real-IP": client_ip,  # From PROXY protocol
    **original_headers
}

# Forward to MCP server
response = await httpx.request(
    "GET",
    "http://simple:3000/mcp",  # Docker service
    headers=headers
)
```

### 4.5 MCP Server Response

The MCP server at `simple:3000` receives the authenticated request and returns SSE stream:

```http
HTTP/1.1 200 OK
Content-Type: text/event-stream
Cache-Control: no-cache
X-Accel-Buffering: no

data: {"jsonrpc":"2.0","id":1,"result":{"tools":[...]}}

data: {"jsonrpc":"2.0","id":2,"result":{"session_id":"sess_123"}}
```

## Token Refresh Flow

### 5.1 Refresh Request

When the access token expires, Claude.ai uses the refresh token:

```http
POST https://auth.atratest.org/token
Content-Type: application/x-www-form-urlencoded

grant_type=refresh_token&
refresh_token=refresh_xyz123...&
client_id=mcp_claude_1735648200&
resource=https://simple-oauth.atratest.org
```

### 5.2 Refresh Response

New access token with same scopes and resources:

```json
{
  "access_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...(new)",
  "token_type": "Bearer",
  "expires_in": 1800,
  "scope": "admin user mcp"
}
```

## Device Flow Alternative

### 6.1 Device Authorization Request

For CLI or device-based authentication:

```http
POST https://auth.atratest.org/device/code
Content-Type: application/x-www-form-urlencoded

client_id=device_flow_client&
scope=mcp&
resource=https://simple-oauth.atratest.org
```

### 6.2 Device Response

```json
{
  "device_code": "dev_abc123...",
  "user_code": "BDSG-HQTM",
  "verification_uri": "https://github.com/login/device",
  "verification_uri_complete": "https://github.com/login/device?user_code=BDSG-HQTM",
  "expires_in": 900,
  "interval": 5
}
```

### 6.3 Device Polling

```http
POST https://auth.atratest.org/device/token
Content-Type: application/x-www-form-urlencoded

grant_type=urn:ietf:params:oauth:grant-type:device_code&
device_code=dev_abc123...&
client_id=device_flow_client
```

### 6.4 GitHub Device Flow Processing

**File**: `src/api/oauth/routes.py:350-650`

```python
@router.post("/device/code")
async def device_code(request, ...):
    # 1. Forward to GitHub device endpoint
    github_response = await httpx.post(
        "https://github.com/login/device/code",
        data={
            "client_id": github_client_id,
            "scope": "read:user user:email"
        }
    )
    
    # 2. Store context with resource
    await redis_client.setex(
        f"oauth:device:{device_code}",
        900,
        json.dumps({
            "resources": ["https://simple-oauth.atratest.org"],
            "requested_scope": "mcp",
            "proxy_hostname": proxy_hostname
        })
    )
    
    return github_response.json()

@router.post("/device/token")
async def device_token(device_code, ...):
    # 1. Poll GitHub for completion
    github_response = await httpx.post(
        "https://api.github.com/login/oauth/access_token",
        data={"device_code": device_code, ...}
    )
    
    if "access_token" in github_response:
        # 2. Get user info from GitHub
        user_info = await get_github_user(github_response["access_token"])
        
        # 3. Load stored context
        context = await redis_client.get(f"oauth:device:{device_code}")
        
        # 4. Assign scopes based on proxy config
        # (Same scope assignment logic as callback)
        
        # 5. Generate JWT tokens
        return {
            "access_token": jwt_token,
            "refresh_token": refresh_token,
            "scope": "admin user mcp"
        }
```

## System Architecture

### 7.1 Component Layers

```
┌─────────────────────────────────────────────────────────────┐
│                         Claude.ai                            │
│                    (OAuth Client Application)                │
└─────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────┐
│                   OAuth Authorization Server                 │
│                   (auth.atratest.org:443)                   │
│  • Client Registration (/register)                          │
│  • Authorization (/authorize)                               │
│  • Token Exchange (/token)                                  │
│  • GitHub Integration                                       │
└─────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────┐
│                      GitHub OAuth                           │
│                  (github.com/login/oauth)                   │
│  • User Authentication                                      │
│  • Permission Grants                                        │
└─────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────┐
│                    Protected Resource                        │
│              (simple-oauth.atratest.org/mcp)                │
│  • JWT Validation                                           │
│  • Scope Checking                                           │
│  • User Allowlists                                          │
│  • MCP Protocol Handler                                     │
└─────────────────────────────────────────────────────────────┘
```

### 7.2 Data Flow

```
1. Registration → Client Credentials
2. Authorization → GitHub Login → User Verification
3. Callback → Scope Assignment → Authorization Code
4. Token Exchange → JWT Generation → Access Token
5. MCP Request → Token Validation → Authenticated Access
```

## Security Model

### 8.1 Multi-Layer Security

1. **Client Authentication**: Client ID + Secret validation
2. **User Authentication**: GitHub OAuth integration
3. **User Authorization**: Per-proxy allowlists (`auth_required_users`)
4. **Scope Assignment**: Per-proxy scope configuration
   - `oauth_admin_users`: Users who get admin scope
   - `oauth_user_users`: Users who get user scope
   - `oauth_mcp_users`: Users who get mcp scope
5. **Resource Protection**: Audience validation in JWT
6. **PKCE**: Protection against authorization code interception
7. **Time Limits**: Short-lived tokens (30 min access, 1 year refresh)

### 8.2 Trust Boundaries

```
External → OAuth Server: Full validation
OAuth Server → GitHub: Trusted identity provider
Proxy → Backend: Complete trust (X-Auth-* headers)
```

### 8.3 Scope Hierarchy

- **admin**: Full write access to all APIs
- **user**: Read access to all APIs
- **mcp**: Access to MCP protocol endpoints

### 8.4 Per-Proxy Configuration

Each proxy can have:
- Custom GitHub OAuth App credentials
- Specific user allowlists
- Different scope assignments
- Unique protected resource metadata

## Debugging Tools

### 9.1 OAuth Flow Debugging

```bash
# Check OAuth status
just oauth status

# View OAuth logs
just log oauth-debug

# Test token validation
curl -H "Authorization: Bearer <token>" https://simple-oauth.atratest.org/mcp

# Check proxy configuration
just proxy show simple-oauth.atratest.org
```

### 9.2 Redis Keys for Debugging

```bash
# OAuth states (5 min TTL)
oauth:state:<state_token>

# Authorization codes (10 min TTL)
oauth:code:<auth_code>

# Access tokens (30 min TTL)
oauth:token:<jti>

# Refresh tokens (1 year TTL)
oauth:refresh:<refresh_token>

# Client registrations (90 days TTL)
oauth:client:<client_id>

# Device flow states (15 min TTL)
oauth:device:<device_code>
```

## Summary

The complete flow from Claude.ai to the MCP endpoint involves:

1. **Client Registration**: Dynamic registration via RFC 7591
2. **OAuth Authorization**: GitHub-based user authentication with per-proxy user checks
3. **Scope Assignment**: Based on proxy-specific configuration
4. **Token Generation**: JWT with resource-specific audiences
5. **Token Validation**: At proxy layer with full context
6. **Authenticated Access**: MCP endpoint receives validated requests

This architecture provides:
- **Security**: Multi-layer validation and user control
- **Flexibility**: Per-proxy configuration
- **Compliance**: Full MCP 2025-06-18 specification support
- **Scalability**: Stateless JWT validation
- **Maintainability**: Clear separation of concerns