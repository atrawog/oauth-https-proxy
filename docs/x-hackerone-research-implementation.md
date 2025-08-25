# X-HackerOne-Research Header Implementation

## Summary
Successfully implemented the X-HackerOne-Research header feature that adds this header to ALL proxy responses, including error responses like 401 Authentication Required.

## Implementation Details

### 1. Model Changes (src/proxy/models.py)
- Added `custom_response_headers: Optional[Dict[str, str]] = None` to ProxyTarget model
- Added same field to ProxyTargetRequest and ProxyTargetUpdate models
- Added `hacker_one_research_header: Optional[str] = None` to ProxyResourceConfig model

### 2. API Changes (src/api/routers/v1/proxies.py)
- Updated `configure_proxy_resource` endpoint to set X-HackerOne-Research in custom_response_headers when provided

### 3. Proxy Handler Changes (src/proxy/handler.py)
- Added `_add_custom_response_headers` method to add custom headers to response headers
- Updated ALL Response objects to include custom_response_headers:
  - OPTIONS responses
  - Successful proxy responses (StreamingResponse)
  - 401 Authentication Required responses
  - 403 Forbidden responses
  - 503 Service Unavailable responses
  - 302 Redirect responses
  - All error responses

### 4. Command Updates (justfile)
- Updated `proxy resource-set` command to accept `hacker-one-research` parameter
- Fixed jq syntax error (missing `end` statement)

## Usage
To set the X-HackerOne-Research header on a proxy:
```bash
just proxy resource-set <hostname> <token> [endpoint] [scopes] [stateful] [override-backend] [bearer-methods] [doc-suffix] [server-info] [custom-metadata] "your-email@example.com"
```

## Testing Results
Confirmed the header appears in all response types:
- ✅ 401 responses with WWW-Authenticate preserved
- ✅ 405 Method Not Allowed responses  
- ✅ 200 OK responses
- ✅ All error responses

Example 401 response:
```
HTTP/1.1 401 
www-authenticate: Bearer, realm="auth.atradev.org", as_uri="https://auth.atradev.org/.well-known/oauth-authorization-server", resource_uri="https://everything.atradev.org/.well-known/oauth-protected-resource"
x-hackerone-research: atrawog
content-length: 23
x-instance-name: everything.atradev.org
date: Tue, 05 Aug 2025 06:21:06 GMT
server: hypercorn-h11
```

## Important Notes
- The header is added to response headers sent to clients, not request headers forwarded to backends
- Existing headers (like WWW-Authenticate) are preserved
- The header is added to ALL responses from the proxy, including errors