# Proxy Resource Commands Reference

## Overview

The `proxy-resource-*` commands manage the OAuth 2.0 Protected Resource Metadata (RFC 9728) for proxy targets. These commands allow full control over all fields returned by the `/.well-known/oauth-protected-resource` endpoint.

## Commands

### proxy-resource-set

Set protected resource metadata for a proxy.

```bash
just proxy-resource-set <hostname> [token] [options]
```

**Parameters:**
- `hostname` - The proxy hostname (required)
- `token` - Bearer token for authentication (defaults to ADMIN_TOKEN)
- `endpoint` - Resource endpoint path (default: "/mcp")
- `scopes` - Space-separated list of supported scopes (default: "mcp:read mcp:write")
- `stateful` - Whether the resource maintains state (default: "false")
- `override-backend` - Override backend's metadata endpoint (default: "false")
- `bearer-methods` - Space-separated bearer token methods (default: "header")
- `doc-suffix` - Documentation URL suffix (default: "/docs")
- `server-info` - JSON object with additional server information (default: "{}")
- `custom-metadata` - JSON object with custom metadata fields (default: "{}")

**Examples:**

Basic usage:
```bash
just proxy-resource-set example.com
```

Full configuration:
```bash
just proxy-resource-set example.com ADMIN \
  endpoint="/api/mcp" \
  scopes="mcp:read mcp:write mcp:admin" \
  stateful="true" \
  bearer-methods="header body" \
  doc-suffix="/documentation" \
  server-info='{"version":"1.0","name":"Example MCP"}' \
  custom-metadata='{"custom_field":"value"}'
```

### proxy-resource-clear

Clear protected resource metadata for a proxy.

```bash
just proxy-resource-clear <hostname> [token]
```

**Parameters:**
- `hostname` - The proxy hostname (required)
- `token` - Bearer token for authentication (defaults to ADMIN_TOKEN)

**Example:**
```bash
just proxy-resource-clear example.com
```

### proxy-resource-show

Show the current protected resource metadata configuration.

```bash
just proxy-resource-show <hostname>
```

**Parameters:**
- `hostname` - The proxy hostname (required)

**Example:**
```bash
just proxy-resource-show example.com
```

Output includes:
- configured - Whether resource metadata is configured
- endpoint - Resource endpoint path
- scopes - Supported scopes
- stateful - State maintenance flag
- mcp_versions - Supported MCP versions
- server_info - Additional server information
- override_backend - Backend override flag
- bearer_methods - Supported bearer token methods
- resource_documentation_suffix - Documentation URL suffix
- custom_metadata - Custom metadata fields

### test-proxy-resource

Test the protected resource metadata endpoint for a proxy.

```bash
just test-proxy-resource <hostname>
```

**Parameters:**
- `hostname` - The proxy hostname (required)

**Example:**
```bash
just test-proxy-resource example.com
```

This command:
1. Fetches `https://<hostname>/.well-known/oauth-protected-resource`
2. Displays the HTTP status code
3. Shows the JSON response
4. Shows the proxy's resource configuration

## Protected Resource Metadata Fields

The `/.well-known/oauth-protected-resource` endpoint returns:

### Standard Fields (RFC 9728)
- `resource` - The resource URI (computed from hostname + endpoint)
- `authorization_servers` - Array of OAuth server URLs (from auth configuration)
- `scopes_supported` - Supported scopes (from scopes parameter)
- `bearer_methods_supported` - Bearer token methods (from bearer-methods parameter)
- `resource_documentation` - Documentation URL (resource URI + doc-suffix)
- `jwks_uri` - JWKS endpoint URL (if auth is enabled)

### Custom Fields
- Any fields from `server-info` parameter
- Any fields from `custom-metadata` parameter

## Examples

### Basic MCP Resource
```bash
just proxy-resource-set mcp.example.com
```

Result at `https://mcp.example.com/.well-known/oauth-protected-resource`:
```json
{
  "resource": "https://mcp.example.com/mcp",
  "authorization_servers": ["https://auth.example.com"],
  "scopes_supported": ["mcp:read", "mcp:write"],
  "bearer_methods_supported": ["header"],
  "resource_documentation": "https://mcp.example.com/mcp/docs",
  "jwks_uri": "https://auth.example.com/jwks"
}
```

### Advanced Configuration
```bash
just proxy-resource-set api.example.com ADMIN \
  endpoint="/v1" \
  scopes="read write admin" \
  bearer-methods="header query" \
  doc-suffix="/api-docs" \
  server-info='{"api_version":"v1","rate_limit":1000}' \
  custom-metadata='{"environment":"production","region":"us-east-1"}'
```

Result:
```json
{
  "resource": "https://api.example.com/v1",
  "authorization_servers": ["https://auth.example.com"],
  "scopes_supported": ["read", "write", "admin"],
  "bearer_methods_supported": ["header", "query"],
  "resource_documentation": "https://api.example.com/v1/api-docs",
  "jwks_uri": "https://auth.example.com/jwks",
  "api_version": "v1",
  "rate_limit": 1000,
  "environment": "production",
  "region": "us-east-1"
}
```

## Migration from proxy-mcp Commands

The `proxy-mcp-*` commands have been renamed to `proxy-resource-*` to better reflect their purpose of managing OAuth 2.0 Protected Resource Metadata:

- `proxy-mcp-enable` → `proxy-resource-set`
- `proxy-mcp-disable` → `proxy-resource-clear`
- `proxy-mcp-show` → `proxy-resource-show`
- `test-proxy-mcp` → `test-proxy-resource`

All existing parameters are supported, with additional parameters for full metadata control.