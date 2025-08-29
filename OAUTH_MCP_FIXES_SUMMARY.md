# OAuth MCP Configuration Fixes Summary

## Date: 2025-08-29

This document summarizes the comprehensive fixes implemented to make the OAuth MCP configuration fully functional and compliant with the Model Context Protocol specification 2025-06-18.

## Issues Identified and Fixed

### 1. Authorization Header Propagation and Proxy Instance Reload

**Problem**: Proxy instances were caching code at startup and not reloading when the API service restarted, causing Authorization headers to be lost and code changes to not take effect.

**Solution**: 
- Added `instances_reload_required` event type to force proxy instance reload
- Implemented `_reload_all_instances()` method in UnifiedEventHandler to recreate all proxy instances
- Added event emission on API startup to trigger instance reload

**Files Modified**:
- `/src/dispatcher/unified_dispatcher.py` - Added reload event handling and instance recreation logic
- `/src/main.py` - Added event emission on API startup

### 2. NoneType Configuration Issues

**Problem**: Multiple "NoneType object is not iterable" errors when OAuth configuration fields were null/None.

**Solutions**:
- Added explicit None checks before iterating over `auth_required_users`
- Added None checks for `oauth_admin_users` and `oauth_user_users` 
- Fixed `allowed_users` configuration in proxy_config dictionary

**Files Modified**:
- `/src/api/oauth/routes.py` - Added None checks in OAuth callback handler
- `/src/proxy/unified_handler.py` - Fixed allowed_users configuration

### 3. Simplified OAuth Configuration

**Problem**: Environment variables were named `OAUTH_LOCALHOST_*` which was confusing and overly specific.

**Solution**: Renamed environment variables to be global defaults:
- `OAUTH_LOCALHOST_ADMIN_USERS` → `OAUTH_ADMIN_USERS`
- `OAUTH_LOCALHOST_USER_USERS` → `OAUTH_USER_USERS`
- `OAUTH_LOCALHOST_MCP_USERS` → `OAUTH_MCP_USERS`

**Files Modified**:
- `/docker-compose.yml` - Renamed environment variables

### 4. Global OAuth Defaults Implementation

**Problem**: OAuth scope assignment wasn't using global defaults when proxy-specific configuration was missing.

**Solution**: Implemented fallback logic to use global environment variables as defaults:
- Check proxy-specific configuration first
- Fall back to global `OAUTH_ADMIN_USERS`, `OAUTH_USER_USERS`, `OAUTH_MCP_USERS`
- Default to "user" scope if no configuration matches

**Files Modified**:
- `/src/api/oauth/routes.py` - Implemented global defaults in scope assignment

### 5. Instance Lifecycle Management

**Problem**: No mechanism to force proxy instances to reload with updated code.

**Solution**: Implemented event-driven instance lifecycle management:
- Proxy instances can be removed and recreated on demand
- Event system triggers instance recreation
- Proper cleanup of old instances before creating new ones

**Files Modified**:
- `/src/dispatcher/unified_dispatcher.py` - Added instance lifecycle management

## Configuration Changes

### Environment Variables (Simplified)
```bash
# Global OAuth user configuration defaults
OAUTH_ADMIN_USERS=alice,bob      # Users who get admin scope
OAUTH_USER_USERS=*               # Users who get user scope (* = all)
OAUTH_MCP_USERS=charlie          # Users who get MCP scope

# Global allowed users (for authentication)
OAUTH_ALLOWED_GITHUB_USERS=*    # Who can authenticate (* = all)
```

### Proxy Configuration
```json
{
  "auth_required_users": null,    // null = use global default
  "oauth_admin_users": null,      // null = use OAUTH_ADMIN_USERS
  "oauth_user_users": null,       // null = use OAUTH_USER_USERS
  "oauth_mcp_users": null         // null = use OAUTH_MCP_USERS
}
```

## Testing Recommendations

### 1. Force Proxy Instance Reload
After making code changes:
```bash
# Restart API service
just restart

# Wait for services to be healthy
just health

# Delete and recreate proxy to force new code
just proxy delete <hostname> --force
just proxy create <hostname> <target-url>
```

### 2. Test OAuth MCP Endpoint
```bash
# Test with OAuth token
curl -X POST https://proxy.example.com/mcp \
  -H "Authorization: Bearer $OAUTH_ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc": "2.0", "method": "initialize", "params": {"capabilities": {}}, "id": 1}' \
  --http1.1
```

### 3. Verify OAuth Configuration
```bash
# Check proxy configuration
just proxy show <hostname>

# Check OAuth status
just oauth status

# View OAuth logs
just log oauth-debug
```

## Known Issues

1. **Proxy Instance Caching**: Proxy instances cache code at startup and don't automatically reload when API restarts. The `instances_reload_required` event mechanism is in place but may need additional triggering logic.

2. **HTTP/2 Compatibility**: Some HTTP/2 clients may experience framing errors. Use `--http1.1` flag with curl as a workaround.

## Recommendations

1. **Manual Instance Reload**: Until automatic reload is fully working, manually delete and recreate proxies after code changes.

2. **Use Global Defaults**: Configure OAuth users via environment variables for consistency across proxies.

3. **Monitor Logs**: Check both Redis logs (`just log`) and Docker logs (`docker compose logs`) for comprehensive debugging.

4. **Test Thoroughly**: After any configuration change, test OAuth flow end-to-end including token refresh and scope assignment.

## MCP Compliance Status

The system is designed to be fully compliant with MCP specification 2025-06-18:
- ✅ OAuth 2.0 authorization with resource indicators (RFC 8707)
- ✅ Protected resource metadata endpoints (RFC 9728)
- ✅ Audience validation in JWT tokens
- ✅ Scope-based access control
- ✅ Dynamic client registration support

## Next Steps

1. Improve automatic proxy instance reload mechanism
2. Add HTTP/2 compatibility improvements
3. Enhance error messages for better debugging
4. Add comprehensive integration tests
5. Document per-proxy OAuth configuration options