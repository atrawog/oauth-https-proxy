# OAuth Token and MCP Endpoint Logging Enhancements

This document summarizes the comprehensive logging enhancements implemented to debug OAuth token and MCP endpoint issues.

## 1. OAuth Token Generation Logging (src/api/oauth/routes.py)

### Enhanced Token Creation Context
- **Before Token Generation**: Log detailed context including authorized resources, requested resources, final token resources, and audience values that will be set
- **After Token Generation**: Extract and log complete JWT token claims including:
  - Token JTI, audience, expiration, issuer
  - Complete claims payload (excluding sensitive tokens)
  - Resource validation status
  - Audience type and count analysis

### Refresh Token Logging
- Log refresh token context with resource mappings
- Complete token details for refreshed tokens
- Resource validation between refresh and access tokens

## 2. Proxy Handler Authentication Logging (src/proxy/handler.py)

### Detailed Authentication Flow
- **Starting Authentication**: Log detailed context including auth proxy, mode, request details, MCP status
- **Auth Verification Request**: Log headers being sent to OAuth service, resource URI construction
- **Auth Response Analysis**: Log raw OAuth server responses with headers, body previews, and status codes
- **Authentication Failures**: Comprehensive failure analysis with specific error types and context

### Enhanced Error Logging
- Connection errors with timeout configuration details
- Detailed error context for all auth service interactions
- User authorization failure logging (users, emails, groups)

## 3. Audience Validation Logging (src/api/oauth/async_resource_protector.py)

### Critical 403 invalid_audience Error Debugging
- **External IP Tracking**: All audience validation failures now log the external client IP causing the issue
- **Detailed Context**: Complete token claims, request headers, resource matching analysis
- **Debugging Hints**: Structured debugging information including:
  - Expected vs actual audience values
  - Case-sensitive matching analysis
  - OAuth authorization flow suggestions
  - Complete request context with client IP

### Token Validation Logging
- Detailed JWT validation process logging
- Algorithm and issuer validation steps
- Success/failure analysis with client IP tracking

## 4. MCP Metadata Endpoint Logging (src/api/server.py)

### Comprehensive Request Context
- **Request Details**: Method, path, headers, query parameters with client IP
- **Hostname Resolution**: Detailed logging of forwarded vs direct host headers
- **Proxy Target Resolution**: Available proxies for debugging when target not found
- **MCP Configuration**: Auth integration details, metadata structure

### Response Logging
- Complete metadata being returned
- Auth server integration details
- JWKS URI configuration
- Scope and resource documentation URLs

## 5. Request/Response Body Logging (src/shared/logging.py)

### Critical Endpoint Detection
Automatic enhanced logging for:
- `/token` - OAuth token exchange
- `/mcp` - MCP protocol endpoints  
- `/authorize` - OAuth authorization
- `/verify` - Token verification
- `/introspect` - Token introspection
- `/.well-known/oauth-protected-resource` - MCP metadata
- `/.well-known/oauth-authorization-server` - OAuth metadata

### Enhanced Body Logging
- **Request Bodies**: Form data parsing with sensitive field masking
- **Response Bodies**: JSON parsing with token masking for OAuth responses
- **Size Management**: Increased limits for critical endpoints
- **Error Analysis**: Enhanced error response logging

### OAuth Failure Analysis
- Specific analysis for 401/403 responses on critical endpoints
- WWW-Authenticate header logging
- Failure type classification

## 6. JWT Token Validator Logging (src/api/oauth/resource_protector.py)

### Detailed Validation Process
- Algorithm selection and key availability
- Claims extraction and validation steps
- Redis revocation checking with key details
- Comprehensive error analysis for JOSE and validation errors

## 7. Redis Serialization Fix (src/shared/request_logger.py)

### Boolean Value Handling
- Proper string conversion for all Redis hash field values
- JSON serialization for complex data types
- Null value handling to prevent Redis errors

## Key Benefits

1. **External IP Tracking**: All 403 invalid_audience errors now include the external client IP causing the issue
2. **Complete Context**: Full request/response context for OAuth and MCP endpoints
3. **Resource Validation**: Detailed audience validation with debugging hints
4. **Error Classification**: Structured error analysis with specific failure types
5. **Debugging Hints**: Actionable suggestions for common OAuth/MCP issues
6. **Performance**: Efficient logging with appropriate size limits and masking

## Usage for Debugging

### Finding 403 Audience Errors
```bash
# Search logs for audience validation failures with client IP
just app-logs-search "invalid_audience"
just app-logs-errors 1 50 | grep "403"
```

### OAuth Token Issues
```bash
# Search for token generation issues
just app-logs-search "TOKEN DETAILS"
just app-logs-search "COMPLETE TOKEN DETAILS"
```

### MCP Metadata Problems
```bash
# Search for MCP endpoint issues
just app-logs-search "MCP metadata"
just app-logs-search "METADATA DETAILS"
```

### Authentication Flow Debugging
```bash
# Search for auth flow issues
just app-logs-search "DETAILED FAILURE ANALYSIS"
just app-logs-search "AUTH VERIFICATION"
```

All logging now includes external client IP addresses to help identify which clients are experiencing OAuth token and MCP endpoint issues.