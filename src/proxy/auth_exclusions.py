"""Default authentication exclusion paths for OAuth and MCP compliance."""

# OAuth 2.1 and MCP metadata endpoints that must be publicly accessible
DEFAULT_AUTH_EXCLUSIONS = [
    # All well-known endpoints must be publicly accessible
    "/.well-known/",  # This will match any path starting with /.well-known/
    
    # JWKS endpoint for token verification
    "/jwks",
    
    # OAuth endpoints that may need pre-auth access
    "/authorize",  # Initial authorization request
    "/token",      # Token endpoint (for client credentials flow)
    "/register",   # Dynamic client registration
    
    # Health and status endpoints
    "/health",
]

def get_default_exclusions():
    """Get the default list of paths excluded from authentication."""
    return DEFAULT_AUTH_EXCLUSIONS.copy()

def merge_exclusions(custom_exclusions=None):
    """Merge custom exclusions with defaults, avoiding duplicates."""
    result = set(DEFAULT_AUTH_EXCLUSIONS)
    if custom_exclusions:
        result.update(custom_exclusions)
    return sorted(list(result))