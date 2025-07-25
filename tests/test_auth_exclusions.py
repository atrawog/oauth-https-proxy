"""Test authentication exclusions for OAuth/MCP endpoints."""

import pytest
import httpx
import os
from src.proxy.auth_exclusions import DEFAULT_AUTH_EXCLUSIONS, merge_exclusions

def test_default_exclusions():
    """Test that default exclusions include all required OAuth/MCP endpoints."""
    required_endpoints = [
        "/.well-known/oauth-authorization-server",
        "/.well-known/oauth-protected-resource",
        "/jwks",
        "/authorize",
        "/token",
        "/register",
        "/health"
    ]
    
    for endpoint in required_endpoints:
        assert endpoint in DEFAULT_AUTH_EXCLUSIONS, f"{endpoint} should be in default exclusions"

def test_merge_exclusions():
    """Test merging custom exclusions with defaults."""
    custom = ["/custom/path", "/another/path"]
    merged = merge_exclusions(custom)
    
    # Should include all defaults
    for default in DEFAULT_AUTH_EXCLUSIONS:
        assert default in merged
    
    # Should include custom paths
    for custom_path in custom:
        assert custom_path in merged
    
    # Should be sorted
    assert merged == sorted(merged)
    
    # Should not have duplicates
    custom_with_dup = ["/custom/path", "/jwks"]  # /jwks is already in defaults
    merged_dup = merge_exclusions(custom_with_dup)
    assert merged_dup.count("/jwks") == 1

def test_oauth_discovery_endpoint_accessible():
    """Test that OAuth discovery endpoint is accessible without authentication."""
    base_domain = os.getenv("BASE_DOMAIN", "atradev.org")
    
    # Test OAuth endpoints on the auth domain itself
    # These endpoints should be accessible without authentication due to auth exclusions
    with httpx.Client(verify=False) as client:
        # Test OAuth authorization server metadata endpoint on auth domain
        response = client.get(
            f"https://auth.{base_domain}/.well-known/oauth-authorization-server",
            follow_redirects=False
        )
        
        # Should return 200 with metadata
        assert response.status_code == 200, \
            f"OAuth discovery endpoint should be accessible, got {response.status_code}"
        
        # Test JWKS endpoint
        response = client.get(
            f"https://auth.{base_domain}/jwks",
            follow_redirects=False
        )
        
        assert response.status_code == 200, \
            f"JWKS endpoint should be accessible without auth, got {response.status_code}"

@pytest.mark.skip(reason="Requires proxy with auth enabled - echo services don't have auth configured")
def test_protected_endpoint_requires_auth():
    """Test that non-excluded endpoints still require authentication."""
    base_domain = os.getenv("BASE_DOMAIN", "atradev.org")
    test_domain = f"echo-stateful.{base_domain}"
    
    # This test requires a proxy with auth enabled
    # The echo services don't have auth configured by default
    # To properly test this, we would need to:
    # 1. Create a test proxy with auth enabled
    # 2. Test that regular endpoints require auth
    # 3. Test that excluded endpoints don't require auth
    pass