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

@pytest.mark.asyncio
async def test_oauth_discovery_endpoint_accessible():
    """Test that OAuth discovery endpoint is accessible without authentication."""
    base_url = os.getenv("TEST_BASE_URL", "http://localhost:80")
    test_domain = os.getenv("TEST_DOMAIN", "echo-stateful.atradev.org")
    
    if "localhost" in base_url:
        assert False, "FAILURE: Test requires real domain setup"
    
    # Test OAuth authorization server metadata endpoint
    async with httpx.AsyncClient() as client:
        # This should NOT return 401
        response = await client.get(
            f"https://{test_domain}/.well-known/oauth-authorization-server",
            follow_redirects=False
        )
        
        # Should either:
        # - Return 200 with metadata (if routed correctly)
        # - Return 404 (if route not found)
        # - Return 502/503 (if backend not available)
        # But NOT 401 (authentication required)
        assert response.status_code != 401, \
            f"OAuth discovery endpoint should not require authentication, got {response.status_code}"
        
        # Test MCP protected resource metadata endpoint
        response = await client.get(
            f"https://{test_domain}/.well-known/oauth-protected-resource",
            follow_redirects=False
        )
        
        assert response.status_code != 401, \
            f"MCP metadata endpoint should not require authentication, got {response.status_code}"

@pytest.mark.asyncio
async def test_protected_endpoint_requires_auth():
    """Test that non-excluded endpoints still require authentication."""
    base_url = os.getenv("TEST_BASE_URL", "http://localhost:80")
    test_domain = os.getenv("TEST_DOMAIN", "echo-stateful.atradev.org")
    
    if "localhost" in base_url:
        assert False, "FAILURE: Test requires real domain setup"
    
    async with httpx.AsyncClient() as client:
        # Regular endpoints should still require auth
        response = await client.get(
            f"https://{test_domain}/api/data",
            follow_redirects=False
        )
        
        # Should return 401 for protected endpoints
        assert response.status_code == 401, \
            f"Protected endpoint should require authentication, got {response.status_code}"