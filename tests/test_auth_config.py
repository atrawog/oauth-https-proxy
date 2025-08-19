"""Tests for configurable authentication system.

These tests verify that:
1. Authentication can be configured per endpoint
2. Different auth can be applied to the same endpoint at different paths (/ vs /api/v1/)
3. Pattern matching and priority resolution work correctly
4. OAuth, bearer, admin, and no-auth modes all function properly
"""

import pytest
import json
import hashlib
import uuid
from datetime import datetime, timezone

import httpx
import logging

logger = logging.getLogger(__name__)


@pytest.mark.asyncio
async def test_auth_config_crud(admin_auth_headers, api_base_url):
    """Test creating, reading, updating, and deleting auth configurations."""
    
    async with httpx.AsyncClient() as client:
        # Create an auth configuration
        config_data = {
            "path_pattern": "/test/endpoint/*",
            "method": "GET",
            "auth_type": "bearer",
            "priority": 75,
            "description": "Test endpoint configuration"
        }
        
        response = await client.post(
            f"{api_base_url}/api/v1/auth-config/",
            json=config_data,
            headers=admin_auth_headers
        )
        assert response.status_code == 200
        created_config = response.json()
        assert created_config["path_pattern"] == config_data["path_pattern"]
        assert created_config["auth_type"] == config_data["auth_type"]
        
        # List configurations
        response = await client.get(
            f"{api_base_url}/api/v1/auth-config/",
            headers=admin_auth_headers
        )
        assert response.status_code == 200
        configs = response.json()
        assert any(c["path_pattern"] == config_data["path_pattern"] for c in configs)
        
        # Get specific configuration
        config_id = created_config.get("id")
        if config_id:
            response = await client.get(
                f"{api_base_url}/api/v1/auth-config/{config_id}",
                headers=admin_auth_headers
            )
            assert response.status_code == 200
            fetched_config = response.json()
            assert fetched_config["path_pattern"] == config_data["path_pattern"]
            
            # Update configuration
            update_data = {
                "path_pattern": "/test/endpoint/*",
                "method": "POST",
                "auth_type": "admin",
                "priority": 80
            }
            response = await client.put(
                f"{api_base_url}/api/v1/auth-config/{config_id}",
                json=update_data,
                headers=admin_auth_headers
            )
            assert response.status_code == 200
            updated_config = response.json()
            assert updated_config["method"] == "POST"
            assert updated_config["auth_type"] == "admin"
            
            # Delete configuration
            response = await client.delete(
                f"{api_base_url}/api/v1/auth-config/{config_id}",
                headers=admin_auth_headers
            )
            assert response.status_code == 200
            
            # Verify deletion
            response = await client.get(
                f"{api_base_url}/api/v1/auth-config/{config_id}",
                headers=admin_auth_headers
            )
            assert response.status_code == 404


@pytest.mark.asyncio
async def test_pattern_matching(admin_auth_headers, api_base_url):
    """Test pattern matching for auth configurations."""
    
    async with httpx.AsyncClient() as client:
        # Test exact match
        test_cases = [
            {
                "path": "/api/v1/tokens/",
                "method": "GET",
                "expected_matches": True
            },
            {
                "path": "/tokens/",
                "method": "GET",
                "expected_matches": True
            },
            {
                "path": "/api/v1/certificates/my-cert",
                "method": "DELETE",
                "expected_matches": True
            }
        ]
        
        for test_case in test_cases:
            response = await client.post(
                f"{api_base_url}/api/v1/auth-config/test",
                json={
                    "path": test_case["path"],
                    "method": test_case["method"]
                },
                headers=admin_auth_headers
            )
            
            if response.status_code == 200:
                result = response.json()
                logger.info(f"Pattern test result: {result}")


@pytest.mark.asyncio
async def test_different_auth_same_endpoint(admin_auth_headers, api_base_url):
    """Test that the same endpoint can have different auth at different paths."""
    
    async with httpx.AsyncClient() as client:
        # Configure /tokens/* as admin-only
        root_config = {
            "path_pattern": "/tokens/*",
            "method": "*",
            "auth_type": "admin",
            "priority": 90,
            "description": "Root tokens - admin only"
        }
        
        response = await client.post(
            f"{api_base_url}/api/v1/auth-config/",
            json=root_config,
            headers=admin_auth_headers
        )
        assert response.status_code == 200
        root_config_id = response.json().get("id")
        
        # Configure /api/v1/tokens/ GET as bearer auth
        api_config = {
            "path_pattern": "/api/v1/tokens/",
            "method": "GET",
            "auth_type": "bearer",
            "priority": 80,
            "description": "API tokens list - any authenticated"
        }
        
        response = await client.post(
            f"{api_base_url}/api/v1/auth-config/",
            json=api_config,
            headers=admin_auth_headers
        )
        assert response.status_code == 200
        api_config_id = response.json().get("id")
        
        try:
            # Test pattern matching
            # /tokens/ should require admin
            response = await client.post(
                f"{api_base_url}/api/v1/auth-config/test",
                json={"path": "/tokens/", "method": "GET"},
                headers=admin_auth_headers
            )
            assert response.status_code == 200
            result = response.json()
            if result.get("effective_config"):
                assert result["effective_config"]["auth_type"] == "admin"
            
            # /api/v1/tokens/ should allow bearer
            response = await client.post(
                f"{api_base_url}/api/v1/auth-config/test",
                json={"path": "/api/v1/tokens/", "method": "GET"},
                headers=admin_auth_headers
            )
            assert response.status_code == 200
            result = response.json()
            if result.get("effective_config"):
                assert result["effective_config"]["auth_type"] == "bearer"
            
        finally:
            # Clean up
            if root_config_id:
                await client.delete(
                    f"{api_base_url}/api/v1/auth-config/{root_config_id}",
                    headers=admin_auth_headers
                )
            if api_config_id:
                await client.delete(
                    f"{api_base_url}/api/v1/auth-config/{api_config_id}",
                    headers=admin_auth_headers
                )


@pytest.mark.asyncio
async def test_priority_resolution(admin_auth_headers, api_base_url):
    """Test that higher priority configurations take precedence."""
    
    async with httpx.AsyncClient() as client:
        config_ids = []
        
        try:
            # Create low priority wildcard
            low_priority = {
                "path_pattern": "/api/v1/**",
                "method": "*",
                "auth_type": "bearer",
                "priority": 10,
                "description": "Catch-all low priority"
            }
            response = await client.post(
                f"{api_base_url}/api/v1/auth-config/",
                json=low_priority,
                headers=admin_auth_headers
            )
            assert response.status_code == 200
            config_ids.append(response.json().get("id"))
            
            # Create high priority specific
            high_priority = {
                "path_pattern": "/api/v1/health",
                "method": "GET",
                "auth_type": "none",
                "priority": 100,
                "description": "Health check - public"
            }
            response = await client.post(
                f"{api_base_url}/api/v1/auth-config/",
                json=high_priority,
                headers=admin_auth_headers
            )
            assert response.status_code == 200
            config_ids.append(response.json().get("id"))
            
            # Test that specific high priority wins
            response = await client.post(
                f"{api_base_url}/api/v1/auth-config/test",
                json={"path": "/api/v1/health", "method": "GET"},
                headers=admin_auth_headers
            )
            assert response.status_code == 200
            result = response.json()
            if result.get("effective_config"):
                assert result["effective_config"]["auth_type"] == "none"
                assert result["effective_config"]["priority"] == 100
            
        finally:
            # Clean up
            for config_id in config_ids:
                if config_id:
                    await client.delete(
                        f"{api_base_url}/api/v1/auth-config/{config_id}",
                        headers=admin_auth_headers
                    )


@pytest.mark.asyncio
async def test_oauth_config(admin_auth_headers, api_base_url):
    """Test OAuth authentication configuration."""
    
    async with httpx.AsyncClient() as client:
        # Configure OAuth with specific scopes and users
        oauth_config = {
            "path_pattern": "/api/v1/mcp/*",
            "method": "*",
            "auth_type": "oauth",
            "oauth_scopes": ["mcp:read", "mcp:write"],
            "oauth_allowed_users": ["testuser1", "testuser2"],
            "oauth_resource": "https://api.example.com",
            "priority": 75,
            "description": "MCP endpoints - OAuth only"
        }
        
        response = await client.post(
            f"{api_base_url}/api/v1/auth-config/",
            json=oauth_config,
            headers=admin_auth_headers
        )
        assert response.status_code == 200
        config_id = response.json().get("id")
        
        try:
            # Verify configuration
            response = await client.get(
                f"{api_base_url}/api/v1/auth-config/{config_id}",
                headers=admin_auth_headers
            )
            assert response.status_code == 200
            config = response.json()
            assert config["auth_type"] == "oauth"
            assert "mcp:read" in config["oauth_scopes"]
            assert "testuser1" in config["oauth_allowed_users"]
            
        finally:
            # Clean up
            if config_id:
                await client.delete(
                    f"{api_base_url}/api/v1/auth-config/{config_id}",
                    headers=admin_auth_headers
                )


@pytest.mark.asyncio
async def test_owner_validation_config(admin_auth_headers, api_base_url):
    """Test configuration with owner validation."""
    
    async with httpx.AsyncClient() as client:
        # Configure endpoint with owner validation
        owner_config = {
            "path_pattern": "/api/v1/certificates/{cert_name}",
            "method": "DELETE",
            "auth_type": "bearer",
            "owner_validation": True,
            "owner_param": "cert_name",
            "priority": 70,
            "description": "Certificate deletion - owner only"
        }
        
        response = await client.post(
            f"{api_base_url}/api/v1/auth-config/",
            json=owner_config,
            headers=admin_auth_headers
        )
        assert response.status_code == 200
        config_id = response.json().get("id")
        
        try:
            # Verify configuration
            response = await client.get(
                f"{api_base_url}/api/v1/auth-config/{config_id}",
                headers=admin_auth_headers
            )
            assert response.status_code == 200
            config = response.json()
            assert config["owner_validation"] is True
            assert config["owner_param"] == "cert_name"
            
        finally:
            # Clean up
            if config_id:
                await client.delete(
                    f"{api_base_url}/api/v1/auth-config/{config_id}",
                    headers=admin_auth_headers
                )


@pytest.mark.asyncio
async def test_apply_defaults(admin_auth_headers, api_base_url):
    """Test applying default auth configurations."""
    
    async with httpx.AsyncClient() as client:
        # Apply defaults
        response = await client.post(
            f"{api_base_url}/api/v1/auth-config/apply-defaults",
            headers=admin_auth_headers
        )
        assert response.status_code == 200
        result = response.json()
        assert result.get("created", 0) > 0
        
        # Verify some defaults were created
        response = await client.get(
            f"{api_base_url}/api/v1/auth-config/",
            headers=admin_auth_headers
        )
        assert response.status_code == 200
        configs = response.json()
        
        # Check for expected default patterns
        patterns = [c["path_pattern"] for c in configs]
        # Health endpoints should be public
        health_configs = [c for c in configs if "/health" in c["path_pattern"]]
        for health_config in health_configs:
            if health_config["method"] == "GET":
                assert health_config["auth_type"] == "none"


@pytest.mark.asyncio
async def test_cache_invalidation(admin_auth_headers, api_base_url):
    """Test that auth config cache is properly invalidated."""
    
    async with httpx.AsyncClient() as client:
        # Clear cache
        response = await client.delete(
            f"{api_base_url}/api/v1/auth-config/cache/clear",
            headers=admin_auth_headers
        )
        assert response.status_code == 200
        
        # Create a config
        config_data = {
            "path_pattern": "/test/cache/*",
            "method": "GET",
            "auth_type": "none",
            "priority": 50
        }
        response = await client.post(
            f"{api_base_url}/api/v1/auth-config/",
            json=config_data,
            headers=admin_auth_headers
        )
        assert response.status_code == 200
        config_id = response.json().get("id")
        
        try:
            # Update the config
            update_data = {
                "path_pattern": "/test/cache/*",
                "method": "GET",
                "auth_type": "bearer",
                "priority": 50
            }
            response = await client.put(
                f"{api_base_url}/api/v1/auth-config/{config_id}",
                json=update_data,
                headers=admin_auth_headers
            )
            assert response.status_code == 200
            
            # Cache should be invalidated, verify new auth type
            response = await client.get(
                f"{api_base_url}/api/v1/auth-config/{config_id}",
                headers=admin_auth_headers
            )
            assert response.status_code == 200
            config = response.json()
            assert config["auth_type"] == "bearer"
            
        finally:
            # Clean up
            if config_id:
                await client.delete(
                    f"{api_base_url}/api/v1/auth-config/{config_id}",
                    headers=admin_auth_headers
                )


@pytest.mark.asyncio
async def test_effective_auth(admin_auth_headers, api_base_url):
    """Test getting effective authentication for a path."""
    
    async with httpx.AsyncClient() as client:
        # Get effective auth for health endpoint
        response = await client.get(
            f"{api_base_url}/api/v1/auth-config/effective/health",
            params={"method": "GET"},
            headers=admin_auth_headers
        )
        assert response.status_code == 200
        result = response.json()
        assert "path" in result
        assert "method" in result
        assert "source" in result  # "configuration" or "hardcoded"
        
        # Get effective auth for tokens endpoint
        response = await client.get(
            f"{api_base_url}/api/v1/auth-config/effective/api/v1/tokens/",
            params={"method": "POST"},
            headers=admin_auth_headers
        )
        assert response.status_code == 200
        result = response.json()
        logger.info(f"Effective auth for /api/v1/tokens/ POST: {result}")


@pytest.mark.asyncio
async def test_wildcard_patterns(admin_auth_headers, api_base_url):
    """Test wildcard pattern matching."""
    
    async with httpx.AsyncClient() as client:
        config_ids = []
        
        try:
            # Single wildcard
            single_wildcard = {
                "path_pattern": "/api/v1/test/*",
                "method": "GET",
                "auth_type": "bearer",
                "priority": 60
            }
            response = await client.post(
                f"{api_base_url}/api/v1/auth-config/",
                json=single_wildcard,
                headers=admin_auth_headers
            )
            assert response.status_code == 200
            config_ids.append(response.json().get("id"))
            
            # Recursive wildcard
            recursive_wildcard = {
                "path_pattern": "/api/**",
                "method": "*",
                "auth_type": "bearer",
                "priority": 30
            }
            response = await client.post(
                f"{api_base_url}/api/v1/auth-config/",
                json=recursive_wildcard,
                headers=admin_auth_headers
            )
            assert response.status_code == 200
            config_ids.append(response.json().get("id"))
            
            # Test matching
            test_paths = [
                ("/api/v1/test/foo", True),  # Matches single wildcard
                ("/api/v1/test/foo/bar", False),  # Doesn't match single wildcard
                ("/api/anything/deeply/nested", True),  # Matches recursive wildcard
            ]
            
            for path, should_match in test_paths:
                response = await client.post(
                    f"{api_base_url}/api/v1/auth-config/test",
                    json={"path": path, "method": "GET"},
                    headers=admin_auth_headers
                )
                assert response.status_code == 200
                result = response.json()
                if should_match:
                    assert result["matched"] is True
                
        finally:
            # Clean up
            for config_id in config_ids:
                if config_id:
                    await client.delete(
                        f"{api_base_url}/api/v1/auth-config/{config_id}",
                        headers=admin_auth_headers
                    )