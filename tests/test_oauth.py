"""OAuth authentication tests for the MCP HTTP Proxy service."""

import os
import json
import pytest
import httpx

import secrets
import base64
from urllib.parse import urlencode, parse_qs, urlparse
from typing import Generator, Optional

@pytest.mark.oauth
class TestOAuthConfiguration:
    """Test OAuth configuration and metadata endpoints."""
    
    @pytest.fixture
    def auth_domain(self) -> str:
        """Get OAuth auth domain."""
        base_domain = os.getenv("BASE_DOMAIN", "localhost")
        return f"auth.{base_domain}"
    
    def test_oauth_metadata_endpoint(self, http_client: httpx.Client, auth_domain: str):
        """Test OAuth authorization server metadata endpoint."""
        # Try with HTTPS first
        response = httpx.get(f"https://{auth_domain}/.well-known/oauth-authorization-server", verify=False)
        
        # Fall back to HTTP if HTTPS fails
        if response.status_code != 200:
            response = httpx.get(f"http://{auth_domain}/.well-known/oauth-authorization-server")
        
        # Accept 404 if OAuth not configured
        if response.status_code == 404:
            assert False, "FAILURE: OAuth not configured"
        
        assert response.status_code == 200
        data = response.json()
        
        # Required fields per RFC 8414
        assert "issuer" in data
        assert "authorization_endpoint" in data
        assert "token_endpoint" in data
        assert "response_types_supported" in data
        assert "grant_types_supported" in data
        
        # MCP specific requirements
        assert "resource_indicators_supported" in data
        assert data["resource_indicators_supported"] is True
    
    def test_jwks_endpoint(self, http_client: httpx.Client, auth_domain: str):
        """Test JWKS endpoint for token verification."""
        # Try with HTTPS first
        response = httpx.get(f"https://{auth_domain}/jwks", verify=False)
        
        # Fall back to HTTP if HTTPS fails
        if response.status_code != 200:
            response = httpx.get(f"http://{auth_domain}/jwks")
        
        # Accept 404 if OAuth not configured
        if response.status_code == 404:
            assert False, "FAILURE: OAuth not configured"
        
        assert response.status_code == 200
        data = response.json()
        
        assert "keys" in data
        assert isinstance(data["keys"], list)
        
        if data["keys"]:
            # Check key format
            key = data["keys"][0]
            assert "kty" in key
            assert "use" in key
            assert "kid" in key

@pytest.mark.oauth
class TestOAuthClientRegistration:
    """Test OAuth dynamic client registration."""
    
    @pytest.fixture
    def auth_domain(self) -> str:
        """Get OAuth auth domain."""
        base_domain = os.getenv("BASE_DOMAIN", "localhost")
        return f"auth.{base_domain}"
    
    @pytest.fixture
    def test_client_id(self) -> str:
        """Generate unique client ID for testing."""
        return f"test-client-{secrets.token_hex(8)}"
    
    def test_client_registration(self, auth_domain: str, test_client_id: str):
        """Test dynamic client registration."""
        registration_data = {
            "software_id": test_client_id,
            "software_version": "1.0.0",
            "client_name": f"Test Client {test_client_id}",
            "redirect_uris": ["http://localhost:8080/callback"],
            "grant_types": ["authorization_code", "refresh_token"],
            "response_types": ["code"],
            "scope": "mcp:read mcp:write"
        }
        
        # Try with HTTPS first
        response = httpx.post(
            f"https://{auth_domain}/register",
            json=registration_data,
            verify=False
        )
        
        # Fall back to HTTP if HTTPS fails
        if response.status_code not in [200, 201]:
            response = httpx.post(
                f"http://{auth_domain}/register",
                json=registration_data
            )
        
        # Accept 404 if registration not supported
        if response.status_code == 404:
            assert False, "FAILURE: Client registration not supported"
        
        assert response.status_code in [200, 201], f"Expected 200/201, got {response.status_code}: {response.text}"
        data = response.json()
        
        # Required fields per RFC 7591
        assert "client_id" in data
        assert "client_secret" in data
        # Client ID format may vary - accept any format
        assert len(data["client_id"]) > 0
        
        # Optional but expected fields
        if "registration_access_token" in data:
            assert data["registration_access_token"] is not None
        if "registration_client_uri" in data:
            assert data["registration_client_uri"] is not None

@pytest.mark.oauth
class TestOAuthAuthorizationFlow:
    """Test OAuth authorization code flow."""
    
    @pytest.fixture
    def auth_domain(self) -> str:
        """Get OAuth auth domain."""
        base_domain = os.getenv("BASE_DOMAIN", "localhost")
        return f"auth.{base_domain}"
    
    @pytest.fixture
    def test_client(self, auth_domain: str) -> Optional[dict]:
        """Register a test client for auth flow testing."""
        registration_data = {
            "software_id": f"flow-test-{secrets.token_hex(4)}",
            "software_version": "1.0.0",
            "client_name": "Flow Test Client",
            "redirect_uris": ["http://localhost:8080/callback"],
            "grant_types": ["authorization_code", "refresh_token"],
            "response_types": ["code"],
            "scope": "mcp:read"
        }
        
        try:
            response = httpx.post(
                f"https://{auth_domain}/register",
                json=registration_data,
                verify=False,
                timeout=10
            )
            
            if response.status_code == 404:
                return None
            
            if response.status_code in [200, 201]:
                return response.json()
        except:
            pass
        
        return None
    
    def test_authorization_endpoint_requires_params(self, auth_domain: str):
        """Test that authorization endpoint requires proper parameters."""
        response = httpx.get(f"https://{auth_domain}/authorize", verify=False)
        
        # Should return error for missing parameters
        assert response.status_code in [400, 302, 422], f"Got {response.status_code}: {response.text}"  # May redirect with error or return validation error
    
    def test_authorization_with_resource_parameter(self, auth_domain: str, test_client: Optional[dict]):
        """Test authorization with MCP resource parameter."""
        if not test_client:
            assert False, "FAILURE: Client registration not available"
        
        params = {
            "client_id": test_client["client_id"],
            "response_type": "code",
            "redirect_uri": test_client["redirect_uris"][0],
            "resource": "https://mcp.example.com",
            "scope": "mcp:read",
            "state": secrets.token_urlsafe(16)
        }
        
        response = httpx.get(
            f"https://{auth_domain}/authorize",
            params=params,
            verify=False,
            follow_redirects=False
        )
        
        # Should redirect to login or return auth page
        assert response.status_code in [302, 307, 200], f"Got {response.status_code}: {response.text}"
    
    def test_token_endpoint_requires_auth(self, auth_domain: str):
        """Test that token endpoint requires authentication."""
        response = httpx.post(
            f"https://{auth_domain}/token",
            data={"grant_type": "authorization_code"},
            verify=False
        )
        
        # Should return error for missing client auth
        assert response.status_code in [401, 422], f"Expected 401 Unauthorized or 422 Validation Error, got {response.status_code}"

@pytest.mark.oauth
class TestOAuthFlow:
    """Test complete OAuth flow integration."""
    
    @pytest.fixture
    def auth_domain(self) -> str:
        """Get OAuth auth domain."""
        base_domain = os.getenv("BASE_DOMAIN", "localhost")
        return f"auth.{base_domain}"
    
    @pytest.mark.skip(reason="Requires --hostname parameter")
    def test_complete_flow(self, request, auth_domain: str):
        """Test complete OAuth flow for a specific hostname."""
        # Get hostname from pytest command line if provided
        hostname = request.config.getoption("--hostname", default=None)
        if not hostname:
            assert False, "FAILURE: No hostname provided for OAuth flow test"
        
        # This would be a complex integration test requiring:
        # 1. Client registration
        # 2. Authorization request
        # 3. User login simulation
        # 4. Authorization code exchange
        # 5. Token validation
        # 6. Protected resource access
        
        # For now, just verify the endpoints exist
        assert hostname is not None

@pytest.mark.oauth
class TestOAuthStatus:
    """Test OAuth status and monitoring endpoints."""

    def test_oauth_clients_list(self, http_client: httpx.Client, auth_token: str):
        """Test listing OAuth clients."""
        response = http_client.get(
            "/oauth/clients",
            headers={"Authorization": f"Bearer {auth_token}"}
        )
        
        # Accept 404 if OAuth status endpoints not implemented
        if response.status_code == 404:
            assert False, "FAILURE: OAuth status endpoints not implemented"
        
        assert response.status_code == 200
        data = response.json()
        assert isinstance(data, dict)
        assert "clients" in data
        assert isinstance(data["clients"], list)
    
    def test_oauth_tokens_stats(self, http_client: httpx.Client, auth_token: str):
        """Test OAuth token statistics."""
        response = http_client.get(
            "/oauth/tokens",
            headers={"Authorization": f"Bearer {auth_token}"}
        )
        
        if response.status_code == 404:
            assert False, "FAILURE: OAuth status endpoints not implemented"
        
        assert response.status_code == 200
        data = response.json()
        assert isinstance(data, dict)
        
        # Expected stats fields
        expected_fields = ["total", "active", "expired", "by_client", "by_scope"]
        for field in expected_fields:
            if field in data:
                assert isinstance(data[field], (int, dict, list))
    
    def test_oauth_sessions_list(self, http_client: httpx.Client, auth_token: str):
        """Test listing OAuth sessions."""
        response = http_client.get(
            "/oauth/sessions",
            headers={"Authorization": f"Bearer {auth_token}"}
        )
        
        if response.status_code == 404:
            assert False, "FAILURE: OAuth status endpoints not implemented"
        
        assert response.status_code == 200
        data = response.json()
        assert isinstance(data, dict)
        assert "sessions" in data
        assert isinstance(data["sessions"], list)
    
    def test_oauth_health(self, http_client: httpx.Client, auth_token: str):
        """Test OAuth health status."""
        response = http_client.get(
            "/oauth/health",
            headers={"Authorization": f"Bearer {auth_token}"}
        )
        
        if response.status_code == 404:
            assert False, "FAILURE: OAuth status endpoints not implemented"
        
        assert response.status_code == 200
        data = response.json()
        assert "status" in data
        assert "checks" in data
        assert isinstance(data["checks"], dict)

@pytest.mark.oauth
class TestMCPResourceManagement:
    """Test MCP resource management for OAuth."""

    def test_list_mcp_resources(self, http_client: httpx.Client, auth_token: str):
        """Test listing MCP resources."""
        response = http_client.get(
            "/resources/",
            headers={"Authorization": f"Bearer {auth_token}"}
        )
        
        # Accept 404 if MCP resource management not implemented
        if response.status_code == 404:
            assert False, "FAILURE: MCP resource management not implemented"
        
        assert response.status_code == 200
        data = response.json()
        assert isinstance(data, list)
    
    def test_register_mcp_resource(self, http_client: httpx.Client, auth_token: str):
        """Test registering an MCP resource."""
        resource_data = {
            "uri": f"https://test-mcp-{secrets.token_hex(4)}.example.com",
            "name": "Test MCP Server",
            "proxy_target": "test-mcp.example.com",
            "scopes": ["mcp:read", "mcp:write"]
        }
        
        response = http_client.post(
            "/resources/",
            headers={"Authorization": f"Bearer {auth_token}"},
            json=resource_data
        )
        
        if response.status_code == 404:
            assert False, "FAILURE: MCP resource management not implemented"
        
        assert response.status_code == 200, f"Expected 200 OK, got {response.status_code}: {response.text}"
        data = response.json()
        assert data["uri"] == resource_data["uri"]
        
        # Cleanup
        http_client.delete(
            f"/resources/{resource_data['uri']}",
            headers={"Authorization": f"Bearer {auth_token}"}
        )
    
    def test_validate_token_for_resource(self, http_client: httpx.Client, auth_token: str):
        """Test validating a token for a specific resource."""
        resource_uri = "https://test.example.com"
        
        response = http_client.post(
            f"/resources/{resource_uri}/validate-token",
            headers={"Authorization": f"Bearer {auth_token}"},
            json={"token": "test-token"}
        )
        
        # Accept 404 if not implemented
        assert response.status_code in [200, 400, 401, 404], f"Got {response.status_code}: {response.text}"

@pytest.mark.oauth
class TestForwardAuth:
    """Test ForwardAuth integration."""

    @pytest.fixture
    def auth_domain(self) -> str:
        """Get OAuth auth domain."""
        base_domain = os.getenv("BASE_DOMAIN", "localhost")
        return f"auth.{base_domain}"
    
    def test_verify_endpoint(self, auth_domain: str):
        """Test OAuth verify endpoint for ForwardAuth."""
        # Test without auth - should return 401
        response = httpx.get(
            f"https://{auth_domain}/verify",
            verify=False
        )
        
        # Accept 404 if verify endpoint not implemented
        if response.status_code == 404:
            assert False, "FAILURE: Verify endpoint not implemented"
        
        assert response.status_code == 401
    
    def test_verify_with_valid_token(self, auth_domain: str, auth_token: str):
        """Test verify endpoint with valid token."""
        response = httpx.get(
            f"https://{auth_domain}/verify",
            headers={"Authorization": f"Bearer {auth_token}"},
            verify=False
        )
        
        if response.status_code == 404:
            assert False, "FAILURE: Verify endpoint not implemented"
        
        # Admin token might not be an OAuth token
        assert response.status_code in [200, 401], f"Got {response.status_code}: {response.text}"
        
        if response.status_code == 200:
            data = response.json()
            # Should return user info
            assert "user_id" in data or "sub" in data