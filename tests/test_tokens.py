"""Token management tests for the MCP HTTP Proxy service."""

import os
import pytest
import httpx
import secrets
from typing import Generator

@pytest.fixture
def test_token_name():
    """Generate unique token name for testing."""
    return f"test-token-{secrets.token_hex(4)}"

@pytest.fixture  
def test_token_email():
    """Get test email for token generation."""
    return os.getenv("TEST_EMAIL", "test@example.com")

@pytest.fixture
def generated_token(http_client: httpx.Client, auth_token: str, test_token_name: str, test_token_email: str) -> Generator[dict, None, None]:
    """Generate a test token via API and clean up after test."""
    # Create token via API
    response = http_client.post(
        "/tokens/",
        headers={"Authorization": f"Bearer {auth_token}"},
        json={"name": test_token_name, "cert_email": test_token_email}
    )
    
    # FAIL HARD if creation doesn't work
    assert response.status_code == 200, f"Failed to create token: {response.status_code} - {response.text}"
    
    token_data = response.json()
    yield token_data
    
    # Cleanup via API - FAIL HARD if cleanup doesn't work
    cleanup_response = http_client.delete(
        f"/tokens/{test_token_name}",
        headers={"Authorization": f"Bearer {auth_token}"}
    )
    assert cleanup_response.status_code in [200, 204], f"Cleanup failed: {cleanup_response.status_code}"

@pytest.mark.tokens
class TestTokenGeneration:
    """Test token generation functionality via API."""
    
    def test_generate_token_requires_auth(self, http_client: httpx.Client, test_token_name: str, test_token_email: str):
        """Test that token generation requires authentication."""
        response = http_client.post(
            "/tokens/",
            json={"name": test_token_name, "cert_email": test_token_email}
        )
        assert response.status_code == 403, f"Expected 403 Forbidden, got {response.status_code}"
    
    def test_generate_token_creates_valid_token(self, http_client: httpx.Client, auth_token: str, test_token_name: str, test_token_email: str):
        """Test that token generation creates a valid token."""
        response = http_client.post(
            "/tokens/",
            headers={"Authorization": f"Bearer {auth_token}"},
            json={"name": test_token_name, "cert_email": test_token_email}
        )
        
        assert response.status_code == 200
        data = response.json()
        assert "name" in data
        assert "token" in data
        assert data["name"] == test_token_name
        assert data["token"].startswith("acm_")
        
        # Cleanup
        http_client.delete(
            f"/tokens/{test_token_name}",
            headers={"Authorization": f"Bearer {auth_token}"}
        )
    
    def test_token_name_uniqueness(self, http_client: httpx.Client, auth_token: str, generated_token: dict):
        """Test that token names must be unique."""
        # Try to create another token with the same name
        response = http_client.post(
            "/tokens/",
            headers={"Authorization": f"Bearer {auth_token}"},
            json={"name": generated_token["name"], "cert_email": "other@example.com"}
        )
        
        # Should reject duplicate name with 409 Conflict
        assert response.status_code == 409, f"Expected 409 Conflict for duplicate name, got {response.status_code}: {response.text}"

@pytest.mark.tokens
class TestTokenRetrieval:
    """Test token retrieval functionality via API."""
    
    def test_list_tokens(self, http_client: httpx.Client, auth_token: str, generated_token: dict):
        """Test listing all tokens."""
        response = http_client.get(
            "/tokens/",
            headers={"Authorization": f"Bearer {auth_token}"}
        )
        
        assert response.status_code == 200
        tokens = response.json()
        assert isinstance(tokens, list)
        
        # Check that our test token is in the list
        token_names = [t["name"] for t in tokens]
        assert generated_token["name"] in token_names
    
    def test_get_token_by_name(self, http_client: httpx.Client, auth_token: str, generated_token: dict):
        """Test retrieving token by name."""
        response = http_client.get(
            f"/tokens/{generated_token['name']}",
            headers={"Authorization": f"Bearer {auth_token}"}
        )
        
        assert response.status_code == 200
        data = response.json()
        assert data["name"] == generated_token["name"]
        assert "token" in data
    
    def test_get_nonexistent_token(self, http_client: httpx.Client, auth_token: str):
        """Test retrieving non-existent token."""
        response = http_client.get(
            "/tokens/nonexistent-token",
            headers={"Authorization": f"Bearer {auth_token}"}
        )
        
        assert response.status_code == 404

@pytest.mark.tokens
class TestTokenDeletion:
    """Test token deletion functionality via API."""
    
    def test_delete_token_requires_auth(self, http_client: httpx.Client, generated_token: dict):
        """Test that token deletion requires authentication."""
        response = http_client.delete(f"/tokens/{generated_token['name']}")
        assert response.status_code == 403, f"Expected 403 Forbidden, got {response.status_code}"
    
    def test_delete_nonexistent_token(self, http_client: httpx.Client, auth_token: str):
        """Test deleting non-existent token."""
        response = http_client.delete(
            "/tokens/nonexistent-token",
            headers={"Authorization": f"Bearer {auth_token}"}
        )
        
        assert response.status_code == 404

@pytest.mark.tokens
class TestTokenEmailUpdate:
    """Test token email update functionality via API."""
    
    def test_update_token_email(self, http_client: httpx.Client, auth_token: str, generated_token: dict):
        """Test updating token email."""
        new_email = "updated@example.com"
        
        response = http_client.put(
            "/tokens/email",
            headers={"Authorization": f"Bearer {generated_token['token']}"},
            json={"email": new_email}  # Note: endpoint expects "email" not "cert_email"
        )
        
        assert response.status_code == 200
        data = response.json()
        assert data["cert_email"] == new_email
    
    def test_update_token_email_invalid_email(self, http_client: httpx.Client, auth_token: str, generated_token: dict):
        """Test updating token with invalid email."""
        response = http_client.put(
            "/tokens/email",
            headers={"Authorization": f"Bearer {generated_token['token']}"},
            json={"email": "not-an-email"}
        )
        
        # Should validate email format with 422 Unprocessable Entity
        assert response.status_code == 422, f"Expected 422 for invalid email, got {response.status_code}: {response.text}"

@pytest.mark.tokens
class TestTokenInfo:
    """Test token info retrieval via API."""
    
    def test_get_token_info(self, http_client: httpx.Client, generated_token: dict):
        """Test getting token info using the token itself."""
        response = http_client.get(
            "/tokens/info",
            headers={"Authorization": f"Bearer {generated_token['token']}"}
        )
        
        if response.status_code != 200:
            print(f"Error response: {response.text}")
        assert response.status_code == 200
        data = response.json()
        assert data["name"] == generated_token["name"]
        assert "cert_email" in data