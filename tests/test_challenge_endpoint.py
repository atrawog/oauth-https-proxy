"""Test challenge endpoint functionality."""

import httpx
import pytest
from src.storage.redis_storage import RedisStorage, ChallengeToken

def test_challenge_storage_and_retrieval(http_client: httpx.Client):
    """Test that challenges can be stored and retrieved."""
    # Use Redis directly to store a test challenge
    import os
    # Use REDIS_URL from .env - same as the server uses
    redis_url = os.getenv("REDIS_URL")
    assert redis_url, "REDIS_URL must be set in .env"
    storage = RedisStorage(redis_url)
    test_token = "test-challenge-token"
    test_auth = "test-challenge-token.test-authorization-key"
    
    # Store challenge
    assert storage.store_challenge(test_token, test_auth)
    
    # Verify it can be retrieved via API
    response = http_client.get(f"/.well-known/acme-challenge/{test_token}")
    assert response.status_code == 200
    assert response.text == test_auth
    
    # Clean up
    storage.delete_challenge(test_token)

def test_challenge_not_found(http_client: httpx.Client):
    """Test that non-existent challenges return 404."""
    response = http_client.get("/.well-known/acme-challenge/non-existent-token")
    assert response.status_code == 404
    assert response.json() == {"detail": "Challenge not found"}

def test_certificate_list_endpoint(http_client: httpx.Client):
    """Test certificate list endpoint."""
    response = http_client.get("/certificates/")
    # Expect 403 without authentication
    assert response.status_code == 403
    assert "not authenticated" in response.json()["detail"].lower()

def test_health_endpoint(http_client: httpx.Client):
    """Test health check endpoint."""
    response = http_client.get("/health")
    assert response.status_code == 200
    health = response.json()
    assert health["status"] in ["healthy", "degraded"]
    assert "redis" in health
    assert "scheduler" in health
    assert "certificates_loaded" in health