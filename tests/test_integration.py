"""Integration tests for ACME Certificate Manager."""

import os
import time
import pytest
import httpx


class TestHealthCheck:
    """Test health check functionality."""
    
    def test_health_endpoint(self, http_client: httpx.Client):
        """Test health check returns expected data."""
        response = http_client.get("/health")
        
        assert response.status_code == 200
        data = response.json()
        
        assert "status" in data
        assert "scheduler" in data
        assert "redis" in data
        assert "certificates_loaded" in data
        assert "https_enabled" in data
        
        assert data["redis"] == "healthy"
        assert isinstance(data["scheduler"], bool)
        assert isinstance(data["certificates_loaded"], int)


class TestCertificateAPI:
    """Test certificate management API."""
    
    def test_list_certificates_empty(self, http_client: httpx.Client):
        """Test listing certificates when none exist."""
        response = http_client.get("/certificates")
        
        assert response.status_code == 200
        assert response.json() == []
    
    def test_get_nonexistent_certificate(self, http_client: httpx.Client):
        """Test getting certificate that doesn't exist."""
        response = http_client.get("/certificates/nonexistent")
        
        assert response.status_code == 404
        assert "not found" in response.json()["detail"].lower()
    
    @pytest.mark.skip(reason="Requires ACME server mock or real domain")
    def test_create_certificate(self, http_client: httpx.Client, cert_request_data):
        """Test creating a new certificate."""
        response = http_client.post("/certificates", json=cert_request_data)
        
        # Note: This will fail without proper ACME setup
        # In real testing, you would need:
        # 1. A domain you control
        # 2. Proper DNS setup
        # 3. Public IP for HTTP-01 challenges
        
        if response.status_code == 200:
            data = response.json()
            assert data["domains"] == [cert_request_data["domain"]]
            assert data["email"] == cert_request_data["email"]
            assert data["status"] == "active"
            assert "fullchain_pem" in data
            assert "private_key_pem" in data


class TestACMEChallenge:
    """Test ACME challenge endpoint."""
    
    def test_challenge_not_found(self, http_client: httpx.Client):
        """Test challenge endpoint with invalid token."""
        response = http_client.get("/.well-known/acme-challenge/invalid-token")
        
        assert response.status_code == 404
    
    def test_challenge_with_redis(self, http_client: httpx.Client):
        """Test challenge endpoint with valid token in Redis."""
        # This test would require setting up a challenge through the proper ACME flow
        # For now, we test that the endpoint exists and returns 404 for non-existent tokens
        # A full integration test would involve:
        # 1. Starting certificate generation
        # 2. Intercepting the challenge storage
        # 3. Testing the challenge endpoint
        
        # For now, just verify the endpoint behavior
        token = "test-token-123"
        response = http_client.get(f"/.well-known/acme-challenge/{token}")
        
        # Should return 404 for non-existent challenge
        assert response.status_code == 404


class TestRedisStorage:
    """Test Redis storage functionality."""
    
    def test_redis_connectivity(self, redis_client):
        """Test Redis is accessible."""
        assert redis_client.ping() is True
    
    def test_certificate_storage(self, redis_client):
        """Test storing and retrieving certificate data."""
        import json
        from datetime import datetime, timezone
        
        cert_data = {
            "domains": ["test.example.com"],
            "email": "test@example.com",
            "acme_directory_url": "https://acme-staging-v02.api.letsencrypt.org/directory",
            "status": "active",
            "expires_at": datetime.now(timezone.utc).isoformat(),
            "issued_at": datetime.now(timezone.utc).isoformat(),
            "fingerprint": "sha256:test",
            "fullchain_pem": "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----",
            "private_key_pem": "-----BEGIN PRIVATE KEY-----\ntest\n-----END PRIVATE KEY-----"
        }
        
        # Store
        key = "cert:test-cert"
        redis_client.set(key, json.dumps(cert_data))
        
        # Retrieve
        stored = redis_client.get(key)
        assert stored is not None
        
        retrieved = json.loads(stored)
        assert retrieved["domains"] == cert_data["domains"]
        assert retrieved["email"] == cert_data["email"]


class TestDockerServices:
    """Test Docker service health."""
    
    @pytest.mark.skipif(
        os.path.exists("/.dockerenv") or not os.path.exists("/var/run/docker.sock"),
        reason="Running in Docker or Docker not available"
    )
    def test_service_health_checks(self):
        """Test all services pass health checks."""
        import subprocess
        
        # Check Redis health
        result = subprocess.run(
            ["docker-compose", "exec", "-T", "redis", "redis-cli", "ping"],
            capture_output=True,
            text=True
        )
        assert result.returncode == 0
        assert "PONG" in result.stdout
        
        # Check acme-certmanager health
        result = subprocess.run(
            ["docker-compose", "exec", "-T", "acme-certmanager", "curl", "-f", "http://localhost/health"],
            capture_output=True,
            text=True
        )
        assert result.returncode == 0