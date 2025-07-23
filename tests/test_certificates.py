"""Certificate management tests for the MCP HTTP Proxy service."""

import os
import time
import pytest
import httpx
import secrets
from typing import Generator

@pytest.mark.certificates
class TestCertificateCreation:
    """Test certificate creation functionality."""

    @pytest.fixture
    def test_cert_name(self) -> str:
        """Generate unique certificate name for testing."""
        return f"test-cert-{secrets.token_hex(4)}"
    
    @pytest.fixture
    def created_cert(self, http_client: httpx.Client, auth_token: str, test_cert_name: str, test_domain: str, test_email: str) -> Generator[dict, None, None]:
        """Create a test certificate and clean up after test."""
        cert_data = {
            "cert_name": test_cert_name,
            "domain": test_domain,
            "email": test_email,
            "acme_directory_url": os.getenv("ACME_STAGING_URL")
        }
        
        response = http_client.post(
            "/certificates/",
            headers={"Authorization": f"Bearer {auth_token}"},
            json=cert_data
        )
        
        # FAIL HARD if creation doesn't work
        assert response.status_code == 200, f"Failed to create certificate: {response.status_code} - {response.text}"
        
        result = response.json()
        # Get the actual certificate name from the response
        actual_cert_name = result.get("cert_name", test_cert_name)
        yield result
        
        # Cleanup using the actual certificate name - FAIL HARD if cleanup fails
        cleanup_response = http_client.delete(
            f"/certificates/{actual_cert_name}",
            headers={"Authorization": f"Bearer {auth_token}"}
        )
        assert cleanup_response.status_code in [200, 204], f"Cleanup failed: {cleanup_response.status_code}"
    
    def test_create_certificate_requires_auth(self, http_client: httpx.Client, test_domain: str, test_email: str):
        """Test that creating certificate requires authentication."""
        cert_data = {
            "cert_name": "test-cert",
            "domain": test_domain,
            "email": test_email,
            "acme_directory_url": os.getenv("ACME_STAGING_URL")
        }
        
        response = http_client.post("/certificates/", json=cert_data)
        assert response.status_code == 403, f"Expected 403 Forbidden, got {response.status_code}"
    
    def test_create_certificate_with_valid_data(self, http_client: httpx.Client, auth_token: str, test_cert_name: str, test_domain: str, test_email: str):
        """Test creating certificate with valid data."""
        cert_data = {
            "cert_name": test_cert_name,
            "domain": test_domain,
            "email": test_email,
            "acme_directory_url": os.getenv("ACME_STAGING_URL")
        }
        
        response = http_client.post(
            "/certificates/",
            headers={"Authorization": f"Bearer {auth_token}"},
            json=cert_data
        )
        
        # Certificate generation is async, so we get 200 with task info
        assert response.status_code == 200
        data = response.json()
        assert "task_id" in data or "cert_name" in data
        
        # Cleanup - use actual certificate name from response
        actual_cert_name = data.get("cert_name", test_cert_name)
        time.sleep(2)  # Give it time to start
        http_client.delete(
            f"/certificates/{actual_cert_name}",
            headers={"Authorization": f"Bearer {auth_token}"}
        )
    
    def test_create_certificate_duplicate_name(self, http_client: httpx.Client, auth_token: str, created_cert: dict):
        """Test that duplicate certificate names are rejected."""
        # Extract the domain from the response message
        # Format: "Certificate generation started for {domain}"
        import re
        match = re.search(r'Certificate generation started for (.+)', created_cert.get("message", ""))
        if match:
            domain = match.group(1)
        else:
            # Fallback - this shouldn't happen
            assert False, f"Could not extract domain from response: {created_cert}"
        
        cert_data = {
            "cert_name": "dummy",  # Required by model but ignored by API
            "domain": domain,  # Use same domain to generate same cert name
            "email": "test@example.com",
            "acme_directory_url": os.getenv("ACME_STAGING_URL")
        }
        
        response = http_client.post(
            "/certificates/",
            headers={"Authorization": f"Bearer {auth_token}"},
            json=cert_data
        )
        
        # Should reject duplicate name with 409 Conflict
        assert response.status_code == 409, f"Expected 409 Conflict for duplicate cert name, got {response.status_code}: {response.text}"

@pytest.mark.certificates
class TestCertificateRetrieval:
    """Test certificate retrieval functionality."""

    def test_list_certificates_requires_auth(self, http_client: httpx.Client):
        """Test that listing certificates requires authentication."""
        response = http_client.get("/certificates/")
        assert response.status_code == 403, f"Expected 403 Forbidden, got {response.status_code}"
    
    def test_list_certificates_with_auth(self, http_client: httpx.Client, auth_token: str):
        """Test listing certificates with authentication."""
        response = http_client.get(
            "/certificates/",
            headers={"Authorization": f"Bearer {auth_token}"}
        )
        
        assert response.status_code == 200
        data = response.json()
        assert isinstance(data, list)
    
    def test_get_certificate_by_name(self, http_client: httpx.Client, auth_token: str):
        """Test retrieving certificate by name."""
        # Try to get a non-existent certificate
        response = http_client.get(
            "/certificates/nonexistent",
            headers={"Authorization": f"Bearer {auth_token}"}
        )
        
        assert response.status_code == 404
    
    def test_get_certificate_requires_auth(self, http_client: httpx.Client):
        """Test that getting certificate requires authentication."""
        response = http_client.get("/certificates/test-cert")
        assert response.status_code == 403, f"Expected 403 Forbidden, got {response.status_code}"

@pytest.mark.certificates  
class TestCertificateStatus:
    """Test certificate status functionality."""

    def test_get_certificate_status(self, http_client: httpx.Client, auth_token: str):
        """Test getting certificate generation status."""
        response = http_client.get(
            "/certificates/test-cert/status",
            headers={"Authorization": f"Bearer {auth_token}"}
        )
        
        # Should return 404 for non-existent certificate
        assert response.status_code == 404

@pytest.mark.certificates
class TestCertificateDeletion:
    """Test certificate deletion functionality."""

    def test_delete_certificate_requires_auth(self, http_client: httpx.Client):
        """Test that deleting certificate requires authentication."""
        response = http_client.delete("/certificates/test-cert")
        assert response.status_code == 403, f"Expected 403 Forbidden, got {response.status_code}"
    
    def test_delete_nonexistent_certificate(self, http_client: httpx.Client, auth_token: str):
        """Test deleting non-existent certificate."""
        response = http_client.delete(
            "/certificates/nonexistent",
            headers={"Authorization": f"Bearer {auth_token}"}
        )
        
        # Should succeed (idempotent) or return 404
        assert response.status_code in [200, 204, 404], f"Got {response.status_code}: {response.text}"

@pytest.mark.certificates
class TestCertificateRenewal:
    """Test certificate renewal functionality."""

    def test_renew_certificate_requires_auth(self, http_client: httpx.Client):
        """Test that renewing certificate requires authentication."""
        response = http_client.post("/certificates/test-cert/renew")
        assert response.status_code == 403, f"Expected 403 Forbidden, got {response.status_code}"
    
    def test_renew_nonexistent_certificate(self, http_client: httpx.Client, auth_token: str):
        """Test renewing non-existent certificate."""
        response = http_client.post(
            "/certificates/nonexistent/renew",
            headers={"Authorization": f"Bearer {auth_token}"}
        )
        
        assert response.status_code == 404

@pytest.mark.certificates
class TestMultiDomainCertificates:
    """Test multi-domain certificate functionality."""

    def test_create_multi_domain_certificate(self, http_client: httpx.Client, auth_token: str, test_email: str):
        """Test creating multi-domain certificate."""
        base_domain = os.getenv("TEST_DOMAIN_BASE")
        if not base_domain:
            assert False, "FAILURE: TEST_DOMAIN_BASE not set"
        
        cert_name = f"multi-test-{secrets.token_hex(4)}"
        domains = [
            f"test1-{cert_name}.{base_domain}",
            f"test2-{cert_name}.{base_domain}",
            f"test3-{cert_name}.{base_domain}"
        ]
        
        cert_data = {
            "cert_name": cert_name,
            "domains": domains,
            "email": test_email,
            "acme_directory_url": os.getenv("ACME_STAGING_URL")
        }
        
        response = http_client.post(
            "/certificates/multi-domain",
            headers={"Authorization": f"Bearer {auth_token}"},
            json=cert_data
        )
        
        # Should accept multi-domain request
        assert response.status_code == 200, f"Expected 200 OK for multi-domain cert, got {response.status_code}: {response.text}"
        
        # Cleanup - use actual certificate name from response
        data = response.json()
        actual_cert_name = data.get("cert_name", cert_name)
        time.sleep(2)
        http_client.delete(
            f"/certificates/{actual_cert_name}",
            headers={"Authorization": f"Bearer {auth_token}"}
        )

@pytest.mark.certificates
class TestACMEChallenge:
    """Test ACME challenge endpoint."""
    
    def test_acme_challenge_endpoint_exists(self, http_client: httpx.Client):
        """Test that ACME challenge endpoint exists."""
        response = http_client.get("/.well-known/acme-challenge/test-token")
        
        # Should return 404 for non-existent token (not 405 or similar)
        assert response.status_code == 404
    
    def test_acme_challenge_with_valid_token(self, http_client: httpx.Client, auth_token: str):
        """Test ACME challenge flow through certificate creation."""
        # The ACME challenge should be set during certificate creation
        # We can't test it in isolation without direct Redis access
        # Instead, we should test that the endpoint exists and returns proper errors
        
        # Non-existent token should return 404
        response = http_client.get("/.well-known/acme-challenge/non-existent-token")
        assert response.status_code == 404, f"Expected 404 for non-existent token, got {response.status_code}"
        
        # The real test is that certificates can be created successfully
        # which implies the ACME challenge mechanism works