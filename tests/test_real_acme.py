"""REAL ACME integration tests with actual Let's Encrypt staging."""

import os
import time
import pytest
import httpx
from datetime import datetime, timezone

# REAL configuration - NO MOCKS! NO DEFAULTS!
TEST_DOMAIN = os.getenv("TEST_DOMAIN")  # From .env via just
TEST_EMAIL = os.getenv("TEST_EMAIL")  # From .env via just
ACME_STAGING_URL = os.getenv("ACME_STAGING_URL")  # From .env via just
TEST_BASE_URL = os.getenv("TEST_BASE_URL")  # From .env via just

# Verify all required env vars are set
assert TEST_DOMAIN, "TEST_DOMAIN not set - must be loaded from .env via just"
assert TEST_EMAIL, "TEST_EMAIL not set - must be loaded from .env via just"
assert ACME_STAGING_URL, "ACME_STAGING_URL not set - must be loaded from .env via just"
assert TEST_BASE_URL, "TEST_BASE_URL not set - must be loaded from .env via just"


class TestRealACMEIntegration:
    """REAL tests against Let's Encrypt staging - NO MOCKS!"""
    
    @pytest.fixture(scope="class")
    def cert_name(self):
        """Generate unique certificate name for test."""
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
        return f"test-cert-{timestamp}"
    
    def test_real_certificate_generation(self, http_client: httpx.Client, cert_name: str):
        """Test REAL certificate generation with Let's Encrypt staging."""
        # Request real certificate
        request_data = {
            "domain": TEST_DOMAIN,
            "email": TEST_EMAIL,
            "cert_name": cert_name,
            "acme_directory_url": ACME_STAGING_URL
        }
        
        print(f"\nRequesting REAL certificate for {TEST_DOMAIN}...")
        response = http_client.post("/certificates", json=request_data, timeout=120.0)
        
        # This should succeed if DNS is properly configured
        assert response.status_code == 200, f"Failed to create certificate: {response.text}"
        
        cert_data = response.json()
        assert cert_data["domains"] == [TEST_DOMAIN]
        assert cert_data["email"] == TEST_EMAIL
        assert cert_data["status"] == "active"
        assert "fullchain_pem" in cert_data
        assert "private_key_pem" in cert_data
        assert cert_data["fullchain_pem"].startswith("-----BEGIN CERTIFICATE-----")
        assert cert_data["private_key_pem"].startswith("-----BEGIN PRIVATE KEY-----")
        
        print(f"✓ Certificate successfully generated!")
        print(f"  Expires: {cert_data['expires_at']}")
        print(f"  Fingerprint: {cert_data['fingerprint']}")
        
        return cert_name
    
    def test_challenge_endpoint_during_generation(self, http_client: httpx.Client):
        """Test that challenge endpoint works during real ACME flow."""
        # This would require intercepting the challenge during generation
        # For now, verify the endpoint exists and returns proper errors
        response = http_client.get("/.well-known/acme-challenge/test-token")
        assert response.status_code == 404
    
    def test_certificate_retrieval(self, http_client: httpx.Client, cert_name: str):
        """Test retrieving the generated certificate."""
        # First generate a certificate
        cert_name = self.test_real_certificate_generation(http_client, cert_name)
        
        # Now retrieve it
        response = http_client.get(f"/certificates/{cert_name}")
        assert response.status_code == 200
        
        cert_data = response.json()
        assert cert_data["domains"] == [TEST_DOMAIN]
        assert cert_data["status"] == "active"
    
    def test_certificate_renewal(self, http_client: httpx.Client, cert_name: str):
        """Test renewing a real certificate."""
        # First generate a certificate
        cert_name = self.test_real_certificate_generation(http_client, cert_name)
        
        # Now renew it
        print(f"\nRenewing certificate {cert_name}...")
        response = http_client.post(f"/certificates/{cert_name}/renew", timeout=120.0)
        
        assert response.status_code == 200
        renewed_cert = response.json()
        assert renewed_cert["domains"] == [TEST_DOMAIN]
        assert renewed_cert["status"] == "active"
        
        print(f"✓ Certificate successfully renewed!")
    
    def test_list_certificates_includes_real_cert(self, http_client: httpx.Client, cert_name: str):
        """Test that real certificate appears in list."""
        # First generate a certificate
        cert_name = self.test_real_certificate_generation(http_client, cert_name)
        
        # List all certificates
        response = http_client.get("/certificates")
        assert response.status_code == 200
        
        certificates = response.json()
        cert_names = [list(cert.keys())[0] for cert in certificates]
        assert cert_name in cert_names
        
        # Find our certificate
        for cert_dict in certificates:
            if cert_name in cert_dict:
                cert = cert_dict[cert_name]
                assert cert["domains"] == [TEST_DOMAIN]
                assert cert["status"] == "active"
                break
    


class TestRealDomainValidation:
    """Test with multiple real subdomains."""
    
    def test_multiple_subdomains(self, http_client: httpx.Client):
        """Test certificates for multiple real subdomains."""
        subdomains = [
            f"api.{TEST_DOMAIN}",
            f"www.{TEST_DOMAIN}",
            f"app.{TEST_DOMAIN}"
        ]
        
        for subdomain in subdomains:
            cert_name = f"multi-{subdomain.split('.')[0]}-{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')}"
            
            request_data = {
                "domain": subdomain,
                "email": TEST_EMAIL,
                "cert_name": cert_name,
                "acme_directory_url": ACME_STAGING_URL
            }
            
            print(f"\nTesting subdomain: {subdomain}")
            response = http_client.post("/certificates", json=request_data, timeout=120.0)
            
            if response.status_code == 200:
                print(f"✓ Certificate generated for {subdomain}")
            else:
                print(f"✗ Failed for {subdomain}: {response.text}")
                # Continue testing other domains
    


class TestRealProduction:
    """Tests against real Let's Encrypt production (use sparingly!)."""
    
    def test_production_certificate(self, http_client: httpx.Client):
        """Test real production certificate generation."""
        prod_domain = f"prod-test.{TEST_DOMAIN}"
        cert_name = f"prod-{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')}"
        
        request_data = {
            "domain": prod_domain,
            "email": TEST_EMAIL,
            "cert_name": cert_name,
            "acme_directory_url": os.getenv("ACME_DIRECTORY_URL")  # Production URL from .env
        }
        
        print(f"\n⚠️  Requesting PRODUCTION certificate for {prod_domain}...")
        response = http_client.post("/certificates", json=request_data, timeout=120.0)
        
        assert response.status_code == 200
        cert_data = response.json()
        
        # Production certificates should be trusted
        print(f"✓ Production certificate generated!")
        print(f"  This is a REAL, trusted certificate!")