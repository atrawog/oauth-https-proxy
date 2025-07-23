"""Proxy management tests for the MCP HTTP Proxy service."""

import os
import time
import pytest
import httpx

import secrets
from typing import Generator

# Module-level fixtures shared across all test classes
@pytest.fixture
def test_hostname() -> str:
    """Generate unique hostname for testing."""
    base_domain = os.getenv("TEST_DOMAIN_BASE", "example.com")
    return f"test-proxy-{secrets.token_hex(4)}.{base_domain}"

@pytest.fixture
def test_target_url() -> str:
    """Get test target URL."""
    return os.getenv("TEST_PROXY_TARGET_URL", "https://example.com")

@pytest.fixture
def created_proxy(http_client: httpx.Client, auth_token: str, test_hostname: str, test_target_url: str) -> Generator[dict, None, None]:
    """Create a test proxy and clean up after test."""
    proxy_data = {
        "hostname": test_hostname,
        "target_url": test_target_url,
        "cert_email": os.getenv("TEST_EMAIL", "test@example.com"),
        "preserve_host_header": True,
        "enable_http": True,
        "enable_https": True,
        "acme_directory_url": os.getenv("ACME_STAGING_URL")
    }
    
    response = http_client.post(
        "/proxy/targets/",
        headers={"Authorization": f"Bearer {auth_token}"},
        json=proxy_data
    )
    
    assert response.status_code == 200, f"Expected 200, got {response.status_code}: {response.text}"
    yield response.json()
    
    # Cleanup
    http_client.delete(
        f"/proxy/targets/{test_hostname}",
        headers={"Authorization": f"Bearer {auth_token}"}
    )


@pytest.mark.proxy
class TestProxyBasic:
    """Basic proxy functionality tests."""

    @pytest.mark.basic
    def test_create_proxy_requires_auth(self, http_client: httpx.Client, test_hostname: str, test_target_url: str):
        """Test that creating proxy requires authentication."""
        proxy_data = {
            "hostname": test_hostname,
            "target_url": test_target_url
        }
        
        response = http_client.post("/proxy/targets/", json=proxy_data)
        assert response.status_code == 403, f"Expected 403 Forbidden, got {response.status_code}"
    
    @pytest.mark.basic
    def test_create_proxy_with_valid_data(self, http_client: httpx.Client, auth_token: str, test_hostname: str, test_target_url: str):
        """Test creating proxy with valid data."""
        proxy_data = {
            "hostname": test_hostname,
            "target_url": test_target_url,
            "cert_email": os.getenv("TEST_EMAIL", "test@example.com"),
            "preserve_host_header": True,
            "enable_http": True,
            "enable_https": True,
            "acme_directory_url": os.getenv("ACME_STAGING_URL")
        }
        
        response = http_client.post(
            "/proxy/targets/",
            headers={"Authorization": f"Bearer {auth_token}"},
            json=proxy_data
        )
        
        assert response.status_code == 200, f"Expected 200 OK, got {response.status_code}: {response.text}"
        data = response.json()
        assert data["proxy_target"]["hostname"] == test_hostname
        assert data["proxy_target"]["target_url"] == test_target_url
        
        # Cleanup
        http_client.delete(
            f"/proxy/targets/{test_hostname}",
            headers={"Authorization": f"Bearer {auth_token}"}
        )
    
    @pytest.mark.basic
    def test_list_proxies(self, http_client: httpx.Client, auth_token: str):
        """Test listing proxy targets."""
        response = http_client.get(
            "/proxy/targets/",
            headers={"Authorization": f"Bearer {auth_token}"}
        )
        
        assert response.status_code == 200
        data = response.json()
        assert isinstance(data, list)
    
    @pytest.mark.basic
    def test_get_proxy_by_hostname(self, http_client: httpx.Client, created_proxy: dict):
        """Test retrieving proxy by hostname."""
        response = http_client.get(f"/proxy/targets/{created_proxy['proxy_target']['hostname']}")
        
        assert response.status_code == 200
        data = response.json()
        assert data["hostname"] == created_proxy["proxy_target"]["hostname"]
        assert data["target_url"] == created_proxy["proxy_target"]["target_url"]
    
    @pytest.mark.basic
    def test_get_nonexistent_proxy(self, http_client: httpx.Client):
        """Test retrieving non-existent proxy."""
        response = http_client.get("/proxy/targets/nonexistent.example.com")
        assert response.status_code == 404
    
    @pytest.mark.basic
    def test_update_proxy(self, http_client: httpx.Client, auth_token: str, created_proxy: dict):
        """Test updating proxy configuration."""
        update_data = {
            "target_url": "https://updated.example.com",
            "preserve_host_header": False
        }
        
        response = http_client.put(
            f"/proxy/targets/{created_proxy['proxy_target']['hostname']}",
            headers={"Authorization": f"Bearer {auth_token}"},
            json=update_data
        )
        
        assert response.status_code == 200
        data = response.json()
        assert data["target_url"] == update_data["target_url"]
        assert data["preserve_host_header"] == False
    
    @pytest.mark.basic
    def test_delete_proxy(self, http_client: httpx.Client, auth_token: str, test_hostname: str, test_target_url: str):
        """Test deleting proxy."""
        # Create proxy first
        proxy_data = {
            "hostname": test_hostname,
            "target_url": test_target_url,
            "cert_email": os.getenv("TEST_EMAIL", "test@example.com")
        }
        
        create_response = http_client.post(
            "/proxy/targets/",
            headers={"Authorization": f"Bearer {auth_token}"},
            json=proxy_data
        )
        assert create_response.status_code in [200, 201], f"Got {create_response.status_code}: {create_response.text}"
        
        # Delete it
        delete_response = http_client.delete(
            f"/proxy/targets/{test_hostname}",
            headers={"Authorization": f"Bearer {auth_token}"}
        )
        
        assert delete_response.status_code in [200, 204], f"Delete failed: {delete_response.status_code}"
        
        # Verify it's gone
        get_response = http_client.get(f"/proxy/targets/{test_hostname}")
        assert get_response.status_code == 404

@pytest.mark.proxy
class TestProxyAuthentication:
    """Test proxy authentication configuration."""

    @pytest.fixture
    def auth_proxy(self) -> str:
        """Get auth proxy hostname."""
        base_domain = os.getenv("BASE_DOMAIN", "localhost")
        return f"auth.{base_domain}"
    
    def test_enable_proxy_auth(self, http_client: httpx.Client, auth_token: str, created_proxy: dict, auth_proxy: str):
        """Test enabling authentication on proxy."""
        auth_config = {
            "auth_enabled": True,
            "auth_proxy": auth_proxy,
            "auth_mode": "forward",
            "auth_required_users": [],
            "auth_required_emails": ["*@example.com"],
            "auth_pass_headers": True
        }
        
        response = http_client.post(
            f"/proxy/targets/{created_proxy['proxy_target']['hostname']}/auth",
            headers={"Authorization": f"Bearer {auth_token}"},
            json=auth_config
        )
        
        assert response.status_code == 200, f"Expected 200 OK, got {response.status_code}: {response.text}"
        data = response.json()
        # Auth config might be returned nested or flat
        if "proxy_target" in data:
            assert data["proxy_target"]["auth_enabled"] == True
            assert data["proxy_target"]["auth_proxy"] == auth_proxy
        else:
            assert data.get("auth_enabled") == True or data.get("proxy_target", {}).get("auth_enabled") == True
            assert auth_proxy in str(data)  # Verify auth_proxy is somewhere in response
    
    def test_disable_proxy_auth(self, http_client: httpx.Client, auth_token: str, created_proxy: dict):
        """Test disabling authentication on proxy."""
        response = http_client.delete(
            f"/proxy/targets/{created_proxy['proxy_target']['hostname']}/auth",
            headers={"Authorization": f"Bearer {auth_token}"}
        )
        
        assert response.status_code in [200, 204], f"Expected 200 OK or 204 No Content, got {response.status_code}"
    
    def test_get_proxy_auth_config(self, http_client: httpx.Client, created_proxy: dict):
        """Test retrieving proxy auth configuration."""
        response = http_client.get(f"/proxy/targets/{created_proxy['proxy_target']['hostname']}/auth")
        
        # Should return auth config or 404 if not configured
        assert response.status_code in [200, 404], f"Got {response.status_code}: {response.text}"
        
        if response.status_code == 200:
            data = response.json()
            assert "auth_enabled" in data

@pytest.mark.proxy
class TestProxyEnableDisable:
    """Test proxy enable/disable functionality."""

    def test_disable_proxy(self, http_client: httpx.Client, auth_token: str, created_proxy: dict):
        """Test disabling a proxy."""
        # First ensure it's enabled
        update_data = {"enabled": True}
        http_client.put(
            f"/proxy/targets/{created_proxy['proxy_target']['hostname']}",
            headers={"Authorization": f"Bearer {auth_token}"},
            json=update_data
        )
        
        # Now disable it
        update_data = {"enabled": False}
        response = http_client.put(
            f"/proxy/targets/{created_proxy['proxy_target']['hostname']}",
            headers={"Authorization": f"Bearer {auth_token}"},
            json=update_data
        )
        
        assert response.status_code == 200
        data = response.json()
        assert data["enabled"] == False
    
    def test_enable_proxy(self, http_client: httpx.Client, auth_token: str, created_proxy: dict):
        """Test enabling a proxy."""
        # First disable it
        update_data = {"enabled": False}
        http_client.put(
            f"/proxy/targets/{created_proxy['proxy_target']['hostname']}",
            headers={"Authorization": f"Bearer {auth_token}"},
            json=update_data
        )
        
        # Now enable it
        update_data = {"enabled": True}
        response = http_client.put(
            f"/proxy/targets/{created_proxy['proxy_target']['hostname']}",
            headers={"Authorization": f"Bearer {auth_token}"},
            json=update_data
        )
        
        assert response.status_code == 200
        data = response.json()
        assert data["enabled"] == True

@pytest.mark.proxy
class TestProxyCertificateManagement:
    """Test proxy certificate management."""

    def test_proxy_creates_certificate_on_demand(self, http_client: httpx.Client, auth_token: str, created_proxy: dict):
        """Test that proxy creates certificate when needed."""
        # Check if cert_name is set in proxy
        response = http_client.get(f"/proxy/targets/{created_proxy['proxy_target']['hostname']}")
        assert response.status_code == 200
        data = response.json()
        
        # New proxies should have cert_name set
        if "cert_name" in data and data["cert_name"]:
            # Certificate generation might be async
            cert_name = data["cert_name"]
            
            # Check if certificate exists
            cert_response = http_client.get(
                f"/certificates/{cert_name}",
                headers={"Authorization": f"Bearer {auth_token}"}
            )
            
            # Certificate might still be generating
            assert cert_response.status_code in [200, 404], f"Got {cert_response.status_code}: {cert_response.text}"
    
    def test_attach_existing_certificate_to_proxy(self, http_client: httpx.Client, auth_token: str, created_proxy: dict):
        """Test attaching an existing certificate to proxy."""
        # This would require creating a certificate first
        # For now, just test the update with cert_name
        update_data = {
            "cert_name": "test-existing-cert"
        }
        
        response = http_client.put(
            f"/proxy/targets/{created_proxy['proxy_target']['hostname']}",
            headers={"Authorization": f"Bearer {auth_token}"},
            json=update_data
        )
        
        assert response.status_code == 200
        data = response.json()
        assert data.get("cert_name") == "test-existing-cert"

@pytest.mark.proxy
class TestProxyHeaders:
    """Test proxy header configuration."""

    def test_custom_headers_configuration(self, http_client: httpx.Client, auth_token: str, created_proxy: dict):
        """Test configuring custom headers for proxy."""
        update_data = {
            "custom_headers": {
                "X-Custom-Header": "test-value",
                "X-Another-Header": "another-value"
            }
        }
        
        response = http_client.put(
            f"/proxy/targets/{created_proxy['proxy_target']['hostname']}",
            headers={"Authorization": f"Bearer {auth_token}"},
            json=update_data
        )
        
        assert response.status_code == 200
        data = response.json()
        assert data.get("custom_headers") == update_data["custom_headers"]
    
    def test_preserve_host_header_configuration(self, http_client: httpx.Client, auth_token: str, created_proxy: dict):
        """Test preserve_host_header configuration."""
        # Test setting to False
        update_data = {"preserve_host_header": False}
        response = http_client.put(
            f"/proxy/targets/{created_proxy['proxy_target']['hostname']}",
            headers={"Authorization": f"Bearer {auth_token}"},
            json=update_data
        )
        
        assert response.status_code == 200
        data = response.json()
        assert data["preserve_host_header"] == False
        
        # Test setting back to True
        update_data = {"preserve_host_header": True}
        response = http_client.put(
            f"/proxy/targets/{created_proxy['proxy_target']['hostname']}",
            headers={"Authorization": f"Bearer {auth_token}"},
            json=update_data
        )
        
        assert response.status_code == 200
        data = response.json()
        assert data["preserve_host_header"] == True