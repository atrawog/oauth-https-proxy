"""Health check tests for the MCP HTTP Proxy service."""

import pytest
import httpx

class TestHealthCheck:
    """Test basic health check functionality."""
    
    def test_health_endpoint_returns_success(self, http_client: httpx.Client):
        """Test that health endpoint returns 200 status."""
        response = http_client.get("/health")
        assert response.status_code == 200
    
    def test_health_endpoint_returns_json(self, http_client: httpx.Client):
        """Test that health endpoint returns valid JSON."""
        response = http_client.get("/health")
        assert response.headers.get("content-type") == "application/json"
        data = response.json()
        assert isinstance(data, dict)
    
    def test_health_endpoint_contains_required_fields(self, http_client: httpx.Client):
        """Test that health endpoint contains all required fields."""
        response = http_client.get("/health")
        data = response.json()
        
        required_fields = [
            "status",
            "scheduler", 
            "redis",
            "certificates_loaded",
            "https_enabled",
            "orphaned_resources"
        ]
        
        for field in required_fields:
            assert field in data, f"Missing required field: {field}"
    
    def test_health_endpoint_field_types(self, http_client: httpx.Client):
        """Test that health endpoint fields have correct types."""
        response = http_client.get("/health")
        data = response.json()
        
        assert isinstance(data["status"], str)
        assert isinstance(data["scheduler"], bool)
        assert isinstance(data["redis"], str)
        assert isinstance(data["certificates_loaded"], int)
        assert isinstance(data["https_enabled"], bool)
        assert isinstance(data["orphaned_resources"], (int, dict))
    
    def test_health_redis_status(self, http_client: httpx.Client):
        """Test that Redis is reported as healthy."""
        response = http_client.get("/health")
        data = response.json()
        
        assert data["redis"] == "healthy"
    
    def test_health_scheduler_running(self, http_client: httpx.Client):
        """Test that scheduler is reported as running."""
        response = http_client.get("/health")
        data = response.json()
        
        # Scheduler should be running in production
        assert data["scheduler"] is True
    
    def test_health_certificates_loaded(self, http_client: httpx.Client):
        """Test that certificates loaded count is non-negative."""
        response = http_client.get("/health")
        data = response.json()
        
        assert data["certificates_loaded"] >= 0
    
    @pytest.mark.parametrize("timeout", [5, 10, 30])
    def test_health_endpoint_response_time(self, http_client: httpx.Client, timeout):
        """Test that health endpoint responds within timeout."""
        # Create a client with specific timeout
        with httpx.Client(base_url=http_client.base_url, timeout=timeout) as client:
            response = client.get("/health")
            assert response.status_code == 200