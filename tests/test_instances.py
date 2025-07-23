"""Instance management tests for the MCP HTTP Proxy service."""

import os
import pytest
import httpx
import secrets
from typing import Generator


@pytest.fixture
def created_instance(http_client: httpx.Client, auth_token: str) -> Generator[dict, None, None]:
    """Create a test instance and clean up after test."""
    test_instance_name = f"test-instance-{secrets.token_hex(4)}"
    instance_data = {
        "name": test_instance_name,
        "target_url": "http://test-backend:8080",
        "description": "Test instance for pytest"
    }
    
    response = http_client.post(
        "/instances/",
        headers={"Authorization": f"Bearer {auth_token}"},
        json=instance_data
    )
    
    assert response.status_code == 200, f"Expected 200, got {response.status_code}: {response.text}"
    yield response.json()
    
    # Cleanup
    http_client.delete(
        f"/instances/{test_instance_name}",
        headers={"Authorization": f"Bearer {auth_token}"}
    )


@pytest.mark.instances
class TestInstanceManagement:
    """Test named instance management functionality."""
    
    @pytest.fixture
    def test_instance_name(self) -> str:
        """Generate unique instance name for testing."""
        return f"test-instance-{secrets.token_hex(4)}"
            
    def test_create_instance_requires_auth(self, http_client: httpx.Client, test_instance_name: str):
        """Test that creating instance requires authentication."""
        instance_data = {
            "name": test_instance_name,
            "target_url": "http://backend:8080",
            "description": "Test instance"
        }
        
        response = http_client.post("/instances/", json=instance_data)
        assert response.status_code == 403, f"Expected 403 Forbidden, got {response.status_code}"
    
    def test_create_instance_with_valid_data(self, http_client: httpx.Client, auth_token: str, test_instance_name: str):
        """Test creating instance with valid data."""
        instance_data = {
            "name": test_instance_name,
            "target_url": "http://backend:8080",
            "description": "Test backend instance"
        }
        
        response = http_client.post(
            "/instances/",
            headers={"Authorization": f"Bearer {auth_token}"},
            json=instance_data
        )
        
        assert response.status_code == 200, f"Expected 200 OK, got {response.status_code}: {response.text}"
        data = response.json()
        assert data["name"] == test_instance_name
        assert data["target_url"] == instance_data["target_url"]
        assert data["description"] == instance_data["description"]
        
        # Cleanup
        http_client.delete(
            f"/instances/{test_instance_name}",
            headers={"Authorization": f"Bearer {auth_token}"}
        )
    
    def test_list_instances(self, http_client: httpx.Client):
        """Test listing all instances."""
        response = http_client.get("/instances/")
        
        # Instance list might be public
        assert response.status_code == 200
        data = response.json()
        assert isinstance(data, list)
    
    def test_get_instance_by_name(self, http_client: httpx.Client, created_instance: dict):
        """Test retrieving instance by name."""
        response = http_client.get(f"/instances/{created_instance['name']}")
        
        assert response.status_code == 200
        data = response.json()
        assert data["name"] == created_instance["name"]
        assert data["target_url"] == created_instance["target_url"]
    
    def test_get_nonexistent_instance(self, http_client: httpx.Client):
        """Test retrieving non-existent instance."""
        response = http_client.get("/instances/nonexistent-instance")
        assert response.status_code == 404
    
    def test_update_instance(self, http_client: httpx.Client, auth_token: str, created_instance: dict):
        """Test updating instance configuration."""
        update_data = {
            "name": created_instance["name"],
            "target_url": "http://updated-backend:9090",
            "description": "Updated test instance"
        }
        
        response = http_client.put(
            f"/instances/{created_instance['name']}",
            headers={"Authorization": f"Bearer {auth_token}"},
            json=update_data
        )
        
        assert response.status_code == 200
        data = response.json()
        assert data["target_url"] == update_data["target_url"]
        assert data["description"] == update_data["description"]
    
    def test_delete_instance(self, http_client: httpx.Client, auth_token: str, test_instance_name: str):
        """Test deleting instance."""
        # Create instance first
        instance_data = {
            "name": test_instance_name,
            "target_url": "http://backend:8080",
            "description": "Instance to delete"
        }
        
        create_response = http_client.post(
            "/instances/",
            headers={"Authorization": f"Bearer {auth_token}"},
            json=instance_data
        )
        assert create_response.status_code in [200, 201], f"Got {create_response.status_code}: {create_response.text}"
        
        # Delete it
        delete_response = http_client.delete(
            f"/instances/{test_instance_name}",
            headers={"Authorization": f"Bearer {auth_token}"}
        )
        
        assert delete_response.status_code in [200, 204], f"Delete failed: {delete_response.status_code}"
        
        # Verify it's gone
        get_response = http_client.get(f"/instances/{test_instance_name}")
        assert get_response.status_code == 404
    
    def test_create_duplicate_instance(self, http_client: httpx.Client, auth_token: str, created_instance: dict):
        """Test that duplicate instance names are rejected."""
        instance_data = {
            "name": created_instance["name"],
            "target_url": "http://another-backend:8080",
            "description": "Duplicate instance"
        }
        
        response = http_client.post(
            "/instances/",
            headers={"Authorization": f"Bearer {auth_token}"},
            json=instance_data
        )
        
        # Should reject duplicate name
        assert response.status_code == 409, f"Expected 409 Conflict, got {response.status_code}: {response.text}"

@pytest.mark.instances
class TestInstanceValidation:
    """Test instance data validation."""
    
    def test_create_instance_invalid_name(self, http_client: httpx.Client, auth_token: str):
        """Test creating instance with invalid name."""
        instance_data = {
            "name": "invalid name with spaces",
            "target_url": "http://backend:8080",
            "description": "Test"
        }
        
        response = http_client.post(
            "/instances/",
            headers={"Authorization": f"Bearer {auth_token}"},
            json=instance_data
        )
        
        # Should reject invalid name format
        assert response.status_code == 422, f"Expected 422 Unprocessable Entity, got {response.status_code}: {response.text}"
    
    def test_create_instance_invalid_url(self, http_client: httpx.Client, auth_token: str):
        """Test creating instance with invalid target URL."""
        instance_data = {
            "name": f"test-instance-{secrets.token_hex(4)}",
            "target_url": "ht tp://invalid url",
            "description": "Test"
        }
        
        response = http_client.post(
            "/instances/",
            headers={"Authorization": f"Bearer {auth_token}"},
            json=instance_data
        )
        
        # Should reject invalid URL
        assert response.status_code == 422, f"Expected 422 Unprocessable Entity, got {response.status_code}: {response.text}"
    
    def test_create_instance_missing_fields(self, http_client: httpx.Client, auth_token: str):
        """Test creating instance with missing required fields."""
        # Missing target_url
        instance_data = {
            "name": "test-instance",
            "description": "Test"
        }
        
        response = http_client.post(
            "/instances/",
            headers={"Authorization": f"Bearer {auth_token}"},
            json=instance_data
        )
        
        # Should reject missing fields
        assert response.status_code == 422, f"Expected 422 Unprocessable Entity, got {response.status_code}: {response.text}"

@pytest.mark.instances
class TestInstanceUsageInRoutes:
    """Test using instances in route configurations."""
    
    def test_route_with_instance_target(self, http_client: httpx.Client, auth_token: str, created_instance: dict):
        """Test creating route that targets an instance."""
        route_id = f"instance-route-{secrets.token_hex(4)}"
        route_data = {
            "route_id": route_id,
            "path_pattern": f"/api/test/{secrets.token_hex(4)}/",
            "target_type": "instance",
            "target_value": created_instance["name"],
            "priority": 50
        }
        
        response = http_client.post(
            "/routes/",
            headers={"Authorization": f"Bearer {auth_token}"},
            json=route_data
        )
        
        # Accept 404 if routes not implemented
        if response.status_code == 404:
            assert False, "FAILURE: Routes feature not implemented"
        
        assert response.status_code == 200, f"Expected 200 OK, got {response.status_code}: {response.text}"
        
        # Cleanup
        http_client.delete(
            f"/routes/{route_id}",
            headers={"Authorization": f"Bearer {auth_token}"}
        )
    
    def test_route_with_nonexistent_instance(self, http_client: httpx.Client, auth_token: str):
        """Test creating route with non-existent instance."""
        route_id = f"bad-route-{secrets.token_hex(4)}"
        route_data = {
            "route_id": route_id,
            "path_pattern": f"/bad/{secrets.token_hex(4)}/",
            "target_type": "instance",
            "target_value": "nonexistent-instance",
            "priority": 50
        }
        
        response = http_client.post(
            "/routes/",
            headers={"Authorization": f"Bearer {auth_token}"},
            json=route_data
        )
        
        # Skip if routes not implemented
        if response.status_code == 404:
            assert False, "FAILURE: Routes feature not implemented"
        
        # Might accept the route but fail at runtime, or reject immediately
        # Both behaviors are acceptable
        assert response.status_code in [200, 201, 400, 422], f"Got {response.status_code}: {response.text}"
        
        if response.status_code in [200, 201]:
            # Cleanup if created
            http_client.delete(
                f"/routes/{route_id}",
                headers={"Authorization": f"Bearer {auth_token}"}
            )

@pytest.mark.instances
class TestWellKnownInstances:
    """Test well-known instance registrations."""
    
    def test_register_auth_instance(self, http_client: httpx.Client, auth_token: str):
        """Test registering OAuth auth server as instance."""
        instance_data = {
            "name": "auth",
            "target_url": "http://auth:8000",
            "description": "OAuth 2.0 Authorization Server"
        }
        
        response = http_client.post(
            "/instances/",
            headers={"Authorization": f"Bearer {auth_token}"},
            json=instance_data
        )
        
        # Should create new or conflict if exists
        assert response.status_code in [200, 409], f"Expected 200 or 409, got {response.status_code}: {response.text}"
        
        if response.status_code in [200, 201]:
            # Cleanup only if we created it
            http_client.delete(
                "/instances/auth",
                headers={"Authorization": f"Bearer {auth_token}"}
            )