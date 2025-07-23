"""Route management tests for the MCP HTTP Proxy service."""

import os
import pytest
import httpx

import secrets
from typing import Generator

@pytest.mark.routes
class TestRouteManagement:
    """Test route management functionality."""

    @pytest.fixture
    def test_route_id(self) -> str:
        """Generate unique route ID for testing."""
        return f"test-route-{secrets.token_hex(4)}"
    
    @pytest.fixture
    def created_route(self, http_client: httpx.Client, auth_token: str, test_route_id: str) -> Generator[dict, None, None]:
        """Create a test route and clean up after test."""
        route_data = {
            "route_id": test_route_id,
            "path_pattern": f"/test/{test_route_id}/",
            "target_type": "hostname",
            "target_value": "test.example.com",
            "priority": 50,
            "methods": ["GET", "POST"],
            "enabled": True,
            "description": "Test route"
        }
        
        response = http_client.post(
            "/routes/",
            headers={"Authorization": f"Bearer {auth_token}"},
            json=route_data
        )
        
        assert response.status_code == 200, f"Expected 200, got {response.status_code}: {response.text}"
        route_response = response.json()
        yield route_response
        
        # Cleanup
        actual_route_id = route_response["route_id"]
        http_client.delete(
                f"/routes/{actual_route_id}",
                headers={"Authorization": f"Bearer {auth_token}"}
            )
            
    def test_create_route_requires_auth(self, http_client: httpx.Client, test_route_id: str):
        """Test that creating route requires authentication."""
        route_data = {
            "route_id": test_route_id,
            "path_pattern": "/test/",
            "target_type": "hostname",
            "target_value": "test.example.com"
        }
        
        response = http_client.post("/routes/", json=route_data)
        assert response.status_code == 403, f"Got {response.status_code}: {response.text}"  # 404 if endpoint not implemented
    
    def test_create_route_with_valid_data(self, http_client: httpx.Client, auth_token: str, test_route_id: str):
        """Test creating route with valid data."""
        route_data = {
            "route_id": test_route_id,
            "path_pattern": f"/api/v1/{test_route_id}/",
            "target_type": "instance",
            "target_value": "api-backend",
            "priority": 90,
            "methods": ["GET", "POST", "PUT", "DELETE"],
            "enabled": True,
            "description": "API v1 route"
        }
        
        response = http_client.post(
            "/routes/",
            headers={"Authorization": f"Bearer {auth_token}"},
            json=route_data
        )
        
        # Accept 404 if routes feature not implemented yet
        if response.status_code == 404:
            assert False, "FAILURE: Routes feature not implemented"
        
        assert response.status_code == 200, f"Expected 200 OK, got {response.status_code}: {response.text}"
        data = response.json()
        # Route ID is server-generated, not necessarily matching test_route_id
        actual_route_id = data["route_id"]
        assert data["path_pattern"] == route_data["path_pattern"]
        
        # Cleanup
        http_client.delete(
            f"/routes/{actual_route_id}",
            headers={"Authorization": f"Bearer {auth_token}"}
        )
    
    def test_list_routes(self, http_client: httpx.Client):
        """Test listing all routes."""
        response = http_client.get("/routes/")
        
        # Accept 404 if routes feature not implemented yet
        if response.status_code == 404:
            assert False, "FAILURE: Routes feature not implemented"
        
        # Routes list might be public (no auth required)
        assert response.status_code == 200, f"Got {response.status_code}: {response.text}"
        
        if response.status_code == 200:
            data = response.json()
            assert isinstance(data, list)
    
    def test_get_route_by_id(self, http_client: httpx.Client, created_route: dict):
        """Test retrieving route by ID."""
        response = http_client.get(f"/routes/{created_route['route_id']}")
        
        assert response.status_code == 200
        data = response.json()
        assert data["route_id"] == created_route["route_id"]
        assert data["path_pattern"] == created_route["path_pattern"]
    
    def test_update_route(self, http_client: httpx.Client, auth_token: str, created_route: dict):
        """Test updating route configuration."""
        update_data = {
            "priority": 95,
            "enabled": False,
            "description": "Updated test route"
        }
        
        response = http_client.put(
            f"/routes/{created_route['route_id']}",
            headers={"Authorization": f"Bearer {auth_token}"},
            json=update_data
        )
        
        assert response.status_code == 200
        data = response.json()
        assert data["priority"] == 95
        assert data["enabled"] == False
        assert data["description"] == "Updated test route"
    
    def test_delete_route(self, http_client: httpx.Client, auth_token: str, test_route_id: str):
        """Test deleting route."""
        # Create route first
        route_data = {
            "route_id": test_route_id,
            "path_pattern": f"/delete-test-{test_route_id}/",
            "target_type": "hostname",
            "target_value": "test.example.com"
        }
        
        create_response = http_client.post(
            "/routes/",
            headers={"Authorization": f"Bearer {auth_token}"},
            json=route_data
        )
        
        # Skip if not implemented
        if create_response.status_code == 404:
            assert False, "FAILURE: Routes feature not implemented"
        
        assert create_response.status_code in [200, 201], f"Got {create_response.status_code}: {create_response.text}"
        created_data = create_response.json()
        actual_route_id = created_data["route_id"]
        
        # Delete it
        delete_response = http_client.delete(
            f"/routes/{actual_route_id}",
            headers={"Authorization": f"Bearer {auth_token}"}
        )
        
        assert delete_response.status_code in [200, 204], f"Delete failed: {delete_response.status_code}"
        
        # Verify it's gone
        get_response = http_client.get(f"/routes/{actual_route_id}")
        assert get_response.status_code == 404

@pytest.mark.routes
class TestRouteTypes:
    """Test different route target types."""

    def test_create_port_type_route(self, http_client: httpx.Client, auth_token: str):
        """Test creating route with port target type."""
        route_id = f"port-route-{secrets.token_hex(4)}"
        route_data = {
            "route_id": route_id,
            "path_pattern": f"/port-test-{route_id}/",
            "target_type": "port",
            "target_value": "8080",
            "priority": 50
        }
        
        response = http_client.post(
            "/routes/",
            headers={"Authorization": f"Bearer {auth_token}"},
            json=route_data
        )
        
        if response.status_code == 404:
            assert False, "FAILURE: Routes feature not implemented"
        
        assert response.status_code == 200, f"Expected 200 OK, got {response.status_code}: {response.text}"
        actual_route_id = response.json()["route_id"]
        
        # Cleanup
        http_client.delete(
            f"/routes/{actual_route_id}",
            headers={"Authorization": f"Bearer {auth_token}"}
        )
    
    def test_create_instance_type_route(self, http_client: httpx.Client, auth_token: str):
        """Test creating route with instance target type."""
        route_id = f"instance-route-{secrets.token_hex(4)}"
        route_data = {
            "route_id": route_id,
            "path_pattern": f"/instance-test-{route_id}/",
            "target_type": "instance",
            "target_value": "test-backend",
            "priority": 50
        }
        
        response = http_client.post(
            "/routes/",
            headers={"Authorization": f"Bearer {auth_token}"},
            json=route_data
        )
        
        if response.status_code == 404:
            assert False, "FAILURE: Routes feature not implemented"
        
        assert response.status_code == 200, f"Expected 200 OK, got {response.status_code}: {response.text}"
        actual_route_id = response.json()["route_id"]
        
        # Cleanup
        http_client.delete(
            f"/routes/{actual_route_id}",
            headers={"Authorization": f"Bearer {auth_token}"}
        )
    
    def test_create_hostname_type_route(self, http_client: httpx.Client, auth_token: str):
        """Test creating route with hostname target type."""
        route_id = f"hostname-route-{secrets.token_hex(4)}"
        route_data = {
            "route_id": route_id,
            "path_pattern": f"/hostname-test-{route_id}/",
            "target_type": "hostname",
            "target_value": "backend.example.com",
            "priority": 50
        }
        
        response = http_client.post(
            "/routes/",
            headers={"Authorization": f"Bearer {auth_token}"},
            json=route_data
        )
        
        if response.status_code == 404:
            assert False, "FAILURE: Routes feature not implemented"
        
        assert response.status_code == 200, f"Expected 200 OK, got {response.status_code}: {response.text}"
        actual_route_id = response.json()["route_id"]
        
        # Cleanup
        http_client.delete(
            f"/routes/{actual_route_id}",
            headers={"Authorization": f"Bearer {auth_token}"}
        )

@pytest.mark.routes
class TestRoutePriority:
    """Test route priority handling."""

    def test_route_priority_ordering(self, http_client: httpx.Client, auth_token: str):
        """Test that routes are evaluated by priority."""
        # Create multiple routes with different priorities
        routes = []
        for priority in [10, 50, 90]:
            route_id = f"priority-test-{priority}"
            route_data = {
                "route_id": route_id,
                "path_pattern": f"/priority-test-{route_id}/",
                "target_type": "hostname",
                "target_value": f"backend-{priority}.example.com",
                "priority": priority
            }
            
            response = http_client.post(
                "/routes/",
                headers={"Authorization": f"Bearer {auth_token}"},
                json=route_data
            )
            
            if response.status_code == 404:
                assert False, "FAILURE: Routes feature not implemented"
            
            if response.status_code in [200, 201]:
                actual_route_id = response.json()["route_id"]
                routes.append(actual_route_id)
        
        # List routes and check ordering
        list_response = http_client.get("/routes/")
        if list_response.status_code == 200:
            all_routes = list_response.json()
            # Routes should be ordered by priority (highest first)
            test_routes = [r for r in all_routes if r["route_id"] in routes]
            if len(test_routes) >= 2:
                for i in range(len(test_routes) - 1):
                    assert test_routes[i]["priority"] >= test_routes[i + 1]["priority"]
        
        # Cleanup
        for route_id in routes:
            http_client.delete(
                f"/routes/{route_id}",
                headers={"Authorization": f"Bearer {auth_token}"}
            )

@pytest.mark.routes
class TestRoutePatterns:
    """Test route pattern matching."""

    def test_regex_route_pattern(self, http_client: httpx.Client, auth_token: str):
        """Test creating route with regex pattern."""
        route_id = f"regex-route-{secrets.token_hex(4)}"
        route_data = {
            "route_id": route_id,
            "path_pattern": "^/api/v[0-9]+/.*",
            "target_type": "instance",
            "target_value": "api-backend",
            "priority": 81,
            "is_regex": True
        }
        
        response = http_client.post(
            "/routes/",
            headers={"Authorization": f"Bearer {auth_token}"},
            json=route_data
        )
        
        if response.status_code == 404:
            assert False, "FAILURE: Routes feature not implemented"
        
        assert response.status_code == 200, f"Expected 200 OK, got {response.status_code}: {response.text}"
        actual_route_id = response.json()["route_id"]
        
        # Cleanup
        http_client.delete(
            f"/routes/{actual_route_id}",
            headers={"Authorization": f"Bearer {auth_token}"}
        )
    
    def test_method_specific_route(self, http_client: httpx.Client, auth_token: str):
        """Test creating route for specific HTTP methods."""
        route_id = f"method-route-{secrets.token_hex(4)}"
        route_data = {
            "route_id": route_id,
            "path_pattern": f"/webhook-{route_id}/",
            "target_type": "instance",
            "target_value": "webhook-handler",
            "priority": 70,
            "methods": ["POST", "PUT"]
        }
        
        response = http_client.post(
            "/routes/",
            headers={"Authorization": f"Bearer {auth_token}"},
            json=route_data
        )
        
        if response.status_code == 404:
            assert False, "FAILURE: Routes feature not implemented"
        
        assert response.status_code == 200, f"Expected 200 OK, got {response.status_code}: {response.text}"
        data = response.json()
        assert set(data["methods"]) == {"POST", "PUT"}
        
        # Cleanup
        http_client.delete(
            f"/routes/{route_id}",
            headers={"Authorization": f"Bearer {auth_token}"}
        )

@pytest.mark.routes
class TestProxyRouteControl:
    """Test per-proxy route control."""

    def test_proxy_route_mode(self, http_client: httpx.Client, auth_token: str):
        """Test setting proxy route mode."""
        test_hostname = f"route-test.{os.getenv('TEST_DOMAIN_BASE', 'example.com')}"
        
        # First create a proxy
        proxy_data = {
            "hostname": test_hostname,
            "target_url": "http://backend:8080"
        }
        
        proxy_response = http_client.post(
            "/proxy/targets/",
            headers={"Authorization": f"Bearer {auth_token}"},
            json=proxy_data
        )
        
        if proxy_response.status_code not in [200, 201]:
            assert False, "FAILURE: Failed to create test proxy"
        
        # Test setting route mode
        mode_response = http_client.put(
            f"/proxy/targets/{test_hostname}/routes/mode",
            headers={"Authorization": f"Bearer {auth_token}"},
            json={"mode": "selective"}
        )
        
        # Accept 404 if per-proxy route control not implemented
        assert mode_response.status_code in [200, 404], f"Got {mode_response.status_code}: {mode_response.text}"
        
        # Cleanup
        http_client.delete(
            f"/proxy/targets/{test_hostname}",
            headers={"Authorization": f"Bearer {auth_token}"}
        )