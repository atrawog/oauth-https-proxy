"""Tests for Docker service management functionality."""

import pytest
import asyncio
import os
import json
from typing import Dict
from datetime import datetime

from src.storage.redis_storage import RedisStorage
from src.docker.manager import DockerManager
from src.docker.models import (
    DockerServiceConfig,
    DockerServiceInfo,
    DockerServiceUpdate,
    DockerImageAllowlist
)


# Test fixtures
@pytest.fixture
def storage():
    """Create a test storage instance."""
    redis_url = os.getenv("REDIS_URL", "redis://localhost:6379/0")
    storage = RedisStorage(redis_url)
    storage.connect()
    yield storage
    # Cleanup
    storage.disconnect()


@pytest.fixture
def docker_manager(storage):
    """Create a test Docker manager instance."""
    # Use DOCKER_HOST if set, otherwise default to Unix socket
    docker_host = os.getenv("DOCKER_HOST")
    return DockerManager(storage, docker_host)


@pytest.fixture
def test_token_hash():
    """Test token hash for ownership tracking."""
    return "sha256:test_token_hash_12345"


@pytest.fixture
def nginx_service_config():
    """Create a test nginx service configuration."""
    return DockerServiceConfig(
        service_name="test-nginx",
        image="nginx:alpine",
        internal_port=80,
        memory_limit="128m",
        cpu_limit=0.5,
        environment={"TEST_ENV": "true"},
        labels={"test": "true", "managed": "true"}
    )


@pytest.fixture
async def cleanup_service(docker_manager):
    """Cleanup fixture to ensure test services are removed."""
    services_to_cleanup = []
    
    yield services_to_cleanup
    
    # Cleanup any created services
    for service_name in services_to_cleanup:
        try:
            await docker_manager.delete_service(service_name, force=True)
        except Exception:
            pass  # Service might already be deleted


class TestDockerServiceCreation:
    """Test Docker service creation functionality."""
    
    @pytest.mark.asyncio
    async def test_create_service_from_image(self, docker_manager, nginx_service_config, test_token_hash, cleanup_service):
        """Test creating a service from a Docker image."""
        # Create service
        service_info = await docker_manager.create_service(nginx_service_config, test_token_hash)
        cleanup_service.append(service_info.service_name)
        
        # Verify service info
        assert service_info.service_name == "test-nginx"
        assert service_info.image == "nginx:alpine"
        assert service_info.status == "running"
        assert service_info.container_id is not None
        assert service_info.allocated_port >= 11000
        assert service_info.owner_token_hash == test_token_hash
        
        # Verify service exists in storage
        stored_service = await docker_manager.get_service("test-nginx")
        assert stored_service is not None
        assert stored_service.service_name == "test-nginx"
    
    @pytest.mark.asyncio
    async def test_create_service_with_custom_port(self, docker_manager, test_token_hash, cleanup_service):
        """Test creating a service with a specified port."""
        config = DockerServiceConfig(
            service_name="test-httpd",
            image="httpd:alpine",
            internal_port=80,
            external_port=11500,
            memory_limit="64m"
        )
        
        service_info = await docker_manager.create_service(config, test_token_hash)
        cleanup_service.append(service_info.service_name)
        
        assert service_info.allocated_port == 11500
    
    @pytest.mark.asyncio
    async def test_create_service_duplicate_name_fails(self, docker_manager, nginx_service_config, test_token_hash, cleanup_service):
        """Test that creating a service with duplicate name fails."""
        # Create first service
        service_info = await docker_manager.create_service(nginx_service_config, test_token_hash)
        cleanup_service.append(service_info.service_name)
        
        # Try to create duplicate
        with pytest.raises(Exception) as exc_info:
            await docker_manager.create_service(nginx_service_config, test_token_hash)
        
        assert "already exists" in str(exc_info.value).lower()
    
    @pytest.mark.asyncio
    async def test_image_allowlist_validation(self, docker_manager, storage, test_token_hash):
        """Test that only allowed images can be used."""
        # Set restrictive allowlist
        allowlist = DockerImageAllowlist(
            patterns=["nginx:*"],
            registries=["docker.io"]
        )
        storage.redis_client.set("docker_image_allowlist", allowlist.json())
        
        # Try to create service with disallowed image
        config = DockerServiceConfig(
            service_name="test-redis",
            image="redis:alpine",
            internal_port=6379
        )
        
        with pytest.raises(ValueError) as exc_info:
            await docker_manager.create_service(config, test_token_hash)
        
        assert "not in the allowlist" in str(exc_info.value)


class TestDockerServiceManagement:
    """Test Docker service management operations."""
    
    @pytest.mark.asyncio
    async def test_list_services(self, docker_manager, nginx_service_config, test_token_hash, cleanup_service):
        """Test listing Docker services."""
        # Create a service
        service_info = await docker_manager.create_service(nginx_service_config, test_token_hash)
        cleanup_service.append(service_info.service_name)
        
        # List all services
        services = await docker_manager.list_services()
        
        # Find our service
        our_service = next((s for s in services if s.service_name == "test-nginx"), None)
        assert our_service is not None
        assert our_service.owner_token_hash == test_token_hash
    
    @pytest.mark.asyncio
    async def test_list_services_by_owner(self, docker_manager, nginx_service_config, test_token_hash, cleanup_service):
        """Test listing services filtered by owner."""
        # Create a service
        service_info = await docker_manager.create_service(nginx_service_config, test_token_hash)
        cleanup_service.append(service_info.service_name)
        
        # List services by owner
        services = await docker_manager.list_services(owner_token_hash=test_token_hash)
        assert len(services) >= 1
        assert all(s.owner_token_hash == test_token_hash for s in services)
        
        # List with different owner should not include our service
        other_services = await docker_manager.list_services(owner_token_hash="sha256:other_token")
        assert not any(s.service_name == "test-nginx" for s in other_services)
    
    @pytest.mark.asyncio
    async def test_update_service(self, docker_manager, nginx_service_config, test_token_hash, cleanup_service):
        """Test updating a service configuration."""
        # Create a service
        service_info = await docker_manager.create_service(nginx_service_config, test_token_hash)
        cleanup_service.append(service_info.service_name)
        
        # Update service
        updates = DockerServiceUpdate(
            environment={"NEW_VAR": "new_value"},
            memory_limit="256m"
        )
        
        updated_service = await docker_manager.update_service("test-nginx", updates)
        
        assert updated_service.environment["NEW_VAR"] == "new_value"
        assert updated_service.memory_limit == "256m"
    
    @pytest.mark.asyncio
    async def test_stop_start_service(self, docker_manager, nginx_service_config, test_token_hash, cleanup_service):
        """Test stopping and starting a service."""
        # Create a service
        service_info = await docker_manager.create_service(nginx_service_config, test_token_hash)
        cleanup_service.append(service_info.service_name)
        
        # Stop service
        await docker_manager.stop_service("test-nginx")
        
        # Verify stopped
        stopped_service = await docker_manager.get_service("test-nginx")
        assert stopped_service.status in ["exited", "stopped"]
        
        # Start service
        await docker_manager.start_service("test-nginx")
        
        # Verify running
        running_service = await docker_manager.get_service("test-nginx")
        assert running_service.status == "running"
    
    @pytest.mark.asyncio
    async def test_restart_service(self, docker_manager, nginx_service_config, test_token_hash, cleanup_service):
        """Test restarting a service."""
        # Create a service
        service_info = await docker_manager.create_service(nginx_service_config, test_token_hash)
        cleanup_service.append(service_info.service_name)
        
        # Get original container ID
        original_container_id = service_info.container_id
        
        # Restart service
        await docker_manager.restart_service("test-nginx")
        
        # Service should still be running
        restarted_service = await docker_manager.get_service("test-nginx")
        assert restarted_service.status == "running"


class TestDockerServiceLogs:
    """Test Docker service log functionality."""
    
    @pytest.mark.asyncio
    async def test_get_service_logs(self, docker_manager, test_token_hash, cleanup_service):
        """Test retrieving service logs."""
        # Create a service that generates logs
        config = DockerServiceConfig(
            service_name="test-busybox",
            image="busybox:latest",
            internal_port=8080,
            environment={"MESSAGE": "Hello from test"},
            command=["sh", "-c", "while true; do echo $MESSAGE; sleep 1; done"]
        )
        
        service_info = await docker_manager.create_service(config, test_token_hash)
        cleanup_service.append(service_info.service_name)
        
        # Wait for some logs to generate
        await asyncio.sleep(3)
        
        # Get logs
        logs = await docker_manager.get_service_logs("test-busybox", lines=5)
        
        assert len(logs) > 0
        assert any("Hello from test" in log for log in logs)
    
    @pytest.mark.asyncio
    async def test_get_service_logs_with_timestamps(self, docker_manager, nginx_service_config, test_token_hash, cleanup_service):
        """Test retrieving service logs with timestamps."""
        # Create a service
        service_info = await docker_manager.create_service(nginx_service_config, test_token_hash)
        cleanup_service.append(service_info.service_name)
        
        # Get logs with timestamps
        logs = await docker_manager.get_service_logs("test-nginx", lines=10, timestamps=True)
        
        # Logs should have timestamp format (if any logs exist)
        if logs:
            # Timestamps should be in ISO format or similar
            assert any("T" in log or "Z" in log for log in logs if log)


class TestDockerServiceStats:
    """Test Docker service statistics functionality."""
    
    @pytest.mark.asyncio
    async def test_get_service_stats(self, docker_manager, nginx_service_config, test_token_hash, cleanup_service):
        """Test retrieving service resource statistics."""
        # Create a service
        service_info = await docker_manager.create_service(nginx_service_config, test_token_hash)
        cleanup_service.append(service_info.service_name)
        
        # Wait for service to stabilize
        await asyncio.sleep(2)
        
        # Get stats
        stats = await docker_manager.get_service_stats("test-nginx")
        
        assert stats.service_name == "test-nginx"
        assert stats.memory_usage >= 0
        assert stats.memory_limit > 0
        assert stats.cpu_usage >= 0
        assert stats.pids > 0


class TestDockerServiceCleanup:
    """Test Docker service cleanup functionality."""
    
    @pytest.mark.asyncio
    async def test_delete_service(self, docker_manager, nginx_service_config, test_token_hash, cleanup_service):
        """Test deleting a service."""
        # Create a service
        service_info = await docker_manager.create_service(nginx_service_config, test_token_hash)
        
        # Delete service
        await docker_manager.delete_service("test-nginx", force=True)
        
        # Verify service is gone
        deleted_service = await docker_manager.get_service("test-nginx")
        assert deleted_service is None or deleted_service.status == "not_found"
    
    @pytest.mark.asyncio
    async def test_cleanup_orphaned_services(self, docker_manager, storage):
        """Test cleanup of orphaned services."""
        # This test would need to create orphaned containers manually
        # For now, just test that cleanup runs without error
        await docker_manager.cleanup_orphaned_services()
    
    @pytest.mark.asyncio
    async def test_port_allocation_cleanup(self, docker_manager, nginx_service_config, test_token_hash):
        """Test that port allocations are cleaned up properly."""
        # Create and delete a service
        service_info = await docker_manager.create_service(nginx_service_config, test_token_hash)
        allocated_port = service_info.allocated_port
        
        # Delete service
        await docker_manager.delete_service("test-nginx", force=True)
        
        # Port should be available again
        key = f"port_allocation:{allocated_port}"
        port_data = docker_manager.storage.redis_client.get(key)
        assert port_data is None


class TestDockerServiceAPI:
    """Test Docker service API endpoints."""
    
    @pytest.mark.asyncio
    async def test_create_service_via_api(self, base_url, admin_token):
        """Test creating a service through the API."""
        headers = {"Authorization": f"Bearer {admin_token}"}
        
        data = {
            "service_name": "test-api-nginx",
            "image": "nginx:alpine",
            "memory_limit": "128m",
            "cpu_limit": 0.5
        }
        
        response = requests.post(
            f"{base_url}/api/v1/services",
            json=data,
            headers=headers
        )
        
        assert response.status_code == 200
        result = response.json()
        assert result["service"]["service_name"] == "test-api-nginx"
        assert result["service"]["status"] == "running"
        
        # Cleanup
        requests.delete(
            f"{base_url}/api/v1/services/test-api-nginx?force=true",
            headers=headers
        )
    
    @pytest.mark.asyncio
    async def test_list_services_via_api(self, base_url, admin_token):
        """Test listing services through the API."""
        headers = {"Authorization": f"Bearer {admin_token}"}
        
        response = requests.get(
            f"{base_url}/api/v1/services",
            headers=headers
        )
        
        assert response.status_code == 200
        result = response.json()
        assert "services" in result
        assert "total" in result


# Run tests
if __name__ == "__main__":
    pytest.main([__file__, "-v"])