"""Docker service manager implementation."""

import os
import json
import logging
import shutil
import fnmatch
from typing import Dict, List, Optional, Tuple
from datetime import datetime, timezone
from pathlib import Path

from python_on_whales import docker, DockerClient
from python_on_whales.exceptions import DockerException, NoSuchContainer

from .models import (
    DockerServiceConfig,
    DockerServiceInfo,
    DockerServiceUpdate,
    DockerServiceStats,
    DockerImageAllowlist
)
from ..storage.redis_storage import RedisStorage

logger = logging.getLogger(__name__)


class DockerManager:
    """Manages Docker services through the Docker API."""
    
    def __init__(self, storage: RedisStorage, docker_host: str = None):
        """Initialize Docker manager.
        
        Args:
            storage: Redis storage instance
            docker_host: Docker host URL (defaults to DOCKER_HOST env var)
        """
        self.storage = storage
        # Default to Unix socket unless DOCKER_HOST is set
        self.docker_host = docker_host or os.getenv('DOCKER_HOST')
        
        # Initialize Docker client
        try:
            self.client = DockerClient(host=self.docker_host)
            # Test connection
            self.client.version()
            docker_location = self.docker_host or "unix:///var/run/docker.sock"
            logger.info(f"Connected to Docker at {docker_location}")
        except Exception as e:
            logger.error(f"Failed to connect to Docker: {e}")
            raise
            
        self.network_name = "mcp-http-proxy_proxy_network"
        self.port_range = (11000, 20000)
        self.managed_label = "managed=true"
        
    async def create_service(self, config: DockerServiceConfig, token_hash: str) -> DockerServiceInfo:
        """Create and start a new Docker service.
        
        Args:
            config: Service configuration
            token_hash: Hash of the token creating this service
            
        Returns:
            Service information
        """
        # Validate image is allowed
        if config.image and not await self._validate_image_allowed(config.image):
            raise ValueError(f"Image {config.image} is not in the allowlist")
            
        # Allocate port if needed
        if not config.external_port:
            config.external_port = await self._allocate_port()
            logger.info(f"Allocated port {config.external_port} for service {config.service_name}")
            
        # Build image if Dockerfile provided
        if config.dockerfile_path:
            image_tag = await self._build_image(config)
            config.image = image_tag
            logger.info(f"Built image {image_tag} for service {config.service_name}")
            
        # Create container
        try:
            container = await self._create_container(config)
            logger.info(f"Created container {container.id[:12]} for service {config.service_name}")
        except Exception as e:
            # Clean up allocated port on failure
            if config.external_port >= self.port_range[0]:
                await self._release_port(config.external_port)
            raise
            
        # Store service info in Redis
        service_info = DockerServiceInfo(
            **config.dict(),
            status="running",
            container_id=container.id,
            created_at=datetime.now(timezone.utc),
            owner_token_hash=token_hash,
            allocated_port=config.external_port
        )
        
        await self._store_service_info(service_info)
        
        # Auto-register in instance registry
        await self._register_instance(service_info)
        
        return service_info
        
    async def _validate_image_allowed(self, image: str) -> bool:
        """Check if image is in allowlist.
        
        Args:
            image: Docker image name
            
        Returns:
            True if allowed, False otherwise
        """
        # Get allowlist from storage
        allowlist_data = self.storage.redis_client.get("docker_image_allowlist")
        if allowlist_data:
            allowlist = DockerImageAllowlist.parse_raw(allowlist_data)
        else:
            # Use default allowlist
            allowlist = DockerImageAllowlist()
            
        # Extract registry from image name
        parts = image.split('/')
        if len(parts) > 2 or (len(parts) == 2 and '.' in parts[0]):
            registry = parts[0]
        else:
            registry = "docker.io"
            
        # Check registry
        if registry not in allowlist.registries:
            logger.warning(f"Registry {registry} not in allowlist")
            return False
            
        # Check image patterns
        for pattern in allowlist.patterns:
            if fnmatch.fnmatch(image, pattern):
                return True
                
        logger.warning(f"Image {image} does not match any allowed patterns")
        return False
        
    async def _allocate_port(self) -> int:
        """Allocate an unused port from the pool.
        
        Returns:
            Allocated port number
            
        Raises:
            ValueError: If no ports available
        """
        for port in range(*self.port_range):
            key = f"port_allocation:{port}"
            # Try to claim the port atomically
            if self.storage.redis_client.set(key, "allocated", nx=True, ex=86400):
                return port
                
        raise ValueError(f"No ports available in range {self.port_range}")
        
    async def _release_port(self, port: int):
        """Release an allocated port.
        
        Args:
            port: Port number to release
        """
        key = f"port_allocation:{port}"
        self.storage.redis_client.delete(key)
        logger.info(f"Released port {port}")
        
    async def _build_image(self, config: DockerServiceConfig) -> str:
        """Build Docker image from Dockerfile.
        
        Args:
            config: Service configuration
            
        Returns:
            Built image tag
        """
        image_tag = f"mcp-service-{config.service_name}:latest"
        
        # Ensure build context exists
        build_path = Path(config.build_context)
        if not build_path.exists():
            build_path.mkdir(parents=True, exist_ok=True)
            
        # Copy Dockerfile to build context if needed
        dockerfile_src = Path(config.dockerfile_path)
        if dockerfile_src.exists() and dockerfile_src.parent != build_path:
            shutil.copy(dockerfile_src, build_path / "Dockerfile")
            
        # Build with python-on-whales
        logger.info(f"Building image {image_tag} from {config.build_context}")
        self.client.build(
            config.build_context,
            tags=[image_tag],
            build_args=config.build_args,
            rm=True,
            pull=True
        )
        
        return image_tag
        
    async def _create_container(self, config: DockerServiceConfig):
        """Create and start a Docker container.
        
        Args:
            config: Service configuration
            
        Returns:
            Container object
        """
        # Prepare container configuration
        container_config = {
            "image": config.image,
            "name": config.service_name,
            "detach": True,
            "restart": config.restart_policy,
            "envs": config.environment,  # python-on-whales uses 'envs' not 'environment'
            "labels": {**config.labels, "managed": "true"},
            "networks": config.networks if config.networks else ["proxy_network"],
            "publish": [(config.external_port, config.internal_port)]  # python-on-whales format
        }
        
        # Add volumes if specified
        if config.volumes:
            container_config["volumes"] = config.volumes
            
        # Add resource limits
        container_config["memory"] = config.memory_limit  # python-on-whales uses 'memory' not 'mem_limit'
        container_config["cpus"] = config.cpu_limit
        
        # Add security options
        if config.read_only_root:
            container_config["read_only"] = True
            
        if config.user:
            container_config["user"] = config.user
            
        # Add capabilities
        if config.capabilities:
            container_config["cap_add"] = config.capabilities
        
        # Only drop all capabilities if explicitly requested or if read_only_root is True
        if config.read_only_root:
            container_config["cap_drop"] = ["ALL"]
            
        # Add health check if specified
        if config.healthcheck:
            container_config["healthcheck"] = config.healthcheck
            
        # Create and start container
        container = self.client.run(**container_config)
        
        return container
        
    async def _store_service_info(self, service_info: DockerServiceInfo):
        """Store service information in Redis.
        
        Args:
            service_info: Service information to store
        """
        key = f"docker_service:{service_info.service_name}"
        self.storage.redis_client.set(key, service_info.json())
        
        # Also store in a set for listing
        self.storage.redis_client.sadd("docker_services", service_info.service_name)
        
        # Store port allocation with service reference
        if service_info.allocated_port:
            port_key = f"port_allocation:{service_info.allocated_port}"
            self.storage.redis_client.set(
                port_key, 
                json.dumps({
                    "service": service_info.service_name,
                    "allocated_at": service_info.created_at.isoformat()
                })
            )
            
    async def _register_instance(self, service_info: DockerServiceInfo):
        """Register service in instance registry.
        
        Args:
            service_info: Service information
        """
        instance_name = f"docker-{service_info.service_name}"
        target_url = f"http://localhost:{service_info.allocated_port}"
        
        instance_data = {
            "name": instance_name,
            "target_url": target_url,
            "description": f"Docker service: {service_info.service_name}",
            "created_at": service_info.created_at.isoformat(),
            "created_by": "docker-manager"
        }
        
        # Store instance URL mapping
        self.storage.redis_client.set(f"instance_url:{instance_name}", target_url)
        self.storage.redis_client.set(f"instance_info:{instance_name}", json.dumps(instance_data))
        
        logger.info(f"Registered instance {instance_name} -> {target_url}")
        
    async def get_service(self, service_name: str) -> Optional[DockerServiceInfo]:
        """Get service information.
        
        Args:
            service_name: Service name
            
        Returns:
            Service information or None if not found
        """
        key = f"docker_service:{service_name}"
        data = self.storage.redis_client.get(key)
        
        if not data:
            return None
            
        service_info = DockerServiceInfo.parse_raw(data)
        
        # Update status from actual container
        try:
            container = self.client.container.inspect(service_name)
            service_info.status = container.state.status
            service_info.health_status = container.state.health.status if container.state.health else None
        except NoSuchContainer:
            service_info.status = "not_found"
        except Exception as e:
            logger.error(f"Error inspecting container {service_name}: {e}")
            
        return service_info
        
    async def list_services(self, owner_token_hash: Optional[str] = None) -> List[DockerServiceInfo]:
        """List all Docker services.
        
        Args:
            owner_token_hash: Filter by owner token hash
            
        Returns:
            List of service information
        """
        service_names = self.storage.redis_client.smembers("docker_services")
        services = []
        
        for name in service_names:
            service_info = await self.get_service(name)
            if service_info:
                if owner_token_hash and service_info.owner_token_hash != owner_token_hash:
                    continue
                services.append(service_info)
                
        return sorted(services, key=lambda s: s.created_at, reverse=True)
        
    async def update_service(self, service_name: str, updates: DockerServiceUpdate) -> DockerServiceInfo:
        """Update a Docker service.
        
        Args:
            service_name: Service name
            updates: Update configuration
            
        Returns:
            Updated service information
        """
        service_info = await self.get_service(service_name)
        if not service_info:
            raise ValueError(f"Service {service_name} not found")
            
        # Get container
        try:
            container = self.client.container.inspect(service_name)
        except NoSuchContainer:
            raise ValueError(f"Container for service {service_name} not found")
            
        # Apply updates to service info
        update_data = updates.dict(exclude_unset=True)
        for key, value in update_data.items():
            if hasattr(service_info, key) and value is not None:
                setattr(service_info, key, value)
                
        # Some updates require container recreation
        needs_recreate = any([
            updates.memory_limit is not None,
            updates.cpu_limit is not None,
            updates.environment is not None
        ])
        
        if needs_recreate:
            # Stop and remove old container
            self.client.container.stop(service_name)
            self.client.container.remove(service_name)
            
            # Create new container with updated config
            await self._create_container(service_info)
            logger.info(f"Recreated container for service {service_name} with updates")
        else:
            # Apply updates that don't require recreation
            if updates.labels:
                # Update container labels (requires API call)
                # Note: python-on-whales doesn't support label updates directly
                logger.warning("Label updates require container recreation")
                
            if updates.restart_policy:
                # Update restart policy
                self.client.container.update(
                    service_name,
                    restart_policy={"Name": updates.restart_policy}
                )
                
        # Store updated service info
        await self._store_service_info(service_info)
        
        return service_info
        
    async def delete_service(self, service_name: str, force: bool = False):
        """Delete a Docker service and cleanup resources.
        
        Args:
            service_name: Service name
            force: Force deletion even if container is running
        """
        service_info = await self.get_service(service_name)
        if not service_info:
            raise ValueError(f"Service {service_name} not found")
            
        # Stop and remove container
        try:
            container = self.client.container.inspect(service_name)
            if container.state.status == "running" and not force:
                raise ValueError(f"Service {service_name} is running. Use force=True to delete")
                
            self.client.container.stop(service_name)
            self.client.container.remove(service_name)
            logger.info(f"Removed container for service {service_name}")
        except NoSuchContainer:
            logger.warning(f"Container for service {service_name} not found")
            
        # Clean up allocated port
        if service_info.allocated_port:
            await self._release_port(service_info.allocated_port)
            
        # Remove from instance registry
        instance_name = f"docker-{service_name}"
        self.storage.redis_client.delete(f"instance_url:{instance_name}")
        self.storage.redis_client.delete(f"instance_info:{instance_name}")
        
        # Remove service info from Redis
        self.storage.redis_client.delete(f"docker_service:{service_name}")
        self.storage.redis_client.srem("docker_services", service_name)
        
        logger.info(f"Deleted service {service_name} and cleaned up resources")
        
    async def start_service(self, service_name: str):
        """Start a stopped service.
        
        Args:
            service_name: Service name
        """
        try:
            self.client.container.start(service_name)
            logger.info(f"Started service {service_name}")
        except NoSuchContainer:
            raise ValueError(f"Container for service {service_name} not found")
            
    async def stop_service(self, service_name: str):
        """Stop a running service.
        
        Args:
            service_name: Service name
        """
        try:
            self.client.container.stop(service_name)
            logger.info(f"Stopped service {service_name}")
        except NoSuchContainer:
            raise ValueError(f"Container for service {service_name} not found")
            
    async def restart_service(self, service_name: str):
        """Restart a service.
        
        Args:
            service_name: Service name
        """
        try:
            self.client.container.restart(service_name)
            logger.info(f"Restarted service {service_name}")
        except NoSuchContainer:
            raise ValueError(f"Container for service {service_name} not found")
            
    async def get_service_logs(self, service_name: str, lines: int = 100, 
                              timestamps: bool = False) -> List[str]:
        """Get service logs.
        
        Args:
            service_name: Service name
            lines: Number of lines to return
            timestamps: Include timestamps
            
        Returns:
            List of log lines
        """
        try:
            logs = self.client.container.logs(
                service_name,
                tail=lines,
                timestamps=timestamps
            )
            # Split logs into lines
            return logs.splitlines()
        except NoSuchContainer:
            raise ValueError(f"Container for service {service_name} not found")
            
    async def get_service_stats(self, service_name: str) -> DockerServiceStats:
        """Get service resource statistics.
        
        Args:
            service_name: Service name
            
        Returns:
            Service statistics
        """
        try:
            stats = self.client.container.stats(service_name, stream=False)
            
            # Parse stats
            cpu_delta = stats["cpu_stats"]["cpu_usage"]["total_usage"] - \
                        stats["precpu_stats"]["cpu_usage"]["total_usage"]
            system_delta = stats["cpu_stats"]["system_cpu_usage"] - \
                          stats["precpu_stats"]["system_cpu_usage"]
            cpu_usage = (cpu_delta / system_delta) * 100.0 if system_delta > 0 else 0.0
            
            memory_usage = stats["memory_stats"]["usage"]
            memory_limit = stats["memory_stats"]["limit"]
            memory_percentage = (memory_usage / memory_limit) * 100.0 if memory_limit > 0 else 0.0
            
            # Network stats
            network_rx = sum(v["rx_bytes"] for v in stats["networks"].values())
            network_tx = sum(v["tx_bytes"] for v in stats["networks"].values())
            
            # Block I/O stats
            block_read = sum(s["value"] for s in stats.get("blkio_stats", {}).get("io_service_bytes_recursive", [])
                           if s["op"] == "Read")
            block_write = sum(s["value"] for s in stats.get("blkio_stats", {}).get("io_service_bytes_recursive", [])
                            if s["op"] == "Write")
            
            return DockerServiceStats(
                service_name=service_name,
                cpu_usage=cpu_usage,
                memory_usage=memory_usage,
                memory_limit=memory_limit,
                memory_percentage=memory_percentage,
                network_rx_bytes=network_rx,
                network_tx_bytes=network_tx,
                block_read_bytes=block_read,
                block_write_bytes=block_write,
                pids=stats["pids_stats"]["current"]
            )
        except NoSuchContainer:
            raise ValueError(f"Container for service {service_name} not found")
            
    async def cleanup_orphaned_services(self):
        """Remove containers not tracked in Redis."""
        # Get all managed containers
        containers = self.client.container.list(
            all=True,
            filters={"label": self.managed_label}
        )
        
        # Get tracked service names
        tracked_names = self.storage.redis_client.smembers("docker_services")
        
        for container in containers:
            if container.name not in tracked_names:
                logger.warning(f"Found orphaned container: {container.name}")
                try:
                    container.stop()
                    container.remove()
                    logger.info(f"Removed orphaned container: {container.name}")
                except Exception as e:
                    logger.error(f"Failed to remove orphaned container {container.name}: {e}")
                    
        # Also cleanup orphaned port allocations
        await self._cleanup_port_allocations()
        
    async def _cleanup_port_allocations(self):
        """Clean up orphaned port allocations."""
        # Get all port allocation keys
        port_keys = self.storage.redis_client.keys("port_allocation:*")
        
        for key in port_keys:
            data = self.storage.redis_client.get(key)
            if data:
                try:
                    port_info = json.loads(data)
                    if "service" in port_info:
                        # Check if service still exists
                        service_key = f"docker_service:{port_info['service']}"
                        if not self.storage.redis_client.exists(service_key):
                            # Service doesn't exist, release port
                            self.storage.redis_client.delete(key)
                            port = int(key.split(":")[-1])
                            logger.info(f"Released orphaned port {port}")
                except json.JSONDecodeError:
                    # Old format, just "allocated" string
                    pass