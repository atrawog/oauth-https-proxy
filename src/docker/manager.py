"""Docker service manager implementation."""

import os
import json
import logging
import shutil
from typing import Dict, List, Optional, Tuple
from datetime import datetime, timezone
from pathlib import Path

from python_on_whales import docker, DockerClient
from python_on_whales.exceptions import DockerException, NoSuchContainer

from .models import (
    DockerServiceConfig,
    DockerServiceInfo,
    DockerServiceUpdate,
    DockerServiceStats
)
from ..storage.redis_storage import RedisStorage
from ..ports import PortManager, ServicePort

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
        
        # Initialize port manager
        self.port_manager = PortManager(storage)
        
    async def create_service(self, config: DockerServiceConfig, token_hash: str) -> DockerServiceInfo:
        """Create and start a new Docker service.
        
        Args:
            config: Service configuration
            token_hash: Hash of the token creating this service
            
        Returns:
            Service information
        """
        # Build image if Dockerfile provided
        if config.dockerfile_path:
            image_tag = await self._build_image(config)
            config.image = image_tag
            logger.info(f"Built image {image_tag} for service {config.service_name}")
            
            # Detect exposed ports from built image if internal_port is default
            if config.internal_port == 8080:  # Default value
                try:
                    image_info = self.client.image.inspect(image_tag)
                    exposed_ports = image_info.config.exposed_ports
                    if exposed_ports:
                        # Get first exposed port
                        first_port = list(exposed_ports.keys())[0]
                        port_num = int(first_port.split('/')[0])
                        config.internal_port = port_num
                        logger.info(f"Detected exposed port {port_num} from image {image_tag}")
                except Exception as e:
                    logger.warning(f"Failed to detect exposed ports: {e}")
            
        # Allocate ports if expose_ports is enabled
        allocated_ports = []
        if config.expose_ports and config.port_configs:
            try:
                for port_config in config.port_configs:
                    # Allocate the requested port
                    allocated_port = await self.port_manager.allocate_port(
                        purpose="exposed",
                        preferred=port_config['host'],
                        bind_address=port_config.get('bind', config.bind_address)
                    )
                    if allocated_port != port_config['host']:
                        logger.warning(f"Could not allocate requested port {port_config['host']}, got {allocated_port}")
                        port_config['host'] = allocated_port
                    allocated_ports.append(allocated_port)
            except Exception as e:
                # Clean up any allocated ports on failure
                for port in allocated_ports:
                    await self.port_manager.release_port(port)
                raise ValueError(f"Failed to allocate ports: {e}")
        
        # Create container
        try:
            container = await self._create_container(config)
            logger.info(f"Created container {container.id[:12]} for service {config.service_name}")
        except Exception as e:
            # Clean up allocated ports on container creation failure
            for port in allocated_ports:
                await self.port_manager.release_port(port)
            raise
            
        # Store service info in Redis
        service_info = DockerServiceInfo(
            **config.dict(),
            status="running",
            container_id=container.id,
            created_at=datetime.now(timezone.utc),
            owner_token_hash=token_hash,
            allocated_port=0,  # Deprecated field, kept for backward compatibility
            exposed_ports=config.port_configs if config.expose_ports else []
        )
        
        await self._store_service_info(service_info)
        
        # Register ports with port manager
        if config.expose_ports and config.port_configs:
            for port_config in config.port_configs:
                service_port = ServicePort(
                    service_name=config.service_name,
                    port_name=port_config['name'],
                    host_port=port_config['host'],
                    container_port=port_config['container'],
                    bind_address=port_config.get('bind', config.bind_address),
                    protocol=port_config.get('protocol', 'tcp'),
                    source_token_hash=port_config.get('source_token_hash'),
                    source_token_name=port_config.get('source_token_name'),
                    require_token=bool(port_config.get('source_token')),
                    owner_token_hash=token_hash,
                    description=port_config.get('description')
                )
                await self.port_manager.add_service_port(service_port)
        
        # Auto-register as a service for routing
        await self._register_as_service(service_info)
        
        return service_info
        
        
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
        
        # Determine build context based on Dockerfile location
        dockerfile_src = Path(config.dockerfile_path)
        if dockerfile_src.exists():
            # Use the Dockerfile's parent directory as build context
            build_context = str(dockerfile_src.parent.absolute())
            dockerfile_name = dockerfile_src.name
        else:
            # Fall back to default build context
            build_context = Path(config.build_context).absolute()
            dockerfile_name = "Dockerfile"
            
        # Build with python-on-whales
        logger.info(f"Building image {image_tag} from {build_context}")
        # Note: python-on-whales expects the Dockerfile path relative to build context
        # or we can omit the file parameter if the Dockerfile is in the build context root
        self.client.build(
            build_context,
            tags=[image_tag],
            build_args=config.build_args,
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
            "networks": config.networks if config.networks else ["proxy_network"]
        }
        
        # Add port publishing if explicitly enabled
        if config.expose_ports:
            if config.port_configs:
                # Multi-port configuration
                publish = []
                for port_config in config.port_configs:
                    bind_addr = port_config.get('bind', config.bind_address)
                    host_port = port_config['host']
                    container_port = port_config['container']
                    
                    # python-on-whales format: ("host_ip:host_port", container_port)
                    if bind_addr != "0.0.0.0":
                        # Specific bind address
                        publish.append((f"{bind_addr}:{host_port}", container_port))
                    else:
                        # All interfaces - just use (host_port, container_port)
                        publish.append((host_port, container_port))
                    
                container_config["publish"] = publish
            elif config.external_port:
                # Single port configuration - backward compatibility
                container_config["publish"] = [f"{config.bind_address}:{config.external_port}:{config.internal_port}"]
        
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
            
    async def _register_as_service(self, service_info: DockerServiceInfo):
        """Register Docker container as a service for routing.
        
        Args:
            service_info: Service information
        """
        # Service name without docker- prefix for simplicity
        service_name = service_info.service_name
        target_url = f"http://{service_info.service_name}:{service_info.internal_port}"
        
        # Store as a service
        self.storage.redis_client.set(f"service:url:{service_name}", target_url)
        
        # Also store with docker- prefix for compatibility
        docker_name = f"docker-{service_name}"
        self.storage.redis_client.set(f"service:url:{docker_name}", target_url)
        
        logger.info(f"Registered Docker service {service_name} -> {target_url}")
        
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
            
        # Clean up exposed ports
        await self.port_manager.remove_all_service_ports(service_name)
        
        # Remove from service registry
        self.storage.redis_client.delete(f"service:url:{service_name}")
        self.storage.redis_client.delete(f"service:url:docker-{service_name}")
        
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
            # python-on-whales stats returns a list of ContainerStats objects
            stats_list = self.client.container.stats(service_name)
            if not stats_list:
                raise ValueError(f"No stats available for {service_name}")
            stats = stats_list[0]  # Get first sample
            
            # python-on-whales provides processed stats as attributes
            return DockerServiceStats(
                service_name=service_name,
                cpu_usage=stats.cpu_percentage,
                memory_usage=stats.memory_used,
                memory_limit=stats.memory_limit,
                memory_percentage=stats.memory_percentage,
                network_rx_bytes=stats.net_download,
                network_tx_bytes=stats.net_upload,
                block_read_bytes=stats.block_read,
                block_write_bytes=stats.block_write,
                pids=0  # python-on-whales doesn't provide PIDs in stats
            )
        except NoSuchContainer:
            raise ValueError(f"Container for service {service_name} not found")
            
    async def cleanup_orphaned_services(self):
        """Remove containers not tracked in Redis."""
        # Get all managed containers
        # python-on-whales uses 'label' not 'filters'
        containers = self.client.container.list(
            all=True,
            filters={"label": [self.managed_label]}
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
        # Get all port allocation keys using SCAN
        port_keys = []
        cursor = 0
        while True:
            cursor, keys = self.storage.redis_client.scan(cursor, match="port_allocation:*", count=100)
            port_keys.extend(keys)
            if cursor == 0:
                break
        
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
    
    # Port management methods
    
    async def add_port_to_service(self, service_name: str, port_config: Dict, token_hash: str) -> ServicePort:
        """Add a port to an existing service.
        
        Args:
            service_name: Service name
            port_config: Port configuration dictionary
            token_hash: Token hash for authorization
            
        Returns:
            Created ServicePort object
        """
        # Get service info
        service_info = await self.get_service(service_name)
        if not service_info:
            raise ValueError(f"Service {service_name} not found")
        
        # Check ownership
        if service_info.owner_token_hash != token_hash:
            raise ValueError("Not authorized to modify this service")
        
        # Allocate port
        allocated_port = await self.port_manager.allocate_port(
            purpose="exposed",
            preferred=port_config.get('host'),
            bind_address=port_config.get('bind', '127.0.0.1')
        )
        
        # Create ServicePort object
        service_port = ServicePort(
            service_name=service_name,
            port_name=port_config['name'],
            host_port=allocated_port,
            container_port=port_config['container'],
            bind_address=port_config.get('bind', '127.0.0.1'),
            protocol=port_config.get('protocol', 'tcp'),
            source_token_hash=port_config.get('source_token_hash'),
            source_token_name=port_config.get('source_token_name'),
            require_token=bool(port_config.get('source_token')),
            owner_token_hash=token_hash,
            description=port_config.get('description')
        )
        
        # Register port with port manager
        success = await self.port_manager.add_service_port(service_port)
        if not success:
            await self.port_manager.release_port(allocated_port)
            raise ValueError("Failed to register port")
        
        # Update container to expose the new port
        await self._update_container_ports(service_name, service_info)
        
        # Update service info
        if not service_info.exposed_ports:
            service_info.exposed_ports = []
        service_info.exposed_ports.append({
            'name': port_config['name'],
            'host': allocated_port,
            'container': port_config['container'],
            'bind': port_config.get('bind', '127.0.0.1'),
            'protocol': port_config.get('protocol', 'tcp'),
            'source_token': port_config.get('source_token')
        })
        await self._store_service_info(service_info)
        
        return service_port
    
    async def remove_port_from_service(self, service_name: str, port_name: str, token_hash: str) -> bool:
        """Remove a port from a service.
        
        Args:
            service_name: Service name
            port_name: Port name to remove
            token_hash: Token hash for authorization
            
        Returns:
            True if successful
        """
        # Get service info
        service_info = await self.get_service(service_name)
        if not service_info:
            raise ValueError(f"Service {service_name} not found")
        
        # Check ownership
        if service_info.owner_token_hash != token_hash:
            raise ValueError("Not authorized to modify this service")
        
        # Remove port
        success = await self.port_manager.remove_service_port(service_name, port_name)
        if not success:
            return False
        
        # Update service info
        if service_info.exposed_ports:
            service_info.exposed_ports = [
                p for p in service_info.exposed_ports 
                if p.get('name') != port_name
            ]
            await self._store_service_info(service_info)
        
        # Update container to remove the port binding
        await self._update_container_ports(service_name, service_info)
        
        return True
    
    async def get_service_ports(self, service_name: str) -> List[ServicePort]:
        """Get all ports for a service.
        
        Args:
            service_name: Service name
            
        Returns:
            List of ServicePort objects
        """
        return await self.port_manager.get_service_ports(service_name)
    
    async def _update_container_ports(self, service_name: str, service_info: DockerServiceInfo):
        """Update container port bindings.
        
        Note: Docker doesn't support dynamic port updates, so we need to recreate the container.
        
        Args:
            service_name: Service name
            service_info: Service information
        """
        try:
            # Stop and remove old container
            self.client.container.stop(service_name)
            self.client.container.remove(service_name)
            
            # Update config with new port settings
            config = DockerServiceConfig(**service_info.dict(exclude={'status', 'container_id', 'created_at', 
                                                                     'owner_token_hash', 'allocated_port', 
                                                                     'health_status', 'exposed_ports'}))
            config.expose_ports = bool(service_info.exposed_ports)
            config.port_configs = service_info.exposed_ports or []
            
            # Recreate container
            container = await self._create_container(config)
            
            # Update service info with new container ID
            service_info.container_id = container.id
            service_info.status = "running"
            await self._store_service_info(service_info)
            
            logger.info(f"Recreated container for service {service_name} with updated ports")
            
        except Exception as e:
            logger.error(f"Failed to update container ports: {e}")
            raise