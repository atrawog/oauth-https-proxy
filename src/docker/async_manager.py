"""Async Docker manager with full event publishing and tracing.

This module provides Docker service management with comprehensive event
publishing and trace correlation through the unified logging system.
"""

import os
import json
import logging
import shutil
import asyncio
from typing import Dict, List, Optional, Tuple
from datetime import datetime, timezone
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor

from python_on_whales import docker, DockerClient
from python_on_whales.exceptions import DockerException, NoSuchContainer

from .models import (
    DockerServiceConfig,
    DockerServiceInfo,
    DockerServiceUpdate,
    DockerServiceStats
)
from ..storage.async_redis_storage import AsyncRedisStorage
from ..ports.async_manager import AsyncPortManager
from ..ports.models import ServicePort
from ..shared.unified_logger import UnifiedAsyncLogger
from ..storage.redis_clients import RedisClients

logger = logging.getLogger(__name__)

# Global executor for Docker operations
executor = ThreadPoolExecutor(max_workers=5)


class AsyncDockerManager:
    """Async Docker manager with event publishing."""
    
    def __init__(self, storage: AsyncRedisStorage, redis_clients: RedisClients):
        """Initialize async Docker manager.
        
        Args:
            storage: Async Redis storage instance
            redis_clients: Redis clients for logging
        """
        self.storage = storage
        self.redis_clients = redis_clients
        
        # Initialize component-specific logger
        self.logger = UnifiedAsyncLogger(redis_clients, component="docker_manager")
        
        # Docker configuration
        self.docker_host = os.getenv('DOCKER_HOST')
        self.network_name = "mcp-http-proxy_proxy_network"
        self.port_range = (11000, 20000)
        self.managed_label = "managed=true"
        
        # Initialize port manager
        self.port_manager = AsyncPortManager(storage)
        
        # Initialize Docker client (sync - will use in executor)
        self._init_docker_client()
    
    def _init_docker_client(self):
        """Initialize sync Docker client for use in executor."""
        try:
            self.client = DockerClient(host=self.docker_host)
            # Test connection
            self.client.version()
            docker_location = self.docker_host or "unix:///var/run/docker.sock"
            logger.info(f"Connected to Docker at {docker_location}")
        except Exception as e:
            logger.error(f"Failed to connect to Docker: {e}")
            raise
    
    async def create_service(self, config: DockerServiceConfig, token_hash: str) -> DockerServiceInfo:
        """Create and start a new Docker service with full tracing.
        
        Args:
            config: Service configuration
            token_hash: Hash of the token creating this service
            
        Returns:
            Service information
        """
        # Start trace for entire operation
        trace_id = self.logger.start_trace(
            "docker_service_create",
            service_name=config.service_name,
            image=config.image,
            dockerfile=config.dockerfile_path
        )
        
        try:
            # Log service creation start
            await self.logger.info(
                f"Creating Docker service: {config.service_name}",
                trace_id=trace_id,
                image=config.image,
                expose_ports=config.expose_ports
            )
            
            # Build image if Dockerfile provided
            if config.dockerfile_path:
                await self.logger.debug(
                    f"Building image from Dockerfile: {config.dockerfile_path}",
                    trace_id=trace_id
                )
                
                image_tag = await self._build_image_async(config, trace_id)
                config.image = image_tag
                
                await self.logger.info(
                    f"Built image {image_tag} for service {config.service_name}",
                    trace_id=trace_id
                )
                
                # Detect exposed ports from built image
                if config.internal_port == 8080:  # Default value
                    detected_port = await self._detect_exposed_ports(image_tag, trace_id)
                    if detected_port:
                        config.internal_port = detected_port
            
            # Allocate ports if needed
            allocated_ports = []
            if config.expose_ports and config.port_configs:
                allocated_ports = await self._allocate_ports(config, trace_id)
            
            # Create container
            try:
                container = await self._create_container_async(config, trace_id)
                
                await self.logger.info(
                    f"Created container {container.id[:12]} for service {config.service_name}",
                    trace_id=trace_id,
                    container_id=container.id
                )
                
            except Exception as e:
                # Clean up allocated ports on failure
                for port in allocated_ports:
                    await self.port_manager.release_port(port)
                raise
            
            # Store service info
            service_info = DockerServiceInfo(
                **config.dict(),
                status="running",
                container_id=container.id,
                created_at=datetime.now(timezone.utc),
                owner_token_hash=token_hash,
                allocated_port=0,  # Deprecated field
                exposed_ports=config.port_configs if config.expose_ports else []
            )
            
            await self._store_service_info(service_info, trace_id)
            
            # Register ports with port manager
            if config.expose_ports and config.port_configs:
                await self._register_service_ports(config, token_hash, trace_id)
            
            # Publish service created event
            await self.logger.log_service_event(
                service_name=config.service_name,
                event_type="created",
                trace_id=trace_id,
                container_id=container.id,
                image=config.image,
                ports=allocated_ports,
                status="running"
            )
            
            # End trace successfully
            await self.logger.end_trace(trace_id, "success")
            
            return service_info
            
        except Exception as e:
            # Log failure
            await self.logger.error(
                f"Failed to create service {config.service_name}: {str(e)}",
                trace_id=trace_id,
                error_type=type(e).__name__
            )
            
            # Publish failure event
            await self.logger.log_service_event(
                service_name=config.service_name,
                event_type="failed",
                trace_id=trace_id,
                error=str(e),
                stage="creation"
            )
            
            await self.logger.end_trace(trace_id, "error", error=str(e))
            raise
    
    async def _build_image_async(self, config: DockerServiceConfig, trace_id: str) -> str:
        """Build Docker image in executor.
        
        Args:
            config: Service configuration
            trace_id: Trace ID for correlation
            
        Returns:
            Built image tag
        """
        self.logger.add_span(trace_id, "build_image", 
                            dockerfile=config.dockerfile_path)
        
        loop = asyncio.get_event_loop()
        image_tag = await loop.run_in_executor(
            executor,
            self._sync_build_image,
            config
        )
        
        await self.logger.debug(
            f"Image build completed: {image_tag}",
            trace_id=trace_id
        )
        
        return image_tag
    
    def _sync_build_image(self, config: DockerServiceConfig) -> str:
        """Synchronous Docker image build."""
        dockerfile_path = Path(config.dockerfile_path)
        context_path = dockerfile_path.parent
        image_tag = f"{config.service_name}:latest"
        
        self.client.build(
            context_path=str(context_path),
            tags=[image_tag],
            file=str(dockerfile_path)
        )
        
        return image_tag
    
    async def _detect_exposed_ports(self, image_tag: str, trace_id: str) -> Optional[int]:
        """Detect exposed ports from Docker image.
        
        Args:
            image_tag: Image to inspect
            trace_id: Trace ID for correlation
            
        Returns:
            First exposed port or None
        """
        try:
            loop = asyncio.get_event_loop()
            exposed_port = await loop.run_in_executor(
                executor,
                self._sync_detect_ports,
                image_tag
            )
            
            if exposed_port:
                await self.logger.debug(
                    f"Detected exposed port {exposed_port} from image {image_tag}",
                    trace_id=trace_id
                )
            
            return exposed_port
            
        except Exception as e:
            await self.logger.warning(
                f"Failed to detect exposed ports: {e}",
                trace_id=trace_id
            )
            return None
    
    def _sync_detect_ports(self, image_tag: str) -> Optional[int]:
        """Synchronously detect ports from image."""
        image_info = self.client.image.inspect(image_tag)
        exposed_ports = image_info.config.exposed_ports
        if exposed_ports:
            first_port = list(exposed_ports.keys())[0]
            return int(first_port.split('/')[0])
        return None
    
    async def _allocate_ports(self, config: DockerServiceConfig, trace_id: str) -> List[int]:
        """Allocate ports for service.
        
        Args:
            config: Service configuration
            trace_id: Trace ID for correlation
            
        Returns:
            List of allocated port numbers
        """
        allocated_ports = []
        
        for port_config in config.port_configs:
            try:
                allocated_port = await self.port_manager.allocate_port(
                    purpose="exposed",
                    preferred=port_config['host'],
                    bind_address=port_config.get('bind', config.bind_address)
                )
                
                if allocated_port != port_config['host']:
                    await self.logger.warning(
                        f"Could not allocate requested port {port_config['host']}, got {allocated_port}",
                        trace_id=trace_id
                    )
                    port_config['host'] = allocated_port
                
                allocated_ports.append(allocated_port)
                
                await self.logger.debug(
                    f"Allocated port {allocated_port} for {port_config['name']}",
                    trace_id=trace_id
                )
                
            except Exception as e:
                # Clean up any allocated ports on failure
                for port in allocated_ports:
                    await self.port_manager.release_port(port)
                raise ValueError(f"Failed to allocate ports: {e}")
        
        return allocated_ports
    
    async def _create_container_async(self, config: DockerServiceConfig, trace_id: str):
        """Create Docker container in executor.
        
        Args:
            config: Service configuration
            trace_id: Trace ID for correlation
            
        Returns:
            Created container
        """
        self.logger.add_span(trace_id, "create_container",
                            image=config.image)
        
        loop = asyncio.get_event_loop()
        container = await loop.run_in_executor(
            executor,
            self._sync_create_container,
            config
        )
        
        return container
    
    def _sync_create_container(self, config: DockerServiceConfig):
        """Synchronously create Docker container."""
        # Prepare port bindings
        ports = {}
        if config.expose_ports and config.port_configs:
            for port_config in config.port_configs:
                bind_address = port_config.get('bind', config.bind_address)
                # python-on-whales format: (host_binding, container_port)
                ports[f"{port_config['container']}/{port_config.get('protocol', 'tcp')}"] = (
                    f"{bind_address}:{port_config['host']}",
                    port_config['container']
                )
        
        # Create and start container
        container = self.client.container.run(
            config.image,
            name=config.service_name,
            detach=True,
            ports=ports,
            environment=config.environment or {},
            networks=[self.network_name],
            labels={
                self.managed_label: "true",
                "service": config.service_name,
                **(config.labels or {})
            },
            command=config.command,
            mem_limit=config.memory_limit,
            cpus=config.cpu_limit
        )
        
        return container
    
    async def _store_service_info(self, service_info: DockerServiceInfo, trace_id: str):
        """Store service information in Redis.
        
        Args:
            service_info: Service information to store
            trace_id: Trace ID for correlation
        """
        key = f"docker_service:{service_info.service_name}"
        value = service_info.json()
        
        await self.storage.redis_client.set(key, value)
        
        await self.logger.debug(
            f"Stored service info for {service_info.service_name}",
            trace_id=trace_id
        )
    
    async def _register_service_ports(self, config: DockerServiceConfig, 
                                     token_hash: str, trace_id: str):
        """Register service ports with port manager.
        
        Args:
            config: Service configuration
            token_hash: Owner token hash
            trace_id: Trace ID for correlation
        """
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
            
            await self.logger.debug(
                f"Registered port {service_port.port_name} for service {config.service_name}",
                trace_id=trace_id
            )
    
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
        except Exception:
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
            await self.stop_service(service_name)
            await self.delete_service(service_name, force=True)
            
            # Create new container with updated config
            config = DockerServiceConfig(
                service_name=service_name,
                image=service_info.image,
                dockerfile_path=service_info.dockerfile_path,
                internal_port=service_info.internal_port,
                external_port=service_info.external_port,
                memory_limit=updates.memory_limit or service_info.memory_limit,
                cpu_limit=updates.cpu_limit or service_info.cpu_limit,
                environment=updates.environment or service_info.environment,
                command=service_info.command,
                networks=service_info.networks,
                labels=updates.labels or service_info.labels,
                expose_ports=service_info.expose_ports,
                port_configs=service_info.port_configs,
                bind_address=service_info.bind_address
            )
            return await self.create_service(config, service_info.owner_token_hash)
        
        # Store updated service info
        key = f"docker_service:{service_name}"
        await self.storage.redis_client.set(key, service_info.json())
        
        return service_info
    
    async def restart_service(self, service_name: str) -> bool:
        """Restart a service.
        
        Args:
            service_name: Service name
            
        Returns:
            True if successful
        """
        try:
            self.client.container.restart(service_name)
            logger.info(f"Restarted service {service_name}")
            return True
        except Exception as e:
            logger.error(f"Failed to restart service {service_name}: {e}")
            raise ValueError(f"Container for service {service_name} not found")
    
    async def start_service(self, service_name: str) -> bool:
        """Start a stopped Docker service.
        
        Args:
            service_name: Name of the service to start
            
        Returns:
            True if successful
        """
        trace_id = self.logger.start_trace("docker_service_start",
                                          service_name=service_name)
        
        try:
            await self.logger.info(
                f"Starting service {service_name}",
                trace_id=trace_id
            )
            
            # Start container in executor
            loop = asyncio.get_event_loop()
            await loop.run_in_executor(
                executor,
                self._sync_start_container,
                service_name
            )
            
            # Update status
            await self._update_service_status(service_name, "running", trace_id)
            
            # Publish event
            await self.logger.log_service_event(
                service_name=service_name,
                event_type="started",
                trace_id=trace_id
            )
            
            await self.logger.end_trace(trace_id, "success")
            return True
            
        except Exception as e:
            await self.logger.error(
                f"Failed to start service {service_name}: {e}",
                trace_id=trace_id
            )
            
            await self.logger.log_service_event(
                service_name=service_name,
                event_type="start_failed",
                trace_id=trace_id,
                error=str(e)
            )
            
            await self.logger.end_trace(trace_id, "error", error=str(e))
            return False
    
    def _sync_start_container(self, service_name: str):
        """Synchronously start a container."""
        container = self.client.container.get(service_name)
        container.start()
    
    async def stop_service(self, service_name: str) -> bool:
        """Stop a running Docker service.
        
        Args:
            service_name: Name of the service to stop
            
        Returns:
            True if successful
        """
        trace_id = self.logger.start_trace("docker_service_stop",
                                          service_name=service_name)
        
        try:
            await self.logger.info(
                f"Stopping service {service_name}",
                trace_id=trace_id
            )
            
            # Stop container in executor
            loop = asyncio.get_event_loop()
            await loop.run_in_executor(
                executor,
                self._sync_stop_container,
                service_name
            )
            
            # Update status
            await self._update_service_status(service_name, "stopped", trace_id)
            
            # Publish event
            await self.logger.log_service_event(
                service_name=service_name,
                event_type="stopped",
                trace_id=trace_id
            )
            
            await self.logger.end_trace(trace_id, "success")
            return True
            
        except Exception as e:
            await self.logger.error(
                f"Failed to stop service {service_name}: {e}",
                trace_id=trace_id
            )
            
            await self.logger.log_service_event(
                service_name=service_name,
                event_type="stop_failed",
                trace_id=trace_id,
                error=str(e)
            )
            
            await self.logger.end_trace(trace_id, "error", error=str(e))
            return False
    
    def _sync_stop_container(self, service_name: str):
        """Synchronously stop a container."""
        container = self.client.container.get(service_name)
        container.stop(timeout=10)
    
    async def delete_service(self, service_name: str, force: bool = False) -> bool:
        """Delete a Docker service completely.
        
        Args:
            service_name: Name of the service to delete
            force: Force deletion even if running
            
        Returns:
            True if successful
        """
        trace_id = self.logger.start_trace("docker_service_delete",
                                          service_name=service_name,
                                          force=force)
        
        try:
            await self.logger.info(
                f"Deleting service {service_name} (force={force})",
                trace_id=trace_id
            )
            
            # Release ports first
            await self.port_manager.remove_all_service_ports(service_name)
            
            # Delete container in executor
            loop = asyncio.get_event_loop()
            await loop.run_in_executor(
                executor,
                self._sync_delete_container,
                service_name,
                force
            )
            
            # Remove from Redis
            key = f"docker_service:{service_name}"
            await self.storage.redis_client.delete(key)
            
            # Publish event
            await self.logger.log_service_event(
                service_name=service_name,
                event_type="deleted",
                trace_id=trace_id
            )
            
            await self.logger.end_trace(trace_id, "success")
            return True
            
        except Exception as e:
            await self.logger.error(
                f"Failed to delete service {service_name}: {e}",
                trace_id=trace_id
            )
            
            await self.logger.log_service_event(
                service_name=service_name,
                event_type="delete_failed",
                trace_id=trace_id,
                error=str(e)
            )
            
            await self.logger.end_trace(trace_id, "error", error=str(e))
            return False
    
    def _sync_delete_container(self, service_name: str, force: bool):
        """Synchronously delete a container."""
        try:
            container = self.client.container.get(service_name)
            if force:
                container.kill()
            container.remove()
        except NoSuchContainer:
            # Already deleted
            pass
    
    async def get_service_logs(self, service_name: str, lines: int = 100,
                              timestamps: bool = True) -> str:
        """Get logs from a Docker service.
        
        Args:
            service_name: Name of the service
            lines: Number of lines to retrieve
            timestamps: Include timestamps
            
        Returns:
            Log output
        """
        trace_id = self.logger.start_trace("docker_service_logs",
                                          service_name=service_name)
        
        try:
            loop = asyncio.get_event_loop()
            logs = await loop.run_in_executor(
                executor,
                self._sync_get_logs,
                service_name,
                lines,
                timestamps
            )
            
            await self.logger.debug(
                f"Retrieved {len(logs.splitlines())} log lines for {service_name}",
                trace_id=trace_id
            )
            
            await self.logger.end_trace(trace_id, "success")
            return logs
            
        except Exception as e:
            await self.logger.error(
                f"Failed to get logs for {service_name}: {e}",
                trace_id=trace_id
            )
            await self.logger.end_trace(trace_id, "error", error=str(e))
            return f"Error retrieving logs: {e}"
    
    def _sync_get_logs(self, service_name: str, lines: int, timestamps: bool) -> str:
        """Synchronously get container logs."""
        container = self.client.container.get(service_name)
        return container.logs(tail=lines, timestamps=timestamps)
    
    async def get_service_stats(self, service_name: str) -> DockerServiceStats:
        """Get statistics for a Docker service.
        
        Args:
            service_name: Name of the service
            
        Returns:
            Service statistics
        """
        trace_id = self.logger.start_trace("docker_service_stats",
                                          service_name=service_name)
        
        try:
            loop = asyncio.get_event_loop()
            stats = await loop.run_in_executor(
                executor,
                self._sync_get_stats,
                service_name
            )
            
            await self.logger.debug(
                f"Retrieved stats for {service_name}",
                trace_id=trace_id,
                cpu_percent=stats.cpu_percent,
                memory_usage_mb=stats.memory_usage_mb
            )
            
            await self.logger.end_trace(trace_id, "success")
            return stats
            
        except Exception as e:
            await self.logger.error(
                f"Failed to get stats for {service_name}: {e}",
                trace_id=trace_id
            )
            await self.logger.end_trace(trace_id, "error", error=str(e))
            raise
    
    def _sync_get_stats(self, service_name: str) -> DockerServiceStats:
        """Synchronously get container stats."""
        container = self.client.container.get(service_name)
        stats = container.stats(stream=False)
        
        # Calculate CPU percentage
        cpu_delta = stats['cpu_stats']['cpu_usage']['total_usage'] - \
                   stats['precpu_stats']['cpu_usage']['total_usage']
        system_delta = stats['cpu_stats']['system_cpu_usage'] - \
                      stats['precpu_stats']['system_cpu_usage']
        cpu_percent = (cpu_delta / system_delta) * 100 if system_delta > 0 else 0
        
        # Calculate memory usage
        memory_usage = stats['memory_stats']['usage']
        memory_limit = stats['memory_stats']['limit']
        memory_percent = (memory_usage / memory_limit) * 100 if memory_limit > 0 else 0
        
        return DockerServiceStats(
            cpu_percent=cpu_percent,
            memory_usage_mb=memory_usage / (1024 * 1024),
            memory_limit_mb=memory_limit / (1024 * 1024),
            memory_percent=memory_percent,
            network_rx_bytes=stats.get('networks', {}).get('eth0', {}).get('rx_bytes', 0),
            network_tx_bytes=stats.get('networks', {}).get('eth0', {}).get('tx_bytes', 0)
        )
    
    async def _update_service_status(self, service_name: str, status: str, trace_id: str):
        """Update service status in Redis.
        
        Args:
            service_name: Name of the service
            status: New status
            trace_id: Trace ID for correlation
        """
        key = f"docker_service:{service_name}"
        service_data = await self.storage.redis_client.get(key)
        
        if service_data:
            service_info = json.loads(service_data)
            service_info['status'] = status
            await self.storage.redis_client.set(key, json.dumps(service_info))
            
            await self.logger.debug(
                f"Updated service {service_name} status to {status}",
                trace_id=trace_id
            )
    
    async def list_services(self, owner_hash: Optional[str] = None) -> List[DockerServiceInfo]:
        """List all managed Docker services.
        
        Args:
            owner_hash: Optional token hash to filter by owner
        
        Returns:
            List of service information
        """
        services = []
        
        async for key in self.storage.redis_client.scan_iter(match="docker_service:*"):
            service_data = await self.storage.redis_client.get(key)
            if service_data:
                try:
                    service_info = DockerServiceInfo.parse_raw(service_data)
                    # Filter by owner if specified
                    if owner_hash is None or service_info.owner_token_hash == owner_hash:
                        services.append(service_info)
                except Exception as e:
                    logger.error(f"Failed to parse service data: {e}")
        
        return services
    
    async def get_service(self, service_name: str) -> Optional[DockerServiceInfo]:
        """Get service information.
        
        Args:
            service_name: Service name
            
        Returns:
            Service information or None if not found
        """
        key = f"docker_service:{service_name}"
        data = await self.storage.redis_client.get(key)
        
        if not data:
            return None
            
        service_info = DockerServiceInfo.parse_raw(data)
        
        # Update status from actual container if it exists
        try:
            container = self.client.container.inspect(service_name)
            service_info.status = container.state.status
        except Exception:
            # Container might not exist yet, use stored status
            pass
            
        return service_info
    
    async def cleanup_orphaned_services(self) -> int:
        """Clean up orphaned Docker services.
        
        Returns:
            Number of services cleaned up
        """
        trace_id = self.logger.start_trace("docker_cleanup_orphaned")
        cleaned = 0
        
        try:
            # Get all containers with our label
            loop = asyncio.get_event_loop()
            containers = await loop.run_in_executor(
                executor,
                self._sync_list_containers
            )
            
            # Get all services from Redis
            redis_services = {s.service_name for s in await self.list_services()}
            
            # Find orphaned containers
            for container in containers:
                if container.name not in redis_services:
                    await self.logger.warning(
                        f"Found orphaned container: {container.name}",
                        trace_id=trace_id
                    )
                    
                    # Delete the orphaned container
                    try:
                        await loop.run_in_executor(
                            executor,
                            lambda: container.remove(force=True)
                        )
                        cleaned += 1
                        
                        await self.logger.info(
                            f"Removed orphaned container: {container.name}",
                            trace_id=trace_id
                        )
                    except Exception as e:
                        await self.logger.error(
                            f"Failed to remove orphaned container {container.name}: {e}",
                            trace_id=trace_id
                        )
            
            await self.logger.info(
                f"Cleaned up {cleaned} orphaned services",
                trace_id=trace_id
            )
            
            await self.logger.end_trace(trace_id, "success", cleaned_count=cleaned)
            return cleaned
            
        except Exception as e:
            await self.logger.error(
                f"Failed during orphaned service cleanup: {e}",
                trace_id=trace_id
            )
            await self.logger.end_trace(trace_id, "error", error=str(e))
            return cleaned
    
    def _sync_list_containers(self):
        """Synchronously list containers with our label."""
        return self.client.container.list(
            filters={"label": self.managed_label}
        )