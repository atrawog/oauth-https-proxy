"""Docker service models and data structures."""

from typing import Dict, List, Optional, Any
from datetime import datetime
from pydantic import BaseModel, Field, validator
import re


class DockerServiceConfig(BaseModel):
    """Configuration for creating a Docker service."""
    
    service_name: str = Field(..., description="Unique service name")
    image: Optional[str] = Field(None, description="Docker image to use")
    dockerfile_path: Optional[str] = Field(None, description="Path to Dockerfile")
    build_context: Optional[str] = Field("./contexts", description="Build context directory")
    build_args: Dict[str, str] = Field(default_factory=dict, description="Build arguments")
    internal_port: int = Field(8080, description="Port the service listens on")
    external_port: Optional[int] = Field(None, description="External port (auto-assigned if None)")
    environment: Dict[str, str] = Field(default_factory=dict, description="Environment variables")
    volumes: List[str] = Field(default_factory=list, description="Volume mounts")
    networks: List[str] = Field(default_factory=lambda: ["mcp-http-proxy_proxy_network"], description="Networks to join")
    labels: Dict[str, str] = Field(
        default_factory=lambda: {"managed": "true", "created_by": "mcp-proxy"},
        description="Container labels"
    )
    memory_limit: str = Field("512m", description="Memory limit (e.g., 512m, 1g)")
    cpu_limit: float = Field(1.0, description="CPU limit (1.0 = 1 CPU)")
    restart_policy: str = Field("unless-stopped", description="Restart policy")
    healthcheck: Optional[Dict] = Field(None, description="Health check configuration")
    read_only_root: bool = Field(True, description="Make root filesystem read-only")
    user: Optional[str] = Field(None, description="User to run as in container")
    capabilities: List[str] = Field(default_factory=list, description="Linux capabilities to add")
    
    # Multi-port configuration
    expose_ports: bool = Field(False, description="Whether to expose ports directly")
    port_configs: List[Dict[str, Any]] = Field(
        default_factory=list, 
        description="List of port configurations for multi-port support"
    )
    # port_configs example:
    # [
    #   {"name": "http", "host": 8080, "container": 80, "bind": "0.0.0.0"},
    #   {"name": "https", "host": 8443, "container": 443, "bind": "127.0.0.1", "source_token": "admin"}
    # ]
    bind_address: str = Field("127.0.0.1", description="Default bind address for ports")
    
    @validator('service_name')
    def validate_service_name(cls, v):
        """Validate service name format."""
        if not v or not v.strip():
            raise ValueError("Service name cannot be empty")
        # Docker container names can only contain lowercase letters, numbers, dash, and underscore
        if not re.match(r'^[a-z0-9_-]+$', v):
            raise ValueError("Service name can only contain lowercase letters, numbers, dash, and underscore")
        if len(v) > 63:
            raise ValueError("Service name must be 63 characters or less")
        return v
    
    @validator('image')
    def validate_image(cls, v, values):
        """Validate that either image or dockerfile_path is provided."""
        dockerfile_path = values.get('dockerfile_path')
        if not v and not dockerfile_path:
            raise ValueError("Either 'image' or 'dockerfile_path' must be provided")
        return v
    
    @validator('memory_limit')
    def validate_memory_limit(cls, v):
        """Validate memory limit format."""
        if not re.match(r'^\d+[kmg]?$', v.lower()):
            raise ValueError("Invalid memory limit format. Use format like '512m', '1g', '1024k'")
        return v
    
    @validator('cpu_limit')
    def validate_cpu_limit(cls, v):
        """Validate CPU limit."""
        if v <= 0 or v > 32:
            raise ValueError("CPU limit must be between 0 and 32")
        return v
    
    @validator('restart_policy')
    def validate_restart_policy(cls, v):
        """Validate restart policy."""
        valid_policies = ["no", "always", "unless-stopped", "on-failure"]
        if v not in valid_policies:
            raise ValueError(f"Restart policy must be one of: {', '.join(valid_policies)}")
        return v
    
    @validator('volumes')
    def validate_volumes(cls, v):
        """Validate volume mount syntax."""
        for volume in v:
            parts = volume.split(':')
            if len(parts) < 2 or len(parts) > 3:
                raise ValueError(f"Invalid volume format: {volume}. Use 'source:target[:mode]'")
        return v
    
    @validator('bind_address')
    def validate_bind_address(cls, v):
        """Validate bind address."""
        valid_addresses = ["127.0.0.1", "0.0.0.0", "localhost"]
        if v not in valid_addresses:
            raise ValueError(f"Bind address must be one of: {', '.join(valid_addresses)}")
        # Normalize localhost to 127.0.0.1
        if v == "localhost":
            return "127.0.0.1"
        return v
    
    @validator('port_configs')
    def validate_port_configs(cls, v):
        """Validate port configurations."""
        if not v:
            return v
        
        seen_names = set()
        seen_host_ports = set()
        
        for config in v:
            # Validate required fields
            if 'name' not in config or 'host' not in config or 'container' not in config:
                raise ValueError("Port config must have 'name', 'host', and 'container' fields")
            
            # Check for duplicate names
            if config['name'] in seen_names:
                raise ValueError(f"Duplicate port name: {config['name']}")
            seen_names.add(config['name'])
            
            # Check for duplicate host ports
            if config['host'] in seen_host_ports:
                raise ValueError(f"Duplicate host port: {config['host']}")
            seen_host_ports.add(config['host'])
            
            # Validate port ranges
            if not (1 <= config['host'] <= 65535):
                raise ValueError(f"Host port must be between 1 and 65535: {config['host']}")
            if not (1 <= config['container'] <= 65535):
                raise ValueError(f"Container port must be between 1 and 65535: {config['container']}")
            
            # Validate bind address if present
            if 'bind' in config:
                valid_binds = ["127.0.0.1", "0.0.0.0", "localhost"]
                if config['bind'] not in valid_binds:
                    raise ValueError(f"Bind address must be one of: {', '.join(valid_binds)}")
        
        return v


class DockerServiceInfo(DockerServiceConfig):
    """Information about a running Docker service."""
    
    status: str = Field(..., description="Service status (running, stopped, etc.)")
    container_id: Optional[str] = Field(None, description="Container ID")
    created_at: datetime = Field(..., description="Creation timestamp")
    owner_token_hash: str = Field(..., description="Hash of the token that created this service")
    allocated_port: int = Field(..., description="Allocated external port")  # Deprecated, kept for backward compatibility
    health_status: Optional[str] = Field(None, description="Health check status")
    exposed_ports: List[Dict[str, Any]] = Field(default_factory=list, description="List of exposed ports")
    
    class Config:
        """Pydantic configuration."""
        json_encoders = {
            datetime: lambda v: v.isoformat()
        }


class DockerServiceUpdate(BaseModel):
    """Update configuration for a Docker service."""
    
    environment: Optional[Dict[str, str]] = Field(None, description="Environment variables to update")
    memory_limit: Optional[str] = Field(None, description="New memory limit")
    cpu_limit: Optional[float] = Field(None, description="New CPU limit")
    restart_policy: Optional[str] = Field(None, description="New restart policy")
    labels: Optional[Dict[str, str]] = Field(None, description="Labels to update")
    
    @validator('memory_limit')
    def validate_memory_limit(cls, v):
        """Validate memory limit format."""
        if v and not re.match(r'^\d+[kmg]?$', v.lower()):
            raise ValueError("Invalid memory limit format. Use format like '512m', '1g', '1024k'")
        return v
    
    @validator('cpu_limit')
    def validate_cpu_limit(cls, v):
        """Validate CPU limit."""
        if v is not None and (v <= 0 or v > 32):
            raise ValueError("CPU limit must be between 0 and 32")
        return v


class DockerServiceLogs(BaseModel):
    """Response model for service logs."""
    
    service_name: str = Field(..., description="Service name")
    logs: List[str] = Field(..., description="Log lines")
    timestamps: bool = Field(False, description="Whether timestamps are included")
    
    
class DockerServiceStats(BaseModel):
    """Statistics for a Docker service."""
    
    service_name: str = Field(..., description="Service name")
    cpu_usage: float = Field(..., description="CPU usage percentage")
    memory_usage: int = Field(..., description="Memory usage in bytes")
    memory_limit: int = Field(..., description="Memory limit in bytes")
    memory_percentage: float = Field(..., description="Memory usage percentage")
    network_rx_bytes: int = Field(..., description="Network received bytes")
    network_tx_bytes: int = Field(..., description="Network transmitted bytes")
    block_read_bytes: int = Field(..., description="Disk read bytes")
    block_write_bytes: int = Field(..., description="Disk write bytes")
    pids: int = Field(..., description="Number of processes")


class DockerImageAllowlist(BaseModel):
    """Configuration for allowed Docker images."""
    
    patterns: List[str] = Field(
        default_factory=lambda: [
            "nginx:*",
            "httpd:*",
            "node:*-alpine",
            "python:*-slim",
            "alpine:*",
            "busybox:*"
        ],
        description="Allowed image patterns (supports wildcards)"
    )
    registries: List[str] = Field(
        default_factory=lambda: [
            "docker.io",
            "ghcr.io",
            "quay.io"
        ],
        description="Allowed registries"
    )
    
    
class DockerServiceListResponse(BaseModel):
    """Response model for listing Docker services."""
    
    services: List[DockerServiceInfo] = Field(..., description="List of services")
    total: int = Field(..., description="Total number of services")
    
    
class DockerServiceCreateResponse(BaseModel):
    """Response model for service creation."""
    
    service: DockerServiceInfo = Field(..., description="Created service information")
    proxy_created: bool = Field(False, description="Whether a proxy was auto-created")
    instance_registered: bool = Field(False, description="Whether instance was registered")
    warnings: List[str] = Field(default_factory=list, description="Any warnings during creation")