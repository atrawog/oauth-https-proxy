"""Port management models and data structures."""

from datetime import datetime, timezone
from typing import Dict, List, Optional, Any
from pydantic import BaseModel, Field, field_validator


class ServicePort(BaseModel):
    """Represents a single exposed port for a service."""
    service_name: str = Field(..., description="Name of the service")
    port_name: str = Field(..., description="Friendly name for the port (e.g., 'http', 'admin')")
    host_port: int = Field(..., ge=1, le=65535, description="Port on the host")
    container_port: int = Field(..., ge=1, le=65535, description="Port inside the container")
    bind_address: str = Field("127.0.0.1", description="Bind address (127.0.0.1 or 0.0.0.0)")
    protocol: str = Field("tcp", description="Protocol (tcp or udp)")
    
    # Access control
    source_token_hash: Optional[str] = Field(None, description="Hash of token required to access this port")
    source_token_name: Optional[str] = Field(None, description="Human-readable token identifier")
    require_token: bool = Field(False, description="Whether token is required for access")
    
    # Metadata
    owner_token_hash: str = Field(..., description="Hash of token that created this port")
    created_by: Optional[str] = Field(None, description="Name of token that created this port")
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    description: Optional[str] = Field(None, description="Description of what this port is for")
    
    @field_validator('bind_address')
    @classmethod
    def validate_bind_address(cls, v: str) -> str:
        """Validate bind address is either localhost or all interfaces."""
        valid_addresses = ["127.0.0.1", "0.0.0.0", "localhost", "::1", "::"]
        if v not in valid_addresses:
            raise ValueError(f"Bind address must be one of: {', '.join(valid_addresses)}")
        # Normalize localhost variations
        if v in ["localhost", "::1"]:
            return "127.0.0.1"
        if v == "::":
            return "0.0.0.0"
        return v
    
    @field_validator('protocol')
    @classmethod
    def validate_protocol(cls, v: str) -> str:
        """Validate protocol is tcp or udp."""
        v = v.lower()
        if v not in ["tcp", "udp"]:
            raise ValueError("Protocol must be 'tcp' or 'udp'")
        return v
    
    @field_validator('port_name')
    @classmethod
    def validate_port_name(cls, v: str) -> str:
        """Validate port name format."""
        import re
        if not re.match(r'^[a-z0-9_-]+$', v):
            raise ValueError("Port name can only contain lowercase letters, numbers, dash, and underscore")
        if len(v) > 32:
            raise ValueError("Port name must be 32 characters or less")
        return v


class PortAccessToken(BaseModel):
    """Token for accessing exposed ports."""
    token_hash: str = Field(..., description="SHA256 hash of the token")
    token_name: str = Field(..., description="Human-readable name for the token")
    allowed_services: List[str] = Field(default_factory=list, description="List of allowed services (empty = all)")
    allowed_ports: List[int] = Field(default_factory=list, description="List of allowed ports (empty = all)")
    expires_at: Optional[datetime] = Field(None, description="Token expiration time")
    created_by: str = Field(..., description="Token that created this access token")
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    last_used: Optional[datetime] = Field(None, description="Last time this token was used")
    use_count: int = Field(0, description="Number of times this token has been used")
    
    def is_expired(self) -> bool:
        """Check if token is expired."""
        if not self.expires_at:
            return False
        return datetime.now(timezone.utc) > self.expires_at
    
    def can_access_service(self, service_name: str) -> bool:
        """Check if token can access a specific service."""
        if not self.allowed_services:  # Empty list means all services
            return True
        return service_name in self.allowed_services
    
    def can_access_port(self, port: int) -> bool:
        """Check if token can access a specific port."""
        if not self.allowed_ports:  # Empty list means all ports
            return True
        return port in self.allowed_ports


class PortConfiguration(BaseModel):
    """Configuration for creating multiple ports."""
    name: str = Field(..., description="Port name")
    host: int = Field(..., ge=1, le=65535, description="Host port")
    container: int = Field(..., ge=1, le=65535, description="Container port")
    bind: str = Field("127.0.0.1", description="Bind address")
    protocol: str = Field("tcp", description="Protocol")
    token: Optional[str] = Field(None, description="Source token for access control")
    description: Optional[str] = Field(None, description="Port description")


class MultiPortConfig(BaseModel):
    """Configuration for creating a service with multiple ports."""
    ports: List[PortConfiguration] = Field(..., min_items=1, description="List of port configurations")
    
    @field_validator('ports')
    @classmethod
    def validate_unique_names(cls, v: List[PortConfiguration]) -> List[PortConfiguration]:
        """Ensure port names are unique within the configuration."""
        names = [port.name for port in v]
        if len(names) != len(set(names)):
            raise ValueError("Port names must be unique within the configuration")
        return v
    
    @field_validator('ports')
    @classmethod
    def validate_unique_host_ports(cls, v: List[PortConfiguration]) -> List[PortConfiguration]:
        """Ensure host ports are unique within the configuration."""
        host_ports = [port.host for port in v]
        if len(host_ports) != len(set(host_ports)):
            raise ValueError("Host ports must be unique within the configuration")
        return v


class PortAllocation(BaseModel):
    """Tracks port allocation status."""
    port: int = Field(..., ge=1, le=65535, description="Port number")
    service_name: str = Field(..., description="Service using this port")
    port_name: str = Field(..., description="Port name within the service")
    bind_address: str = Field(..., description="Bind address")
    allocated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    purpose: str = Field("exposed", description="Purpose: 'internal' or 'exposed'")