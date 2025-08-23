"""Models for the dispatcher component."""

from dataclasses import dataclass
from typing import Optional, Any
import ssl


@dataclass
class DomainService:
    """Represents a domain service with its routing configuration."""
    hostname: str
    is_api_service: bool  # True for FastAPI (localhost), False for proxy services
    internal_http_port: int
    internal_https_port: int
    ssl_context: Optional[ssl.SSLContext] = None
    
    def __repr__(self):
        return (f"DomainService(proxy_hostname={self.hostname}, "
                f"api={self.is_api_service}, "
                f"http={self.internal_http_port}, "
                f"https={self.internal_https_port})")