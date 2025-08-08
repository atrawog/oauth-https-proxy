"""OAuth HTTPS Proxy Client - A comprehensive CLI for secure proxy management.

This package provides a command-line interface for managing OAuth HTTPS proxy
infrastructure with TLS/ACME support, including certificates, routing, services, 
and authentication.
"""

__version__ = "0.1.0"
__author__ = "OAuth Proxy Team"
__email__ = "admin@example.com"

from oauth_proxy_client.core.client import ProxyClient
from oauth_proxy_client.core.config import Config
from oauth_proxy_client.core.exceptions import (
    ProxyClientError,
    AuthenticationError,
    ConfigurationError,
    APIError,
)

__all__ = [
    "ProxyClient",
    "Config",
    "ProxyClientError",
    "AuthenticationError",
    "ConfigurationError",
    "APIError",
    "__version__",
]