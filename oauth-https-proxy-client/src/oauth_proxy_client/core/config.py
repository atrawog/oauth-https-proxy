"""Configuration management for OAuth Proxy Client.

This module handles all environment variables and configuration files,
ensuring compatibility with the justfile environment variables.
"""

import os
import yaml
from pathlib import Path
from typing import Optional, Dict, Any, List
from dataclasses import dataclass, field
from dotenv import load_dotenv

from .exceptions import ConfigurationError


@dataclass
class Config:
    """Configuration for OAuth Proxy Client.
    
    Environment variables are loaded in priority order:
    1. Command-line arguments
    2. Environment variables  
    3. .env file
    4. Configuration file (~/.oauth-proxy-client.yml)
    5. Default values
    """
    
    # Primary Configuration (matching justfile)
    api_url: str = field(default_factory=lambda: os.getenv('API_URL', 'http://localhost:80'))
    token: Optional[str] = field(default=None)
    
    # Testing Configuration
    test_token: Optional[str] = field(default_factory=lambda: os.getenv('TEST_TOKEN'))
    test_api_url: str = field(default_factory=lambda: os.getenv('TEST_API_URL', 'https://test.atradev.org'))
    test_domain_base: str = field(default_factory=lambda: os.getenv('TEST_DOMAIN_BASE', 'atradev.org'))
    
    # Timeout Configuration (matching proxy behavior)
    request_timeout: int = field(default_factory=lambda: int(os.getenv('PROXY_REQUEST_TIMEOUT', '120')))
    connect_timeout: int = field(default_factory=lambda: int(os.getenv('PROXY_CONNECT_TIMEOUT', '30')))
    
    # Logging
    log_level: str = field(default_factory=lambda: os.getenv('LOG_LEVEL', 'INFO'))
    
    # ACME Configuration
    acme_directory_url: str = field(
        default_factory=lambda: os.getenv('ACME_DIRECTORY_URL', 'https://acme-v02.api.letsencrypt.org/directory')
    )
    acme_staging_url: str = field(
        default_factory=lambda: os.getenv('ACME_STAGING_URL', 'https://acme-staging-v02.api.letsencrypt.org/directory')
    )
    admin_email: Optional[str] = field(default_factory=lambda: os.getenv('ADMIN_EMAIL'))
    
    # OAuth Configuration
    github_client_id: Optional[str] = field(default_factory=lambda: os.getenv('GITHUB_CLIENT_ID'))
    github_client_secret: Optional[str] = field(default_factory=lambda: os.getenv('GITHUB_CLIENT_SECRET'))
    base_domain: str = field(default_factory=lambda: os.getenv('BASE_DOMAIN', 'localhost'))
    oauth_allowed_github_users: str = field(default_factory=lambda: os.getenv('OAUTH_ALLOWED_GITHUB_USERS', '*'))
    
    # MCP Configuration
    mcp_client_id: Optional[str] = field(default_factory=lambda: os.getenv('MCP_CLIENT_ID'))
    mcp_client_secret: Optional[str] = field(default_factory=lambda: os.getenv('MCP_CLIENT_SECRET'))
    mcp_server_url: Optional[str] = field(default_factory=lambda: os.getenv('MCP_SERVER_URL'))
    
    # OAuth Protocol
    oauth_redirect_uri: str = field(default_factory=lambda: os.getenv('OAUTH_REDIRECT_URI', 'urn:ietf:wg:oauth:2.0:oob'))
    
    # Service Management
    docker_gid: str = field(default_factory=lambda: os.getenv('DOCKER_GID', '999'))
    docker_api_version: str = field(default_factory=lambda: os.getenv('DOCKER_API_VERSION', '1.41'))
    
    # Certificate Management
    renewal_check_interval: int = field(default_factory=lambda: int(os.getenv('RENEWAL_CHECK_INTERVAL', '86400')))
    renewal_threshold_days: int = field(default_factory=lambda: int(os.getenv('RENEWAL_THRESHOLD_DAYS', '30')))
    
    # Redis Configuration
    redis_password: Optional[str] = field(default_factory=lambda: os.getenv('REDIS_PASSWORD'))
    redis_url: Optional[str] = field(default_factory=lambda: os.getenv('REDIS_URL'))
    
    # Output formatting
    output_format: str = field(default='auto')  # auto, json, table, yaml, csv
    
    # Profile management
    profile: str = field(default='default')
    config_file: Optional[Path] = field(default=None)
    
    def __post_init__(self):
        """Post-initialization to handle token priority and config file loading."""
        # Handle token priority: explicit > TOKEN > ADMIN_TOKEN > TEST_TOKEN
        if not self.token:
            self.token = (
                os.getenv('TOKEN') or 
                os.getenv('ADMIN_TOKEN') or
                (self.test_token if self.api_url == self.test_api_url else None)
            )
        
        # Load configuration file if specified
        if self.config_file and self.config_file.exists():
            self._load_config_file()
    
    @classmethod
    def from_env(cls, env_file: Optional[Path] = None) -> 'Config':
        """Create config from environment variables and optional .env file.
        
        Args:
            env_file: Path to .env file (default: looks for .env in current dir)
        
        Returns:
            Config instance with loaded values
        """
        # Load .env file if it exists
        if env_file:
            if env_file.exists():
                load_dotenv(env_file)
        elif Path('.env').exists():
            load_dotenv()
        
        return cls()
    
    @classmethod
    def from_file(cls, config_file: Path, profile: str = 'default') -> 'Config':
        """Load configuration from YAML file.
        
        Args:
            config_file: Path to YAML configuration file
            profile: Profile name to load
        
        Returns:
            Config instance with loaded values
        
        Raises:
            ConfigurationError: If file doesn't exist or is invalid
        """
        if not config_file.exists():
            raise ConfigurationError(f"Configuration file not found: {config_file}")
        
        try:
            with open(config_file, 'r') as f:
                data = yaml.safe_load(f)
        except yaml.YAMLError as e:
            raise ConfigurationError(f"Invalid YAML in config file: {e}")
        
        # Get profile-specific config
        profiles = data.get('profiles', {})
        profile_config = profiles.get(profile, {})
        defaults = data.get('defaults', {})
        
        # Merge defaults with profile config
        config_data = {**defaults, **profile_config}
        
        # Create config instance
        config = cls()
        
        # Update with file values (only if not already set by env)
        for key, value in config_data.items():
            if hasattr(config, key):
                # Only override if env var not set
                current_value = getattr(config, key)
                if current_value in (None, '', field(default=None).default):
                    # Expand environment variables in config values
                    if isinstance(value, str) and '${' in value:
                        value = os.path.expandvars(value)
                    setattr(config, key, value)
        
        config.profile = profile
        config.config_file = config_file
        
        return config
    
    def _load_config_file(self):
        """Load additional configuration from file."""
        if not self.config_file or not self.config_file.exists():
            return
        
        try:
            with open(self.config_file, 'r') as f:
                data = yaml.safe_load(f)
            
            profiles = data.get('profiles', {})
            profile_config = profiles.get(self.profile, {})
            
            for key, value in profile_config.items():
                if hasattr(self, key) and getattr(self, key) is None:
                    if isinstance(value, str) and '${' in value:
                        value = os.path.expandvars(value)
                    setattr(self, key, value)
        except Exception:
            pass  # Silently ignore config file errors
    
    def validate(self) -> List[str]:
        """Validate configuration and return list of warnings.
        
        Returns:
            List of warning messages (empty if all valid)
        """
        warnings = []
        
        # Check required fields for certain operations
        if not self.token:
            warnings.append("No authentication token configured (set TOKEN or ADMIN_TOKEN)")
        
        if not self.api_url:
            warnings.append("No base URL configured (set API_URL)")
        
        # Validate URL format
        if self.api_url and not (
            self.api_url.startswith('http://') or 
            self.api_url.startswith('https://')
        ):
            warnings.append(f"Invalid base URL format: {self.api_url}")
        
        return warnings
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert configuration to dictionary.
        
        Returns:
            Dictionary representation of configuration
        """
        return {
            'api_url': self.api_url,
            'token': '***' if self.token else None,  # Mask token
            'test_api_url': self.test_api_url,
            'test_domain_base': self.test_domain_base,
            'request_timeout': self.request_timeout,
            'connect_timeout': self.connect_timeout,
            'log_level': self.log_level,
            'output_format': self.output_format,
            'profile': self.profile,
            'base_domain': self.base_domain,
            'admin_email': self.admin_email,
        }
    
    def get_timeout(self) -> tuple[float, float]:
        """Get timeout tuple for httpx client.
        
        Returns:
            Tuple of (connect_timeout, request_timeout)
        """
        return (float(self.connect_timeout), float(self.request_timeout))
    
    def get_headers(self) -> Dict[str, str]:
        """Get default headers for API requests.
        
        Returns:
            Dictionary of headers including authorization if token is set
        """
        headers = {
            'User-Agent': 'oauth-https-proxy-client/0.1.0',
            'Accept': 'application/json',
        }
        
        if self.token:
            headers['Authorization'] = f'Bearer {self.token}'
        
        return headers
    
    def use_test_config(self):
        """Switch to test configuration."""
        self.api_url = self.test_api_url
        if self.test_token:
            self.token = self.test_token
    
    def __repr__(self) -> str:
        """String representation of config."""
        return f"Config(profile={self.profile}, api_url={self.api_url})"