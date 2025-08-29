"""Centralized configuration management for MCP HTTP Proxy."""

import os
from typing import Optional
from functools import lru_cache


class Config:
    """Configuration class with all environment variables."""
    
    # Server Configuration
    HTTP_PORT: int = int(os.getenv('HTTP_PORT', '80'))
    HTTPS_PORT: int = int(os.getenv('HTTPS_PORT', '443'))
    SERVER_HOST: str = os.getenv('SERVER_HOST', '0.0.0.0')
    API_URL: str = os.getenv('API_URL', 'http://localhost:80')
    
    # Redis Configuration
    REDIS_URL: str = os.getenv('REDIS_URL', 'redis://localhost:6379/0')
    REDIS_PASSWORD: Optional[str] = os.getenv('REDIS_PASSWORD')
    
    # Logging
    LOG_LEVEL: str = os.getenv('LOG_LEVEL', 'INFO').upper()
    LOG_FORMAT: str = os.getenv('LOG_FORMAT', 'json')
    LOG_STORAGE: str = os.getenv('LOG_STORAGE', 'redis')
    LOG_TTL_DAYS: int = int(os.getenv('LOG_TTL_DAYS', '7'))
    LOG_SENSITIVE_MASK: str = os.getenv('LOG_SENSITIVE_MASK', 'true')
    LOG_REQUEST_BODY: str = os.getenv('LOG_REQUEST_BODY', 'true')
    LOG_RESPONSE_BODY: str = os.getenv('LOG_RESPONSE_BODY', 'true')
    LOG_MAX_BODY_SIZE: int = int(os.getenv('LOG_MAX_BODY_SIZE', '10240'))
    LOG_SAMPLING_RATE: float = float(os.getenv('LOG_SAMPLING_RATE', '1.0'))
    LOG_CORRELATION_ID_HEADER: str = os.getenv('LOG_CORRELATION_ID_HEADER', 'X-Correlation-ID')
    LOG_INCLUDE_CORRELATION_ID_RESPONSE: str = os.getenv('LOG_INCLUDE_CORRELATION_ID_RESPONSE', 'true')
    
    # Certificate Configuration
    RSA_KEY_SIZE: int = int(os.getenv('RSA_KEY_SIZE', '2048'))
    SELF_SIGNED_CN: str = os.getenv('SELF_SIGNED_CN', 'localhost')
    SELF_SIGNED_DAYS: int = int(os.getenv('SELF_SIGNED_DAYS', '365'))
    
    # ACME Configuration
    ACME_DIRECTORY_URL: str = os.getenv('ACME_DIRECTORY_URL', 
        'https://acme-v02.api.letsencrypt.org/directory')
    ACME_STAGING_URL: str = os.getenv('ACME_STAGING_URL', 
        'https://acme-staging-v02.api.letsencrypt.org/directory')
    ACME_POLL_MAX_ATTEMPTS: int = int(os.getenv('ACME_POLL_MAX_ATTEMPTS', '60'))
    ACME_POLL_INTERVAL_SECONDS: int = int(os.getenv('ACME_POLL_INTERVAL_SECONDS', '2'))
    ACME_POLL_INITIAL_WAIT: int = int(os.getenv('ACME_POLL_INITIAL_WAIT', '0'))
    
    # Certificate Management
    RENEWAL_CHECK_INTERVAL: int = int(os.getenv('RENEWAL_CHECK_INTERVAL', '86400'))  # 24 hours
    RENEWAL_THRESHOLD_DAYS: int = int(os.getenv('RENEWAL_THRESHOLD_DAYS', '30'))
    CERT_STATUS_RETENTION_SECONDS: int = int(os.getenv('CERT_STATUS_RETENTION_SECONDS', '300'))
    CERT_GEN_MAX_WORKERS: int = int(os.getenv('CERT_GEN_MAX_WORKERS', '5'))
    
    # Proxy Configuration
    PROXY_REQUEST_TIMEOUT: int = int(os.getenv('PROXY_REQUEST_TIMEOUT', '120'))
    PROXY_CONNECT_TIMEOUT: int = int(os.getenv('PROXY_CONNECT_TIMEOUT', '30'))
    FETCHER_NAVIGATION_TIMEOUT: int = int(os.getenv('FETCHER_NAVIGATION_TIMEOUT', '25'))
    
    # OAuth Configuration
    GITHUB_CLIENT_ID: Optional[str] = os.getenv('GITHUB_CLIENT_ID')
    GITHUB_CLIENT_SECRET: Optional[str] = os.getenv('GITHUB_CLIENT_SECRET')
    BASE_DOMAIN: str = os.getenv('BASE_DOMAIN', 'localhost')
    OAUTH_ACCESS_TOKEN_LIFETIME: int = int(os.getenv('OAUTH_ACCESS_TOKEN_LIFETIME', '1800'))  # 30 minutes
    OAUTH_REFRESH_TOKEN_LIFETIME: int = int(os.getenv('OAUTH_REFRESH_TOKEN_LIFETIME', '31536000'))  # 1 year
    OAUTH_SESSION_TIMEOUT: int = int(os.getenv('OAUTH_SESSION_TIMEOUT', '300'))  # 5 minutes
    OAUTH_CLIENT_LIFETIME: int = int(os.getenv('OAUTH_CLIENT_LIFETIME', '7776000'))  # 90 days
    # Security: Only explicitly listed users are allowed (no wildcards)
    OAUTH_ADMIN_USERS: str = os.getenv('OAUTH_ADMIN_USERS', '')  # Users with admin scope
    OAUTH_USER_USERS: str = os.getenv('OAUTH_USER_USERS', '')   # Users with user scope
    
    # JWT Configuration
    OAUTH_JWT_ALGORITHM: str = os.getenv('OAUTH_JWT_ALGORITHM', 'RS256')
    OAUTH_JWT_SECRET: Optional[str] = os.getenv('OAUTH_JWT_SECRET')
    OAUTH_JWT_PRIVATE_KEY_B64: Optional[str] = os.getenv('OAUTH_JWT_PRIVATE_KEY_B64')
    
    # Admin Configuration
    ADMIN_TOKEN: Optional[str] = os.getenv('ADMIN_TOKEN')
    ADMIN_EMAIL: Optional[str] = os.getenv('ADMIN_EMAIL')
    
    # Testing Configuration
    TEST_DOMAIN: Optional[str] = os.getenv('TEST_DOMAIN')
    TEST_EMAIL: Optional[str] = os.getenv('TEST_EMAIL')
    TEST_DOMAIN_BASE: Optional[str] = os.getenv('TEST_DOMAIN_BASE')
    TEST_API_URL: str = os.getenv('TEST_API_URL', 'http://localhost:80')
    TEST_PROXY_TARGET_URL: str = os.getenv('TEST_PROXY_TARGET_URL', 'https://example.com')
    TEST_TOKEN: Optional[str] = os.getenv('TEST_TOKEN')
    
    @classmethod
    def validate(cls) -> None:
        """Validate required configuration values."""
        errors = []
        
        # Check required values
        if not cls.REDIS_URL:
            errors.append("REDIS_URL is required")
        
        if not cls.SERVER_HOST:
            errors.append("SERVER_HOST is required")
            
        # Check port ranges
        if not (1 <= cls.HTTP_PORT <= 65535):
            errors.append(f"HTTP_PORT must be between 1 and 65535, got {cls.HTTP_PORT}")
            
        if not (1 <= cls.HTTPS_PORT <= 65535):
            errors.append(f"HTTPS_PORT must be between 1 and 65535, got {cls.HTTPS_PORT}")
            
        # Check timeout hierarchy
        if cls.FETCHER_NAVIGATION_TIMEOUT >= cls.PROXY_CONNECT_TIMEOUT:
            errors.append("FETCHER_NAVIGATION_TIMEOUT must be less than PROXY_CONNECT_TIMEOUT")
            
        if cls.PROXY_CONNECT_TIMEOUT >= cls.PROXY_REQUEST_TIMEOUT:
            errors.append("PROXY_CONNECT_TIMEOUT must be less than PROXY_REQUEST_TIMEOUT")
        
        if errors:
            raise ValueError(f"Configuration errors: {'; '.join(errors)}")
    
    @classmethod
    def get_redis_url_with_password(cls) -> str:
        """Get Redis URL with password if configured."""
        if cls.REDIS_PASSWORD and cls.REDIS_URL:
            # Parse and reconstruct URL with password
            from urllib.parse import urlparse, urlunparse
            parsed = urlparse(cls.REDIS_URL)
            if not parsed.password:
                # Add password to URL
                netloc = f":{cls.REDIS_PASSWORD}@{parsed.hostname}"
                if parsed.port:
                    netloc += f":{parsed.port}"
                return urlunparse((
                    parsed.scheme,
                    netloc,
                    parsed.path,
                    parsed.params,
                    parsed.query,
                    parsed.fragment
                ))
        return cls.REDIS_URL


@lru_cache()
def get_config() -> Config:
    """Get validated configuration instance."""
    Config.validate()
    return Config()


# For backward compatibility
config = get_config()