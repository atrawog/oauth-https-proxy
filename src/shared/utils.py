"""Common utility functions for MCP HTTP Proxy."""

import hashlib
import secrets
from typing import Optional
from datetime import datetime, timezone


def hash_token(token: str) -> str:
    """Create SHA256 hash of API token."""
    return f"sha256:{hashlib.sha256(token.encode()).hexdigest()}"


def get_current_timestamp() -> datetime:
    """Get current UTC timestamp."""
    return datetime.now(timezone.utc)


def format_timestamp(dt: datetime) -> str:
    """Format datetime to ISO format string."""
    return dt.isoformat()


def parse_timestamp(timestamp_str: str) -> datetime:
    """Parse ISO format timestamp string."""
    return datetime.fromisoformat(timestamp_str)


def is_valid_domain(domain: str) -> bool:
    """Validate domain name format."""
    if not domain or len(domain) > 253:
        return False
    
    # Check for valid characters and structure
    labels = domain.split('.')
    if len(labels) < 2:
        return False
    
    for label in labels:
        if not label or len(label) > 63:
            return False
        if label.startswith('-') or label.endswith('-'):
            return False
        if not all(c.isalnum() or c == '-' for c in label):
            return False
    
    return True


def is_valid_email(email: str) -> bool:
    """Basic email validation."""
    if not email or '@' not in email:
        return False
    
    local, domain = email.rsplit('@', 1)
    if not local or not domain:
        return False
    
    return is_valid_domain(domain)


def sanitize_cert_name(domain: str) -> str:
    """Convert domain to safe certificate name."""
    # Replace dots and other special characters
    safe_name = domain.replace('.', '-').replace('*', 'wildcard')
    # Remove any remaining non-alphanumeric characters except dash
    safe_name = ''.join(c if c.isalnum() or c == '-' else '-' for c in safe_name)
    # Remove multiple consecutive dashes
    while '--' in safe_name:
        safe_name = safe_name.replace('--', '-')
    # Remove leading/trailing dashes
    return safe_name.strip('-')


def get_wildcard_domain(domain: str) -> Optional[str]:
    """Get wildcard domain from a subdomain."""
    parts = domain.split('.')
    if len(parts) > 2:
        return f"*.{'.'.join(parts[1:])}"
    return None


def match_domain_pattern(domain: str, pattern: str) -> bool:
    """Check if domain matches a pattern (supports wildcards)."""
    if pattern == domain:
        return True
    
    if pattern.startswith('*.'):
        # Wildcard match
        base = pattern[2:]
        return domain.endswith(base) and domain.count('.') == pattern.count('.')
    
    return False


def format_file_size(size_bytes: int) -> str:
    """Format bytes to human readable string."""
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if size_bytes < 1024.0:
            return f"{size_bytes:.2f} {unit}"
        size_bytes /= 1024.0
    return f"{size_bytes:.2f} PB"


def parse_bool_env(value: Optional[str], default: bool = False) -> bool:
    """Parse boolean environment variable."""
    if value is None:
        return default
    return value.lower() in ('true', 'yes', '1', 'on')


def build_resource_uri(base_url: str, resource_endpoint: Optional[str] = None) -> str:
    """Build a normalized resource URI for OAuth audience validation.
    
    This function ensures consistent resource URI formatting across:
    - Token generation (audience claim)
    - Protected resource metadata endpoints
    - Audience validation during authentication
    
    Rules:
    - If resource_endpoint is None, empty, or "/", return base_url without trailing slash
    - Otherwise, append resource_endpoint to base_url
    - Always strip trailing slashes from the final result (except for paths like /mcp/)
    
    Args:
        base_url: Base URL like "http://localhost" or "https://example.com"
        resource_endpoint: Optional resource path like "/mcp" or "/"
        
    Returns:
        Normalized resource URI
        
    Examples:
        >>> build_resource_uri("http://localhost", "/")
        "http://localhost"
        >>> build_resource_uri("http://localhost", None)
        "http://localhost"
        >>> build_resource_uri("https://example.com", "/mcp")
        "https://example.com/mcp"
        >>> build_resource_uri("https://example.com/", "/api/v1")
        "https://example.com/api/v1"
    """
    # Normalize base URL (remove trailing slash)
    base = base_url.rstrip('/')
    
    # If no resource endpoint or it's the root, return base URL
    if not resource_endpoint or resource_endpoint == '/':
        return base
    
    # Build the full resource URI
    # Ensure resource_endpoint starts with / for proper joining
    if not resource_endpoint.startswith('/'):
        resource_endpoint = '/' + resource_endpoint
    
    # Combine and return (don't strip trailing slash from paths like /mcp/)
    return base + resource_endpoint