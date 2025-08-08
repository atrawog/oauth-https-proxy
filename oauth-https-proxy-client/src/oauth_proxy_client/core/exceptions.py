"""Exception classes for OAuth HTTPS Proxy Client."""

from typing import Optional, Dict, Any


class ProxyClientError(Exception):
    """Base exception for all proxy client errors."""
    
    def __init__(self, message: str, details: Optional[Dict[str, Any]] = None):
        """Initialize exception with message and optional details.
        
        Args:
            message: Error message
            details: Optional dictionary with additional error details
        """
        super().__init__(message)
        self.message = message
        self.details = details or {}


class ConfigurationError(ProxyClientError):
    """Raised when configuration is invalid or missing."""
    pass


class AuthenticationError(ProxyClientError):
    """Raised when authentication fails."""
    
    def __init__(self, message: str = "Authentication failed", details: Optional[Dict[str, Any]] = None):
        """Initialize authentication error.
        
        Args:
            message: Error message
            details: Optional details about the authentication failure
        """
        super().__init__(message, details)


class APIError(ProxyClientError):
    """Raised when API request fails."""
    
    def __init__(
        self, 
        message: str, 
        status_code: Optional[int] = None,
        response_text: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None
    ):
        """Initialize API error with HTTP details.
        
        Args:
            message: Error message
            status_code: HTTP status code if available
            response_text: Response body text if available
            details: Additional error details
        """
        super().__init__(message, details)
        self.status_code = status_code
        self.response_text = response_text
        
        # Add status code and response to details
        if status_code:
            self.details['status_code'] = status_code
        if response_text:
            self.details['response'] = response_text


class ResourceNotFoundError(APIError):
    """Raised when a requested resource is not found."""
    
    def __init__(self, resource_type: str, resource_id: str):
        """Initialize resource not found error.
        
        Args:
            resource_type: Type of resource (e.g., 'token', 'proxy', 'certificate')
            resource_id: Identifier of the missing resource
        """
        message = f"{resource_type.capitalize()} not found: {resource_id}"
        super().__init__(message, status_code=404)
        self.resource_type = resource_type
        self.resource_id = resource_id


class ValidationError(ProxyClientError):
    """Raised when input validation fails."""
    
    def __init__(self, field: str, message: str, value: Any = None):
        """Initialize validation error.
        
        Args:
            field: Field name that failed validation
            message: Validation error message
            value: The invalid value (optional)
        """
        full_message = f"Validation error for {field}: {message}"
        details = {'field': field, 'error': message}
        if value is not None:
            details['value'] = value
        super().__init__(full_message, details)


class TimeoutError(ProxyClientError):
    """Raised when a request times out."""
    
    def __init__(self, operation: str, timeout: float):
        """Initialize timeout error.
        
        Args:
            operation: Operation that timed out
            timeout: Timeout value in seconds
        """
        message = f"Operation '{operation}' timed out after {timeout} seconds"
        super().__init__(message, {'operation': operation, 'timeout': timeout})


class ConnectionError(ProxyClientError):
    """Raised when connection to the server fails."""
    
    def __init__(self, url: str, reason: Optional[str] = None):
        """Initialize connection error.
        
        Args:
            url: URL that failed to connect
            reason: Optional reason for connection failure
        """
        message = f"Failed to connect to {url}"
        if reason:
            message += f": {reason}"
        super().__init__(message, {'url': url, 'reason': reason})


class RateLimitError(APIError):
    """Raised when rate limit is exceeded."""
    
    def __init__(self, retry_after: Optional[int] = None):
        """Initialize rate limit error.
        
        Args:
            retry_after: Seconds to wait before retrying (if provided by server)
        """
        message = "Rate limit exceeded"
        if retry_after:
            message += f". Retry after {retry_after} seconds"
        super().__init__(message, status_code=429, details={'retry_after': retry_after})


class CertificateError(ProxyClientError):
    """Raised when certificate operations fail."""
    
    def __init__(self, message: str, domain: Optional[str] = None, cert_name: Optional[str] = None):
        """Initialize certificate error.
        
        Args:
            message: Error message
            domain: Domain involved in the error
            cert_name: Certificate name if applicable
        """
        details = {}
        if domain:
            details['domain'] = domain
        if cert_name:
            details['cert_name'] = cert_name
        super().__init__(message, details)


class OAuthError(ProxyClientError):
    """Raised when OAuth operations fail."""
    
    def __init__(self, message: str, error_code: Optional[str] = None, error_description: Optional[str] = None):
        """Initialize OAuth error.
        
        Args:
            message: Error message
            error_code: OAuth error code (e.g., 'invalid_client')
            error_description: Detailed error description from OAuth server
        """
        details = {}
        if error_code:
            details['error'] = error_code
        if error_description:
            details['error_description'] = error_description
        super().__init__(message, details)