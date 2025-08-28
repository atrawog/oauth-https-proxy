"""OAuth Data Sanitization Module.

Provides secure sanitization of OAuth-related sensitive data for logging and reporting.
Ensures no secrets, tokens, or private information are exposed in logs.
"""

import re
from typing import Any, Dict, Optional, Union
import json


class OAuthSanitizer:
    """Utility class for sanitizing OAuth-related sensitive data."""
    
    # Fields that should be completely redacted
    REDACT_FIELDS = {
        'client_secret', 'github_client_secret', 'jwt_private_key', 
        'private_key', 'password', 'redis_password', 'code_verifier',
        'authorization_code', 'device_code', 'user_code'
    }
    
    # Fields that should be partially masked
    MASK_FIELDS = {
        'access_token', 'refresh_token', 'id_token', 'bearer_token',
        'token', 'jwt', 'code', 'state', 'nonce'
    }
    
    @staticmethod
    def sanitize_token(token: str, preview_length: int = 10) -> str:
        """Sanitize a token showing only first N and last 4 characters.
        
        Args:
            token: Token to sanitize
            preview_length: Number of characters to show at start
            
        Returns:
            Sanitized token string
        """
        if not token:
            return "***EMPTY***"
        
        if len(token) <= (preview_length + 8):
            # Token too short to safely show any part
            return f"***{len(token)}_chars***"
        
        return f"{token[:preview_length]}...{token[-4:]}"
    
    @staticmethod
    def sanitize_email(email: str) -> str:
        """Mask email address keeping only first char and domain.
        
        Args:
            email: Email address to sanitize
            
        Returns:
            Sanitized email (e.g., a***@example.com)
        """
        if not email or "@" not in email:
            return "***@***"
        
        parts = email.split("@")
        username = parts[0]
        domain = parts[1] if len(parts) > 1 else "***"
        
        if len(username) > 1:
            return f"{username[0]}***@{domain}"
        return f"***@{domain}"
    
    @staticmethod
    def sanitize_url(url: str) -> str:
        """Sanitize URL removing any credentials or sensitive query params.
        
        Args:
            url: URL to sanitize
            
        Returns:
            Sanitized URL
        """
        if not url:
            return "***"
        
        # Remove password from URLs like redis://:password@host:port
        url = re.sub(r'://[^@]*@', '://***@', url)
        
        # Remove sensitive query parameters
        sensitive_params = ['token', 'key', 'secret', 'password', 'code']
        for param in sensitive_params:
            url = re.sub(f'{param}=[^&]*', f'{param}=***', url, flags=re.IGNORECASE)
        
        return url
    
    @staticmethod
    def sanitize_jwt_claims(claims: Dict[str, Any]) -> Dict[str, Any]:
        """Sanitize JWT claims preserving structure but masking sensitive data.
        
        Args:
            claims: JWT claims dictionary
            
        Returns:
            Sanitized claims dictionary
        """
        if not claims:
            return {}
        
        sanitized = {}
        for key, value in claims.items():
            if key == 'email':
                sanitized[key] = OAuthSanitizer.sanitize_email(value)
            elif key == 'jti':  # JWT ID - show partial
                sanitized[key] = OAuthSanitizer.sanitize_token(str(value), preview_length=8)
            elif key in ('sub', 'username', 'preferred_username'):
                # Keep username/subject visible for debugging
                sanitized[key] = value
            elif key in ('scope', 'aud', 'azp', 'iss'):
                # Keep these visible for debugging OAuth issues
                sanitized[key] = value
            elif key in ('iat', 'exp', 'nbf', 'auth_time'):
                # Keep timestamps visible
                sanitized[key] = value
            elif key == 'orgs':
                # Keep organization list visible
                sanitized[key] = value
            elif isinstance(value, str) and len(value) > 50:
                # Long strings might be tokens or secrets
                sanitized[key] = OAuthSanitizer.sanitize_token(value)
            else:
                sanitized[key] = value
        
        return sanitized
    
    @staticmethod
    def sanitize_headers(headers: Dict[str, str]) -> Dict[str, str]:
        """Sanitize HTTP headers removing authorization and cookies.
        
        Args:
            headers: Headers dictionary
            
        Returns:
            Sanitized headers
        """
        if not headers:
            return {}
        
        sanitized = {}
        for key, value in headers.items():
            lower_key = key.lower()
            
            if lower_key == 'authorization':
                if value.startswith('Bearer '):
                    sanitized[key] = f"Bearer {OAuthSanitizer.sanitize_token(value[7:])}"
                else:
                    sanitized[key] = "***REDACTED***"
            elif lower_key == 'cookie':
                # Show cookie names but not values
                cookies = []
                for cookie in value.split(';'):
                    if '=' in cookie:
                        name = cookie.split('=')[0].strip()
                        cookies.append(f"{name}=***")
                    else:
                        cookies.append("***")
                sanitized[key] = "; ".join(cookies)
            elif lower_key in ('x-api-key', 'x-auth-token', 'api-key'):
                sanitized[key] = OAuthSanitizer.sanitize_token(value)
            else:
                sanitized[key] = value
        
        return sanitized
    
    @staticmethod
    def sanitize_dict(data: Dict[str, Any], depth: int = 0) -> Dict[str, Any]:
        """Recursively sanitize a dictionary.
        
        Args:
            data: Dictionary to sanitize
            depth: Current recursion depth (max 10)
            
        Returns:
            Sanitized dictionary
        """
        if not data or depth > 10:
            return data
        
        sanitized = {}
        for key, value in data.items():
            lower_key = key.lower()
            
            # Complete redaction
            if any(field in lower_key for field in OAuthSanitizer.REDACT_FIELDS):
                sanitized[key] = "***REDACTED***"
            # Partial masking
            elif any(field in lower_key for field in OAuthSanitizer.MASK_FIELDS):
                if isinstance(value, str):
                    sanitized[key] = OAuthSanitizer.sanitize_token(value)
                else:
                    sanitized[key] = "***REDACTED***"
            # Email sanitization
            elif 'email' in lower_key and isinstance(value, str):
                sanitized[key] = OAuthSanitizer.sanitize_email(value)
            # URL sanitization
            elif 'url' in lower_key and isinstance(value, str):
                sanitized[key] = OAuthSanitizer.sanitize_url(value)
            # Headers sanitization
            elif 'header' in lower_key and isinstance(value, dict):
                sanitized[key] = OAuthSanitizer.sanitize_headers(value)
            # JWT claims sanitization
            elif 'claims' in lower_key and isinstance(value, dict):
                sanitized[key] = OAuthSanitizer.sanitize_jwt_claims(value)
            # Recursive sanitization
            elif isinstance(value, dict):
                sanitized[key] = OAuthSanitizer.sanitize_dict(value, depth + 1)
            elif isinstance(value, list):
                sanitized[key] = [
                    OAuthSanitizer.sanitize_dict(item, depth + 1) if isinstance(item, dict)
                    else item
                    for item in value
                ]
            else:
                sanitized[key] = value
        
        return sanitized
    
    @staticmethod
    def sanitize_oauth_event(event_data: Dict[str, Any]) -> Dict[str, Any]:
        """Sanitize a complete OAuth event for logging.
        
        Args:
            event_data: OAuth event data
            
        Returns:
            Sanitized event data safe for logging
        """
        # Start with generic sanitization
        sanitized = OAuthSanitizer.sanitize_dict(event_data)
        
        # Additional OAuth-specific sanitization
        if 'jwt_claims' in sanitized:
            sanitized['jwt_claims'] = OAuthSanitizer.sanitize_jwt_claims(sanitized['jwt_claims'])
        
        if 'tokens' in sanitized:
            tokens = sanitized['tokens']
            if isinstance(tokens, dict):
                for token_type in ['access_token', 'refresh_token', 'id_token']:
                    if token_type in tokens:
                        tokens[token_type] = OAuthSanitizer.sanitize_token(tokens[token_type])
        
        return sanitized
    
    @staticmethod
    def get_safe_preview(data: Any, max_length: int = 100) -> str:
        """Get a safe preview of any data for logging.
        
        Args:
            data: Data to preview
            max_length: Maximum preview length
            
        Returns:
            Safe string preview
        """
        if data is None:
            return "null"
        
        if isinstance(data, dict):
            # Sanitize dict and convert to JSON
            sanitized = OAuthSanitizer.sanitize_dict(data)
            preview = json.dumps(sanitized, default=str)
        elif isinstance(data, (list, tuple)):
            preview = str(data)
        else:
            preview = str(data)
        
        if len(preview) > max_length:
            return f"{preview[:max_length]}..."
        
        return preview