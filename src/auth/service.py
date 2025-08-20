"""Flexible authentication service.

Central service for all authentication and authorization decisions.
"""

import logging
import hashlib
import time
from typing import Optional, Dict, Any, List, Tuple
from datetime import datetime, timezone, timedelta

from fastapi import Request, HTTPException
from fastapi.security import HTTPAuthorizationCredentials

from .models import (
    AuthConfig,
    EndpointAuthConfig,
    RouteAuthConfig,
    ProxyAuthConfig,
    AuthResult,
    TokenValidation,
    OAuthValidation
)

logger = logging.getLogger(__name__)


class FlexibleAuthService:
    """Central service for all authentication decisions.
    
    Handles authentication for API endpoints, routes, and proxies
    with support for multiple auth types.
    """
    
    def __init__(self, storage=None, oauth_components=None):
        """Initialize auth service.
        
        Args:
            storage: Redis storage instance
            oauth_components: OAuth components (resource protector, etc.)
        """
        self.storage = storage
        self.oauth_components = oauth_components
        self._oauth_protector = None
        
        # Auth result cache
        self._cache: Dict[str, Tuple[AuthResult, float]] = {}
        self._cache_ttl = 60  # Default cache TTL in seconds
        
        # Pattern matcher for endpoint configs
        self._endpoint_configs: List[EndpointAuthConfig] = []
        self._configs_loaded = False
    
    async def initialize(self):
        """Initialize the auth service."""
        await self._load_endpoint_configs()
        if self.oauth_components:
            self._oauth_protector = self.oauth_components.get('resource_protector')
    
    async def check_endpoint_auth(
        self,
        request: Request,
        path: str,
        method: str,
        credentials: Optional[HTTPAuthorizationCredentials] = None
    ) -> AuthResult:
        """Check API endpoint authentication.
        
        Args:
            request: FastAPI request
            path: Request path
            method: HTTP method
            credentials: Optional auth credentials
            
        Returns:
            AuthResult with authentication status
        """
        # Check cache
        cache_key = f"endpoint:{method}:{path}:{credentials.credentials if credentials else 'none'}"
        cached_result = self._get_cached_result(cache_key)
        if cached_result:
            return cached_result
        
        # Find matching endpoint config
        config = await self._find_endpoint_config(path, method)
        
        if not config:
            # No config found, default to bearer auth for /api paths
            if path.startswith("/api/"):
                config = EndpointAuthConfig(
                    path_pattern=path,
                    auth_type="bearer"
                )
            else:
                # Public by default for non-API paths
                result = AuthResult(
                    authenticated=True,
                    auth_type="none",
                    principal="anonymous"
                )
                self._cache_result(cache_key, result, 60)
                return result
        
        # Check if config is enabled
        if hasattr(config, 'enabled') and not config.enabled:
            result = AuthResult(
                authenticated=True,
                auth_type="none",
                principal="anonymous",
                metadata={"config_disabled": True}
            )
            self._cache_result(cache_key, result, config.cache_ttl)
            return result
        
        # Apply authentication based on type
        result = await self._apply_auth_config(
            config=config,
            request=request,
            credentials=credentials,
            resource_id=self._extract_resource_id(path, config.owner_param) if config.bearer_check_owner else None
        )
        
        # Cache result
        self._cache_result(cache_key, result, config.cache_ttl)
        
        return result
    
    async def check_route_auth(
        self,
        request: Request,
        route_id: str,
        credentials: Optional[HTTPAuthorizationCredentials] = None
    ) -> AuthResult:
        """Check route-level authentication.
        
        Args:
            request: FastAPI request
            route_id: Route identifier
            credentials: Optional auth credentials
            
        Returns:
            AuthResult with authentication status
        """
        # Check cache
        cache_key = f"route:{route_id}:{credentials.credentials if credentials else 'none'}"
        cached_result = self._get_cached_result(cache_key)
        if cached_result:
            return cached_result
        
        # Get route auth config from storage
        if not self.storage:
            return AuthResult(
                authenticated=True,
                auth_type="none",
                principal="anonymous",
                metadata={"no_storage": True}
            )
        
        route_auth_data = await self.storage.get(f"route:auth:{route_id}")
        if not route_auth_data:
            # No route-specific auth
            return AuthResult(
                authenticated=True,
                auth_type="none",
                principal="anonymous"
            )
        
        # Parse route auth config
        import json
        config_dict = json.loads(route_auth_data) if isinstance(route_auth_data, str) else route_auth_data
        config = RouteAuthConfig(**config_dict)
        
        # Apply authentication
        result = await self._apply_auth_config(
            config=config,
            request=request,
            credentials=credentials
        )
        
        # Cache result
        self._cache_result(cache_key, result, config.cache_ttl)
        
        return result
    
    async def check_proxy_auth(
        self,
        request: Request,
        hostname: str,
        path: str,
        credentials: Optional[HTTPAuthorizationCredentials] = None
    ) -> AuthResult:
        """Check proxy-level authentication.
        
        Args:
            request: FastAPI request
            hostname: Proxy hostname
            path: Request path
            credentials: Optional auth credentials
            
        Returns:
            AuthResult with authentication status
        """
        # Check cache
        cache_key = f"proxy:{hostname}:{path}:{credentials.credentials if credentials else 'none'}"
        cached_result = self._get_cached_result(cache_key)
        if cached_result:
            return cached_result
        
        # Get proxy auth config from storage
        if not self.storage:
            return AuthResult(
                authenticated=True,
                auth_type="none",
                principal="anonymous",
                metadata={"no_storage": True}
            )
        
        proxy_data = await self.storage.get_proxy_target(hostname)
        if not proxy_data:
            return AuthResult(
                authenticated=False,
                error="proxy_not_found",
                error_description=f"No proxy configuration for {hostname}"
            )
        
        # Check if auth is enabled for this proxy
        if not proxy_data.auth_enabled:
            return AuthResult(
                authenticated=True,
                auth_type="none",
                principal="anonymous"
            )
        
        # Check excluded paths
        for excluded_path in proxy_data.auth_excluded_paths or []:
            if path.startswith(excluded_path):
                return AuthResult(
                    authenticated=True,
                    auth_type="none",
                    principal="anonymous",
                    metadata={"excluded_path": True}
                )
        
        # Create ProxyAuthConfig from proxy data
        config = ProxyAuthConfig(
            hostname=hostname,
            auth_type="oauth" if proxy_data.auth_proxy else "bearer",
            oauth_allowed_users=proxy_data.auth_required_users,
            oauth_allowed_emails=proxy_data.auth_required_emails,
            oauth_allowed_groups=proxy_data.auth_required_groups,
            oauth_scopes=proxy_data.auth_allowed_scopes,
            oauth_audiences=proxy_data.auth_allowed_audiences,
            excluded_paths=proxy_data.auth_excluded_paths or [],
            auth_mode=proxy_data.auth_mode or "enforce",
            redirect_url=f"https://{proxy_data.auth_proxy}/authorize" if proxy_data.auth_proxy else None,
            auth_cookie_name=proxy_data.auth_cookie_name or "unified_auth_token",
            auth_header_prefix=proxy_data.auth_header_prefix or "X-Auth-",
            pass_auth_headers=proxy_data.auth_pass_headers if hasattr(proxy_data, 'auth_pass_headers') else True
        )
        
        # Apply authentication
        result = await self._apply_auth_config(
            config=config,
            request=request,
            credentials=credentials
        )
        
        # Add proxy-specific metadata
        if result.authenticated and config.auth_mode == "redirect" and not result.authenticated:
            result.metadata["redirect_url"] = config.redirect_url
        
        # Cache result
        self._cache_result(cache_key, result, config.cache_ttl)
        
        return result
    
    async def validate_bearer_token(
        self,
        token: str,
        check_owner: bool = False,
        resource_id: Optional[str] = None
    ) -> TokenValidation:
        """Validate bearer token with optional ownership check.
        
        Args:
            token: Bearer token to validate
            check_owner: Whether to check resource ownership
            resource_id: Resource ID for ownership check
            
        Returns:
            TokenValidation result
        """
        if not self.storage:
            return TokenValidation(
                valid=False,
                error="no_storage"
            )
        
        # Check token format
        if not token.startswith("acm_"):
            return TokenValidation(
                valid=False,
                error="invalid_format"
            )
        
        # Hash token for lookup
        token_hash = f"sha256:{hashlib.sha256(token.encode()).hexdigest()}"
        
        # Check if admin token
        import os
        admin_token = os.environ.get("ADMIN_TOKEN")
        if admin_token and token == admin_token:
            return TokenValidation(
                valid=True,
                token_hash=token_hash,
                token_name="ADMIN",
                is_admin=True,
                owns_resource=True  # Admin owns everything
            )
        
        # Get token from storage
        token_data = await self.storage.get_api_token(token_hash)
        if not token_data:
            return TokenValidation(
                valid=False,
                error="token_not_found"
            )
        
        # Check ownership if requested
        owns_resource = None
        if check_owner and resource_id:
            # Check if token owns the resource
            resource_owner = await self._get_resource_owner(resource_id)
            owns_resource = resource_owner == token_hash
        
        return TokenValidation(
            valid=True,
            token_hash=token_hash,
            token_name=token_data.get("name"),
            is_admin=False,
            owns_resource=owns_resource,
            cert_email=token_data.get("cert_email"),
            created_at=token_data.get("created_at")
        )
    
    async def validate_oauth_token(
        self,
        token: str,
        required_scopes: Optional[List[str]] = None,
        required_audience: Optional[str] = None,
        allowed_users: Optional[List[str]] = None
    ) -> OAuthValidation:
        """Validate OAuth token with requirements.
        
        Args:
            token: OAuth access token
            required_scopes: Required scopes
            required_audience: Required audience
            allowed_users: Allowed usernames
            
        Returns:
            OAuthValidation result
        """
        if not self._oauth_protector:
            return OAuthValidation(
                valid=False,
                error="oauth_not_configured"
            )
        
        try:
            # Use OAuth resource protector to validate token
            from authlib.integrations.starlette_client import OAuth
            
            # Validate token with protector
            token_info = await self._oauth_protector.validate_token(
                token,
                scopes=required_scopes,
                request=None  # Not needed for basic validation
            )
            
            if not token_info:
                return OAuthValidation(
                    valid=False,
                    error="invalid_token"
                )
            
            # Check audience if required
            if required_audience:
                token_audiences = token_info.get("aud", [])
                if isinstance(token_audiences, str):
                    token_audiences = [token_audiences]
                if required_audience not in token_audiences:
                    return OAuthValidation(
                        valid=False,
                        error="invalid_audience"
                    )
            
            # Check allowed users
            username = token_info.get("username") or token_info.get("sub")
            if allowed_users and username:
                # Check if "*" is in allowed_users (allow all)
                if "*" not in allowed_users and username not in allowed_users:
                    return OAuthValidation(
                        valid=False,
                        error="user_not_allowed"
                    )
            
            return OAuthValidation(
                valid=True,
                username=username,
                user_id=token_info.get("sub"),
                email=token_info.get("email"),
                scopes=token_info.get("scope", "").split() if token_info.get("scope") else [],
                audiences=token_audiences if isinstance(token_audiences, list) else [token_audiences],
                expires_at=datetime.fromtimestamp(token_info.get("exp")) if token_info.get("exp") else None,
                client_id=token_info.get("client_id")
            )
            
        except Exception as e:
            logger.error(f"OAuth token validation error: {e}")
            return OAuthValidation(
                valid=False,
                error=str(e)
            )
    
    async def _apply_auth_config(
        self,
        config: AuthConfig,
        request: Request,
        credentials: Optional[HTTPAuthorizationCredentials],
        resource_id: Optional[str] = None
    ) -> AuthResult:
        """Apply authentication based on config.
        
        Args:
            config: Auth configuration
            request: FastAPI request  
            credentials: Optional auth credentials
            resource_id: Optional resource ID for ownership
            
        Returns:
            AuthResult
        """
        auth_type = config.auth_type
        
        # Handle "none" auth type
        if auth_type == "none":
            return AuthResult(
                authenticated=True,
                auth_type="none",
                principal="anonymous"
            )
        
        # Extract token from credentials or cookies
        token = None
        auth_method = None
        
        if credentials and credentials.credentials:
            token = credentials.credentials
            auth_method = "header"
        elif hasattr(config, 'auth_cookie_name'):
            # Check for cookie auth (for proxy configs)
            cookie_name = config.auth_cookie_name
            token = request.cookies.get(cookie_name)
            auth_method = "cookie"
        
        if not token:
            # Try fallback auth if configured
            if config.fallback_auth:
                config.auth_type = config.fallback_auth
                return await self._apply_auth_config(config, request, credentials, resource_id)
            
            return AuthResult(
                authenticated=False,
                error="no_credentials",
                error_description="No authentication credentials provided",
                www_authenticate=self._get_www_authenticate(auth_type)
            )
        
        # Handle different auth types
        if auth_type == "bearer":
            validation = await self.validate_bearer_token(
                token=token,
                check_owner=config.bearer_check_owner,
                resource_id=resource_id
            )
            
            if not validation.valid:
                return AuthResult(
                    authenticated=False,
                    error=validation.error or "invalid_token",
                    error_description="Invalid bearer token",
                    www_authenticate='Bearer realm="api"'
                )
            
            # Check ownership if required
            if config.bearer_check_owner and validation.owns_resource is False:
                return AuthResult(
                    authenticated=False,
                    error="insufficient_permissions",
                    error_description="Token does not own this resource",
                    www_authenticate='Bearer realm="api" error="insufficient_scope"'
                )
            
            # Check if admin token is allowed
            if not validation.is_admin and not config.bearer_allow_admin:
                # Additional check could go here
                pass
            
            return AuthResult(
                authenticated=True,
                auth_type="bearer",
                principal=validation.token_name,
                token_hash=validation.token_hash,
                metadata={
                    "is_admin": validation.is_admin,
                    "auth_method": auth_method
                }
            )
        
        elif auth_type == "admin":
            validation = await self.validate_bearer_token(token=token)
            
            if not validation.valid or not validation.is_admin:
                return AuthResult(
                    authenticated=False,
                    error="admin_required",
                    error_description="Admin token required",
                    www_authenticate='Bearer realm="admin"'
                )
            
            return AuthResult(
                authenticated=True,
                auth_type="admin",
                principal="ADMIN",
                token_hash=validation.token_hash,
                metadata={
                    "is_admin": True,
                    "auth_method": auth_method
                }
            )
        
        elif auth_type == "oauth":
            validation = await self.validate_oauth_token(
                token=token,
                required_scopes=config.oauth_scopes,
                required_audience=config.oauth_audiences[0] if config.oauth_audiences else None,
                allowed_users=config.oauth_allowed_users
            )
            
            if not validation.valid:
                return AuthResult(
                    authenticated=False,
                    error=validation.error or "invalid_token",
                    error_description="Invalid OAuth token",
                    www_authenticate='Bearer realm="oauth"'
                )
            
            return AuthResult(
                authenticated=True,
                auth_type="oauth",
                principal=validation.username,
                scopes=validation.scopes,
                audiences=validation.audiences,
                metadata={
                    "client_id": validation.client_id,
                    "email": validation.email,
                    "auth_method": auth_method
                }
            )
        
        else:
            return AuthResult(
                authenticated=False,
                error="unknown_auth_type",
                error_description=f"Unknown auth type: {auth_type}"
            )
    
    async def _find_endpoint_config(self, path: str, method: str) -> Optional[EndpointAuthConfig]:
        """Find matching endpoint config for path and method.
        
        Args:
            path: Request path
            method: HTTP method
            
        Returns:
            Matching EndpointAuthConfig or None
        """
        # Load configs if not loaded
        if not self._configs_loaded:
            await self._load_endpoint_configs()
        
        # Sort by priority (higher first)
        sorted_configs = sorted(self._endpoint_configs, key=lambda c: c.priority, reverse=True)
        
        for config in sorted_configs:
            # Check if path matches pattern
            if self._path_matches_pattern(path, config.path_pattern):
                # Check if method matches
                if "*" in config.methods or method in config.methods:
                    return config
        
        return None
    
    async def _load_endpoint_configs(self):
        """Load endpoint configs from storage."""
        if not self.storage:
            self._configs_loaded = True
            return
        
        try:
            configs_data = await self.storage.list_auth_configs()
            self._endpoint_configs = []
            
            for config_data in configs_data:
                try:
                    config = EndpointAuthConfig(**config_data)
                    self._endpoint_configs.append(config)
                except Exception as e:
                    logger.error(f"Invalid endpoint config: {e}")
            
            self._configs_loaded = True
            logger.info(f"Loaded {len(self._endpoint_configs)} endpoint auth configs")
            
        except Exception as e:
            logger.error(f"Error loading endpoint configs: {e}")
            self._configs_loaded = True
    
    def _path_matches_pattern(self, path: str, pattern: str) -> bool:
        """Check if path matches pattern.
        
        Args:
            path: Request path
            pattern: Pattern to match (supports * wildcard)
            
        Returns:
            True if matches
        """
        # Simple pattern matching with * wildcard
        if pattern == "*":
            return True
        
        if "*" in pattern:
            # Convert pattern to regex
            import re
            regex_pattern = pattern.replace("*", ".*")
            regex_pattern = f"^{regex_pattern}$"
            return bool(re.match(regex_pattern, path))
        
        return path == pattern
    
    def _extract_resource_id(self, path: str, owner_param: Optional[str]) -> Optional[str]:
        """Extract resource ID from path.
        
        Args:
            path: Request path
            owner_param: Parameter name to extract
            
        Returns:
            Resource ID or None
        """
        if not owner_param:
            return None
        
        # Simple extraction from path
        # e.g., /api/v1/tokens/{name} with owner_param="name"
        parts = path.strip("/").split("/")
        
        # Look for the parameter in common positions
        # This is simplified - could use more sophisticated parsing
        if len(parts) > 0:
            return parts[-1]  # Last part is often the resource ID
        
        return None
    
    async def _get_resource_owner(self, resource_id: str) -> Optional[str]:
        """Get owner of a resource.
        
        Args:
            resource_id: Resource identifier
            
        Returns:
            Owner token hash or None
        """
        if not self.storage:
            return None
        
        # Try different resource types
        # Check if it's a certificate
        cert_data = await self.storage.get_certificate(resource_id)
        if cert_data:
            return cert_data.get("owner_token_hash")
        
        # Check if it's a proxy
        proxy_data = await self.storage.get_proxy_target(resource_id)
        if proxy_data:
            return proxy_data.owner_token_hash if hasattr(proxy_data, 'owner_token_hash') else None
        
        # Check if it's a service
        service_data = await self.storage.get_docker_service(resource_id)
        if service_data:
            return service_data.get("owner_token_hash")
        
        return None
    
    def _get_www_authenticate(self, auth_type: str) -> str:
        """Get WWW-Authenticate header value.
        
        Args:
            auth_type: Authentication type
            
        Returns:
            WWW-Authenticate header value
        """
        if auth_type == "bearer":
            return 'Bearer realm="api"'
        elif auth_type == "admin":
            return 'Bearer realm="admin"'
        elif auth_type == "oauth":
            return 'Bearer realm="oauth"'
        else:
            return 'Bearer'
    
    def _get_cached_result(self, cache_key: str) -> Optional[AuthResult]:
        """Get cached auth result.
        
        Args:
            cache_key: Cache key
            
        Returns:
            Cached AuthResult or None
        """
        if cache_key in self._cache:
            result, timestamp = self._cache[cache_key]
            if time.time() - timestamp < self._cache_ttl:
                result.cached = True
                result.cache_key = cache_key
                return result
            else:
                del self._cache[cache_key]
        return None
    
    def _cache_result(self, cache_key: str, result: AuthResult, ttl: int):
        """Cache auth result.
        
        Args:
            cache_key: Cache key
            result: Auth result to cache
            ttl: Time to live in seconds
        """
        self._cache[cache_key] = (result, time.time())
        self._cache_ttl = ttl
    
    def clear_cache(self):
        """Clear the auth cache."""
        self._cache.clear()
        self._configs_loaded = False