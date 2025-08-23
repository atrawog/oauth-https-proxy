"""Unified authentication system for configurable endpoint auth.

This module provides a unified authentication interface that supports:
- No authentication (public endpoints)
- Bearer token authentication (reusing existing auth.py)
- Admin token authentication (reusing existing auth.py)
- OAuth authentication (reusing AsyncResourceProtector)

The same patterns and code are used for both API endpoints and proxy authentication.
"""

import logging
import hashlib
from typing import Optional, Tuple, Dict, Any, List
from datetime import datetime, timezone

from fastapi import Request, HTTPException, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials

from .models import UnifiedAuthContext, EndpointAuthConfig
from .pattern_matcher import PathPatternMatcher
# Auth module moved to src.auth - these functions now come from there or are reimplemented
from ..shared.client_ip import get_real_client_ip

logger = logging.getLogger(__name__)

# Helper function to get token info using the new auth system
async def get_current_token_info(request: Request, credentials: Optional[HTTPAuthorizationCredentials]) -> Tuple[Optional[str], Optional[str], Optional[str]]:
    """Get current token information using the new auth system.
    
    Returns:
        Tuple of (token_hash, principal, cert_email)
    """
    if not credentials:
        return None, None, None
    
    # Get auth service from app state
    auth_service = getattr(request.app.state, 'auth_service', None)
    if not auth_service:
        logger.warning("Auth service not found in app state")
        return None, None, None
    
    # Validate the token
    validation = await auth_service.validate_bearer_token(credentials.credentials)
    if not validation.valid:
        return None, None, None
    
    # Get cert email from token data if available
    cert_email = None
    if validation.token_data:
        cert_email = validation.token_data.get('cert_email')
    
    return validation.token_hash, validation.token_name, cert_email

# Reuse the existing security scheme
security = HTTPBearer(auto_error=False)

# Global pattern matcher instance
_pattern_matcher = PathPatternMatcher()


class UnifiedAuthHandler:
    """Unified authentication handler that supports all auth types.
    
    This class reuses existing authentication code from both the OAuth system
    and the bearer token system to provide a consistent interface for all
    authentication types.
    """
    
    def __init__(self):
        self.pattern_matcher = _pattern_matcher
        self._oauth_protector = None
        self._config_cache = {}
        self._cache_ttl = 60  # seconds
        
    async def get_oauth_protector(self, request: Request):
        """Get or create the OAuth resource protector.
        
        Reuses the existing AsyncResourceProtector from the OAuth system.
        """
        if self._oauth_protector is None:
            # Get OAuth components from app state if available
            if hasattr(request.app.state, 'oauth_components'):
                oauth_components = request.app.state.oauth_components
                if oauth_components:
                    from .oauth.async_resource_protector import AsyncResourceProtector
                    self._oauth_protector = oauth_components.get('resource_protector')
        
        return self._oauth_protector
    
    async def get_auth_config(
        self,
        request: Request,
        path: str,
        method: str
    ) -> Optional[EndpointAuthConfig]:
        """Get authentication configuration for a given path and method.
        
        Args:
            request: The FastAPI request
            path: The full request path
            method: The HTTP method
            
        Returns:
            The authentication configuration, or None if no config exists
        """
        # Check cache first
        cache_key = f"{method}:{path}"
        if cache_key in self._config_cache:
            cached_time, cached_config = self._config_cache[cache_key]
            if (datetime.now(timezone.utc) - cached_time).total_seconds() < self._cache_ttl:
                return cached_config
        
        # Get storage
        storage = None
        if hasattr(request.app.state, 'async_storage'):
            storage = request.app.state.async_storage
        elif hasattr(request.app.state, 'storage'):
            storage = request.app.state.storage
        
        if not storage:
            logger.warning("No storage available for auth config lookup")
            return None
        
        # Get all auth configurations from Redis
        try:
            # Fetch all auth configurations
            configs = await self._get_auth_configs(storage)
            
            if not configs:
                return None
            
            # Find the best match
            config_dict = self.pattern_matcher.find_best_match(configs, path, method)
            
            if config_dict:
                # Convert to EndpointAuthConfig model
                config = EndpointAuthConfig(**config_dict)
                
                # Cache the result
                self._config_cache[cache_key] = (datetime.now(timezone.utc), config)
                
                return config
            
        except Exception as e:
            logger.error(f"Error fetching auth config: {e}")
        
        return None
    
    async def _get_auth_configs(self, storage) -> List[dict]:
        """Get all auth configurations from storage.
        
        Args:
            storage: The storage instance (async or sync)
            
        Returns:
            List of auth configuration dictionaries
        """
        configs = []
        
        # Check if storage has async methods
        if hasattr(storage, 'redis_client') and hasattr(storage.redis_client, 'scan_iter'):
            # Async storage
            async for key in storage.redis_client.scan_iter(match="auth:config:pattern:*"):
                if isinstance(key, bytes):
                    key = key.decode('utf-8')
                
                config_data = await storage.redis_client.get(key)
                if config_data:
                    import json
                    try:
                        config = json.loads(config_data)
                        configs.append(config)
                    except json.JSONDecodeError:
                        logger.error(f"Invalid JSON in auth config {key}")
        else:
            # Sync storage fallback
            for key in storage.redis_client.scan_iter(match="auth:config:pattern:*"):
                if isinstance(key, bytes):
                    key = key.decode('utf-8')
                
                config_data = storage.redis_client.get(key)
                if config_data:
                    import json
                    try:
                        config = json.loads(config_data)
                        configs.append(config)
                    except json.JSONDecodeError:
                        logger.error(f"Invalid JSON in auth config {key}")
        
        return configs
    
    async def authenticate_none(
        self,
        request: Request,
        config: EndpointAuthConfig
    ) -> UnifiedAuthContext:
        """Handle no authentication (public endpoints).
        
        Args:
            request: The FastAPI request
            config: The endpoint auth configuration
            
        Returns:
            UnifiedAuthContext for unauthenticated access
        """
        return UnifiedAuthContext(
            authenticated=False,
            auth_type="none",
            request_path=request.state.full_path if hasattr(request.state, 'full_path') else str(request.url.path),
            request_method=request.method,
            matched_pattern=config.path_pattern if config else None,
            client_ip=get_real_client_ip(request),
            user_agent=request.headers.get("user-agent")
        )
    
    async def authenticate_bearer(
        self,
        request: Request,
        config: EndpointAuthConfig,
        credentials: Optional[HTTPAuthorizationCredentials]
    ) -> UnifiedAuthContext:
        """Handle bearer token authentication.
        
        Reuses the existing bearer token validation from auth.py.
        
        Args:
            request: The FastAPI request
            config: The endpoint auth configuration
            credentials: The authorization credentials
            
        Returns:
            UnifiedAuthContext for bearer token auth
        """
        if not credentials:
            raise HTTPException(
                status_code=401,
                detail="Bearer token required",
                headers={"WWW-Authenticate": "Bearer"}
            )
        
        # Reuse existing token validation from auth.py
        try:
            token_hash, principal, cert_email = await get_current_token_info(request, credentials)
        except HTTPException:
            raise
        except Exception as e:
            logger.error(f"Bearer token validation error: {e}")
            raise HTTPException(
                status_code=401,
                detail="Invalid bearer token"
            )
        
        return UnifiedAuthContext(
            authenticated=True,
            auth_type="bearer",
            token_hash=token_hash,
            principal=principal,
            is_admin=principal == "ADMIN",
            cert_email=cert_email,
            request_path=request.state.full_path if hasattr(request.state, 'full_path') else str(request.url.path),
            request_method=request.method,
            matched_pattern=config.path_pattern if config else None,
            client_ip=get_real_client_ip(request),
            user_agent=request.headers.get("user-agent")
        )
    
    async def authenticate_admin(
        self,
        request: Request,
        config: EndpointAuthConfig,
        credentials: Optional[HTTPAuthorizationCredentials]
    ) -> UnifiedAuthContext:
        """Handle admin token authentication.
        
        Reuses the existing admin token validation from auth.py.
        
        Args:
            request: The FastAPI request
            config: The endpoint auth configuration
            credentials: The authorization credentials
            
        Returns:
            UnifiedAuthContext for admin auth
        """
        # First authenticate as bearer
        auth_context = await self.authenticate_bearer(request, config, credentials)
        
        # Then verify it's an admin token
        if not auth_context.is_admin:
            raise HTTPException(
                status_code=403,
                detail="Admin access required"
            )
        
        auth_context.auth_type = "admin"
        return auth_context
    
    async def authenticate_oauth(
        self,
        request: Request,
        config: EndpointAuthConfig,
        credentials: Optional[HTTPAuthorizationCredentials]
    ) -> UnifiedAuthContext:
        """Handle OAuth authentication.
        
        Reuses the existing AsyncResourceProtector from the OAuth system.
        
        Args:
            request: The FastAPI request
            config: The endpoint auth configuration
            credentials: The authorization credentials
            
        Returns:
            UnifiedAuthContext for OAuth auth
        """
        if not credentials:
            raise HTTPException(
                status_code=401,
                detail="OAuth bearer token required",
                headers={"WWW-Authenticate": "Bearer"}
            )
        
        # Get the OAuth resource protector
        protector = await self.get_oauth_protector(request)
        if not protector:
            logger.error("OAuth protector not available")
            raise HTTPException(
                status_code=500,
                detail="OAuth authentication not configured"
            )
        
        # Determine the resource for audience validation
        resource = config.oauth_resource
        if not resource:
            # Default to constructing from request
            host = request.headers.get("host", "localhost")
            proto = request.headers.get("x-forwarded-proto", "https")
            resource = f"{proto}://{host}"
        
        # Validate the OAuth token using the existing protector
        try:
            # The protector expects the request to have the Authorization header
            token_data = await protector.validate_request(request, resource)
            
            if not token_data:
                raise HTTPException(
                    status_code=401,
                    detail="Invalid OAuth token"
                )
            
            # Check required scopes
            if config.oauth_scopes:
                token_scopes = token_data.get("scope", "").split()
                for required_scope in config.oauth_scopes:
                    if required_scope not in token_scopes:
                        raise HTTPException(
                            status_code=403,
                            detail=f"Missing required scope: {required_scope}"
                        )
            
            # Check allowed users if configured
            if config.oauth_allowed_users:
                username = token_data.get("username") or token_data.get("sub")
                if username not in config.oauth_allowed_users:
                    raise HTTPException(
                        status_code=403,
                        detail=f"User {username} is not allowed to access this endpoint"
                    )
            
            # Build the unified auth context
            return UnifiedAuthContext(
                authenticated=True,
                auth_type="oauth",
                oauth_user=token_data.get("username") or token_data.get("sub"),
                oauth_client_id=token_data.get("azp"),
                oauth_scopes=token_data.get("scope", "").split(),
                oauth_audience=token_data.get("aud", []) if isinstance(token_data.get("aud"), list) else [token_data.get("aud")] if token_data.get("aud") else [],
                oauth_token_id=token_data.get("jti"),
                request_path=request.state.full_path if hasattr(request.state, 'full_path') else str(request.url.path),
                request_method=request.method,
                matched_pattern=config.path_pattern if config else None,
                client_ip=get_real_client_ip(request),
                user_agent=request.headers.get("user-agent")
            )
            
        except HTTPException:
            raise
        except Exception as e:
            logger.error(f"OAuth validation error: {e}")
            raise HTTPException(
                status_code=401,
                detail="OAuth authentication failed"
            )
    
    async def authenticate(
        self,
        request: Request,
        credentials: Optional[HTTPAuthorizationCredentials] = None
    ) -> UnifiedAuthContext:
        """Main authentication method that determines and applies the appropriate auth.
        
        Args:
            request: The FastAPI request
            credentials: Optional authorization credentials
            
        Returns:
            UnifiedAuthContext with authentication information
        """
        # Get the full path and method
        path = request.state.full_path if hasattr(request.state, 'full_path') else str(request.url.path)
        method = request.method
        
        # Get the auth configuration for this endpoint
        config = await self.get_auth_config(request, path, method)
        
        # If no config exists, fall back to default bearer auth
        if not config:
            logger.debug(f"No auth config for {method} {path}, using default bearer auth")
            # Default to bearer auth for backwards compatibility
            return await self.authenticate_bearer(request, None, credentials)
        
        # Apply the configured authentication type
        auth_type = config.auth_type.lower()
        
        logger.info(
            f"Applying auth configuration",
            extra={
                "path": path,
                "method": method,
                "auth_type": auth_type,
                "pattern": config.path_pattern,
                "priority": config.priority
            }
        )
        
        if auth_type == "none":
            return await self.authenticate_none(request, config)
        elif auth_type == "bearer":
            return await self.authenticate_bearer(request, config, credentials)
        elif auth_type == "admin":
            return await self.authenticate_admin(request, config, credentials)
        elif auth_type == "oauth":
            return await self.authenticate_oauth(request, config, credentials)
        else:
            logger.error(f"Unknown auth type: {auth_type}")
            raise HTTPException(
                status_code=500,
                detail=f"Unknown authentication type: {auth_type}"
            )


# Global handler instance
_unified_auth_handler = UnifiedAuthHandler()


async def get_unified_auth(
    request: Request,
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security)
) -> UnifiedAuthContext:
    """FastAPI dependency for unified authentication.
    
    This dependency can be used in any endpoint to apply configurable authentication.
    It determines the appropriate auth type based on the endpoint configuration and
    reuses existing authentication code from both OAuth and bearer token systems.
    
    Usage:
        @router.get("/some/endpoint")
        async def my_endpoint(auth: UnifiedAuthContext = Depends(get_unified_auth)):
            if auth.authenticated:
                # Handle authenticated request
                pass
    
    Args:
        request: The FastAPI request (injected)
        credentials: Optional authorization credentials (injected)
        
    Returns:
        UnifiedAuthContext with authentication information
    """
    return await _unified_auth_handler.authenticate(request, credentials)


async def require_unified_auth(
    auth: UnifiedAuthContext = Depends(get_unified_auth)
) -> UnifiedAuthContext:
    """Dependency that requires authentication (any type except 'none').
    
    Args:
        auth: The unified auth context
        
    Returns:
        The auth context if authenticated
        
    Raises:
        HTTPException: If not authenticated
    """
    if not auth.authenticated:
        raise HTTPException(
            status_code=401,
            detail="Authentication required"
        )
    return auth


async def require_unified_admin(
    auth: UnifiedAuthContext = Depends(get_unified_auth)
) -> UnifiedAuthContext:
    """Dependency that requires admin authentication.
    
    Args:
        auth: The unified auth context
        
    Returns:
        The auth context if admin
        
    Raises:
        HTTPException: If not admin
    """
    if not auth.is_admin:
        raise HTTPException(
            status_code=403,
            detail="Admin access required"
        )
    return auth


def invalidate_auth_cache():
    """Invalidate the authentication configuration cache.
    
    Should be called when auth configurations are modified.
    """
    _unified_auth_handler._config_cache.clear()
    logger.info("Authentication configuration cache invalidated")