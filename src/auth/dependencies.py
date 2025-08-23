"""FastAPI dependencies for flexible authentication.

This module provides dependency injection for authentication in FastAPI routes.
"""

import logging
from typing import Optional, Any

from fastapi import Request, HTTPException, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials

from .models import AuthResult
from .service import FlexibleAuthService

logger = logging.getLogger(__name__)

# Security scheme for optional bearer token
security = HTTPBearer(auto_error=False)


class AuthDep:
    """Flexible authentication dependency.
    
    Can be configured to require specific auth types or use
    endpoint configuration from storage.
    """
    
    def __init__(
        self,
        auth_type: Optional[str] = None,
        admin: bool = False,
        check_owner: bool = False,
        owner_param: Optional[str] = None,
        required_scopes: Optional[list] = None,
        required_audience: Optional[str] = None,
        allowed_users: Optional[list] = None
    ):
        """Initialize auth dependency.
        
        Args:
            auth_type: Override auth type (none/bearer/admin/oauth)
            admin: Shortcut for auth_type="admin"
            check_owner: Check resource ownership
            owner_param: Path parameter for resource ID
            required_scopes: Required OAuth scopes
            required_audience: Required OAuth audience
            allowed_users: Allowed OAuth users
        """
        if admin:
            auth_type = "admin"
        
        self.auth_type = auth_type
        self.check_owner = check_owner
        self.owner_param = owner_param
        self.required_scopes = required_scopes
        self.required_audience = required_audience
        self.allowed_users = allowed_users
    
    async def __call__(
        self,
        request: Request,
        credentials: Optional[HTTPAuthorizationCredentials] = Depends(security)
    ) -> AuthResult:
        """Check authentication for request.
        
        Args:
            request: FastAPI request
            credentials: Optional bearer credentials
            
        Returns:
            AuthResult with authentication status
            
        Raises:
            HTTPException: If authentication fails
        """
        # Debug logging
        import sys
        print(f"AuthDep called: has_credentials={credentials is not None}, auth_type={self.auth_type}", file=sys.stderr)
        if credentials:
            print(f"AuthDep credentials preview: {credentials.credentials[:20]}...", file=sys.stderr)
        
        # Get auth service from app state
        auth_service = None
        if hasattr(request.app.state, 'auth_service'):
            auth_service = request.app.state.auth_service
            logger.debug(f"AuthDep: Found auth_service in app.state, type={type(auth_service).__name__}")
        else:
            logger.debug("AuthDep: No auth_service in app.state, creating new one")
            # Try to create auth service from storage
            storage = None
            if hasattr(request.app.state, 'async_storage'):
                storage = request.app.state.async_storage
            elif hasattr(request.app.state, 'storage'):
                storage = request.app.state.storage
            
            oauth_components = None
            if hasattr(request.app.state, 'oauth_components'):
                oauth_components = request.app.state.oauth_components
            
            auth_service = FlexibleAuthService(
                storage=storage,
                oauth_components=oauth_components
            )
            await auth_service.initialize()
            
            # Store for future use
            request.app.state.auth_service = auth_service
        
        # Check authentication
        if self.auth_type:
            print(f"AuthDep: Using specified auth_type={self.auth_type}", file=sys.stderr)
            # Use specified auth type
            from .models import AuthConfig
            config = AuthConfig(
                auth_type=self.auth_type,
                bearer_check_owner=self.check_owner,
                oauth_scopes=self.required_scopes,
                oauth_audiences=[self.required_audience] if self.required_audience else None,
                oauth_allowed_users=self.allowed_users
            )
            
            # Extract resource ID if checking ownership
            resource_id = None
            if self.check_owner and self.owner_param:
                resource_id = request.path_params.get(self.owner_param)
            
            result = await auth_service._apply_auth_config(
                config=config,
                request=request,
                credentials=credentials,
                resource_id=resource_id
            )
        else:
            print(f"AuthDep: Using endpoint configuration for path={request.url.path}", file=sys.stderr)
            # Use endpoint configuration
            result = await auth_service.check_endpoint_auth(
                request=request,
                path=str(request.url.path),
                method=request.method,
                credentials=credentials
            )
            print(f"AuthDep: check_endpoint_auth returned authenticated={result.authenticated}, principal={result.principal}", file=sys.stderr)
        
        # Handle failed authentication
        if not result.authenticated:
            headers = {}
            if result.www_authenticate:
                headers["WWW-Authenticate"] = result.www_authenticate
            
            raise HTTPException(
                status_code=401,
                detail=result.error_description or "Authentication required",
                headers=headers
            )
        
        return result


# Backward compatibility aliases
async def require_auth(
    request: Request,
    credentials: HTTPAuthorizationCredentials = Depends(security)
) -> AuthResult:
    """Require bearer authentication (backward compatibility).
    
    Args:
        request: FastAPI request
        credentials: Bearer credentials
        
    Returns:
        AuthResult
        
    Raises:
        HTTPException: If not authenticated
    """
    dep = AuthDep(auth_type="bearer")
    return await dep(request, credentials)


async def require_admin(
    request: Request,
    credentials: HTTPAuthorizationCredentials = Depends(security)
) -> AuthResult:
    """Require admin authentication (backward compatibility).
    
    Args:
        request: FastAPI request
        credentials: Bearer credentials
        
    Returns:
        AuthResult
        
    Raises:
        HTTPException: If not admin
    """
    dep = AuthDep(auth_type="admin")
    return await dep(request, credentials)


async def require_owner(
    request: Request,
    resource_id: str,
    credentials: HTTPAuthorizationCredentials = Depends(security)
) -> AuthResult:
    """Require resource ownership (backward compatibility).
    
    Args:
        request: FastAPI request
        resource_id: ID of resource to check ownership
        credentials: Bearer credentials
        
    Returns:
        AuthResult
        
    Raises:
        HTTPException: If not owner
    """
    # This is a simplified version - real implementation would
    # need to extract resource_id from path params
    dep = AuthDep(auth_type="bearer", check_owner=True)
    result = await dep(request, credentials)
    
    # Additional ownership check would go here
    # For now, admin always owns everything
    if result.metadata.get("is_admin"):
        return result
    
    # Would check actual ownership here
    return result


async def get_optional_auth(
    request: Request,
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security)
) -> Optional[AuthResult]:
    """Get authentication if present, but don't require it.
    
    Args:
        request: FastAPI request
        credentials: Optional bearer credentials
        
    Returns:
        AuthResult if authenticated, None otherwise
    """
    if not credentials:
        return None
    
    try:
        dep = AuthDep(auth_type="bearer")
        return await dep(request, credentials)
    except HTTPException:
        return None