"""Authentication and scope validation utilities for API endpoints.

This module provides centralized scope validation for the trust-based OAuth system.
The proxy validates OAuth tokens and passes headers that the API trusts completely.
"""

from typing import List, Optional
from fastapi import HTTPException, Request


def check_auth_and_scopes(
    request: Request,
    required_scopes: Optional[List[str]] = None,
    allow_any: bool = False
) -> tuple[str, List[str], bool]:
    """Check authentication headers and validate required scopes.
    
    Args:
        request: FastAPI request object
        required_scopes: List of required scopes (e.g., ["admin"], ["user"], ["mcp"])
                        If None, any authenticated user is allowed
        allow_any: If True, any of the required_scopes is sufficient
                  If False, all required_scopes must be present
    
    Returns:
        Tuple of (auth_user, auth_scopes, is_admin)
        
    Raises:
        HTTPException: 401 if not authenticated
        HTTPException: 403 if authenticated but missing required scopes
    """
    # Get auth headers set by proxy
    auth_user = request.headers.get("X-Auth-User")
    auth_scopes_str = request.headers.get("X-Auth-Scopes", "")
    auth_email = request.headers.get("X-Auth-Email", "")
    
    # Check authentication
    if not auth_user:
        raise HTTPException(
            status_code=401,
            detail="Authentication required",
            headers={"WWW-Authenticate": "Bearer"}
        )
    
    # Parse scopes
    auth_scopes = auth_scopes_str.split() if auth_scopes_str else []
    is_admin = "admin" in auth_scopes
    
    # Admin scope includes all other scopes (hierarchical)
    if is_admin:
        # Admin has implicit access to all scopes
        if "user" not in auth_scopes:
            auth_scopes.append("user")
        if "mcp" not in auth_scopes:
            auth_scopes.append("mcp")
    
    # Check required scopes if specified
    if required_scopes:
        if allow_any:
            # At least one required scope must be present
            if not any(scope in auth_scopes for scope in required_scopes):
                raise HTTPException(
                    status_code=403,
                    detail=f"Insufficient permissions. Required scope(s): {' OR '.join(required_scopes)}, your scopes: {' '.join(auth_scopes)}"
                )
        else:
            # All required scopes must be present
            missing_scopes = [s for s in required_scopes if s not in auth_scopes]
            if missing_scopes:
                raise HTTPException(
                    status_code=403,
                    detail=f"Insufficient permissions. Missing scope(s): {' '.join(missing_scopes)}, your scopes: {' '.join(auth_scopes)}"
                )
    
    return auth_user, auth_scopes, is_admin


def require_admin(request: Request) -> tuple[str, List[str]]:
    """Require admin scope for the request.
    
    Args:
        request: FastAPI request object
        
    Returns:
        Tuple of (auth_user, auth_scopes)
        
    Raises:
        HTTPException: 401 if not authenticated
        HTTPException: 403 if not admin
    """
    auth_user, auth_scopes, is_admin = check_auth_and_scopes(request, required_scopes=["admin"])
    return auth_user, auth_scopes


def require_user(request: Request) -> tuple[str, List[str]]:
    """Require user scope (read access) for the request.
    
    Args:
        request: FastAPI request object
        
    Returns:
        Tuple of (auth_user, auth_scopes)
        
    Raises:
        HTTPException: 401 if not authenticated
        HTTPException: 403 if not user or admin
    """
    auth_user, auth_scopes, _ = check_auth_and_scopes(request, required_scopes=["user"], allow_any=True)
    return auth_user, auth_scopes


def require_mcp(request: Request) -> tuple[str, List[str]]:
    """Require MCP scope for the request.
    
    Args:
        request: FastAPI request object
        
    Returns:
        Tuple of (auth_user, auth_scopes)
        
    Raises:
        HTTPException: 401 if not authenticated
        HTTPException: 403 if not mcp or admin
    """
    auth_user, auth_scopes, _ = check_auth_and_scopes(request, required_scopes=["mcp"], allow_any=True)
    return auth_user, auth_scopes


def get_auth_info(request: Request) -> tuple[str, List[str], bool]:
    """Get authentication info without requiring specific scopes.
    
    Args:
        request: FastAPI request object
        
    Returns:
        Tuple of (auth_user, auth_scopes, is_admin)
        
    Raises:
        HTTPException: 401 if not authenticated
    """
    return check_auth_and_scopes(request, required_scopes=None)