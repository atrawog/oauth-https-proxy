"""Port management API endpoints."""

import logging
from typing import Dict, List, Optional, Tuple
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

from ...auth import require_auth, get_token_info_from_header
from ....ports import PortManager, PortAccessToken, PortAllocation

logger = logging.getLogger(__name__)


class PortCheckRequest(BaseModel):
    """Request to check if a port is available."""
    port: int = Field(..., ge=1, le=65535)
    bind_address: str = Field("127.0.0.1")


class PortCheckResponse(BaseModel):
    """Response for port availability check."""
    port: int
    available: bool
    bind_address: str
    reason: Optional[str] = None


class PortAccessTokenCreate(BaseModel):
    """Request to create a port access token."""
    token_name: str = Field(..., description="Human-readable name for the token")
    allowed_services: List[str] = Field(default_factory=list, description="List of allowed services (empty = all)")
    allowed_ports: List[int] = Field(default_factory=list, description="List of allowed ports (empty = all)")
    expires_in_hours: Optional[int] = Field(None, description="Hours until expiration")


class PortAccessTokenResponse(BaseModel):
    """Response with created token."""
    token_name: str
    token_value: str
    expires_at: Optional[str] = None


class PortRange(BaseModel):
    """Available port range."""
    start: int
    end: int
    count: int


def create_router(storage) -> APIRouter:
    """Create the ports API router."""
    router = APIRouter(tags=["ports"])
    
    # Create port manager instance
    port_manager = PortManager(storage)
    
    @router.get("/", response_model=Dict[int, Dict])
    async def list_allocated_ports(
        token_info: Dict = Depends(require_auth)
    ):
        """List all allocated ports."""
        try:
            ports = await port_manager.get_allocated_ports()
            return ports
        except Exception as e:
            logger.error(f"Error listing allocated ports: {e}")
            raise HTTPException(500, f"Error listing ports: {str(e)}")
    
    @router.get("/available", response_model=List[PortRange])
    async def list_available_port_ranges(
        token_info: Dict = Depends(require_auth)
    ):
        """Get ranges of available ports."""
        try:
            ranges = await port_manager.get_available_port_ranges()
            return [
                PortRange(start=start, end=end, count=end - start + 1)
                for start, end in ranges
                if end - start >= 10  # Only show ranges with at least 10 ports
            ]
        except Exception as e:
            logger.error(f"Error getting available port ranges: {e}")
            raise HTTPException(500, f"Error getting port ranges: {str(e)}")
    
    @router.post("/check", response_model=PortCheckResponse)
    async def check_port_availability(
        request: PortCheckRequest,
        token_info: Dict = Depends(require_auth)
    ):
        """Check if a specific port is available."""
        try:
            available = await port_manager.is_port_available(
                request.port, 
                request.bind_address
            )
            
            response = PortCheckResponse(
                port=request.port,
                available=available,
                bind_address=request.bind_address
            )
            
            if not available:
                if request.port in port_manager.RESTRICTED_PORTS:
                    response.reason = "Port is restricted by system policy"
                else:
                    response.reason = "Port is already allocated"
            
            return response
            
        except Exception as e:
            logger.error(f"Error checking port availability: {e}")
            raise HTTPException(500, f"Error checking port: {str(e)}")
    
    # Port access token endpoints
    
    @router.post("/tokens", response_model=PortAccessTokenResponse)
    async def create_port_access_token(
        request: PortAccessTokenCreate,
        token_info: Dict = Depends(get_token_info_from_header)
    ):
        """Create a new port access token."""
        # Check permissions
        is_admin = token_info.get("name") == "ADMIN"
        if not is_admin:
            raise HTTPException(403, "Admin token required to create port access tokens")
        
        try:
            from datetime import datetime, timedelta, timezone
            
            # Create token object
            token = PortAccessToken(
                token_hash="",  # Will be set by manager
                token_name=request.token_name,
                allowed_services=request.allowed_services,
                allowed_ports=request.allowed_ports,
                created_by=token_info.get("name", "unknown")
            )
            
            # Set expiration if requested
            if request.expires_in_hours:
                token.expires_at = datetime.now(timezone.utc) + timedelta(hours=request.expires_in_hours)
            
            # Create token and get the value
            token_value = await port_manager.create_port_access_token(token)
            
            return PortAccessTokenResponse(
                token_name=request.token_name,
                token_value=token_value,
                expires_at=token.expires_at.isoformat() if token.expires_at else None
            )
            
        except Exception as e:
            logger.error(f"Error creating port access token: {e}")
            raise HTTPException(500, f"Error creating token: {str(e)}")
    
    @router.get("/tokens", response_model=List[PortAccessToken])
    async def list_port_access_tokens(
        token_info: Dict = Depends(get_token_info_from_header)
    ):
        """List all port access tokens."""
        # Check permissions
        is_admin = token_info.get("name") == "ADMIN"
        if not is_admin:
            raise HTTPException(403, "Admin token required to list port access tokens")
        
        try:
            tokens = await port_manager.list_port_access_tokens()
            # Don't expose the hash
            for token in tokens:
                token.token_hash = "***"
            return tokens
        except Exception as e:
            logger.error(f"Error listing port access tokens: {e}")
            raise HTTPException(500, f"Error listing tokens: {str(e)}")
    
    @router.delete("/tokens/{token_name}")
    async def revoke_port_access_token(
        token_name: str,
        token_info: Dict = Depends(get_token_info_from_header)
    ):
        """Revoke a port access token."""
        # Check permissions
        is_admin = token_info.get("name") == "ADMIN"
        if not is_admin:
            raise HTTPException(403, "Admin token required to revoke port access tokens")
        
        try:
            success = await port_manager.revoke_port_access_token(token_name)
            if success:
                return {"message": f"Token {token_name} revoked"}
            else:
                raise HTTPException(404, f"Token {token_name} not found")
        except Exception as e:
            logger.error(f"Error revoking port access token: {e}")
            raise HTTPException(500, f"Error revoking token: {str(e)}")
    
    @router.post("/tokens/validate")
    async def validate_port_access(
        port: int = Query(..., ge=1, le=65535),
        token: Optional[str] = Query(None, description="Port access token"),
        token_info: Dict = Depends(require_auth)
    ):
        """Validate if a token can access a specific port."""
        try:
            valid = await port_manager.validate_port_access(port, token)
            return {
                "port": port,
                "valid": valid,
                "token_provided": token is not None
            }
        except Exception as e:
            logger.error(f"Error validating port access: {e}")
            raise HTTPException(500, f"Error validating access: {str(e)}")
    
    return router