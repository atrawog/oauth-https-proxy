"""MCP Resource management API endpoints."""

import logging
from typing import List, Optional, Dict, Any, Tuple
from fastapi import APIRouter, HTTPException, Depends
from pydantic import BaseModel, Field, field_validator

from ...auth import get_current_token_info, require_admin

logger = logging.getLogger(__name__)


class MCPResource(BaseModel):
    """MCP Resource model."""
    uri: str = Field(..., description="Resource URI (e.g., https://mcp.example.com)")
    name: str = Field(..., description="Human-readable resource name")
    proxy_target: str = Field(..., description="Proxy hostname this resource maps to")
    scopes: List[str] = Field(default_factory=lambda: ["mcp:read", "mcp:write"])
    metadata_url: Optional[str] = Field(None, description="Protected resource metadata URL")
    description: Optional[str] = Field(None, description="Resource description")
    
    @field_validator('uri')
    @classmethod
    def validate_uri(cls, v: str) -> str:
        if not v.startswith(('http://', 'https://')):
            raise ValueError("URI must start with http:// or https://")
        return v


class TokenValidationRequest(BaseModel):
    """Token validation request."""
    token: str = Field(..., description="JWT token to validate")
    scopes: Optional[List[str]] = Field(None, description="Required scopes")


class TokenValidationResponse(BaseModel):
    """Token validation response."""
    valid: bool
    reason: Optional[str] = None
    user_id: Optional[str] = None
    scopes: Optional[List[str]] = None


def create_router(storage):
    """Create resources endpoints router."""
    router = APIRouter(tags=["mcp-resources"])
    
    @router.get("/", response_model=List[MCPResource])
    async def list_resources(
        token_info: Tuple[str, Optional[str], Optional[str]] = Depends(get_current_token_info)
    ):
        """List all registered MCP resources."""
        # Get all resources from Redis using SCAN for production safety
        resources = []
        cursor = 0
        
        while True:
            cursor, keys = storage.redis_client.scan(cursor, match="resource:*", count=100)
            for key in keys:
                resource_data = storage.redis_client.get(key)
                if resource_data:
                    try:
                        resource = json.loads(resource_data)
                        resources.append(MCPResource(**resource))
                    except Exception as e:
                        logger.error(f"Failed to parse resource {key}: {e}")
            
            if cursor == 0:
                break
        
        return resources
    
    @router.post("/", response_model=MCPResource)
    async def register_resource(
        resource: MCPResource,
        token_info: Tuple[str, Optional[str], Optional[str]] = Depends(get_current_token_info)
    ):
        """Register a new MCP resource."""
        # Check if resource already exists
        resource_key = f"resource:{resource.uri}"
        if storage.redis_client.exists(resource_key):
            raise HTTPException(409, f"Resource {resource.uri} already exists")
        
        # Add metadata URL if not provided
        if not resource.metadata_url:
            resource.metadata_url = f"{resource.uri}/.well-known/oauth-protected-resource"
        
        # Store resource
        resource_data = resource.model_dump()
        storage.redis_client.set(resource_key, json.dumps(resource_data))
        
        logger.info(f"Registered MCP resource: {resource.uri}")
        return resource
    
    @router.get("/{uri:path}", response_model=MCPResource)
    async def get_resource(
        uri: str,
        token_info: Tuple[str, Optional[str], Optional[str]] = Depends(get_current_token_info)
    ):
        """Get details of a specific MCP resource."""
        # Reconstruct full URI
        full_uri = f"https://{uri}" if not uri.startswith(('http://', 'https://')) else uri
        resource_key = f"resource:{full_uri}"
        
        resource_data = storage.redis_client.get(resource_key)
        if not resource_data:
            raise HTTPException(404, f"Resource {full_uri} not found")
        
        try:
            resource = json.loads(resource_data)
            return MCPResource(**resource)
        except Exception as e:
            logger.error(f"Failed to parse resource {full_uri}: {e}")
            raise HTTPException(500, "Failed to parse resource data")
    
    @router.put("/{uri:path}", response_model=MCPResource)
    async def update_resource(
        uri: str,
        resource: MCPResource,
        token_info: Tuple[str, Optional[str], Optional[str]] = Depends(get_current_token_info)
    ):
        """Update an existing MCP resource."""
        # Reconstruct full URI
        full_uri = f"https://{uri}" if not uri.startswith(('http://', 'https://')) else uri
        resource_key = f"resource:{full_uri}"
        
        if not storage.redis_client.exists(resource_key):
            raise HTTPException(404, f"Resource {full_uri} not found")
        
        # Ensure URI matches
        if resource.uri != full_uri:
            raise HTTPException(400, "Resource URI cannot be changed")
        
        # Update resource
        resource_data = resource.model_dump()
        storage.redis_client.set(resource_key, json.dumps(resource_data))
        
        logger.info(f"Updated MCP resource: {full_uri}")
        return resource
    
    @router.delete("/{uri:path}")
    async def delete_resource(
        uri: str,
        token_info: Tuple[str, Optional[str], Optional[str]] = Depends(get_current_token_info)
    ):
        """Delete an MCP resource."""
        # Reconstruct full URI
        full_uri = f"https://{uri}" if not uri.startswith(('http://', 'https://')) else uri
        resource_key = f"resource:{full_uri}"
        
        if not storage.redis_client.exists(resource_key):
            raise HTTPException(404, f"Resource {full_uri} not found")
        
        storage.redis_client.delete(resource_key)
        logger.info(f"Deleted MCP resource: {full_uri}")
        
        return {"status": "deleted", "uri": full_uri}
    
    @router.post("/{uri:path}/validate-token", response_model=TokenValidationResponse)
    async def validate_token_for_resource(
        uri: str,
        request: TokenValidationRequest,
        token_info: Tuple[str, Optional[str], Optional[str]] = Depends(get_current_token_info)
    ):
        """Validate a token for a specific resource."""
        # Reconstruct full URI
        full_uri = f"https://{uri}" if not uri.startswith(('http://', 'https://')) else uri
        resource_key = f"resource:{full_uri}"
        
        # Check if resource exists
        if not storage.redis_client.exists(resource_key):
            raise HTTPException(404, f"Resource {full_uri} not found")
        
        # This is a simplified validation - in production you would:
        # 1. Decode the JWT token
        # 2. Verify the signature using the OAuth server's public key
        # 3. Check the 'aud' claim contains this resource URI
        # 4. Check the token hasn't expired
        # 5. Verify the requested scopes are included in the token
        
        # For now, just return a basic response
        return TokenValidationResponse(
            valid=False,
            reason="Token validation not implemented"
        )
    
    @router.post("/auto-register")
    async def auto_register_proxy_resources(
        _: None = Depends(require_admin)
    ):
        """Auto-register MCP resources from proxy configurations."""
        # Get all proxy targets
        proxy_targets = storage.list_proxy_targets()
        registered = []
        
        for target in proxy_targets:
            # Skip if not HTTPS enabled
            if not target.enable_https:
                continue
            
            # Construct resource URI
            resource_uri = f"https://{target.hostname}"
            resource_key = f"resource:{resource_uri}"
            
            # Skip if already registered
            if storage.redis_client.exists(resource_key):
                continue
            
            # Create resource
            resource = MCPResource(
                uri=resource_uri,
                name=f"MCP Server at {target.hostname}",
                proxy_target=target.hostname,
                scopes=["mcp:read", "mcp:write"],
                metadata_url=f"{resource_uri}/.well-known/oauth-protected-resource",
                description=f"Auto-registered from proxy configuration"
            )
            
            # Store resource
            storage.redis_client.set(resource_key, json.dumps(resource.model_dump()))
            registered.append(resource_uri)
            
        return {
            "registered": registered,
            "count": len(registered)
        }
    
    return router


# Import json at the top
import json