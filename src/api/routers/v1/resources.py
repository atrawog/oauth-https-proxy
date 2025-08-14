"""Protected Resource management API endpoints."""

import logging
from typing import List, Optional, Dict, Any, Tuple
from fastapi import APIRouter, HTTPException, Depends
from pydantic import BaseModel, Field, field_validator
from authlib.jose import JsonWebToken
from authlib.jose.errors import JoseError
import redis

from src.api.auth import get_current_token_info, require_admin
from src.api.oauth.config import Settings as OAuthSettings
from src.api.oauth.keys import RSAKeyManager

logger = logging.getLogger(__name__)


class ProtectedResource(BaseModel):
    """Protected Resource model."""
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
    router = APIRouter(tags=["resources"])
    
    @router.get("/", response_model=List[ProtectedResource])
    async def list_resources(
        token_info: Tuple[str, Optional[str], Optional[str]] = Depends(get_current_token_info)
    ):
        """List all registered Protected Resources."""
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
                        resources.append(ProtectedResource(**resource))
                    except Exception as e:
                        logger.error(f"Failed to parse resource {key}: {e}")
            
            if cursor == 0:
                break
        
        return resources
    
    @router.post("/", response_model=ProtectedResource)
    async def register_resource(
        resource: ProtectedResource,
        token_info: Tuple[str, Optional[str], Optional[str]] = Depends(get_current_token_info)
    ):
        """Register a new Protected Resource."""
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
        
        logger.info(f"Registered Protected Resource: {resource.uri}")
        return resource
    
    @router.get("/{uri:path}", response_model=ProtectedResource)
    async def get_resource(
        uri: str,
        token_info: Tuple[str, Optional[str], Optional[str]] = Depends(get_current_token_info)
    ):
        """Get details of a specific Protected Resource."""
        # Reconstruct full URI
        full_uri = f"https://{uri}" if not uri.startswith(('http://', 'https://')) else uri
        resource_key = f"resource:{full_uri}"
        
        resource_data = storage.redis_client.get(resource_key)
        if not resource_data:
            raise HTTPException(404, f"Resource {full_uri} not found")
        
        try:
            resource = json.loads(resource_data)
            return ProtectedResource(**resource)
        except Exception as e:
            logger.error(f"Failed to parse resource {full_uri}: {e}")
            raise HTTPException(500, "Failed to parse resource data")
    
    @router.put("/{uri:path}", response_model=ProtectedResource)
    async def update_resource(
        uri: str,
        resource: ProtectedResource,
        token_info: Tuple[str, Optional[str], Optional[str]] = Depends(get_current_token_info)
    ):
        """Update an existing Protected Resource."""
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
        
        logger.info(f"Updated Protected Resource: {full_uri}")
        return resource
    
    @router.delete("/{uri:path}")
    async def delete_resource(
        uri: str,
        token_info: Tuple[str, Optional[str], Optional[str]] = Depends(get_current_token_info)
    ):
        """Delete a Protected Resource."""
        # Reconstruct full URI
        full_uri = f"https://{uri}" if not uri.startswith(('http://', 'https://')) else uri
        resource_key = f"resource:{full_uri}"
        
        if not storage.redis_client.exists(resource_key):
            raise HTTPException(404, f"Resource {full_uri} not found")
        
        storage.redis_client.delete(resource_key)
        logger.info(f"Deleted Protected Resource: {full_uri}")
        
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
        
        # Initialize OAuth components for validation
        oauth_settings = OAuthSettings()
        key_manager = RSAKeyManager()
        try:
            key_manager.load_or_generate_keys()
        except Exception as e:
            logger.error(f"Failed to load RSA keys for token validation: {e}")
            return TokenValidationResponse(
                valid=False,
                reason="Internal error: Unable to load validation keys"
            )
        
        # Initialize JWT decoder
        jwt = JsonWebToken(algorithms=[oauth_settings.jwt_algorithm])
        
        try:
            # Decode and validate token
            claims = None
            if oauth_settings.jwt_algorithm == "RS256":
                # Use RSA public key for RS256 verification
                claims = jwt.decode(
                    request.token,
                    key_manager.public_key,
                    claims_options={
                        "iss": {"essential": True},
                        "exp": {"essential": True},
                        "jti": {"essential": True},
                    },
                )
            else:
                # HS256 fallback
                claims = jwt.decode(
                    request.token,
                    oauth_settings.jwt_secret,
                    claims_options={
                        "iss": {"essential": True},
                        "exp": {"essential": True},
                        "jti": {"essential": True},
                    },
                )
            
            # Validate issuer
            issuer = claims.get("iss", "")
            valid_issuer = (
                issuer.endswith(f".{oauth_settings.base_domain}") or
                issuer == f"https://auth.{oauth_settings.base_domain}" or
                issuer == f"http://auth.{oauth_settings.base_domain}" or
                (issuer.startswith("https://") and oauth_settings.base_domain in issuer) or
                (issuer.startswith("http://") and oauth_settings.base_domain in issuer)
            )
            
            if not valid_issuer:
                logger.warning(f"Token has invalid issuer: {issuer}")
                return TokenValidationResponse(
                    valid=False,
                    reason=f"Invalid token issuer"
                )
            
            # Validate claims (including expiry)
            claims.validate()
            
            # Check if token exists in Redis (not revoked)
            jti = claims["jti"]
            token_key = f"oauth:token:{jti}"
            if not storage.redis_client.exists(token_key):
                logger.warning(f"Token {jti} has been revoked or doesn't exist")
                return TokenValidationResponse(
                    valid=False,
                    reason="Token has been revoked"
                )
            
            # Check audience claim contains this resource URI
            audience = claims.get("aud", [])
            if isinstance(audience, str):
                audience = [audience]
            
            if full_uri not in audience:
                logger.warning(f"Token audience {audience} doesn't include resource {full_uri}")
                return TokenValidationResponse(
                    valid=False,
                    reason="Token not authorized for this resource"
                )
            
            # Check requested scopes are included in token
            token_scopes = claims.get("scope", "").split()
            if request.scopes:
                missing_scopes = [s for s in request.scopes if s not in token_scopes]
                if missing_scopes:
                    logger.warning(f"Token missing required scopes: {missing_scopes}")
                    return TokenValidationResponse(
                        valid=False,
                        reason=f"Missing required scopes: {', '.join(missing_scopes)}"
                    )
            
            # Token is valid
            logger.info(f"Token {jti} validated successfully for resource {full_uri}")
            return TokenValidationResponse(
                valid=True,
                user_id=claims.get("sub"),
                scopes=token_scopes
            )
            
        except JoseError as e:
            logger.error(f"JWT validation failed: {e}")
            return TokenValidationResponse(
                valid=False,
                reason="Invalid token format or signature"
            )
        except Exception as e:
            logger.error(f"Unexpected error during token validation: {e}")
            return TokenValidationResponse(
                valid=False,
                reason="Internal validation error"
            )
    
    @router.post("/auto-register")
    async def auto_register_proxy_resources(
        _: None = Depends(require_admin)
    ):
        """Auto-register Protected Resources from proxy configurations."""
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
            resource = ProtectedResource(
                uri=resource_uri,
                name=f"Protected Resource at {target.hostname}",
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