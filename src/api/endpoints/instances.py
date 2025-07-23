"""Instance registry endpoints for named instance management."""

import json
import logging
from typing import Dict, List, Optional
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Response
from pydantic import BaseModel, Field, validator

from ..auth import require_auth, get_token_info_from_header

logger = logging.getLogger(__name__)


class InstanceCreateRequest(BaseModel):
    """Request model for creating a named instance."""
    name: str = Field(..., description="Instance name (e.g., 'oauth-server', 'api')")
    target_url: str = Field(..., description="Target URL (e.g., 'http://service:8000')")
    description: str = Field("", description="Instance description")
    
    @validator('name')
    def validate_name(cls, v):
        """Validate instance name."""
        if not v or not v.strip():
            raise ValueError("Instance name cannot be empty")
        # Only allow alphanumeric, dash, and underscore
        import re
        if not re.match(r'^[a-zA-Z0-9_-]+$', v):
            raise ValueError("Instance name can only contain letters, numbers, dash, and underscore")
        return v.lower()
    
    @validator('target_url')
    def validate_target_url(cls, v):
        """Validate target URL."""
        from urllib.parse import urlparse
        
        # If it doesn't start with http:// or https://, prepend http://
        if not v.startswith(('http://', 'https://')):
            v = f"http://{v}"
        
        # Validate the URL
        try:
            result = urlparse(v)
            # Check if scheme and netloc are present
            if not all([result.scheme, result.netloc]):
                raise ValueError("Invalid URL format")
            # Check for spaces in the URL
            if ' ' in v:
                raise ValueError("URL cannot contain spaces")
        except Exception:
            raise ValueError("Invalid URL format")
        
        return v


class InstanceInfo(BaseModel):
    """Instance information model."""
    name: str
    target_url: str
    description: str
    created_at: datetime
    created_by: Optional[str]


def create_router(storage) -> APIRouter:
    """Create the instances API router."""
    router = APIRouter(prefix="/instances", tags=["instances"])
    
    @router.post("/", response_model=InstanceInfo)
    async def create_instance(
        request: InstanceCreateRequest,
        token_info: Dict = Depends(get_token_info_from_header)
    ):
        """Register a new named instance for routing."""
        try:
            # Check if instance already exists
            existing = storage.redis_client.get(f"instance_url:{request.name}")
            if existing:
                raise HTTPException(409, f"Instance '{request.name}' already exists")
            
            # Create instance info
            instance_info = {
                "name": request.name,
                "target_url": request.target_url,
                "description": request.description,
                "created_at": datetime.now(timezone.utc).isoformat(),
                "created_by": token_info.get("name", "unknown")
            }
            
            # Store in Redis
            storage.redis_client.set(f"instance_url:{request.name}", request.target_url)
            storage.redis_client.set(f"instance_info:{request.name}", json.dumps(instance_info))
            
            logger.info(f"Registered instance '{request.name}' -> {request.target_url}")
            
            return InstanceInfo(**instance_info)
            
        except HTTPException:
            raise
        except Exception as e:
            logger.error(f"Failed to create instance: {e}")
            raise HTTPException(500, f"Failed to create instance: {str(e)}")
    
    @router.get("/", response_model=List[InstanceInfo])
    async def list_instances():
        """List all registered instances."""
        try:
            instances = []
            
            # Get all instance URLs
            for key in storage.redis_client.scan_iter(match="instance_url:*"):
                name = key.split(":")[-1]
                target_url = storage.redis_client.get(key)
                
                # Try to get additional info
                info_key = f"instance_info:{name}"
                info_data = storage.redis_client.get(info_key)
                
                if info_data:
                    try:
                        info = json.loads(info_data)
                        instances.append(InstanceInfo(**info))
                    except Exception:
                        # Fallback if info is corrupted
                        instances.append(InstanceInfo(
                            name=name,
                            target_url=target_url,
                            description="",
                            created_at=datetime.now(timezone.utc),
                            created_by=None
                        ))
                else:
                    # No info stored, create basic entry
                    instances.append(InstanceInfo(
                        name=name,
                        target_url=target_url,
                        description="",
                        created_at=datetime.now(timezone.utc),
                        created_by=None
                    ))
            
            # Sort by name
            instances.sort(key=lambda x: x.name)
            return instances
            
        except Exception as e:
            logger.error(f"Failed to list instances: {e}")
            raise HTTPException(500, f"Failed to list instances: {str(e)}")
    
    @router.get("/{name}", response_model=InstanceInfo)
    async def get_instance(name: str):
        """Get details of a specific instance."""
        try:
            # Get instance URL
            target_url = storage.redis_client.get(f"instance_url:{name}")
            if not target_url:
                raise HTTPException(404, f"Instance '{name}' not found")
            
            # Try to get additional info
            info_data = storage.redis_client.get(f"instance_info:{name}")
            if info_data:
                try:
                    info = json.loads(info_data)
                    return InstanceInfo(**info)
                except Exception:
                    pass
            
            # Return basic info
            return InstanceInfo(
                name=name,
                target_url=target_url,
                description="",
                created_at=datetime.now(timezone.utc),
                created_by=None
            )
            
        except HTTPException:
            raise
        except Exception as e:
            logger.error(f"Failed to get instance: {e}")
            raise HTTPException(500, f"Failed to get instance: {str(e)}")
    
    @router.delete("/{name}", status_code=204)
    async def delete_instance(
        name: str,
        token_info: Dict = Depends(get_token_info_from_header)
    ):
        """Delete a named instance."""
        try:
            # Check if instance exists
            if not storage.redis_client.exists(f"instance_url:{name}"):
                raise HTTPException(404, f"Instance '{name}' not found")
            
            # Check if any routes reference this instance
            routes_using_instance = []
            for key in storage.redis_client.scan_iter(match="route:*"):
                # Skip index keys
                if key.startswith("route:priority:") or key.startswith("route:unique:"):
                    continue
                route_data = storage.redis_client.get(key)
                if route_data and f'"target_value": "{name}"' in route_data:
                    routes_using_instance.append(key.split(":")[-1])
            
            if routes_using_instance:
                raise HTTPException(
                    400, 
                    f"Cannot delete instance '{name}' - used by routes: {', '.join(routes_using_instance[:5])}"
                )
            
            # Delete instance
            storage.redis_client.delete(f"instance_url:{name}")
            storage.redis_client.delete(f"instance_info:{name}")
            storage.redis_client.delete(f"instance:{name}")  # Legacy port-based entry
            
            logger.info(f"Deleted instance '{name}'")
            return Response(status_code=204)
            
        except HTTPException:
            raise
        except Exception as e:
            logger.error(f"Failed to delete instance: {e}")
            raise HTTPException(500, f"Failed to delete instance: {str(e)}")
    
    @router.put("/{name}", response_model=InstanceInfo)
    async def update_instance(
        name: str,
        request: InstanceCreateRequest,
        token_info: Dict = Depends(get_token_info_from_header)
    ):
        """Update an existing instance."""
        try:
            # Check if instance exists
            if not storage.redis_client.exists(f"instance_url:{name}"):
                raise HTTPException(404, f"Instance '{name}' not found")
            
            # If renaming, check new name doesn't exist
            if request.name != name and storage.redis_client.exists(f"instance_url:{request.name}"):
                raise HTTPException(400, f"Instance '{request.name}' already exists")
            
            # Get existing info
            info_data = storage.redis_client.get(f"instance_info:{name}")
            if info_data:
                try:
                    existing_info = json.loads(info_data)
                except Exception:
                    existing_info = {}
            else:
                existing_info = {}
            
            # Update instance info
            instance_info = {
                "name": request.name,
                "target_url": request.target_url,
                "description": request.description,
                "created_at": existing_info.get("created_at", datetime.now(timezone.utc).isoformat()),
                "created_by": existing_info.get("created_by", token_info.get("name", "unknown")),
                "updated_at": datetime.now(timezone.utc).isoformat(),
                "updated_by": token_info.get("name", "unknown")
            }
            
            # If renaming, delete old entries
            if request.name != name:
                storage.redis_client.delete(f"instance_url:{name}")
                storage.redis_client.delete(f"instance_info:{name}")
                storage.redis_client.delete(f"instance:{name}")
            
            # Store updated info
            storage.redis_client.set(f"instance_url:{request.name}", request.target_url)
            storage.redis_client.set(f"instance_info:{request.name}", json.dumps(instance_info))
            
            logger.info(f"Updated instance '{name}' -> '{request.name}': {request.target_url}")
            
            return InstanceInfo(**instance_info)
            
        except HTTPException:
            raise
        except Exception as e:
            logger.error(f"Failed to update instance: {e}")
            raise HTTPException(500, f"Failed to update instance: {str(e)}")
    
    return router