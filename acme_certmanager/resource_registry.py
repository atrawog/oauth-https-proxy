"""Optional Protected Resource Registry for tracking protected resources and their metadata.

NOTE: This is NOT required by the MCP specification. It's an administrative
feature for managing and tracking protected resources. The MCP spec only requires:
- OAuth servers to handle the 'resource' parameter
- MCP servers to implement /.well-known/oauth-protected-resource
"""

import json
from typing import Optional, List, Dict, Any
from datetime import datetime
import redis
import logging

logger = logging.getLogger(__name__)


class ProtectedResourceRegistry:
    """Optional registry for protected resources.
    
    This is an administrative feature, NOT required by RFC 8707 or RFC 9728.
    It provides convenient management of MCP resources but is not necessary
    for MCP specification compliance.
    """
    
    def __init__(self, redis_client: redis.Redis):
        self.redis = redis_client
        self.key_prefix = "resource:"
        self.index_key = "resource:index"
    
    async def register_resource(
        self,
        resource_uri: str,
        proxy_hostname: str,
        name: str,
        scopes: Optional[List[str]] = None,
        metadata: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """Register a protected resource with its metadata.
        
        Args:
            resource_uri: The resource URI (e.g., https://mcp.example.com)
            proxy_hostname: The proxy hostname serving this resource
            name: Human-readable name for the resource
            scopes: List of supported scopes (defaults to mcp:read, mcp:write)
            metadata: Additional metadata about the resource
            
        Returns:
            The registered resource object
        """
        if scopes is None:
            scopes = ["mcp:read", "mcp:write", "mcp:session"]
        
        resource_data = {
            "uri": resource_uri,
            "proxy_hostname": proxy_hostname,
            "name": name,
            "scopes": scopes,
            "metadata_url": f"{resource_uri}/.well-known/oauth-protected-resource",
            "registered_at": datetime.utcnow().isoformat(),
            "metadata": metadata or {}
        }
        
        # Store resource data
        key = f"{self.key_prefix}{resource_uri}"
        await self.redis.set(key, json.dumps(resource_data))
        
        # Add to index for listing
        await self.redis.sadd(self.index_key, resource_uri)
        
        logger.info(f"Registered protected resource: {resource_uri}")
        return resource_data
    
    async def get_resource(self, resource_uri: str) -> Optional[Dict[str, Any]]:
        """Get a registered resource by URI.
        
        Args:
            resource_uri: The resource URI
            
        Returns:
            The resource object or None if not found
        """
        key = f"{self.key_prefix}{resource_uri}"
        data = await self.redis.get(key)
        
        if data:
            return json.loads(data)
        return None
    
    async def list_resources(self) -> List[Dict[str, Any]]:
        """List all registered resources.
        
        Returns:
            List of resource objects
        """
        # Get all resource URIs from index
        resource_uris = await self.redis.smembers(self.index_key)
        
        resources = []
        for uri in resource_uris:
            resource = await self.get_resource(uri)
            if resource:
                resources.append(resource)
        
        return sorted(resources, key=lambda r: r.get("registered_at", ""))
    
    async def update_resource(
        self,
        resource_uri: str,
        updates: Dict[str, Any]
    ) -> Optional[Dict[str, Any]]:
        """Update a registered resource.
        
        Args:
            resource_uri: The resource URI
            updates: Fields to update
            
        Returns:
            The updated resource object or None if not found
        """
        resource = await self.get_resource(resource_uri)
        if not resource:
            return None
        
        # Update fields
        resource.update(updates)
        resource["updated_at"] = datetime.utcnow().isoformat()
        
        # Save back to Redis
        key = f"{self.key_prefix}{resource_uri}"
        await self.redis.set(key, json.dumps(resource))
        
        logger.info(f"Updated protected resource: {resource_uri}")
        return resource
    
    async def delete_resource(self, resource_uri: str) -> bool:
        """Delete a registered resource.
        
        Args:
            resource_uri: The resource URI
            
        Returns:
            True if deleted, False if not found
        """
        key = f"{self.key_prefix}{resource_uri}"
        
        # Check if exists
        if not await self.redis.exists(key):
            return False
        
        # Delete from storage and index
        await self.redis.delete(key)
        await self.redis.srem(self.index_key, resource_uri)
        
        logger.info(f"Deleted protected resource: {resource_uri}")
        return True
    
    async def find_resources_by_proxy(self, proxy_hostname: str) -> List[Dict[str, Any]]:
        """Find all resources served by a specific proxy.
        
        Args:
            proxy_hostname: The proxy hostname
            
        Returns:
            List of resource objects
        """
        all_resources = await self.list_resources()
        return [r for r in all_resources if r.get("proxy_hostname") == proxy_hostname]
    
    async def validate_token_for_resource(
        self,
        resource_uri: str,
        token_audience: List[str],
        required_scope: Optional[str] = None
    ) -> bool:
        """Validate if a token is valid for a resource.
        
        Args:
            resource_uri: The resource URI
            token_audience: The audience claim from the token
            required_scope: Optional required scope
            
        Returns:
            True if token is valid for resource
        """
        # Check if resource is in token audience
        if resource_uri not in token_audience:
            return False
        
        # If scope validation requested
        if required_scope:
            resource = await self.get_resource(resource_uri)
            if not resource:
                return False
            
            # Check if resource supports the required scope
            if required_scope not in resource.get("scopes", []):
                return False
        
        return True
    
    async def auto_register_proxy_resources(self) -> int:
        """Auto-register resources based on existing proxy targets.
        
        This scans proxy targets and registers any that have certificates
        as protected resources.
        
        Returns:
            Number of resources registered
        """
        registered = 0
        
        # Get all proxy targets
        proxy_keys = await self.redis.keys("proxy:*")
        
        for key in proxy_keys:
            proxy_data = await self.redis.get(key)
            if not proxy_data:
                continue
            
            proxy = json.loads(proxy_data)
            hostname = proxy.get("hostname")
            
            # Only register if HTTPS is enabled and has a certificate
            if proxy.get("enable_https") and proxy.get("cert_name"):
                proto = "https"
                resource_uri = f"{proto}://{hostname}"
                
                # Check if already registered
                if await self.get_resource(resource_uri):
                    continue
                
                # Register as protected resource
                await self.register_resource(
                    resource_uri=resource_uri,
                    proxy_hostname=hostname,
                    name=f"Protected Resource at {hostname}",
                    metadata={
                        "auto_registered": True,
                        "cert_name": proxy.get("cert_name"),
                        "target_url": proxy.get("target_url")
                    }
                )
                registered += 1
        
        if registered > 0:
            logger.info(f"Auto-registered {registered} protected resources")
        
        return registered