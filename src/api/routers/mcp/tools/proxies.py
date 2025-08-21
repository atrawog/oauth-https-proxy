"""Proxy management MCP tools including authentication and resource configuration."""

from typing import Any, Dict, List, Optional
from datetime import datetime, timezone
import logging
import json

from .base import BaseMCPTools

logger = logging.getLogger(__name__)


class ProxyTools(BaseMCPTools):
    """MCP tools for proxy management including auth and resources."""
    
    def register_tools(self):
        """Register all proxy management tools."""
        
        # Note: proxy_list, proxy_create, proxy_delete are in mcp_server.py
        # We'll add extended proxy tools here
        
        @self.mcp.tool(
            annotations={
                "title": "Show Proxy Details",
                "readOnlyHint": True,
                "destructiveHint": False,
                "idempotentHint": True,
                "openWorldHint": False
            }
        )
        async def proxy_show(
            hostname: str,
            token: Optional[str] = None
        ) -> Dict[str, Any]:
            """Show detailed proxy configuration.
            
            Args:
                hostname: Proxy hostname
                token: Optional API token for ownership check
                
            Returns:
                Dictionary with full proxy details
            """
            session_id = self.get_session_context()
            
            async with self.logger.trace_context(
                "mcp_tool_proxy_show",
                session_id=session_id,
                hostname=hostname
            ):
                # Get proxy
                proxy = await self.storage.get_proxy_target(hostname)
                if not proxy:
                    raise ValueError(f"Proxy '{hostname}' not found")
                
                # Check ownership if token provided
                user = "anonymous"
                if token:
                    token_info = await self.validate_token(token)
                    user = token_info.get("name", "unknown")
                    
                    owner_token = getattr(proxy, 'owner_token', None) if hasattr(proxy, 'owner_token') else proxy.get('owner_token') if isinstance(proxy, dict) else None
                    if owner_token != token_info["name"] and token_info["name"].upper() != "ADMIN":
                        raise PermissionError("You can only view proxies you own")
                
                # Get auth configuration (this may not exist, handle gracefully)
                auth_config = None
                try:
                    # Try to get from Redis directly
                    auth_data = await self.storage.redis_client.get(f"proxy:auth:{hostname}")
                    if auth_data:
                        import json
                        auth_config = json.loads(auth_data)
                except:
                    auth_config = None
                
                # Get protected resource metadata (may not exist)
                resource_metadata = None
                try:
                    resource_data = await self.storage.redis_client.get(f"resource:{hostname}")
                    if resource_data:
                        import json
                        resource_metadata = json.loads(resource_data)
                except:
                    resource_metadata = None
                
                # OAuth server metadata is not stored separately, skip it
                oauth_server_metadata = None
                
                # Build result handling both dict and object
                if isinstance(proxy, dict):
                    result = {
                        "hostname": proxy.get("hostname", ""),
                        "target_url": proxy.get("target_url", ""),
                        "enable_http": proxy.get("enable_http", True),
                        "enable_https": proxy.get("enable_https", True),
                        "cert_name": proxy.get("cert_name", None),
                        "owner": proxy.get("owner_token", ""),
                        "auth_enabled": proxy.get("auth_enabled", False),
                        "auth_config": auth_config,
                        "resource_metadata": resource_metadata,
                        "oauth_server_metadata": oauth_server_metadata
                    }
                else:
                    # Handle Pydantic model
                    result = {
                        "hostname": getattr(proxy, 'hostname', ""),
                        "target_url": getattr(proxy, 'target_url', ""),
                        "enable_http": getattr(proxy, 'enable_http', True),
                        "enable_https": getattr(proxy, 'enable_https', True),
                        "cert_name": getattr(proxy, 'cert_name', None),
                        "owner": getattr(proxy, 'owner_token', ""),
                        "auth_enabled": getattr(proxy, 'auth_enabled', False),
                        "auth_config": auth_config,
                        "resource_metadata": resource_metadata,
                        "oauth_server_metadata": oauth_server_metadata
                    }
                
                # Log audit event
                await self.log_audit_event(
                    action="proxy_show",
                    session_id=session_id,
                    user=user,
                    details={"hostname": hostname}
                )
                
                return result
        
        # ========== Proxy Authentication Tools ==========
        
        @self.mcp.tool(
            annotations={
                "title": "Enable Proxy Authentication",
                "readOnlyHint": False,
                "destructiveHint": False,
                "idempotentHint": True,
                "openWorldHint": False
            }
        )
        async def proxy_auth_enable(
            hostname: str,
            auth_proxy: str,
            mode: str,
            token: str,
            allowed_scopes: Optional[str] = None,
            allowed_audiences: Optional[str] = None
        ) -> Dict[str, Any]:
            """Enable OAuth authentication for a proxy.
            
            Args:
                hostname: Proxy hostname
                auth_proxy: OAuth server hostname
                mode: Authentication mode (forward, redirect, etc.)
                token: API token for authentication
                allowed_scopes: Comma-separated list of allowed scopes
                allowed_audiences: Comma-separated list of allowed audiences
                
            Returns:
                Dictionary with configuration status
            """
            session_id = self.get_session_context()
            
            async with self.logger.trace_context(
                "mcp_tool_proxy_auth_enable",
                session_id=session_id,
                hostname=hostname
            ):
                # Validate token
                token_info = await self.validate_token(token)
                user = token_info.get("name", "unknown")
                
                # Get proxy
                proxy = await self.storage.get_proxy_target(hostname)
                if not proxy:
                    raise ValueError(f"Proxy '{hostname}' not found")
                
                # Check ownership
                owner_token = getattr(proxy, 'owner_token', '') if hasattr(proxy, 'owner_token') else proxy.get('owner_token', '') if isinstance(proxy, dict) else ''
                await self.check_ownership(token_info, owner_token, "proxy")
                
                # Parse scopes and audiences
                scopes_list = [s.strip() for s in allowed_scopes.split(",")] if allowed_scopes else []
                audiences_list = [a.strip() for a in allowed_audiences.split(",")] if allowed_audiences else []
                
                # Enable authentication
                auth_config = {
                    "enabled": True,
                    "auth_proxy": auth_proxy,
                    "mode": mode,
                    "allowed_scopes": scopes_list,
                    "allowed_audiences": audiences_list
                }
                
                # Store auth config in Redis
                import json
                await self.storage.redis_client.set(f"proxy:auth:{hostname}", json.dumps(auth_config))
                
                # Update proxy auth_enabled flag
                if isinstance(proxy, dict):
                    proxy["auth_enabled"] = True
                else:
                    proxy.auth_enabled = True
                await self.storage.store_proxy_target(hostname, proxy)
                
                # Log audit event
                await self.log_audit_event(
                    action="proxy_auth_enable",
                    session_id=session_id,
                    user=user,
                    details={
                        "hostname": hostname,
                        "auth_proxy": auth_proxy,
                        "mode": mode
                    }
                )
                
                return {
                    "status": "enabled",
                    "hostname": hostname,
                    "auth_proxy": auth_proxy,
                    "mode": mode,
                    "message": f"Authentication enabled for proxy '{hostname}'"
                }
        
        @self.mcp.tool(
            annotations={
                "title": "Disable Proxy Authentication",
                "readOnlyHint": False,
                "destructiveHint": False,
                "idempotentHint": True,
                "openWorldHint": False
            }
        )
        async def proxy_auth_disable(
            hostname: str,
            token: str
        ) -> Dict[str, Any]:
            """Disable OAuth authentication for a proxy.
            
            Args:
                hostname: Proxy hostname
                token: API token for authentication
                
            Returns:
                Dictionary with status
            """
            session_id = self.get_session_context()
            
            async with self.logger.trace_context(
                "mcp_tool_proxy_auth_disable",
                session_id=session_id,
                hostname=hostname
            ):
                # Validate token
                token_info = await self.validate_token(token)
                user = token_info.get("name", "unknown")
                
                # Get proxy
                proxy = await self.storage.get_proxy_target(hostname)
                if not proxy:
                    raise ValueError(f"Proxy '{hostname}' not found")
                
                # Check ownership
                owner_token = getattr(proxy, 'owner_token', '') if hasattr(proxy, 'owner_token') else proxy.get('owner_token', '') if isinstance(proxy, dict) else ''
                await self.check_ownership(token_info, owner_token, "proxy")
                
                # Delete auth config from Redis
                await self.storage.redis_client.delete(f"proxy:auth:{hostname}")
                
                # Update proxy auth_enabled flag
                if isinstance(proxy, dict):
                    proxy["auth_enabled"] = False
                else:
                    proxy.auth_enabled = False
                await self.storage.store_proxy_target(hostname, proxy)
                
                # Log audit event
                await self.log_audit_event(
                    action="proxy_auth_disable",
                    session_id=session_id,
                    user=user,
                    details={"hostname": hostname}
                )
                
                return {
                    "status": "disabled",
                    "hostname": hostname,
                    "message": f"Authentication disabled for proxy '{hostname}'"
                }
        
        @self.mcp.tool(
            annotations={
                "title": "Configure Proxy Authentication",
                "readOnlyHint": False,
                "destructiveHint": False,
                "idempotentHint": True,
                "openWorldHint": False
            }
        )
        async def proxy_auth_config(
            hostname: str,
            token: str,
            users: Optional[str] = None,
            emails: Optional[str] = None,
            groups: Optional[str] = None,
            scopes: Optional[str] = None,
            audiences: Optional[str] = None
        ) -> Dict[str, Any]:
            """Configure authentication settings for a proxy.
            
            Args:
                hostname: Proxy hostname
                token: API token for authentication
                users: Comma-separated list of allowed usernames
                emails: Comma-separated list of allowed emails
                groups: Comma-separated list of allowed groups
                scopes: Comma-separated list of required scopes
                audiences: Comma-separated list of allowed audiences
                
            Returns:
                Dictionary with configuration status
            """
            session_id = self.get_session_context()
            
            async with self.logger.trace_context(
                "mcp_tool_proxy_auth_config",
                session_id=session_id,
                hostname=hostname
            ):
                # Validate token
                token_info = await self.validate_token(token)
                user = token_info.get("name", "unknown")
                
                # Get proxy
                proxy = await self.storage.get_proxy_target(hostname)
                if not proxy:
                    raise ValueError(f"Proxy '{hostname}' not found")
                
                # Check ownership
                owner_token = getattr(proxy, 'owner_token', '') if hasattr(proxy, 'owner_token') else proxy.get('owner_token', '') if isinstance(proxy, dict) else ''
                await self.check_ownership(token_info, owner_token, "proxy")
                
                # Get existing config from Redis
                auth_config = {}
                try:
                    auth_data = await self.storage.redis_client.get(f"proxy:auth:{hostname}")
                    if auth_data:
                        import json
                        auth_config = json.loads(auth_data)
                except:
                    auth_config = {}
                
                # Update config
                if users is not None:
                    auth_config["allowed_users"] = [u.strip() for u in users.split(",")] if users else []
                if emails is not None:
                    auth_config["allowed_emails"] = [e.strip() for e in emails.split(",")] if emails else []
                if groups is not None:
                    auth_config["allowed_groups"] = [g.strip() for g in groups.split(",")] if groups else []
                if scopes is not None:
                    auth_config["allowed_scopes"] = [s.strip() for s in scopes.split(",")] if scopes else []
                if audiences is not None:
                    auth_config["allowed_audiences"] = [a.strip() for a in audiences.split(",")] if audiences else []
                
                # Store updated auth config in Redis
                import json
                await self.storage.redis_client.set(f"proxy:auth:{hostname}", json.dumps(auth_config))
                
                # Log audit event
                await self.log_audit_event(
                    action="proxy_auth_config",
                    session_id=session_id,
                    user=user,
                    details={"hostname": hostname, "config": auth_config}
                )
                
                return {
                    "status": "configured",
                    "hostname": hostname,
                    "config": auth_config,
                    "message": f"Authentication configured for proxy '{hostname}'"
                }
        
        @self.mcp.tool(
            annotations={
                "title": "Show Proxy Authentication",
                "readOnlyHint": True,
                "destructiveHint": False,
                "idempotentHint": True,
                "openWorldHint": False
            }
        )
        async def proxy_auth_show(
            hostname: str,
            token: Optional[str] = None
        ) -> Dict[str, Any]:
            """Show authentication configuration for a proxy.
            
            Args:
                hostname: Proxy hostname
                token: Optional API token for ownership check
                
            Returns:
                Dictionary with authentication configuration
            """
            session_id = self.get_session_context()
            
            async with self.logger.trace_context(
                "mcp_tool_proxy_auth_show",
                session_id=session_id,
                hostname=hostname
            ):
                # Get proxy
                proxy = await self.storage.get_proxy_target(hostname)
                if not proxy:
                    raise ValueError(f"Proxy '{hostname}' not found")
                
                # Check ownership if token provided
                user = "anonymous"
                if token:
                    token_info = await self.validate_token(token)
                    user = token_info.get("name", "unknown")
                    
                    owner_token = getattr(proxy, 'owner_token', None) if hasattr(proxy, 'owner_token') else proxy.get('owner_token') if isinstance(proxy, dict) else None
                    if owner_token != token_info["name"] and token_info["name"].upper() != "ADMIN":
                        raise PermissionError("You can only view proxies you own")
                
                # Get auth config from Redis
                auth_config = {}
                try:
                    auth_data = await self.storage.redis_client.get(f"proxy:auth:{hostname}")
                    if auth_data:
                        import json
                        auth_config = json.loads(auth_data)
                except:
                    auth_config = {}
                
                auth_enabled = getattr(proxy, 'auth_enabled', False) if hasattr(proxy, 'auth_enabled') else proxy.get('auth_enabled', False) if isinstance(proxy, dict) else False
                
                result = {
                    "hostname": hostname,
                    "auth_enabled": auth_enabled,
                    "config": auth_config
                }
                
                # Log audit event
                await self.log_audit_event(
                    action="proxy_auth_show",
                    session_id=session_id,
                    user=user,
                    details={"hostname": hostname}
                )
                
                return result
        
        # ========== Protected Resource Metadata Tools ==========
        
        @self.mcp.tool(
            annotations={
                "title": "Set Protected Resource Metadata",
                "readOnlyHint": False,
                "destructiveHint": False,
                "idempotentHint": True,
                "openWorldHint": False
            }
        )
        async def proxy_resource_set(
            hostname: str,
            endpoint: str,
            scopes: str,
            token: str,
            stateful: bool = False,
            override_backend: bool = False,
            bearer_methods: str = "header",
            doc_suffix: str = "/docs",
            server_info: Optional[str] = None,
            custom_metadata: Optional[str] = None
        ) -> Dict[str, Any]:
            """Set protected resource metadata for a proxy.
            
            Args:
                hostname: Proxy hostname
                endpoint: API endpoint path
                scopes: Comma-separated list of supported scopes
                token: API token for authentication
                stateful: Whether the resource is stateful
                override_backend: Override backend server info
                bearer_methods: Bearer token methods (header, body, query)
                doc_suffix: Documentation endpoint suffix
                server_info: JSON string with server info
                custom_metadata: JSON string with custom metadata
                
            Returns:
                Dictionary with configuration status
            """
            session_id = self.get_session_context()
            
            async with self.logger.trace_context(
                "mcp_tool_proxy_resource_set",
                session_id=session_id,
                hostname=hostname
            ):
                # Validate token
                token_info = await self.validate_token(token)
                user = token_info.get("name", "unknown")
                
                # Get proxy
                proxy = await self.storage.get_proxy_target(hostname)
                if not proxy:
                    raise ValueError(f"Proxy '{hostname}' not found")
                
                # Check ownership
                owner_token = getattr(proxy, 'owner_token', '') if hasattr(proxy, 'owner_token') else proxy.get('owner_token', '') if isinstance(proxy, dict) else ''
                await self.check_ownership(token_info, owner_token, "proxy")
                
                # Parse JSON strings
                server_info_dict = {}
                if server_info:
                    try:
                        server_info_dict = json.loads(server_info)
                    except json.JSONDecodeError:
                        raise ValueError("Invalid JSON for server_info")
                
                custom_metadata_dict = {}
                if custom_metadata:
                    try:
                        custom_metadata_dict = json.loads(custom_metadata)
                    except json.JSONDecodeError:
                        raise ValueError("Invalid JSON for custom_metadata")
                
                # Create resource metadata
                metadata = {
                    "endpoint": endpoint,
                    "scopes_supported": [s.strip() for s in scopes.split(",")],
                    "stateful": stateful,
                    "override_backend_server": override_backend,
                    "bearer_methods_supported": [m.strip() for m in bearer_methods.split(",")],
                    "doc_suffix": doc_suffix,
                    "server_info": server_info_dict,
                    "custom_metadata": custom_metadata_dict
                }
                
                # Store resource metadata in Redis
                import json
                await self.storage.redis_client.set(f"resource:{hostname}", json.dumps(metadata))
                
                # Log audit event
                await self.log_audit_event(
                    action="proxy_resource_set",
                    session_id=session_id,
                    user=user,
                    details={"hostname": hostname, "endpoint": endpoint}
                )
                
                return {
                    "status": "configured",
                    "hostname": hostname,
                    "metadata": metadata,
                    "message": f"Protected resource metadata set for proxy '{hostname}'"
                }
        
        @self.mcp.tool(
            annotations={
                "title": "Show Protected Resource Metadata",
                "readOnlyHint": True,
                "destructiveHint": False,
                "idempotentHint": True,
                "openWorldHint": False
            }
        )
        async def proxy_resource_show(
            hostname: str,
            token: Optional[str] = None
        ) -> Dict[str, Any]:
            """Show protected resource metadata for a proxy.
            
            Args:
                hostname: Proxy hostname
                token: Optional API token for ownership check
                
            Returns:
                Dictionary with resource metadata
            """
            session_id = self.get_session_context()
            
            async with self.logger.trace_context(
                "mcp_tool_proxy_resource_show",
                session_id=session_id,
                hostname=hostname
            ):
                # Get proxy
                proxy = await self.storage.get_proxy_target(hostname)
                if not proxy:
                    raise ValueError(f"Proxy '{hostname}' not found")
                
                # Check ownership if token provided
                user = "anonymous"
                if token:
                    token_info = await self.validate_token(token)
                    user = token_info.get("name", "unknown")
                    
                    owner_token = getattr(proxy, 'owner_token', None) if hasattr(proxy, 'owner_token') else proxy.get('owner_token') if isinstance(proxy, dict) else None
                    if owner_token != token_info["name"] and token_info["name"].upper() != "ADMIN":
                        raise PermissionError("You can only view proxies you own")
                
                # Get metadata from Redis
                metadata = None
                try:
                    resource_data = await self.storage.redis_client.get(f"resource:{hostname}")
                    if resource_data:
                        import json
                        if isinstance(resource_data, bytes):
                            resource_data = resource_data.decode('utf-8')
                        metadata = json.loads(resource_data)
                except Exception as e:
                    logger.warning(f"Error getting resource metadata: {e}")
                    metadata = None
                
                result = {
                    "hostname": hostname,
                    "metadata": metadata or {}
                }
                
                # Log audit event
                await self.log_audit_event(
                    action="proxy_resource_show",
                    session_id=session_id,
                    user=user,
                    details={"hostname": hostname}
                )
                
                return result
        
        @self.mcp.tool(
            annotations={
                "title": "Clear Protected Resource Metadata",
                "readOnlyHint": False,
                "destructiveHint": True,
                "idempotentHint": True,
                "openWorldHint": False
            }
        )
        async def proxy_resource_clear(
            hostname: str,
            token: str
        ) -> Dict[str, Any]:
            """Clear protected resource metadata for a proxy.
            
            Args:
                hostname: Proxy hostname
                token: API token for authentication
                
            Returns:
                Dictionary with status
            """
            session_id = self.get_session_context()
            
            async with self.logger.trace_context(
                "mcp_tool_proxy_resource_clear",
                session_id=session_id,
                hostname=hostname
            ):
                # Validate token
                token_info = await self.validate_token(token)
                user = token_info.get("name", "unknown")
                
                # Get proxy
                proxy = await self.storage.get_proxy_target(hostname)
                if not proxy:
                    raise ValueError(f"Proxy '{hostname}' not found")
                
                # Check ownership
                owner_token = getattr(proxy, 'owner_token', '') if hasattr(proxy, 'owner_token') else proxy.get('owner_token', '') if isinstance(proxy, dict) else ''
                await self.check_ownership(token_info, owner_token, "proxy")
                
                # Clear metadata from Redis
                await self.storage.redis_client.delete(f"resource:{hostname}")
                
                # Log audit event
                await self.log_audit_event(
                    action="proxy_resource_clear",
                    session_id=session_id,
                    user=user,
                    details={"hostname": hostname}
                )
                
                return {
                    "status": "cleared",
                    "hostname": hostname,
                    "message": f"Protected resource metadata cleared for proxy '{hostname}'"
                }
        
        @self.mcp.tool(
            annotations={
                "title": "List Protected Resources",
                "readOnlyHint": True,
                "destructiveHint": False,
                "idempotentHint": True,
                "openWorldHint": False
            }
        )
        async def proxy_resource_list(
            token: Optional[str] = None
        ) -> Dict[str, Any]:
            """List all proxies with protected resource metadata.
            
            Args:
                token: Optional API token for filtering
                
            Returns:
                Dictionary with list of protected resources
            """
            session_id = self.get_session_context()
            
            async with self.logger.trace_context(
                "mcp_tool_proxy_resource_list",
                session_id=session_id
            ):
                user = "anonymous"
                filter_owner = None
                
                if token:
                    token_info = await self.validate_token(token)
                    user = token_info.get("name", "unknown")
                    # Non-admin users only see their own resources
                    if token_info["name"].upper() != "ADMIN":
                        filter_owner = token_info["name"]
                
                # Get all proxies with resource metadata
                resources = []
                proxies = await self.storage.list_proxy_targets()
                
                for proxy in proxies:
                    # Filter by owner if needed
                    owner_token = getattr(proxy, 'owner_token', None) if hasattr(proxy, 'owner_token') else proxy.get('owner_token') if isinstance(proxy, dict) else None
                    if filter_owner and owner_token != filter_owner:
                        continue
                    
                    # Get metadata from Redis
                    metadata = None
                    hostname = getattr(proxy, 'hostname', None) if hasattr(proxy, 'hostname') else proxy.get('hostname') if isinstance(proxy, dict) else None
                    if hostname:
                        try:
                            resource_data = await self.storage.redis_client.get(f"resource:{hostname}")
                            if resource_data:
                                import json
                                if isinstance(resource_data, bytes):
                                    resource_data = resource_data.decode('utf-8')
                                metadata = json.loads(resource_data)
                        except Exception as e:
                            logger.debug(f"No resource metadata for {hostname}: {e}")
                            metadata = None
                    
                    if metadata:
                        resources.append({
                            "hostname": hostname,
                            "endpoint": metadata.get("endpoint", "/api"),
                            "scopes": metadata.get("scopes_supported", []),
                            "stateful": metadata.get("stateful", False),
                            "owner": owner_token
                        })
                
                # Log audit event
                await self.log_audit_event(
                    action="proxy_resource_list",
                    session_id=session_id,
                    user=user,
                    details={"count": len(resources)}
                )
                
                return {
                    "resources": resources,
                    "count": len(resources)
                }