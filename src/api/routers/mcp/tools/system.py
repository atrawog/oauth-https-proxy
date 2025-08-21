"""System configuration and management MCP tools."""

import json
from typing import Any, Dict, Optional
from datetime import datetime, timezone
import logging

from .base import BaseMCPTools

logger = logging.getLogger(__name__)


class SystemTools(BaseMCPTools):
    """MCP tools for system configuration and management."""
    
    def register_tools(self):
        """Register all system management tools."""
        
        @self.mcp.tool(
            annotations={
                "title": "Export System Configuration",
                "readOnlyHint": True,
                "destructiveHint": False,
                "idempotentHint": True,
                "openWorldHint": False
            }
        )
        async def config_save(
            admin_token: str,
            include_tokens: bool = False,
            include_secrets: bool = False
        ) -> Dict[str, Any]:
            """Export system configuration for backup.
            
            Args:
                admin_token: Admin token for authentication
                include_tokens: Include API tokens in export
                include_secrets: Include secrets (OAuth secrets, private keys)
                
            Returns:
                Dictionary with full system configuration
            """
            session_id = self.get_session_context()
            
            async with self.logger.trace_context(
                "mcp_tool_config_save",
                session_id=session_id
            ):
                # Validate admin token
                token_info = await self.validate_token(admin_token, require_admin=True)
                user = token_info.get("name", "unknown")
                
                config = {
                    "version": "1.0",
                    "exported_at": datetime.now(timezone.utc).isoformat(),
                    "exported_by": user
                }
                
                # Export tokens (if requested)
                if include_tokens:
                    tokens = []
                    async for key in self.storage.redis_client.scan_iter(match="token:*"):
                        if isinstance(key, bytes):
                            key = key.decode('utf-8')
                        parts = key.split(":")
                        if len(parts) == 2:
                            token_data = await self.storage.get_api_token_by_name(parts[1])
                            if token_data:
                                token_export = {
                                    "name": token_data["name"],
                                    "cert_email": token_data.get("cert_email", "")
                                }
                                if include_secrets:
                                    token_export["token"] = token_data["token"]
                                tokens.append(token_export)
                    config["tokens"] = tokens
                
                # Export certificates
                certs = await self.storage.list_certificates()
                cert_exports = []
                for cert in certs:
                    cert_export = {
                        "cert_name": cert["cert_name"],
                        "domains": cert.get("domains", []),
                        "email": cert.get("email", ""),
                        "staging": cert.get("staging", False),
                        "owner_token": cert.get("owner_token", "")
                    }
                    if include_secrets and cert.get("fullchain_pem"):
                        cert_export["fullchain_pem"] = cert["fullchain_pem"]
                        cert_export["privkey_pem"] = cert.get("privkey_pem", "")
                    cert_exports.append(cert_export)
                config["certificates"] = cert_exports
                
                # Export proxies
                proxies = await self.storage.list_proxy_targets()
                proxy_exports = []
                for proxy in proxies:
                    proxy_export = {
                        "hostname": proxy.hostname,
                        "target_url": proxy.target_url,
                        "enable_http": proxy.enable_http,
                        "enable_https": proxy.enable_https,
                        "cert_name": proxy.cert_name,
                        "auth_enabled": proxy.auth_enabled,
                        "owner_token": proxy.owner_token
                    }
                    
                    # Include auth config
                    auth_config = await self.storage.get_proxy_auth_config(proxy.hostname)
                    if auth_config:
                        proxy_export["auth_config"] = auth_config
                    
                    # Include resource metadata
                    resource_metadata = await self.storage.get_protected_resource_metadata(proxy.hostname)
                    if resource_metadata:
                        proxy_export["resource_metadata"] = resource_metadata
                    
                    proxy_exports.append(proxy_export)
                config["proxies"] = proxy_exports
                
                # Export routes
                routes = await self.storage.list_routes()
                route_exports = []
                for route in routes:
                    route_exports.append({
                        "route_id": route.route_id,
                        "path_pattern": route.path_pattern,
                        "target_type": route.target_type,
                        "target_value": route.target_value,
                        "priority": route.priority,
                        "methods": route.methods,
                        "is_regex": route.is_regex,
                        "scope": route.get("scope", "proxy"),
                        "enabled": route.enabled
                    })
                config["routes"] = route_exports
                
                # Export services
                services = []
                # Docker services
                docker_services = await self.storage.list_docker_services()
                for service in docker_services:
                    services.append({
                        "type": "docker",
                        "name": service["name"],
                        "image": service.get("image", ""),
                        "ports": service.get("ports", []),
                        "memory": service.get("memory", "512m"),
                        "cpu": service.get("cpu", 1.0),
                        "owner_token": service.get("owner_token", "")
                    })
                
                # External services
                external_services = await self.storage.list_external_services()
                for service in external_services:
                    services.append({
                        "type": "external",
                        "name": service["name"],
                        "target_url": service["target_url"],
                        "description": service.get("description", ""),
                        "owner_token": service.get("owner_token", "")
                    })
                config["services"] = services
                
                # Export OAuth clients (if include_secrets)
                if include_secrets:
                    oauth_clients = await self.storage.list_oauth_clients()
                    config["oauth_clients"] = oauth_clients
                
                # Log audit event
                await self.log_audit_event(
                    action="config_save",
                    session_id=session_id,
                    user=user,
                    details={
                        "include_tokens": include_tokens,
                        "include_secrets": include_secrets,
                        "exported_items": {
                            "tokens": len(config.get("tokens", [])),
                            "certificates": len(config.get("certificates", [])),
                            "proxies": len(config.get("proxies", [])),
                            "routes": len(config.get("routes", [])),
                            "services": len(config.get("services", []))
                        }
                    }
                )
                
                return {
                    "status": "exported",
                    "config": config,
                    "message": "Configuration exported successfully"
                }
        
        @self.mcp.tool(
            annotations={
                "title": "Import System Configuration",
                "readOnlyHint": False,
                "destructiveHint": True,
                "idempotentHint": False,
                "openWorldHint": False
            }
        )
        async def config_load(
            config_json: str,
            admin_token: str,
            force: bool = False
        ) -> Dict[str, Any]:
            """Import system configuration from backup.
            
            Args:
                config_json: JSON string with configuration to import
                admin_token: Admin token for authentication
                force: Force overwrite existing configuration
                
            Returns:
                Dictionary with import results
            """
            session_id = self.get_session_context()
            
            async with self.logger.trace_context(
                "mcp_tool_config_load",
                session_id=session_id
            ):
                # Validate admin token
                token_info = await self.validate_token(admin_token, require_admin=True)
                user = token_info.get("name", "unknown")
                
                # Parse configuration
                try:
                    config = json.loads(config_json)
                except json.JSONDecodeError as e:
                    raise ValueError(f"Invalid JSON configuration: {e}")
                
                if not isinstance(config, dict) or "version" not in config:
                    raise ValueError("Invalid configuration format")
                
                results = {
                    "imported": {
                        "tokens": 0,
                        "certificates": 0,
                        "proxies": 0,
                        "routes": 0,
                        "services": 0
                    },
                    "skipped": {
                        "tokens": 0,
                        "certificates": 0,
                        "proxies": 0,
                        "routes": 0,
                        "services": 0
                    },
                    "errors": []
                }
                
                # Import tokens
                if "tokens" in config:
                    for token_data in config["tokens"]:
                        try:
                            existing = await self.storage.get_api_token_by_name(token_data["name"])
                            if existing and not force:
                                results["skipped"]["tokens"] += 1
                                continue
                            
                            if "token" in token_data:
                                await self.storage.store_api_token(
                                    token_data["name"],
                                    token_data["token"],
                                    cert_email=token_data.get("cert_email")
                                )
                                results["imported"]["tokens"] += 1
                        except Exception as e:
                            results["errors"].append(f"Token {token_data['name']}: {e}")
                
                # Import certificates
                if "certificates" in config:
                    for cert_data in config["certificates"]:
                        try:
                            existing = await self.storage.get_certificate(cert_data["cert_name"])
                            if existing and not force:
                                results["skipped"]["certificates"] += 1
                                continue
                            
                            await self.storage.store_certificate_config(
                                cert_data["cert_name"],
                                cert_data
                            )
                            results["imported"]["certificates"] += 1
                        except Exception as e:
                            results["errors"].append(f"Certificate {cert_data['cert_name']}: {e}")
                
                # Import proxies
                if "proxies" in config:
                    for proxy_data in config["proxies"]:
                        try:
                            existing = await self.storage.get_proxy_target(proxy_data["hostname"])
                            if existing and not force:
                                results["skipped"]["proxies"] += 1
                                continue
                            
                            await self.storage.create_proxy_target(proxy_data)
                            
                            # Import auth config if present
                            if "auth_config" in proxy_data:
                                await self.storage.set_proxy_auth_config(
                                    proxy_data["hostname"],
                                    proxy_data["auth_config"]
                                )
                            
                            # Import resource metadata if present
                            if "resource_metadata" in proxy_data:
                                await self.storage.set_protected_resource_metadata(
                                    proxy_data["hostname"],
                                    proxy_data["resource_metadata"]
                                )
                            
                            results["imported"]["proxies"] += 1
                        except Exception as e:
                            results["errors"].append(f"Proxy {proxy_data['hostname']}: {e}")
                
                # Import routes
                if "routes" in config:
                    for route_data in config["routes"]:
                        try:
                            existing = await self.storage.get_route(route_data["route_id"])
                            if existing and not force:
                                results["skipped"]["routes"] += 1
                                continue
                            
                            await self.storage.store_route(
                                route_data["route_id"],
                                route_data
                            )
                            results["imported"]["routes"] += 1
                        except Exception as e:
                            results["errors"].append(f"Route {route_data['route_id']}: {e}")
                
                # Import services
                if "services" in config:
                    for service_data in config["services"]:
                        try:
                            if service_data["type"] == "docker":
                                existing = await self.storage.get_service_config(service_data["name"])
                                if existing and not force:
                                    results["skipped"]["services"] += 1
                                    continue
                                
                                await self.storage.store_service_config(
                                    service_data["name"],
                                    service_data
                                )
                            elif service_data["type"] == "external":
                                existing = await self.storage.get_external_service(service_data["name"])
                                if existing and not force:
                                    results["skipped"]["services"] += 1
                                    continue
                                
                                await self.storage.store_external_service(
                                    service_data["name"],
                                    service_data
                                )
                            
                            results["imported"]["services"] += 1
                        except Exception as e:
                            results["errors"].append(f"Service {service_data['name']}: {e}")
                
                # Log audit event
                await self.log_audit_event(
                    action="config_load",
                    session_id=session_id,
                    user=user,
                    details={
                        "force": force,
                        "imported": results["imported"],
                        "skipped": results["skipped"],
                        "error_count": len(results["errors"])
                    }
                )
                
                results["status"] = "completed"
                results["message"] = f"Configuration import completed. Imported: {sum(results['imported'].values())} items, Skipped: {sum(results['skipped'].values())} items"
                
                if results["errors"]:
                    results["message"] += f", Errors: {len(results['errors'])}"
                
                return results