"""Workflow automation MCP tools."""

from typing import Any, Dict, Optional
from datetime import datetime, timezone
import logging

from .base import BaseMCPTools

logger = logging.getLogger(__name__)


class WorkflowTools(BaseMCPTools):
    """MCP tools for workflow automation."""
    
    def register_tools(self):
        """Register all workflow automation tools."""
        
        @self.mcp.tool(
            annotations={
                "title": "Quick Proxy Setup",
                "readOnlyHint": False,
                "destructiveHint": False,
                "idempotentHint": False,
                "openWorldHint": True
            }
        )
        async def quickstart(
            proxy_hostname: str,
            target_url: str,
            token: str,
            enable_auth: bool = False,
            email: Optional[str] = None
        ) -> Dict[str, Any]:
            """Quick setup of proxy with automatic certificate.
            
            Args:
                hostname: Proxy hostname
                target_url: Target URL to proxy to
                token: API token for authentication
                enable_auth: Enable OAuth authentication
                email: Certificate email (uses token email if not provided)
                
            Returns:
                Dictionary with setup status
            """
            session_id = self.get_session_context()
            
            async with self.logger.trace_context(
                "mcp_tool_quickstart",
                session_id=session_id, proxy_hostname=proxy_hostname
            ) as trace_id:
                # Validate token
                token_info = await self.validate_token(token)
                user = token_info.get("name", "unknown")
                cert_email = email or token_info.get("cert_email")
                
                if not cert_email:
                    raise ValueError("Email required for certificate generation")
                
                results = {
                    "proxy_hostname": proxy_hostname,
                    "target_url": target_url,
                    "steps": []
                }
                
                # Step 1: Create proxy
                try:
                    proxy_data = {
                        "proxy_hostname": proxy_hostname,
                        "target_url": target_url,
                        "enable_http": True,
                        "enable_https": True,
                        "auth_enabled": enable_auth,
                        "owner_token": token_info["name"]
                    }
                    await self.storage.create_proxy_target(proxy_data)
                    results["steps"].append({
                        "step": "create_proxy",
                        "status": "success",
                        "message": f"Proxy {proxy_hostname} created"
                    })
                except Exception as e:
                    results["steps"].append({
                        "step": "create_proxy",
                        "status": "failed",
                        "error": str(e)
                    })
                    return results
                
                # Step 2: Request certificate
                try:
                    cert_name = f"auto-{proxy_hostname}"
                    
                    # Publish workflow event for certificate
                    await self.publish_workflow_event(
                        event_type="certificate_requested", proxy_hostname=proxy_hostname,
                        data={
                            "cert_name": cert_name,
                            "domains": [hostname],
                            "email": cert_email,
                            "requested_by": "mcp_quickstart",
                            "session_id": session_id,
                            "user": user
                        },
                        trace_id=trace_id
                    )
                    
                    results["steps"].append({
                        "step": "request_certificate",
                        "status": "success",
                        "message": f"Certificate {cert_name} requested"
                    })
                    results["cert_name"] = cert_name
                except Exception as e:
                    results["steps"].append({
                        "step": "request_certificate",
                        "status": "failed",
                        "error": str(e)
                    })
                
                # Step 3: Enable auth if requested
                if enable_auth:
                    try:
                        auth_config = {
                            "enabled": True,
                            "auth_proxy": f"auth.{hostname.split('.', 1)[1]}",  # Use same base domain
                            "mode": "forward"
                        }
                        await self.storage.set_proxy_auth_config(hostname, auth_config)
                        
                        results["steps"].append({
                            "step": "enable_auth",
                            "status": "success",
                            "message": "OAuth authentication enabled"
                        })
                    except Exception as e:
                        results["steps"].append({
                            "step": "enable_auth",
                            "status": "failed",
                            "error": str(e)
                        })
                
                # Publish workflow event
                await self.publish_workflow_event(
                    event_type="quickstart_completed", proxy_hostname=proxy_hostname,
                    data={
                        "target_url": target_url,
                        "auth_enabled": enable_auth,
                        "steps_completed": len([s for s in results["steps"] if s["status"] == "success"]),
                        "session_id": session_id,
                        "user": user
                    },
                    trace_id=trace_id
                )
                
                # Log audit event
                await self.log_audit_event(
                    action="quickstart",
                    session_id=session_id,
                    user=user,
                    details=results
                )
                
                results["status"] = "completed"
                results["message"] = f"Proxy {proxy_hostname} setup completed"
                return results
        
        @self.mcp.tool(
            annotations={
                "title": "Setup OAuth for Domain",
                "readOnlyHint": False,
                "destructiveHint": False,
                "idempotentHint": False,
                "openWorldHint": False
            }
        )
        async def oauth_setup(
            domain: str,
            admin_token: str,
            generate_key: bool = False
        ) -> Dict[str, Any]:
            """Setup OAuth authentication for a domain.
            
            Args:
                domain: Domain to setup OAuth for
                admin_token: Admin token for authentication
                generate_key: Generate new JWT signing key
                
            Returns:
                Dictionary with OAuth setup status
            """
            session_id = self.get_session_context()
            
            async with self.logger.trace_context(
                "mcp_tool_oauth_setup",
                session_id=session_id,
                domain=domain
            ) as trace_id:
                # Validate admin token
                token_info = await self.validate_token(admin_token, require_admin=True)
                user = token_info.get("name", "unknown")
                
                results = {
                    "domain": domain,
                    "steps": []
                }
                
                # Step 1: Create OAuth routes
                oauth_routes = [
                    ("/.well-known/oauth-authorization-server", "oauth_metadata"),
                    ("/authorize", "oauth_authorize"),
                    ("/token", "oauth_token"),
                    ("/introspect", "oauth_introspect"),
                    ("/revoke", "oauth_revoke"),
                    ("/userinfo", "oauth_userinfo"),
                    ("/register", "oauth_register")
                ]
                
                for path, target in oauth_routes:
                    try:
                        route_id = f"oauth_{target}_{domain}"
                        route_config = {
                            "route_id": route_id,
                            "path_pattern": path,
                            "target_type": "oauth",
                            "target_value": target,
                            "priority": 10,  # High priority for OAuth
                            "proxy_hostname": domain,
                            "enabled": True
                        }
                        await self.storage.store_route(route_id, route_config)
                        
                        results["steps"].append({
                            "step": f"create_route_{target}",
                            "status": "success",
                            "path": path
                        })
                    except Exception as e:
                        results["steps"].append({
                            "step": f"create_route_{target}",
                            "status": "failed",
                            "error": str(e)
                        })
                
                # Step 2: Generate JWT key if requested
                if generate_key:
                    try:
                        import secrets
                        key = secrets.token_urlsafe(64)
                        results["jwt_key"] = key
                        results["steps"].append({
                            "step": "generate_jwt_key",
                            "status": "success",
                            "message": "JWT signing key generated"
                        })
                    except Exception as e:
                        results["steps"].append({
                            "step": "generate_jwt_key",
                            "status": "failed",
                            "error": str(e)
                        })
                
                # Publish workflow event
                await self.publish_workflow_event(
                    event_type="oauth_setup_completed", proxy_hostname=domain,
                    data={
                        "routes_created": len([s for s in results["steps"] if s.get("path")]),
                        "key_generated": generate_key,
                        "session_id": session_id,
                        "user": user
                    },
                    trace_id=trace_id
                )
                
                # Log audit event
                await self.log_audit_event(
                    action="oauth_setup",
                    session_id=session_id,
                    user=user,
                    details={"domain": domain, "routes_created": len(oauth_routes)}
                )
                
                results["status"] = "completed"
                results["message"] = f"OAuth setup completed for {domain}"
                return results
        
        @self.mcp.tool(
            annotations={
                "title": "Create App with Proxy",
                "readOnlyHint": False,
                "destructiveHint": False,
                "idempotentHint": False,
                "openWorldHint": True
            }
        )
        async def create_app(
            name: str,
            image: str,
            token: str,
            hostname: Optional[str] = None,
            port: int = 80
        ) -> Dict[str, Any]:
            """Create Docker service with automatic proxy setup.
            
            Args:
                name: Service/app name
                image: Docker image
                token: API token for authentication
                hostname: Optional hostname for proxy (auto-generated if not provided)
                port: Service port
                
            Returns:
                Dictionary with app creation status
            """
            session_id = self.get_session_context()
            
            async with self.logger.trace_context(
                "mcp_tool_create_app",
                session_id=session_id,
                app_name=name
            ) as trace_id:
                # Validate token
                token_info = await self.validate_token(token)
                user = token_info.get("name", "unknown")
                
                # Auto-generate hostname if not provided
                if not hostname:
                    import os
                    base_domain = os.getenv("BASE_DOMAIN", "localhost")
                    proxy_hostname = f"{name}.{base_domain}"
                
                results = {
                    "name": name,
                    "image": image,
                    "proxy_hostname": proxy_hostname,
                    "steps": []
                }
                
                # Step 1: Create Docker service
                try:
                    service_config = {
                        "name": name,
                        "image": image,
                        "ports": [{"internal": port, "external": port}],
                        "owner_token": token_info["name"]
                    }
                    await self.storage.store_service_config(name, service_config)
                    
                    # Publish workflow event for service creation
                    await self.publish_workflow_event(
                        event_type="service_create_requested",
                        data={
                            "service_name": name,
                            "image": image,
                            "requested_by": "mcp_create_app",
                            "session_id": session_id,
                            "user": user
                        },
                        trace_id=trace_id
                    )
                    
                    results["steps"].append({
                        "step": "create_service",
                        "status": "success",
                        "message": f"Service {name} created"
                    })
                except Exception as e:
                    results["steps"].append({
                        "step": "create_service",
                        "status": "failed",
                        "error": str(e)
                    })
                    return results
                
                # Step 2: Create proxy
                try:
                    target_url = f"http://{name}:{port}"
                    proxy_data = {
                        "proxy_hostname": proxy_hostname,
                        "target_url": target_url,
                        "enable_http": True,
                        "enable_https": True,
                        "owner_token": token_info["name"]
                    }
                    await self.storage.create_proxy_target(proxy_data)
                    
                    results["steps"].append({
                        "step": "create_proxy",
                        "status": "success",
                        "message": f"Proxy {proxy_hostname} -> {target_url} created"
                    })
                    results["target_url"] = target_url
                except Exception as e:
                    results["steps"].append({
                        "step": "create_proxy",
                        "status": "failed",
                        "error": str(e)
                    })
                
                # Log audit event
                await self.log_audit_event(
                    action="create_app",
                    session_id=session_id,
                    user=user,
                    details=results
                )
                
                results["status"] = "completed"
                results["message"] = f"App {name} created with proxy at {proxy_hostname}"
                return results
        
        @self.mcp.tool(
            annotations={
                "title": "Cleanup Orphaned Resources",
                "readOnlyHint": False,
                "destructiveHint": True,
                "idempotentHint": True,
                "openWorldHint": False
            }
        )
        async def cleanup_resources(
            admin_token: str,
            orphaned_only: bool = True
        ) -> Dict[str, Any]:
            """Clean up orphaned or unused resources.
            
            Args:
                admin_token: Admin token for authentication
                orphaned_only: Only clean orphaned resources
                
            Returns:
                Dictionary with cleanup results
            """
            session_id = self.get_session_context()
            
            async with self.logger.trace_context(
                "mcp_tool_cleanup_resources",
                session_id=session_id
            ):
                # Validate admin token
                token_info = await self.validate_token(admin_token, require_admin=True)
                user = token_info.get("name", "unknown")
                
                results = {
                    "orphaned_proxies": [],
                    "orphaned_certificates": [],
                    "orphaned_services": [],
                    "orphaned_routes": []
                }
                
                # Find orphaned proxies (with deleted owner tokens)
                proxies = await self.storage.list_proxy_targets()
                for proxy in proxies:
                    owner_token = await self.storage.get_api_token_by_name(proxy.owner_token)
                    if not owner_token:
                        results["orphaned_proxies"].append(proxy.proxy_hostname)
                        if not orphaned_only:
                            await self.storage.delete_proxy_target(proxy.proxy_hostname)
                
                # Find orphaned certificates
                certs = await self.storage.list_certificates()
                for cert in certs:
                    owner_token = await self.storage.get_api_token_by_name(cert.get("owner_token", ""))
                    if not owner_token:
                        results["orphaned_certificates"].append(cert["cert_name"])
                        if not orphaned_only:
                            await self.storage.delete_certificate(cert["cert_name"])
                
                # Log audit event
                await self.log_audit_event(
                    action="cleanup_resources",
                    session_id=session_id,
                    user=user,
                    details={
                        "orphaned_only": orphaned_only,
                        "found": {
                            "proxies": len(results["orphaned_proxies"]),
                            "certificates": len(results["orphaned_certificates"])
                        }
                    }
                )
                
                results["status"] = "completed"
                results["message"] = f"Found {len(results['orphaned_proxies'])} orphaned proxies, {len(results['orphaned_certificates'])} orphaned certificates"
                
                if not orphaned_only:
                    results["message"] += " (deleted)"
                
                return results