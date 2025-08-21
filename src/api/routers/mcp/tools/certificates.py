"""Certificate management MCP tools."""

from typing import Any, Dict, List, Optional
from datetime import datetime, timezone
import logging

from .base import BaseMCPTools

logger = logging.getLogger(__name__)


class CertificateTools(BaseMCPTools):
    """MCP tools for certificate management."""
    
    def register_tools(self):
        """Register all certificate management tools."""
        
        # Note: cert_list is already defined in mcp_server.py
        # We'll add the extended certificate tools here
        
        @self.mcp.tool(
            annotations={
                "title": "Create SSL Certificate",
                "readOnlyHint": False,
                "destructiveHint": False,
                "idempotentHint": False,
                "openWorldHint": True
            }
        )
        async def cert_create(
            name: str,
            domain: str,
            token: str,
            staging: bool = False,
            email: Optional[str] = None
        ) -> Dict[str, Any]:
            """Create a new SSL certificate.
            
            Args:
                name: Name for the certificate
                domain: Domain for the certificate (can be comma-separated for multiple)
                token: API token for authentication
                staging: Use Let's Encrypt staging environment
                email: Certificate notification email (uses token email if not provided)
                
            Returns:
                Dictionary with certificate creation status
            """
            session_id = self.get_session_context()
            
            async with self.logger.trace_context(
                "mcp_tool_cert_create",
                session_id=session_id,
                cert_name=name,
                domain=domain
            ) as trace_id:
                # Validate token
                token_info = await self.validate_token(token)
                user = token_info.get("name", "unknown")
                cert_email = email or token_info.get("cert_email")
                
                if not cert_email:
                    raise ValueError("Email required for certificate creation")
                
                if not self.cert_manager:
                    raise RuntimeError("Certificate manager not available")
                
                # Parse domains (comma-separated)
                domains = [d.strip() for d in domain.split(",")]
                
                # Check if certificate already exists
                existing = await self.storage.get_certificate(name)
                if existing:
                    raise ValueError(f"Certificate '{name}' already exists")
                
                # Store certificate configuration
                cert_data = {
                    "cert_name": name,
                    "domains": domains,
                    "email": cert_email,
                    "staging": staging,
                    "owner_token": token_info["name"],
                    "created_at": datetime.now(timezone.utc).isoformat()
                }
                
                await self.storage.store_certificate_config(name, cert_data)
                
                # Publish workflow event for certificate creation
                await self.publish_workflow_event(
                    event_type="certificate_requested",
                    hostname=domains[0],
                    data={
                        "cert_name": name,
                        "domains": domains,
                        "email": cert_email,
                        "staging": staging,
                        "requested_by": "mcp",
                        "session_id": session_id,
                        "user": user
                    },
                    trace_id=trace_id
                )
                
                # Log audit event
                await self.log_audit_event(
                    action="cert_create",
                    session_id=session_id,
                    user=user,
                    details={
                        "cert_name": name,
                        "domains": domains,
                        "staging": staging
                    }
                )
                
                return {
                    "status": "requested",
                    "name": name,
                    "domains": domains,
                    "staging": staging,
                    "email": cert_email,
                    "message": f"Certificate '{name}' creation initiated"
                }
        
        @self.mcp.tool(
            annotations={
                "title": "Show Certificate Details",
                "readOnlyHint": True,
                "destructiveHint": False,
                "idempotentHint": True,
                "openWorldHint": False
            }
        )
        async def cert_show(
            name: str,
            pem: bool = False,
            token: Optional[str] = None
        ) -> Dict[str, Any]:
            """Show certificate details.
            
            Args:
                name: Name of the certificate
                pem: Include PEM data in response
                token: Optional API token for ownership check
                
            Returns:
                Dictionary with certificate details
            """
            session_id = self.get_session_context()
            
            async with self.logger.trace_context(
                "mcp_tool_cert_show",
                session_id=session_id,
                cert_name=name
            ):
                # Get certificate
                cert = await self.storage.get_certificate(name)
                if not cert:
                    raise ValueError(f"Certificate '{name}' not found")
                
                # Check ownership if token provided
                user = "anonymous"
                if token:
                    token_info = await self.validate_token(token)
                    user = token_info.get("name", "unknown")
                    
                    # Check if user owns this certificate
                    owner_token = getattr(cert, 'owner_token', None) if hasattr(cert, 'owner_token') else cert.get('owner_token') if isinstance(cert, dict) else None
                    if owner_token != token_info["name"] and token_info["name"].upper() != "ADMIN":
                        raise PermissionError("You can only view certificates you own")
                
                # Parse expiry
                expires_at = None
                expires_at_val = getattr(cert, 'expires_at', None) if hasattr(cert, 'expires_at') else cert.get('expires_at') if isinstance(cert, dict) else None
                if expires_at_val:
                    try:
                        expires_at = datetime.fromisoformat(
                            expires_at_val.replace('Z', '+00:00')
                        )
                    except:
                        pass
                
                # Build response - handle both dict and object
                if isinstance(cert, dict):
                    result = {
                        "name": cert.get("cert_name", ""),
                        "domains": cert.get("domains", []),
                        "email": cert.get("email", ""),
                        "staging": cert.get("staging", False),
                        "owner": cert.get("owner_token", ""),
                        "created_at": cert.get("created_at", ""),
                        "expires_at": expires_at.isoformat() if expires_at else None,
                        "status": "active" if expires_at and expires_at > datetime.now(timezone.utc) else "expired"
                    }
                else:
                    # Handle Pydantic model
                    result = {
                        "name": getattr(cert, 'cert_name', ""),
                        "domains": getattr(cert, 'domains', []),
                        "email": getattr(cert, 'email', ""),
                        "staging": getattr(cert, 'staging', False),
                        "owner": getattr(cert, 'owner_token', ""),
                        "created_at": getattr(cert, 'created_at', ""),
                        "expires_at": expires_at.isoformat() if expires_at else None,
                        "status": "active" if expires_at and expires_at > datetime.now(timezone.utc) else "expired"
                    }
                
                # Include PEM data if requested
                if pem:
                    fullchain_pem = getattr(cert, 'fullchain_pem', None) if hasattr(cert, 'fullchain_pem') else cert.get('fullchain_pem') if isinstance(cert, dict) else None
                    if fullchain_pem:
                        result["fullchain_pem"] = fullchain_pem
                        privkey_pem = getattr(cert, 'privkey_pem', None) if hasattr(cert, 'privkey_pem') else cert.get('privkey_pem') if isinstance(cert, dict) else None
                        if privkey_pem:
                            result["privkey_pem"] = privkey_pem
                
                # Log audit event
                await self.log_audit_event(
                    action="cert_show",
                    session_id=session_id,
                    user=user,
                    details={"cert_name": name, "include_pem": pem}
                )
                
                return result
        
        @self.mcp.tool(
            annotations={
                "title": "Delete SSL Certificate",
                "readOnlyHint": False,
                "destructiveHint": True,
                "idempotentHint": True,
                "openWorldHint": False
            }
        )
        async def cert_delete(
            name: str,
            token: str,
            force: bool = False
        ) -> Dict[str, Any]:
            """Delete a certificate.
            
            Args:
                name: Name of the certificate to delete
                token: API token for authentication
                force: Force deletion even if in use
                
            Returns:
                Dictionary with deletion status
            """
            session_id = self.get_session_context()
            
            async with self.logger.trace_context(
                "mcp_tool_cert_delete",
                session_id=session_id,
                cert_name=name
            ) as trace_id:
                # Validate token
                token_info = await self.validate_token(token)
                user = token_info.get("name", "unknown")
                
                # Get certificate
                cert = await self.storage.get_certificate(name)
                if not cert:
                    raise ValueError(f"Certificate '{name}' not found")
                
                # Check ownership
                owner_token = getattr(cert, 'owner_token', '') if hasattr(cert, 'owner_token') else cert.get('owner_token', '') if isinstance(cert, dict) else ''
                await self.check_ownership(token_info, owner_token, "certificate")
                
                # Check if certificate is in use by proxies
                if not force:
                    proxies = await self.storage.list_proxy_targets()
                    for proxy in proxies:
                        if proxy.cert_name == name:
                            raise ValueError(
                                f"Certificate '{name}' is in use by proxy '{proxy.hostname}'. "
                                "Use force=true to delete anyway."
                            )
                
                # Delete certificate
                success = await self.storage.delete_certificate(name)
                if not success:
                    raise RuntimeError(f"Failed to delete certificate '{name}'")
                
                # Publish workflow event
                domains = getattr(cert, 'domains', [""]) if hasattr(cert, 'domains') else cert.get('domains', [""]) if isinstance(cert, dict) else [""]
                await self.publish_workflow_event(
                    event_type="certificate_deleted",
                    hostname=domains[0] if domains else "",
                    data={
                        "cert_name": name,
                        "deleted_by": "mcp",
                        "session_id": session_id,
                        "user": user,
                        "forced": force
                    },
                    trace_id=trace_id
                )
                
                # Log audit event
                await self.log_audit_event(
                    action="cert_delete",
                    session_id=session_id,
                    user=user,
                    details={"cert_name": name, "forced": force}
                )
                
                return {
                    "status": "deleted",
                    "name": name,
                    "message": f"Certificate '{name}' deleted successfully"
                }
        
        @self.mcp.tool(
            annotations={
                "title": "Renew SSL Certificate",
                "readOnlyHint": False,
                "destructiveHint": False,
                "idempotentHint": True,
                "openWorldHint": True
            }
        )
        async def cert_renew(
            name: str,
            token: str,
            force: bool = False,
            wait: bool = True
        ) -> Dict[str, Any]:
            """Renew a certificate.
            
            Args:
                name: Name of the certificate to renew
                token: API token for authentication
                force: Force renewal even if not near expiry
                wait: Wait for renewal to complete
                
            Returns:
                Dictionary with renewal status
            """
            session_id = self.get_session_context()
            
            async with self.logger.trace_context(
                "mcp_tool_cert_renew",
                session_id=session_id,
                cert_name=name
            ) as trace_id:
                # Validate token
                token_info = await self.validate_token(token)
                user = token_info.get("name", "unknown")
                
                # Get certificate
                cert = await self.storage.get_certificate(name)
                if not cert:
                    raise ValueError(f"Certificate '{name}' not found")
                
                # Check ownership
                owner_token = getattr(cert, 'owner_token', '') if hasattr(cert, 'owner_token') else cert.get('owner_token', '') if isinstance(cert, dict) else ''
                await self.check_ownership(token_info, owner_token, "certificate")
                
                if not self.cert_manager:
                    raise RuntimeError("Certificate manager not available")
                
                # Check if renewal is needed
                expires_at_val = getattr(cert, 'expires_at', None) if hasattr(cert, 'expires_at') else cert.get('expires_at') if isinstance(cert, dict) else None
                if not force and expires_at_val:
                    try:
                        expires_at = datetime.fromisoformat(
                            expires_at_val.replace('Z', '+00:00')
                        )
                        days_until_expiry = (expires_at - datetime.now(timezone.utc)).days
                        if days_until_expiry > 30:
                            return {
                                "status": "not_needed",
                                "name": name,
                                "days_until_expiry": days_until_expiry,
                                "message": f"Certificate '{name}' does not need renewal yet ({days_until_expiry} days until expiry)"
                            }
                    except:
                        pass
                
                # Publish workflow event for renewal
                domains = getattr(cert, 'domains', [""]) if hasattr(cert, 'domains') else cert.get('domains', [""]) if isinstance(cert, dict) else [""]
                await self.publish_workflow_event(
                    event_type="certificate_renewal_requested",
                    hostname=domains[0] if domains else "",
                    data={
                        "cert_name": name,
                        "domains": domains,
                        "forced": force,
                        "requested_by": "mcp",
                        "session_id": session_id,
                        "user": user
                    },
                    trace_id=trace_id
                )
                
                # Log audit event
                await self.log_audit_event(
                    action="cert_renew",
                    session_id=session_id,
                    user=user,
                    details={"cert_name": name, "forced": force}
                )
                
                return {
                    "status": "renewal_initiated",
                    "name": name,
                    "message": f"Certificate '{name}' renewal initiated"
                }
        
        @self.mcp.tool(
            annotations={
                "title": "Convert Certificate to Production",
                "readOnlyHint": False,
                "destructiveHint": False,
                "idempotentHint": False,
                "openWorldHint": True
            }
        )
        async def cert_convert_to_production(
            name: str,
            token: str,
            wait: bool = True,
            force: bool = False
        ) -> Dict[str, Any]:
            """Convert a staging certificate to production.
            
            Args:
                name: Name of the certificate to convert
                token: API token for authentication
                wait: Wait for conversion to complete
                force: Force conversion even if not staging
                
            Returns:
                Dictionary with conversion status
            """
            session_id = self.get_session_context()
            
            async with self.logger.trace_context(
                "mcp_tool_cert_convert",
                session_id=session_id,
                cert_name=name
            ) as trace_id:
                # Validate token
                token_info = await self.validate_token(token)
                user = token_info.get("name", "unknown")
                
                # Get certificate
                cert = await self.storage.get_certificate(name)
                if not cert:
                    raise ValueError(f"Certificate '{name}' not found")
                
                # Check ownership
                owner_token = getattr(cert, 'owner_token', '') if hasattr(cert, 'owner_token') else cert.get('owner_token', '') if isinstance(cert, dict) else ''
                await self.check_ownership(token_info, owner_token, "certificate")
                
                # Check if it's a staging certificate
                is_staging = getattr(cert, 'staging', False) if hasattr(cert, 'staging') else cert.get('staging', False) if isinstance(cert, dict) else False
                if not is_staging and not force:
                    return {
                        "status": "already_production",
                        "name": name,
                        "message": f"Certificate '{name}' is already a production certificate"
                    }
                
                if not self.cert_manager:
                    raise RuntimeError("Certificate manager not available")
                
                # Update certificate configuration
                if isinstance(cert, dict):
                    cert["staging"] = False
                else:
                    cert.staging = False
                await self.storage.store_certificate_config(name, cert)
                
                # Publish workflow event for conversion
                domains = getattr(cert, 'domains', [""]) if hasattr(cert, 'domains') else cert.get('domains', [""]) if isinstance(cert, dict) else [""]
                await self.publish_workflow_event(
                    event_type="certificate_convert_to_production",
                    hostname=domains[0] if domains else "",
                    data={
                        "cert_name": name,
                        "domains": domains,
                        "requested_by": "mcp",
                        "session_id": session_id,
                        "user": user
                    },
                    trace_id=trace_id
                )
                
                # Log audit event
                await self.log_audit_event(
                    action="cert_convert_to_production",
                    session_id=session_id,
                    user=user,
                    details={"cert_name": name}
                )
                
                return {
                    "status": "conversion_initiated",
                    "name": name,
                    "message": f"Certificate '{name}' conversion to production initiated"
                }