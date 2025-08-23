"""Token management MCP tools."""

import secrets
from typing import Any, Dict, List, Optional
from datetime import datetime, timezone
import logging

from .base import BaseMCPTools

logger = logging.getLogger(__name__)


class TokenTools(BaseMCPTools):
    """MCP tools for token management."""
    
    def register_tools(self):
        """Register all token management tools."""
        
        @self.mcp.tool(
            annotations={
                "title": "Generate API Token",
                "readOnlyHint": False,
                "destructiveHint": False,
                "idempotentHint": False,
                "openWorldHint": False
            }
        )
        async def token_generate(
            name: str,
            email: str,
            admin_token: str
        ) -> Dict[str, Any]:
            """Generate a new API token.
            
            Args:
                name: Name for the token
                email: Certificate email for the token
                admin_token: Admin token for authentication
                
            Returns:
                Dictionary with token details including the generated token value
            """
            session_id = self.get_session_context()
            
            async with self.logger.trace_context(
                "mcp_tool_token_generate",
                session_id=session_id,
                token_name=name
            ):
                # Validate admin token
                token_info = await self.validate_token(admin_token, require_admin=True)
                user = token_info.get("name", "unknown")
                
                # Check if token name already exists
                existing = await self.storage.get_api_token_by_name(name)
                if existing:
                    raise ValueError(f"Token '{name}' already exists")
                
                # Prevent creating tokens with reserved names
                if name.upper() == "ADMIN":
                    raise ValueError("Cannot create token with reserved name 'ADMIN'")
                
                # Generate secure token
                token_value = f"acm_{secrets.token_urlsafe(32)}"
                
                # Store token
                result = await self.storage.store_api_token(name, token_value, cert_email=email)
                if not result:
                    raise RuntimeError("Failed to create token")
                
                # Log audit event
                await self.log_audit_event(
                    action="token_generate",
                    session_id=session_id,
                    user=user,
                    details={"token_name": name, "cert_email": email}
                )
                
                return {
                    "status": "created",
                    "name": name,
                    "token": token_value,
                    "cert_email": email,
                    "created_at": datetime.now(timezone.utc).isoformat(),
                    "message": f"Token '{name}' created successfully. Save the token value - it cannot be retrieved again!"
                }
        
        @self.mcp.tool(
            annotations={
                "title": "List API Tokens",
                "readOnlyHint": True,
                "destructiveHint": False,
                "idempotentHint": True,
                "openWorldHint": False
            }
        )
        async def token_list(
            admin_token: Optional[str] = None
        ) -> Dict[str, Any]:
            """List all API tokens.
            
            Args:
                admin_token: Admin token for authentication (optional for read-only)
                
            Returns:
                Dictionary with list of tokens and their details
            """
            session_id = self.get_session_context()
            
            async with self.logger.trace_context(
                "mcp_tool_token_list",
                session_id=session_id
            ):
                # Admin token optional for listing (read-only operation)
                user = "anonymous"
                if admin_token:
                    try:
                        token_info = await self.validate_token(admin_token)
                        user = token_info.get("name", "unknown")
                    except:
                        pass
                
                tokens = []
                
                # Get all token keys by scanning
                async for key in self.storage.redis_client.scan_iter(match="token:*"):
                    # Decode byte string if needed
                    if isinstance(key, bytes):
                        key = key.decode('utf-8')
                    
                    # Skip if it's not a direct token key
                    parts = key.split(":")
                    if len(parts) != 2:
                        continue
                    
                    token_name = parts[1]
                    token_data = await self.storage.get_api_token_by_name(token_name)
                    
                    if token_data:
                        # Count owned resources
                        cert_count = await self.storage.count_certificates_by_owner(token_data['hash'])
                        proxy_count = await self.storage.count_proxies_by_owner(token_data['hash'])
                        
                        # Parse created_at
                        created_at = datetime.now(timezone.utc)
                        if 'created_at' in token_data:
                            try:
                                created_at = datetime.fromisoformat(
                                    token_data['created_at'].replace('Z', '+00:00')
                                )
                            except:
                                pass
                        
                        tokens.append({
                            "name": token_data['name'],
                            "cert_email": token_data.get('cert_email', ''),
                            "created_at": created_at.isoformat(),
                            "certificate_count": cert_count,
                            "proxy_count": proxy_count,
                            "is_admin": (token_data['name'].upper() == 'ADMIN')
                        })
                
                # Sort by name
                tokens.sort(key=lambda t: t['name'])
                
                # Log audit event
                await self.log_audit_event(
                    action="token_list",
                    session_id=session_id,
                    user=user,
                    details={"count": len(tokens)}
                )
                
                return {
                    "tokens": tokens,
                    "count": len(tokens)
                }
        
        @self.mcp.tool(
            annotations={
                "title": "Show Token Details",
                "readOnlyHint": True,
                "destructiveHint": False,
                "idempotentHint": True,
                "openWorldHint": False
            }
        )
        async def token_show(
            name: str,
            admin_token: str
        ) -> Dict[str, Any]:
            """Show detailed information about a specific token.
            
            Args:
                name: Name of the token to show
                admin_token: Admin token for authentication
                
            Returns:
                Dictionary with full token details including owned resources
            """
            session_id = self.get_session_context()
            
            async with self.logger.trace_context(
                "mcp_tool_token_show",
                session_id=session_id,
                token_name=name
            ):
                # Validate admin token
                token_info = await self.validate_token(admin_token, require_admin=True)
                user = token_info.get("name", "unknown")
                
                # Get token data
                token_data = await self.storage.get_api_token_by_name(name)
                if not token_data:
                    raise ValueError(f"Token '{name}' not found")
                
                # Get owned resources
                certificates = await self.storage.list_certificate_names_by_owner(token_data['hash'])
                proxies = await self.storage.list_proxy_names_by_owner(token_data['hash'])
                
                # Parse created_at
                created_at = datetime.now(timezone.utc)
                if 'created_at' in token_data:
                    try:
                        created_at = datetime.fromisoformat(
                            token_data['created_at'].replace('Z', '+00:00')
                        )
                    except:
                        pass
                
                # Log audit event
                await self.log_audit_event(
                    action="token_show",
                    session_id=session_id,
                    user=user,
                    details={"token_name": name}
                )
                
                return {
                    "name": token_data['name'],
                    "token": token_data['token'],  # Full token for admin
                    "cert_email": token_data.get('cert_email', ''),
                    "created_at": created_at.isoformat(),
                    "certificate_count": len(certificates),
                    "proxy_count": len(proxies),
                    "is_admin": (token_data['name'].upper() == 'ADMIN'),
                    "certificates": certificates,
                    "proxies": proxies
                }
        
        @self.mcp.tool(
            annotations={
                "title": "Delete API Token",
                "readOnlyHint": False,
                "destructiveHint": True,
                "idempotentHint": True,
                "openWorldHint": False
            }
        )
        async def token_delete(
            name: str,
            admin_token: str,
            cascade: bool = True
        ) -> Dict[str, Any]:
            """Delete an API token.
            
            Args:
                name: Name of the token to delete
                admin_token: Admin token for authentication
                cascade: Whether to delete owned resources (default: True)
                
            Returns:
                Dictionary with deletion status and affected resources
            """
            session_id = self.get_session_context()
            
            async with self.logger.trace_context(
                "mcp_tool_token_delete",
                session_id=session_id,
                token_name=name
            ) as trace_id:
                # Validate admin token
                token_info = await self.validate_token(admin_token, require_admin=True)
                user = token_info.get("name", "unknown")
                
                # Prevent deleting admin token
                if name.upper() == "ADMIN":
                    raise ValueError("Cannot delete the ADMIN token")
                
                # Get token to check it exists
                token_data = await self.storage.get_api_token_by_name(name)
                if not token_data:
                    raise ValueError(f"Token '{name}' not found")
                
                # Delete token (with cascade if requested)
                if cascade:
                    result = await self.storage.delete_api_token_cascade_by_name(name)
                    deleted_certs = result.get('deleted_certificates', [])
                    deleted_proxies = result.get('deleted_proxies', [])
                else:
                    success = await self.storage.delete_api_token_by_name(name)
                    if not success:
                        raise RuntimeError(f"Failed to delete token '{name}'")
                    deleted_certs = []
                    deleted_proxies = []
                
                # Publish workflow events for cascaded deletions
                for proxy in deleted_proxies:
                    await self.publish_workflow_event(
                        event_type="proxy_deleted", proxy_hostname=proxy,
                        data={
                            "deleted_by": "mcp_token_cascade",
                            "session_id": session_id,
                            "user": user
                        },
                        trace_id=trace_id
                    )
                
                # Log audit event
                await self.log_audit_event(
                    action="token_delete",
                    session_id=session_id,
                    user=user,
                    details={
                        "token_name": name,
                        "cascade": cascade,
                        "deleted_certificates": deleted_certs,
                        "deleted_proxies": deleted_proxies
                    }
                )
                
                return {
                    "status": "deleted",
                    "name": name,
                    "deleted_certificates": deleted_certs,
                    "deleted_proxies": deleted_proxies,
                    "message": f"Token '{name}' deleted successfully"
                }
        
        @self.mcp.tool(
            annotations={
                "title": "Update Token Email",
                "readOnlyHint": False,
                "destructiveHint": False,
                "idempotentHint": True,
                "openWorldHint": False
            }
        )
        async def token_email(
            email: str,
            token: str
        ) -> Dict[str, Any]:
            """Update certificate email for the current token.
            
            Args:
                email: New certificate email address
                token: API token (updates its own email)
                
            Returns:
                Dictionary with update status
            """
            session_id = self.get_session_context()
            
            async with self.logger.trace_context(
                "mcp_tool_token_email",
                session_id=session_id,
                new_email=email
            ):
                # Validate token
                token_info = await self.validate_token(token)
                user = token_info.get("name", "unknown")
                
                # Update email
                success = await self.storage.update_api_token_email(token, email)
                if not success:
                    raise RuntimeError("Failed to update token email")
                
                # Log audit event
                await self.log_audit_event(
                    action="token_email",
                    session_id=session_id,
                    user=user,
                    details={
                        "token_name": user,
                        "new_email": email
                    }
                )
                
                return {
                    "status": "updated",
                    "name": user,
                    "cert_email": email,
                    "message": f"Certificate email updated successfully for token '{user}'"
                }