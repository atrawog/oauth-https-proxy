"""OAuth management MCP tools."""

import secrets
from typing import Any, Dict, List, Optional
from datetime import datetime, timezone
import logging

from .base import BaseMCPTools

logger = logging.getLogger(__name__)


class OAuthTools(BaseMCPTools):
    """MCP tools for OAuth management."""
    
    def register_tools(self):
        """Register all OAuth management tools."""
        
        @self.mcp.tool(
            annotations={
                "title": "Register OAuth Client",
                "readOnlyHint": False,
                "destructiveHint": False,
                "idempotentHint": False,
                "openWorldHint": False
            }
        )
        async def oauth_client_register(
            name: str,
            redirect_uri: str,
            scope: str,
            admin_token: str
        ) -> Dict[str, Any]:
            """Register a new OAuth client.
            
            Args:
                name: Client name
                redirect_uri: Redirect URI for the client
                scope: Space-separated list of scopes
                admin_token: Admin token for authentication
                
            Returns:
                Dictionary with client registration details
            """
            session_id = self.get_session_context()
            
            async with self.logger.trace_context(
                "mcp_tool_oauth_client_register",
                session_id=session_id,
                client_name=name
            ):
                # Validate admin token
                token_info = await self.validate_token(admin_token, require_admin=True)
                user = token_info.get("name", "unknown")
                
                # Create client configuration
                client_config = {
                    "name": name,
                    "redirect_uris": [redirect_uri],
                    "scopes": scope.split(),
                    "created_at": datetime.now(timezone.utc).isoformat()
                }
                
                # Register client (would integrate with OAuth server)
                client_id = f"client_{name.lower().replace(' ', '_')}"
                client_secret = f"secret_{secrets.token_urlsafe(32)}"
                
                # Store client configuration in Redis
                import json
                client_data = {
                    **client_config,
                    "client_id": client_id,
                    "client_secret": client_secret
                }
                await self.storage.redis_client.set(
                    f"oauth:client:{client_id}",
                    json.dumps(client_data)
                )
                
                # Log audit event
                await self.log_audit_event(
                    action="oauth_client_register",
                    session_id=session_id,
                    user=user,
                    details={"client_id": client_id, "name": name}
                )
                
                return {
                    "status": "registered",
                    "client_id": client_id,
                    "client_secret": client_secret,
                    "name": name,
                    "redirect_uri": redirect_uri,
                    "scopes": scope,
                    "message": f"OAuth client '{name}' registered successfully"
                }
        
        @self.mcp.tool(
            annotations={
                "title": "List OAuth Clients",
                "readOnlyHint": True,
                "destructiveHint": False,
                "idempotentHint": True,
                "openWorldHint": False
            }
        )
        async def oauth_clients_list(
            active_only: bool = False,
            page: int = 1,
            per_page: int = 50,
            admin_token: Optional[str] = None
        ) -> Dict[str, Any]:
            """List registered OAuth clients.
            
            Args:
                active_only: Only show active clients
                page: Page number for pagination
                per_page: Items per page
                admin_token: Optional admin token for full details
                
            Returns:
                Dictionary with list of OAuth clients
            """
            session_id = self.get_session_context()
            
            async with self.logger.trace_context(
                "mcp_tool_oauth_clients_list",
                session_id=session_id
            ):
                user = "anonymous"
                show_secrets = False
                
                if admin_token:
                    try:
                        token_info = await self.validate_token(admin_token, require_admin=True)
                        user = token_info.get("name", "unknown")
                        show_secrets = True
                    except:
                        pass
                
                # Get OAuth clients from Redis
                clients = []
                try:
                    # Get all OAuth client keys
                    client_keys = await self.storage.redis_client.keys("oauth:client:*")
                    for key in client_keys:
                        if isinstance(key, bytes):
                            key = key.decode('utf-8')
                        client_data = await self.storage.redis_client.get(key)
                        if client_data:
                            import json
                            if isinstance(client_data, bytes):
                                client_data = client_data.decode('utf-8')
                            client = json.loads(client_data)
                            clients.append(client)
                except Exception as e:
                    logger.warning(f"Error listing OAuth clients: {e}")
                    clients = []
                
                # Filter active only if requested
                if active_only:
                    clients = [c for c in clients if c.get("active", True)]
                
                # Paginate
                start_idx = (page - 1) * per_page
                end_idx = start_idx + per_page
                paginated_clients = clients[start_idx:end_idx]
                
                # Format response
                client_list = []
                for client in paginated_clients:
                    client_data = {
                        "client_id": client["client_id"],
                        "name": client.get("name", ""),
                        "redirect_uris": client.get("redirect_uris", []),
                        "scopes": client.get("scopes", []),
                        "created_at": client.get("created_at", ""),
                        "active": client.get("active", True)
                    }
                    
                    # Include secret only for admin
                    if show_secrets:
                        client_data["client_secret"] = client.get("client_secret", "")
                    
                    client_list.append(client_data)
                
                # Log audit event
                await self.log_audit_event(
                    action="oauth_clients_list",
                    session_id=session_id,
                    user=user,
                    details={"page": page, "count": len(client_list)}
                )
                
                return {
                    "clients": client_list,
                    "pagination": {
                        "page": page,
                        "per_page": per_page,
                        "total": len(clients),
                        "total_pages": (len(clients) + per_page - 1) // per_page
                    }
                }
        
        @self.mcp.tool(
            annotations={
                "title": "List OAuth Tokens",
                "readOnlyHint": True,
                "destructiveHint": False,
                "idempotentHint": True,
                "openWorldHint": False
            }
        )
        async def oauth_token_list(
            token_type: Optional[str] = None,
            client_id: Optional[str] = None,
            username: Optional[str] = None,
            page: int = 1,
            per_page: int = 50,
            include_expired: bool = False,
            admin_token: str = None
        ) -> Dict[str, Any]:
            """List OAuth access and refresh tokens.
            
            Args:
                token_type: Filter by token type (access, refresh)
                client_id: Filter by client ID
                username: Filter by username
                page: Page number for pagination
                per_page: Items per page
                include_expired: Include expired tokens
                admin_token: Admin token for authentication (required)
                
            Returns:
                Dictionary with list of OAuth tokens
            """
            session_id = self.get_session_context()
            
            async with self.logger.trace_context(
                "mcp_tool_oauth_token_list",
                session_id=session_id
            ):
                # Validate admin token
                token_info = await self.validate_token(admin_token, require_admin=True)
                user = token_info.get("name", "unknown")
                
                # Query OAuth tokens
                filters = {}
                if token_type:
                    filters["token_type"] = token_type
                if client_id:
                    filters["client_id"] = client_id
                if username:
                    filters["username"] = username
                
                tokens = await self.storage.list_oauth_tokens(filters)
                
                # Filter expired if requested
                if not include_expired:
                    now = datetime.now(timezone.utc)
                    tokens = [
                        t for t in tokens
                        if not t.get("expires_at") or 
                        datetime.fromisoformat(t["expires_at"]) > now
                    ]
                
                # Paginate
                start_idx = (page - 1) * per_page
                end_idx = start_idx + per_page
                paginated_tokens = tokens[start_idx:end_idx]
                
                # Format response (don't include actual token values)
                token_list = []
                for token in paginated_tokens:
                    token_list.append({
                        "token_id": token.get("jti", ""),
                        "token_type": token.get("token_type", ""),
                        "client_id": token.get("client_id", ""),
                        "username": token.get("username", ""),
                        "scopes": token.get("scopes", []),
                        "created_at": token.get("created_at", ""),
                        "expires_at": token.get("expires_at", ""),
                        "active": token.get("active", True)
                    })
                
                # Log audit event
                await self.log_audit_event(
                    action="oauth_token_list",
                    session_id=session_id,
                    user=user,
                    details={
                        "filters": filters,
                        "page": page,
                        "count": len(token_list)
                    }
                )
                
                return {
                    "tokens": token_list,
                    "pagination": {
                        "page": page,
                        "per_page": per_page,
                        "total": len(tokens),
                        "total_pages": (len(tokens) + per_page - 1) // per_page
                    }
                }
        
        @self.mcp.tool(
            annotations={
                "title": "List OAuth Sessions",
                "readOnlyHint": True,
                "destructiveHint": False,
                "idempotentHint": True,
                "openWorldHint": False
            }
        )
        async def oauth_sessions_list(
            admin_token: str
        ) -> Dict[str, Any]:
            """List active OAuth sessions.
            
            Args:
                admin_token: Admin token for authentication (required)
                
            Returns:
                Dictionary with list of active sessions
            """
            session_id = self.get_session_context()
            
            async with self.logger.trace_context(
                "mcp_tool_oauth_sessions_list",
                session_id=session_id
            ):
                # Validate admin token
                token_info = await self.validate_token(admin_token, require_admin=True)
                user = token_info.get("name", "unknown")
                
                # Get active sessions
                sessions = await self.storage.list_oauth_sessions()
                
                # Format response
                session_list = []
                for session in sessions:
                    session_list.append({
                        "session_id": session["session_id"],
                        "username": session.get("username", ""),
                        "client_id": session.get("client_id", ""),
                        "created_at": session.get("created_at", ""),
                        "last_activity": session.get("last_activity", ""),
                        "ip_address": session.get("ip_address", "")
                    })
                
                # Log audit event
                await self.log_audit_event(
                    action="oauth_sessions_list",
                    session_id=session_id,
                    user=user,
                    details={"count": len(session_list)}
                )
                
                return {
                    "sessions": session_list,
                    "count": len(session_list)
                }