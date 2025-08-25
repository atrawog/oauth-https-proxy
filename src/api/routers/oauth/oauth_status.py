"""OAuth Status API for monitoring OAuth clients, tokens, and sessions.

This module provides read-only endpoints to inspect the OAuth system state
by directly accessing Redis data from the OAuth server.
"""

import asyncio
import json
import logging
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Optional, Any, Tuple
from collections import defaultdict
import hashlib

from fastapi import APIRouter, Query, HTTPException, Depends, Request
from pydantic import BaseModel, Field

# Authentication is handled by proxy, API trusts headers
from ....storage import UnifiedStorage

logger = logging.getLogger(__name__)

# Sensitive fields that should never be exposed
SENSITIVE_FIELDS = {
    "client_secret", "client_secret_hash",
    "registration_access_token", "token_value",
    "refresh_token", "access_token", "private_key",
    "password", "secret"
}

# Pydantic models for responses
class ClientSummary(BaseModel):
    client_id: str
    client_name: Optional[str]
    created_at: str
    expires_at: Optional[str]
    is_active: bool
    days_until_expiry: Optional[int]
    token_count: int = 0
    last_token_issued: Optional[str] = None
    registration_client_uri: Optional[str] = None
    last_used: Optional[str] = None
    usage_count: int = 0

class ClientDetail(BaseModel):
    client_id: str
    client_name: Optional[str]
    created_at: str
    expires_at: Optional[str]
    is_active: bool
    metadata: Dict[str, Any] = {}
    usage_stats: Dict[str, Any] = {}
    proxy_associations: List[Dict[str, Any]] = []

class TokenSummary(BaseModel):
    jti: str
    token_type: str  # "access" or "refresh"
    client_id: Optional[str]
    client_name: Optional[str]
    user_id: Optional[str]
    username: Optional[str]
    issued_at: str
    expires_at: str
    is_expired: bool
    time_remaining: Optional[str]  # e.g., "5m", "2h", "expired"
    scope: Optional[str]
    audience: Optional[List[str]] = []  # Resource URIs
    last_used: Optional[str] = None
    usage_count: int = 0

class TokenDetail(BaseModel):
    jti: str
    token_type: str
    client_id: Optional[str]
    client_name: Optional[str]
    user: Dict[str, Any] = {}
    issued_at: str
    expires_at: str
    is_expired: bool
    time_until_expiry: Optional[int]
    scope: Optional[str]
    claims: Dict[str, Any] = {}
    usage: Dict[str, Any] = {}

class SessionSummary(BaseModel):
    session_id: str
    user_id: str
    username: Optional[str]
    email: Optional[str]
    created_at: str
    last_activity: str
    duration_minutes: int
    active_tokens: int
    accessed_proxies: List[str] = []

class OAuthMetrics(BaseModel):
    timestamp: str
    clients: Dict[str, Any]
    tokens: Dict[str, Any]
    auth_flows: Dict[str, Any]
    errors: Dict[str, Any]

class OAuthHealth(BaseModel):
    status: str
    checks: Dict[str, str]
    last_successful_auth: Optional[str]
    auth_proxy: Dict[str, Any]

class ProxyOAuthStatus(BaseModel):
    hostname: str
    auth_enabled: bool
    auth_mode: Optional[str]
    auth_proxy: Optional[str]
    active_sessions: int
    recent_auth_failures: int
    last_auth_success: Optional[str]

def filter_sensitive(data: Dict[str, Any]) -> Dict[str, Any]:
    """Remove sensitive fields from data."""
    if not isinstance(data, dict):
        return data
    
    filtered = {}
    for key, value in data.items():
        # Skip if key contains sensitive terms
        if any(term in key.lower() for term in SENSITIVE_FIELDS):
            continue
        
        # Recursively filter nested dicts
        if isinstance(value, dict):
            filtered[key] = filter_sensitive(value)
        elif isinstance(value, list):
            # Filter lists of dicts
            filtered[key] = [
                filter_sensitive(item) if isinstance(item, dict) else item
                for item in value
            ]
        else:
            filtered[key] = value
    
    return filtered

def hash_token_id(token_id: str) -> str:
    """Hash token ID for security."""
    return hashlib.sha256(token_id.encode()).hexdigest()[:16]

def parse_timestamp(timestamp: Any) -> datetime:
    """Parse various timestamp formats."""
    if isinstance(timestamp, (int, float)):
        return datetime.fromtimestamp(timestamp, tz=timezone.utc)
    elif isinstance(timestamp, str):
        try:
            return datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
        except:
            return datetime.now(timezone.utc)
    else:
        return datetime.now(timezone.utc)

def format_timestamp(dt: datetime) -> str:
    """Format datetime to ISO string."""
    return dt.isoformat().replace('+00:00', 'Z')

class OAuthStatusRouter:
    """OAuth status API router."""
    
    def __init__(self, storage: RedisStorage):
        self.storage = storage
        self.router = APIRouter(tags=["oauth"])
        self._setup_routes()
    
    def _setup_routes(self):
        """Setup all OAuth status routes.
        
        Note on Authentication:
        Most OAuth status endpoints are intentionally public to support monitoring and debugging.
        - All endpoints filter sensitive data (tokens, secrets, keys)
        - Session revocation requires authentication to prevent abuse
        - Public access enables health monitoring by external systems
        - Consider adding authentication if deployment requires stricter access control
        """
        # Client management endpoints
        self.router.get("/clients", response_model=Dict)(self.list_clients)
        self.router.get("/clients/{client_id}", response_model=ClientDetail)(self.get_client)
        self.router.get("/clients/{client_id}/tokens", response_model=Dict)(self.list_client_tokens)
        
        # Token status endpoints
        self.router.get("/tokens", response_model=Dict)(self.list_tokens)
        self.router.get("/tokens/{jti}", response_model=TokenDetail)(self.get_token_detail)
        
        # Session management endpoints
        self.router.get("/sessions", response_model=Dict)(self.list_sessions)
        self.router.get("/sessions/{session_id}", response_model=SessionSummary)(self.get_session)
        self.router.delete("/sessions/{session_id}")(self.revoke_session)
        
        # Monitoring endpoints
        self.router.get("/metrics", response_model=OAuthMetrics)(self.get_metrics)
        self.router.get("/health", response_model=OAuthHealth)(self.check_health)
        
        # Proxy integration endpoints
        self.router.get("/proxies", response_model=Dict)(self.list_proxy_oauth_status)
        self.router.get("/proxies/{proxy_hostname}/sessions", response_model=Dict)(self.list_proxy_sessions)
    
    async def list_clients(
        self,
        active_only: bool = Query(True, description="Show only non-expired clients"),
        page: int = Query(1, ge=1, description="Page number"),
        per_page: int = Query(20, ge=1, le=100, description="Items per page"),
        sort_by: str = Query("created_at", description="Sort field"),
        order: str = Query("desc", description="Sort order (asc/desc)")
    ) -> Dict:
        """List all registered OAuth clients."""
        try:
            # Scan for OAuth client keys
            clients = []
            client_pattern = "oauth:client:*"
            
            for key in self.storage.redis_client.scan_iter(match=client_pattern):
                client_data = self.storage.redis_client.get(key)
                if client_data:
                    try:
                        client = json.loads(client_data)
                        # Filter sensitive fields
                        client = filter_sensitive(client)
                        
                        # Parse timestamps
                        created_at = parse_timestamp(client.get("created_at", 0))
                        expires_at = None
                        is_active = True
                        days_until_expiry = None
                        
                        if "client_secret_expires_at" in client:
                            expires_at = parse_timestamp(client["client_secret_expires_at"])
                            is_active = expires_at > datetime.now(timezone.utc)
                            if is_active:
                                days_until_expiry = (expires_at - datetime.now(timezone.utc)).days
                        
                        # Skip expired if active_only
                        if active_only and not is_active:
                            continue
                        
                        # Count tokens for this client using the client_tokens set
                        client_id = client.get("client_id")
                        token_count = 0
                        if client_id:
                            token_key = f"oauth:client_tokens:{client_id}"
                            token_count = self.storage.redis_client.scard(token_key)
                            # Debug logging
                            if client_id == "client_Ebb8g95l9shqpxykc0pmBg":
                                logger.info(f"DEBUG: Token count for {client_id}: {token_count} (key: {token_key})")
                        
                        # Get last token issued timestamp
                        last_token_issued = None
                        if client.get("last_token_issued"):
                            last_token_issued = format_timestamp(parse_timestamp(client["last_token_issued"]))
                        
                        # Get last used timestamp
                        last_used = None
                        if client.get("last_used"):
                            last_used = format_timestamp(parse_timestamp(client["last_used"]))
                        
                        # Get usage count
                        usage_count = client.get("usage_count", 0)
                        
                        clients.append({
                            "client_id": client_id,
                            "client_name": client.get("client_name"),
                            "created_at": format_timestamp(created_at),
                            "expires_at": format_timestamp(expires_at) if expires_at else None,
                            "is_active": is_active,
                            "days_until_expiry": days_until_expiry,
                            "token_count": token_count,
                            "last_token_issued": last_token_issued,
                            "registration_client_uri": client.get("registration_client_uri"),
                            "last_used": last_used,
                            "usage_count": usage_count
                        })
                    except Exception as e:
                        logger.error(f"Error parsing client data: {e}")
                        continue
            
            # Sort clients - primary by last_used (desc), secondary by created_at (desc)
            # Clients with no last_used (never used) should appear after used clients
            reverse = (order == "desc")
            
            # Custom sort: last_used first (most recent), then created_at
            def sort_key(client):
                # For last_used, None should sort last (treat as epoch 0)
                last_used = client.get("last_used")
                if last_used:
                    # Convert ISO format back to timestamp for sorting
                    try:
                        dt = datetime.fromisoformat(last_used.replace('Z', '+00:00'))
                        last_used_ts = dt.timestamp()
                    except:
                        last_used_ts = 0
                else:
                    last_used_ts = 0
                
                # For created_at, use as secondary sort
                created_at = client.get("created_at", "")
                try:
                    dt = datetime.fromisoformat(created_at.replace('Z', '+00:00'))
                    created_at_ts = dt.timestamp()
                except:
                    created_at_ts = 0
                
                # Return tuple for two-level sort
                return (last_used_ts, created_at_ts)
            
            # Sort with most recently used first, then most recently created
            clients.sort(key=sort_key, reverse=True)
            
            # Paginate
            total = len(clients)
            start = (page - 1) * per_page
            end = start + per_page
            paginated_clients = clients[start:end]
            
            # Summary stats
            active_count = sum(1 for c in clients if c["is_active"])
            expired_count = total - active_count
            
            return {
                "clients": paginated_clients,
                "pagination": {
                    "total": total,
                    "page": page,
                    "per_page": per_page,
                    "pages": (total + per_page - 1) // per_page
                },
                "summary": {
                    "total_clients": total,
                    "active_clients": active_count,
                    "expired_clients": expired_count
                }
            }
            
        except Exception as e:
            logger.error(f"Error listing OAuth clients: {e}")
            raise HTTPException(500, f"Failed to list OAuth clients: {str(e)}")
    
    async def get_client(self, client_id: str) -> ClientDetail:
        """Get detailed information about a specific OAuth client."""
        try:
            # Get client data
            client_key = f"oauth:client:{client_id}"
            client_data = self.storage.redis_client.get(client_key)
            
            if not client_data:
                raise HTTPException(404, f"OAuth client not found: {client_id}")
            
            client = json.loads(client_data)
            client = filter_sensitive(client)
            
            # Parse timestamps
            created_at = parse_timestamp(client.get("created_at", 0))
            expires_at = None
            is_active = True
            
            if "client_secret_expires_at" in client:
                expires_at = parse_timestamp(client["client_secret_expires_at"])
                is_active = expires_at > datetime.now(timezone.utc)
            
            # Get proxy associations
            proxy_associations = []
            proxies = self.storage.list_proxy_targets()
            for proxy in proxies:
                if proxy.auth_enabled and proxy.auth_proxy:
                    # Check if any sessions for this client accessed this proxy
                    proxy_associations.append({
                        "proxy_hostname": proxy.proxy_hostname,
                        "auth_enabled": proxy.auth_enabled,
                        "auth_mode": proxy.auth_mode,
                        "active_sessions": 0  # TODO: Count active sessions
                    })
            
            return ClientDetail(
                client_id=client.get("client_id"),
                client_name=client.get("client_name"),
                created_at=format_timestamp(created_at),
                expires_at=format_timestamp(expires_at) if expires_at else None,
                is_active=is_active,
                metadata={
                    "software_id": client.get("software_id"),
                    "software_version": client.get("software_version"),
                    "redirect_uris": json.loads(client.get("redirect_uris", "[]")),
                    "grant_types": json.loads(client.get("grant_types", "[]")),
                    "response_types": json.loads(client.get("response_types", "[]")),
                    "scope": client.get("scope")
                },
                usage_stats={
                    "total_tokens_issued": 0,  # TODO: Implement
                    "active_tokens": 0,  # TODO: Implement
                    "total_authorizations": 0,  # TODO: Implement
                    "failed_authorizations": 0,  # TODO: Implement
                    "last_authorization": None  # TODO: Implement
                },
                proxy_associations=proxy_associations
            )
            
        except HTTPException:
            raise
        except Exception as e:
            logger.error(f"Error getting OAuth client {client_id}: {e}")
            raise HTTPException(500, f"Failed to get OAuth client: {str(e)}")
    
    async def list_client_tokens(self, client_id: str) -> Dict:
        """List tokens issued to a specific client."""
        # TODO: Implement when token storage pattern is known
        return {
            "tokens": [],
            "summary": {
                "total_tokens": 0,
                "active_tokens": 0,
                "expired_tokens": 0
            }
        }
    
    async def list_tokens(
        self,
        token_type: Optional[str] = Query(None, description="Filter by token type (access/refresh)"),
        include_expired: bool = Query(False, description="Include expired tokens"),
        username: Optional[str] = Query(None, description="Filter by username"),
        client_id: Optional[str] = Query(None, description="Filter by client ID"),
        page: int = Query(1, ge=1, description="Page number"),
        per_page: int = Query(50, ge=1, le=100, description="Items per page")
    ) -> Dict:
        """List all OAuth tokens with detailed information."""
        try:
            tokens = []
            now = datetime.now(timezone.utc)
            
            # Get client mapping for names
            client_names = {}
            for key in self.storage.redis_client.scan_iter(match="oauth:client:*"):
                client_data = self.storage.redis_client.get(key)
                if client_data:
                    try:
                        client = json.loads(client_data)
                        client_names[client.get("client_id")] = client.get("client_name", "Unknown")
                    except:
                        pass
            
            # Scan for access tokens
            if not token_type or token_type == "access":
                for key in self.storage.redis_client.scan_iter(match="oauth:token:*"):
                    token_data = self.storage.redis_client.get(key)
                    if token_data:
                        try:
                            token = json.loads(token_data)
                            jti = key.decode() if isinstance(key, bytes) else key
                            jti = jti.replace("oauth:token:", "")
                            
                            # Parse timestamps
                            issued_at = parse_timestamp(token.get("iat", token.get("created_at", 0)))
                            expires_at = parse_timestamp(token.get("exp", token.get("expires_at", 0)))
                            is_expired = expires_at <= now
                            
                            # Skip expired tokens if not requested
                            if not include_expired and is_expired:
                                continue
                            
                            # Apply filters
                            if username and token.get("username") != username:
                                continue
                            if client_id and token.get("client_id") != client_id:
                                continue
                            
                            # Calculate time remaining
                            time_remaining = None
                            if is_expired:
                                time_remaining = "expired"
                            else:
                                diff = expires_at - now
                                if diff.days > 0:
                                    time_remaining = f"{diff.days}d"
                                elif diff.seconds > 3600:
                                    time_remaining = f"{diff.seconds // 3600}h"
                                else:
                                    time_remaining = f"{diff.seconds // 60}m"
                            
                            # Get audience (resource URIs)
                            audience = token.get("aud", [])
                            if isinstance(audience, str):
                                audience = [audience]
                            
                            # Get usage data for this token
                            last_used = None
                            usage_count = 0
                            usage_key = f"oauth:token_usage:{jti}"
                            usage_data = self.storage.redis_client.get(usage_key)
                            if usage_data:
                                try:
                                    usage = json.loads(usage_data)
                                    if usage.get("last_used"):
                                        last_used = format_timestamp(parse_timestamp(usage["last_used"]))
                                    usage_count = usage.get("usage_count", 0)
                                except:
                                    pass
                            
                            tokens.append({
                                "jti": jti,
                                "token_type": "access",
                                "client_id": token.get("client_id"),
                                "client_name": client_names.get(token.get("client_id"), None),
                                "user_id": token.get("sub", token.get("user_id")),
                                "username": token.get("username"),
                                "issued_at": format_timestamp(issued_at),
                                "expires_at": format_timestamp(expires_at),
                                "is_expired": is_expired,
                                "time_remaining": time_remaining,
                                "scope": token.get("scope"),
                                "audience": audience,
                                "last_used": last_used,
                                "usage_count": usage_count,
                                "_sort_key": expires_at.timestamp()  # For sorting
                            })
                        except Exception as e:
                            logger.error(f"Error parsing token data: {e}")
                            continue
            
            # Scan for refresh tokens
            if not token_type or token_type == "refresh":
                for key in self.storage.redis_client.scan_iter(match="oauth:refresh:*"):
                    refresh_data = self.storage.redis_client.get(key)
                    if refresh_data:
                        try:
                            refresh = json.loads(refresh_data)
                            token_id = key.decode() if isinstance(key, bytes) else key
                            token_id = token_id.replace("oauth:refresh:", "")
                            
                            # Parse timestamps - refresh tokens have different structure
                            created_at = parse_timestamp(refresh.get("created_at", 0))
                            # Refresh tokens typically expire in 1 year
                            expires_at = created_at + timedelta(days=365)  # TODO: Get actual lifetime from config
                            is_expired = expires_at <= now
                            
                            # Skip expired tokens if not requested
                            if not include_expired and is_expired:
                                continue
                            
                            # Apply filters
                            if username and refresh.get("username") != username:
                                continue
                            if client_id and refresh.get("client_id") != client_id:
                                continue
                            
                            # Calculate time remaining
                            time_remaining = None
                            if is_expired:
                                time_remaining = "expired"
                            else:
                                diff = expires_at - now
                                if diff.days > 0:
                                    time_remaining = f"{diff.days}d"
                                elif diff.seconds > 3600:
                                    time_remaining = f"{diff.seconds // 3600}h"
                                else:
                                    time_remaining = f"{diff.seconds // 60}m"
                            
                            # Get usage data for this refresh token
                            last_used = None
                            usage_count = 0
                            usage_key = f"oauth:refresh_usage:{token_id}"
                            usage_data = self.storage.redis_client.get(usage_key)
                            if usage_data:
                                try:
                                    usage = json.loads(usage_data)
                                    if usage.get("last_used"):
                                        last_used = format_timestamp(parse_timestamp(usage["last_used"]))
                                    usage_count = usage.get("usage_count", 0)
                                except:
                                    pass
                            
                            tokens.append({
                                "jti": f"rfr_{token_id[:16]}",  # Prefix to distinguish refresh tokens
                                "token_type": "refresh",
                                "client_id": refresh.get("client_id"),
                                "client_name": client_names.get(refresh.get("client_id"), None),
                                "user_id": refresh.get("user_id", refresh.get("sub")),
                                "username": refresh.get("username"),
                                "issued_at": format_timestamp(created_at),
                                "expires_at": format_timestamp(expires_at),
                                "is_expired": is_expired,
                                "time_remaining": time_remaining,
                                "scope": refresh.get("scope"),
                                "audience": refresh.get("resources", []),
                                "last_used": last_used,
                                "usage_count": usage_count,
                                "_sort_key": expires_at.timestamp()  # For sorting
                            })
                        except Exception as e:
                            logger.error(f"Error parsing refresh token data: {e}")
                            continue
            
            # Sort tokens by expiration time (expiring soon first)
            tokens.sort(key=lambda x: x["_sort_key"])
            
            # Remove sort key from results
            for token in tokens:
                token.pop("_sort_key", None)
            
            # Calculate statistics
            total = len(tokens)
            active_count = sum(1 for t in tokens if not t["is_expired"])
            expired_count = total - active_count
            access_count = sum(1 for t in tokens if t["token_type"] == "access")
            refresh_count = sum(1 for t in tokens if t["token_type"] == "refresh")
            
            # Paginate
            start = (page - 1) * per_page
            end = start + per_page
            paginated_tokens = tokens[start:end]
            
            return {
                "tokens": paginated_tokens,
                "pagination": {
                    "total": total,
                    "page": page,
                    "per_page": per_page,
                    "pages": (total + per_page - 1) // per_page
                },
                "summary": {
                    "total_tokens": total,
                    "active_tokens": active_count,
                    "expired_tokens": expired_count,
                    "access_tokens": access_count,
                    "refresh_tokens": refresh_count
                }
            }
            
        except Exception as e:
            logger.error(f"Error listing OAuth tokens: {e}")
            raise HTTPException(500, f"Failed to list OAuth tokens: {str(e)}")
    
    async def get_token_detail(self, jti: str) -> TokenDetail:
        """Get specific token information."""
        # TODO: Implement when token storage pattern is known
        raise HTTPException(404, "Token not found")
    
    async def list_sessions(self) -> Dict:
        """List active user sessions."""
        # TODO: Implement when session storage pattern is known
        return {
            "sessions": [],
            "summary": {
                "total_sessions": 0,
                "unique_users": 0,
                "average_session_duration": 0
            }
        }
    
    async def get_session(self, session_id: str) -> SessionSummary:
        """Get detailed session information."""
        # TODO: Implement when session storage pattern is known
        raise HTTPException(404, "Session not found")
    
    async def revoke_session(
        self,
        request: Request,
        session_id: str
    ):
        """Revoke a session and all associated tokens."""
        # Get auth info from headers (set by proxy)
        auth_user = request.headers.get("X-Auth-User")
        if not auth_user:
            raise HTTPException(401, "Authentication required")
        auth_scopes = request.headers.get("X-Auth-Scopes", "").split()
        is_admin = "admin" in auth_scopes
        
        # Check permissions - admin scope required for mutations
        if not is_admin:
            raise HTTPException(403, "Admin scope required")
        # Session ID in our context is the username or user ID
        # We'll revoke all tokens associated with that user
        
        # Check if we're looking at user tokens pattern
        user_tokens_key = f"oauth:user_tokens:{session_id}"
        
        # Get all token JTIs for this user
        token_jtis = self.storage.redis_client.smembers(user_tokens_key)
        
        if not token_jtis:
            # Try with oauth:token pattern for direct token revocation
            token_key = f"oauth:token:{session_id}"
            if self.storage.redis_client.exists(token_key):
                # This is a direct token JTI, revoke it
                self.storage.redis_client.delete(token_key)
                logger.info(f"Revoked single token: {session_id}")
                return {"status": "success", "tokens_revoked": 1}
            else:
                raise HTTPException(404, f"No session or tokens found for ID: {session_id}")
        
        # Revoke all tokens for this user
        tokens_revoked = 0
        for jti_bytes in token_jtis:
            jti = jti_bytes.decode() if isinstance(jti_bytes, bytes) else jti_bytes
            token_key = f"oauth:token:{jti}"
            
            # Delete the token from Redis
            if self.storage.redis_client.delete(token_key):
                tokens_revoked += 1
                logger.info(f"Revoked token {jti} for session {session_id}")
            
            # Also remove from client tokens if present
            token_data = self.storage.redis_client.get(token_key)
            if token_data:
                try:
                    token_info = json.loads(token_data)
                    client_id = token_info.get("client_id")
                    if client_id:
                        self.storage.redis_client.srem(f"oauth:client_tokens:{client_id}", jti)
                except Exception as e:
                    logger.warning(f"Error cleaning up client token reference: {e}")
        
        # Clear the user's token set
        self.storage.redis_client.delete(user_tokens_key)
        
        logger.info(f"Revoked session for {session_id}: {tokens_revoked} tokens revoked")
        
        return {
            "status": "success",
            "session_id": session_id,
            "tokens_revoked": tokens_revoked
        }
    
    async def get_metrics(self) -> OAuthMetrics:
        """Get OAuth system metrics for monitoring."""
        try:
            # Count clients
            total_clients = 0
            active_clients = 0
            expiring_soon = 0
            
            for key in self.storage.redis_client.scan_iter(match="oauth:client:*"):
                total_clients += 1
                client_data = self.storage.redis_client.get(key)
                if client_data:
                    client = json.loads(client_data)
                    if "client_secret_expires_at" in client:
                        expires_at = parse_timestamp(client["client_secret_expires_at"])
                        if expires_at > datetime.now(timezone.utc):
                            active_clients += 1
                            days_until = (expires_at - datetime.now(timezone.utc)).days
                            if days_until <= 30:
                                expiring_soon += 1
            
            return OAuthMetrics(
                timestamp=format_timestamp(datetime.now(timezone.utc)),
                clients={
                    "total": total_clients,
                    "active": active_clients,
                    "expiring_soon": expiring_soon
                },
                tokens={
                    "access_tokens": {
                        "total": 0,  # TODO: Implement
                        "active": 0,
                        "issued_last_hour": 0,
                        "expired_last_hour": 0
                    },
                    "refresh_tokens": {
                        "total": 0,  # TODO: Implement
                        "active": 0,
                        "used_last_hour": 0
                    }
                },
                auth_flows={
                    "authorization_requests": {
                        "last_hour": 0,  # TODO: Implement
                        "success_rate": 0.0
                    },
                    "token_requests": {
                        "last_hour": 0,  # TODO: Implement
                        "success_rate": 0.0
                    }
                },
                errors={
                    "invalid_client": 0,  # TODO: Implement
                    "invalid_grant": 0,
                    "unauthorized_client": 0
                }
            )
            
        except Exception as e:
            logger.error(f"Error getting OAuth metrics: {e}")
            raise HTTPException(500, f"Failed to get OAuth metrics: {str(e)}")
    
    async def check_health(self) -> OAuthHealth:
        """Check OAuth integration health."""
        try:
            import httpx
            from src.api.oauth.config import Settings as OAuthSettings
            from src.api.oauth.keys import RSAKeyManager
            
            checks = {}
            oauth_settings = OAuthSettings()
            
            # Check Redis connection
            try:
                self.storage.redis_client.ping()
                checks["redis_connection"] = "ok"
            except:
                checks["redis_connection"] = "failed"
            
            # Check auth proxy
            auth_proxy = None
            proxies = self.storage.list_proxy_targets()
            for proxy in proxies:
                if proxy.proxy_hostname.startswith("auth."):
                    auth_proxy = proxy
                    break
            
            if auth_proxy:
                checks["auth_proxy_configured"] = "ok"
                
                # Actually check if OAuth server is reachable
                try:
                    auth_url = f"https://{auth_proxy.hostname}/.well-known/oauth-authorization-server"
                    async with httpx.AsyncClient(verify=False, timeout=5.0) as client:
                        response = await client.get(auth_url)
                        if response.status_code == 200:
                            checks["oauth_server_reachable"] = "ok"
                            # Verify it returns valid metadata
                            metadata = response.json()
                            if "issuer" in metadata and "token_endpoint" in metadata:
                                checks["oauth_metadata_valid"] = "ok"
                            else:
                                checks["oauth_metadata_valid"] = "invalid_metadata"
                        else:
                            checks["oauth_server_reachable"] = f"http_{response.status_code}"
                            checks["oauth_metadata_valid"] = "unreachable"
                except Exception as e:
                    checks["oauth_server_reachable"] = f"error: {str(e)[:50]}"
                    checks["oauth_metadata_valid"] = "unreachable"
            else:
                checks["oauth_server_reachable"] = "no_auth_proxy"
                checks["auth_proxy_configured"] = "failed"
                checks["oauth_metadata_valid"] = "no_auth_proxy"
            
            # Check RSA keys are available for token validation
            try:
                key_manager = RSAKeyManager()
                key_manager.load_or_generate_keys()
                checks["rsa_keys_available"] = "ok"
            except Exception as e:
                checks["rsa_keys_available"] = f"failed: {str(e)[:50]}"
            
            # Check JWKS endpoint
            if auth_proxy:
                try:
                    jwks_url = f"https://{auth_proxy.hostname}/jwks"
                    async with httpx.AsyncClient(verify=False, timeout=5.0) as client:
                        response = await client.get(jwks_url)
                        if response.status_code == 200:
                            jwks_data = response.json()
                            if "keys" in jwks_data and len(jwks_data["keys"]) > 0:
                                checks["jwks_endpoint"] = "ok"
                            else:
                                checks["jwks_endpoint"] = "no_keys"
                        else:
                            checks["jwks_endpoint"] = f"http_{response.status_code}"
                except Exception as e:
                    checks["jwks_endpoint"] = f"error: {str(e)[:50]}"
            else:
                checks["jwks_endpoint"] = "no_auth_proxy"
            
            # Check token validation capability
            if checks.get("rsa_keys_available") == "ok":
                checks["token_validation"] = "ready"
            else:
                checks["token_validation"] = "keys_not_available"
            
            # Check for recent successful authentications
            last_auth_time = None
            try:
                # Look for recent tokens in Redis
                token_count = 0
                for key in self.storage.redis_client.scan_iter(match="oauth:token:*", count=10):
                    token_count += 1
                    if token_count > 0:
                        # Found at least one token, system has been used
                        checks["recent_activity"] = "active"
                        break
                else:
                    checks["recent_activity"] = "no_recent_tokens"
            except:
                checks["recent_activity"] = "unknown"
            
            # Determine overall status
            critical_checks = ["redis_connection", "auth_proxy_configured", "rsa_keys_available"]
            critical_failed = [k for k in critical_checks if checks.get(k, "failed") != "ok"]
            
            if critical_failed:
                status = "unhealthy"
            else:
                non_critical_failed = [k for k, v in checks.items() 
                                      if k not in critical_checks and v != "ok" and not v.startswith("ready")]
                status = "degraded" if non_critical_failed else "healthy"
            
            return OAuthHealth(
                status=status,
                checks=checks,
                last_successful_auth=last_auth_time,
                auth_proxy={
                    "proxy_hostname": auth_proxy.hostname if auth_proxy else None,
                    "status": "active" if auth_proxy and auth_proxy.enabled else "inactive",
                    "certificate_valid": bool(auth_proxy.cert_name) if auth_proxy else False
                } if auth_proxy else {}
            )
            
        except Exception as e:
            logger.error(f"Error checking OAuth health: {e}")
            raise HTTPException(500, f"Failed to check OAuth health: {str(e)}")
    
    async def list_proxy_oauth_status(self) -> Dict:
        """Show OAuth status for all proxies."""
        try:
            proxies = []
            auth_enabled_count = 0
            active_session_count = 0
            
            for proxy in self.storage.list_proxy_targets():
                if proxy.auth_enabled:
                    auth_enabled_count += 1
                
                proxy_status = {
                    "proxy_hostname": proxy.proxy_hostname,
                    "auth_enabled": proxy.auth_enabled,
                    "auth_mode": proxy.auth_mode if proxy.auth_enabled else None,
                    "auth_proxy": proxy.auth_proxy if proxy.auth_enabled else None,
                    "active_sessions": 0,  # TODO: Count active sessions
                    "recent_auth_failures": 0,  # TODO: Track auth failures
                    "last_auth_success": None  # TODO: Track last success
                }
                
                if proxy_status["active_sessions"] > 0:
                    active_session_count += 1
                
                proxies.append(proxy_status)
            
            return {
                "proxies": proxies,
                "summary": {
                    "total_proxies": len(proxies),
                    "auth_enabled_proxies": auth_enabled_count,
                    "proxies_with_active_sessions": active_session_count
                }
            }
            
        except Exception as e:
            logger.error(f"Error listing proxy OAuth status: {e}")
            raise HTTPException(500, f"Failed to list proxy OAuth status: {str(e)}")
    
    async def list_proxy_sessions(self, proxy_hostname: str) -> Dict:
        """List active sessions for a specific proxy."""
        # TODO: Implement when session tracking is available
        return {
            "proxy_hostname": proxy_hostname,
            "sessions": [],
            "total_sessions": 0
        }


def create_oauth_status_router(storage: RedisStorage) -> APIRouter:
    """Create and return the OAuth status router."""
    oauth_router = OAuthStatusRouter(storage)
    return oauth_router.router
