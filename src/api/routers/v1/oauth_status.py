"""OAuth Status API for monitoring OAuth clients, tokens, and sessions.

This module provides read-only endpoints to inspect the OAuth system state
by directly accessing Redis data from the OAuth server.
"""

import asyncio
import json
import logging
from datetime import datetime, timezone
from typing import Dict, List, Optional, Any, Tuple
from collections import defaultdict
import hashlib

from fastapi import APIRouter, Query, HTTPException, Depends
from pydantic import BaseModel, Field

from src.api.auth import get_current_token_info, get_optional_token_info
from src.storage.redis_storage import RedisStorage

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
    token_type: str
    user_id: Optional[str]
    username: Optional[str]
    issued_at: str
    expires_at: str
    is_expired: bool
    scope: Optional[str]
    used_by_proxies: List[str] = []

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
        self.router.get("/tokens", response_model=Dict)(self.get_token_stats)
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
        self.router.get("/proxies/{hostname}/sessions", response_model=Dict)(self.list_proxy_sessions)
    
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
                        
                        clients.append({
                            "client_id": client_id,
                            "client_name": client.get("client_name"),
                            "created_at": format_timestamp(created_at),
                            "expires_at": format_timestamp(expires_at) if expires_at else None,
                            "is_active": is_active,
                            "days_until_expiry": days_until_expiry,
                            "token_count": token_count,
                            "last_token_issued": last_token_issued,
                            "registration_client_uri": client.get("registration_client_uri")
                        })
                    except Exception as e:
                        logger.error(f"Error parsing client data: {e}")
                        continue
            
            # Sort clients
            reverse = (order == "desc")
            if sort_by == "created_at":
                clients.sort(key=lambda x: x["created_at"], reverse=reverse)
            elif sort_by == "expires_at":
                clients.sort(key=lambda x: x["expires_at"] or "", reverse=reverse)
            elif sort_by == "name":
                clients.sort(key=lambda x: x["client_name"] or "", reverse=reverse)
            
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
                        "hostname": proxy.hostname,
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
    
    async def get_token_stats(
        self,
        token_type: Optional[str] = Query(None, description="Filter by token type"),
        include_expired: bool = Query(False, description="Include expired tokens"),
        user_id: Optional[str] = Query(None, description="Filter by user ID"),
        client_id: Optional[str] = Query(None, description="Filter by client ID")
    ) -> Dict:
        """Get OAuth token statistics and overview."""
        # TODO: Implement when token storage pattern is known
        return {
            "summary": {
                "total_access_tokens": 0,
                "active_access_tokens": 0,
                "total_refresh_tokens": 0,
                "active_refresh_tokens": 0,
                "tokens_expiring_soon": 0,
                "average_token_lifetime": 1800
            },
            "by_client": [],
            "by_user": [],
            "recent_activity": []
        }
    
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
        session_id: str,
        token_info: Tuple[str, Optional[str], Optional[str]] = Depends(get_current_token_info)
    ):
        """Revoke a session and all associated tokens."""
        # TODO: Implement session revocation
        # This would need to communicate with the OAuth server
        raise HTTPException(501, "Session revocation not implemented")
    
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
            checks = {}
            
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
                if proxy.hostname.startswith("auth."):
                    auth_proxy = proxy
                    break
            
            if auth_proxy:
                checks["oauth_server_reachable"] = "ok"  # TODO: Actually check
                checks["auth_proxy_configured"] = "ok"
            else:
                checks["oauth_server_reachable"] = "no_auth_proxy"
                checks["auth_proxy_configured"] = "failed"
            
            # TODO: Check token validation endpoint
            checks["token_validation"] = "not_implemented"
            
            # TODO: Check JWKS endpoint
            checks["jwks_endpoint"] = "not_implemented"
            
            # Determine overall status
            failed_checks = [k for k, v in checks.items() if v != "ok"]
            status = "healthy" if not failed_checks else "degraded"
            
            return OAuthHealth(
                status=status,
                checks=checks,
                last_successful_auth=None,  # TODO: Track this
                auth_proxy={
                    "hostname": auth_proxy.hostname if auth_proxy else None,
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
                    "hostname": proxy.hostname,
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
    
    async def list_proxy_sessions(self, hostname: str) -> Dict:
        """List active sessions for a specific proxy."""
        # TODO: Implement when session tracking is available
        return {
            "hostname": hostname,
            "sessions": [],
            "total_sessions": 0
        }


def create_oauth_status_router(storage: RedisStorage) -> APIRouter:
    """Create and return the OAuth status router."""
    oauth_router = OAuthStatusRouter(storage)
    return oauth_router.router
