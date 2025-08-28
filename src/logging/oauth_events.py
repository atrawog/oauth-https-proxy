"""OAuth Event Logging Module.

Provides structured logging of OAuth authentication and authorization events
with proper sanitization and multiple indexes for efficient querying.
"""

import time
import json
import asyncio
from typing import Any, Dict, Optional, List
from datetime import datetime, timedelta
from src.shared.logger import log_info, log_debug, log_warning, log_error
from src.shared.sanitizer import OAuthSanitizer


class OAuthEventLogger:
    """Handles structured logging of OAuth events to Redis."""
    
    # OAuth event types
    EVENT_AUTH_REQUEST = "auth_request"
    EVENT_AUTH_CALLBACK = "auth_callback"
    EVENT_TOKEN_EXCHANGE = "token_exchange"
    EVENT_TOKEN_REFRESH = "token_refresh"
    EVENT_TOKEN_VALIDATION = "token_validation"
    EVENT_TOKEN_REVOCATION = "token_revocation"
    EVENT_TOKEN_INTROSPECTION = "token_introspection"
    EVENT_DEVICE_AUTH = "device_auth"
    EVENT_DEVICE_POLL = "device_poll"
    EVENT_DEVICE_COMPLETE = "device_complete"
    EVENT_SCOPE_CHECK = "scope_check"
    EVENT_USER_CHECK = "user_check"
    EVENT_AUDIENCE_CHECK = "audience_check"
    EVENT_CLIENT_AUTH = "client_auth"
    EVENT_PKCE_VALIDATION = "pkce_validation"
    EVENT_JWT_DECODE = "jwt_decode"
    
    def __init__(self, redis_client):
        """Initialize OAuth event logger with Redis client.
        
        Args:
            redis_client: Async Redis client
        """
        self.redis = redis_client
        self.sanitizer = OAuthSanitizer()
    
    async def log_event(
        self,
        event_type: str,
        client_ip: str,
        proxy_hostname: Optional[str] = None,
        user_id: Optional[str] = None,
        client_id: Optional[str] = None,
        success: bool = True,
        error_reason: Optional[str] = None,
        event_data: Optional[Dict[str, Any]] = None,
        duration_ms: Optional[float] = None
    ):
        """Log a structured OAuth event.
        
        Args:
            event_type: Type of OAuth event
            client_ip: Client IP address
            proxy_hostname: Proxy hostname involved
            user_id: User identifier (username or sub)
            client_id: OAuth client identifier
            success: Whether the operation succeeded
            error_reason: Reason for failure if not successful
            event_data: Additional event-specific data
            duration_ms: Operation duration in milliseconds
        """
        try:
            # Sanitize event data
            sanitized_data = self.sanitizer.sanitize_oauth_event(event_data or {})
            
            # Build event entry
            entry = {
                "timestamp": time.time(),
                "timestamp_iso": datetime.utcnow().isoformat(),
                "event_type": event_type,
                "client_ip": client_ip,
                "proxy_hostname": proxy_hostname or "unknown",
                "user_id": user_id or "anonymous",
                "client_id": client_id or "unknown",
                "success": success,
                "error_reason": error_reason,
                "duration_ms": duration_ms,
                "data": sanitized_data
            }
            
            # Convert to JSON for storage
            entry_json = json.dumps(entry, default=str)
            
            # Store in main OAuth event stream
            await self.redis.xadd(
                "stream:oauth:events",
                {"entry": entry_json},
                maxlen=100000  # Keep last 100k events
            )
            
            # Add to multiple indexes for efficient querying
            timestamp = time.time()
            
            # Index by event type
            await self.redis.zadd(
                f"idx:oauth:type:{event_type}",
                {entry_json: timestamp}
            )
            
            # Index by user
            if user_id:
                await self.redis.zadd(
                    f"idx:oauth:user:{user_id}",
                    {entry_json: timestamp}
                )
            
            # Index by proxy
            if proxy_hostname:
                await self.redis.zadd(
                    f"idx:oauth:proxy:{proxy_hostname}",
                    {entry_json: timestamp}
                )
            
            # Index by client
            if client_id:
                await self.redis.zadd(
                    f"idx:oauth:client:{client_id}",
                    {entry_json: timestamp}
                )
            
            # Index by IP
            await self.redis.zadd(
                f"idx:oauth:ip:{client_ip}",
                {entry_json: timestamp}
            )
            
            # Index failures separately
            if not success:
                await self.redis.zadd(
                    "idx:oauth:failures",
                    {entry_json: timestamp}
                )
            
            # Set TTL on indexes (keep for 7 days)
            ttl = 7 * 24 * 3600
            for key in [
                f"idx:oauth:type:{event_type}",
                f"idx:oauth:user:{user_id}" if user_id else None,
                f"idx:oauth:proxy:{proxy_hostname}" if proxy_hostname else None,
                f"idx:oauth:client:{client_id}" if client_id else None,
                f"idx:oauth:ip:{client_ip}",
            ]:
                if key:
                    await self.redis.expire(key, ttl)
            
        except Exception as e:
            log_error(f"Failed to log OAuth event: {e}", component="oauth_events")
    
    async def log_auth_request(
        self,
        client_ip: str,
        client_id: str,
        redirect_uri: str,
        response_type: str,
        scope: str,
        state: str,
        proxy_hostname: Optional[str] = None,
        code_challenge: Optional[str] = None,
        resource: Optional[List[str]] = None
    ):
        """Log OAuth authorization request."""
        event_data = {
            "client_id": client_id,
            "redirect_uri": redirect_uri,
            "response_type": response_type,
            "scope": scope,
            "state": state,
            "code_challenge": code_challenge,
            "resource": resource,
            "pkce_enabled": bool(code_challenge)
        }
        
        await self.log_event(
            event_type=self.EVENT_AUTH_REQUEST,
            client_ip=client_ip,
            proxy_hostname=proxy_hostname,
            client_id=client_id,
            event_data=event_data
        )
    
    async def log_token_validation(
        self,
        client_ip: str,
        proxy_hostname: str,
        token_preview: str,
        jwt_claims: Dict[str, Any],
        validation_result: bool,
        error_reason: Optional[str] = None,
        duration_ms: Optional[float] = None
    ):
        """Log JWT token validation event."""
        event_data = {
            "token_preview": token_preview,
            "jwt_claims": jwt_claims,
            "validation_checks": {
                "signature_valid": validation_result and not error_reason,
                "not_expired": "exp" in jwt_claims and jwt_claims.get("exp", 0) > time.time(),
                "audience_valid": proxy_hostname in (jwt_claims.get("aud", []) if isinstance(jwt_claims.get("aud"), list) else [jwt_claims.get("aud")]) if jwt_claims.get("aud") else False,
                "issuer_valid": bool(jwt_claims.get("iss")),
            },
            "user_info": {
                "sub": jwt_claims.get("sub"),
                "username": jwt_claims.get("username"),
                "email": jwt_claims.get("email"),
                "scope": jwt_claims.get("scope"),
                "orgs": jwt_claims.get("orgs", [])
            }
        }
        
        await self.log_event(
            event_type=self.EVENT_TOKEN_VALIDATION,
            client_ip=client_ip,
            proxy_hostname=proxy_hostname,
            user_id=jwt_claims.get("username") or jwt_claims.get("sub"),
            client_id=jwt_claims.get("azp") or jwt_claims.get("client_id"),
            success=validation_result,
            error_reason=error_reason,
            event_data=event_data,
            duration_ms=duration_ms
        )
    
    async def log_scope_check(
        self,
        client_ip: str,
        proxy_hostname: str,
        user_id: str,
        required_scopes: List[str],
        user_scopes: List[str],
        check_passed: bool,
        request_path: str,
        request_method: str
    ):
        """Log scope validation check."""
        event_data = {
            "required_scopes": required_scopes,
            "user_scopes": user_scopes,
            "missing_scopes": list(set(required_scopes) - set(user_scopes)),
            "request_path": request_path,
            "request_method": request_method,
            "admin_override": "admin" in user_scopes
        }
        
        await self.log_event(
            event_type=self.EVENT_SCOPE_CHECK,
            client_ip=client_ip,
            proxy_hostname=proxy_hostname,
            user_id=user_id,
            success=check_passed,
            error_reason="Insufficient scopes" if not check_passed else None,
            event_data=event_data
        )
    
    async def log_user_allowlist_check(
        self,
        client_ip: str,
        proxy_hostname: str,
        user_id: str,
        allowed_users: Optional[List[str]],
        check_passed: bool
    ):
        """Log user allowlist validation."""
        event_data = {
            "user": user_id,
            "allowed_users": allowed_users if allowed_users else ["*"],
            "allowlist_type": "specific" if allowed_users and allowed_users != ["*"] else "all_users"
        }
        
        await self.log_event(
            event_type=self.EVENT_USER_CHECK,
            client_ip=client_ip,
            proxy_hostname=proxy_hostname,
            user_id=user_id,
            success=check_passed,
            error_reason="User not in allowlist" if not check_passed else None,
            event_data=event_data
        )
    
    async def log_token_exchange(
        self,
        client_ip: str,
        grant_type: str,
        client_id: str,
        success: bool,
        error_reason: Optional[str] = None,
        user_id: Optional[str] = None,
        scope: Optional[str] = None,
        resource: Optional[List[str]] = None,
        duration_ms: Optional[float] = None
    ):
        """Log token exchange event."""
        event_data = {
            "grant_type": grant_type,
            "client_id": client_id,
            "scope": scope,
            "resource": resource,
            "token_generated": success
        }
        
        await self.log_event(
            event_type=self.EVENT_TOKEN_EXCHANGE,
            client_ip=client_ip,
            user_id=user_id,
            client_id=client_id,
            success=success,
            error_reason=error_reason,
            event_data=event_data,
            duration_ms=duration_ms
        )
    
    async def log_auth_callback(
        self,
        client_ip: str,
        state: str,
        github_user: Optional[str] = None,
        github_email: Optional[str] = None,
        github_orgs: Optional[List[str]] = None,
        assigned_scope: Optional[str] = None,
        success: bool = True,
        error_reason: Optional[str] = None
    ):
        """Log OAuth callback from GitHub."""
        event_data = {
            "state": state,
            "github_user": github_user,
            "github_email": github_email,
            "github_orgs": github_orgs or [],
            "assigned_scope": assigned_scope,
            "auth_source": "github"
        }
        
        await self.log_event(
            event_type=self.EVENT_AUTH_CALLBACK,
            client_ip=client_ip,
            user_id=github_user,
            success=success,
            error_reason=error_reason,
            event_data=event_data
        )
    
    async def get_user_events(
        self,
        user_id: str,
        hours: int = 24,
        limit: int = 100
    ) -> List[Dict[str, Any]]:
        """Get OAuth events for a specific user.
        
        Args:
            user_id: User identifier
            hours: Hours to look back
            limit: Maximum number of events
            
        Returns:
            List of OAuth events
        """
        try:
            start_time = time.time() - (hours * 3600)
            events = await self.redis.zrevrangebyscore(
                f"idx:oauth:user:{user_id}",
                "+inf",
                start_time,
                start=0,
                num=limit
            )
            
            return [json.loads(event) for event in events]
        except Exception as e:
            log_error(f"Failed to get user OAuth events: {e}", component="oauth_events")
            return []
    
    async def get_proxy_events(
        self,
        proxy_hostname: str,
        hours: int = 24,
        limit: int = 100
    ) -> List[Dict[str, Any]]:
        """Get OAuth events for a specific proxy.
        
        Args:
            proxy_hostname: Proxy hostname
            hours: Hours to look back
            limit: Maximum number of events
            
        Returns:
            List of OAuth events
        """
        try:
            start_time = time.time() - (hours * 3600)
            events = await self.redis.zrevrangebyscore(
                f"idx:oauth:proxy:{proxy_hostname}",
                "+inf",
                start_time,
                start=0,
                num=limit
            )
            
            return [json.loads(event) for event in events]
        except Exception as e:
            log_error(f"Failed to get proxy OAuth events: {e}", component="oauth_events")
            return []
    
    async def get_failed_events(
        self,
        hours: int = 24,
        limit: int = 100
    ) -> List[Dict[str, Any]]:
        """Get failed OAuth events.
        
        Args:
            hours: Hours to look back
            limit: Maximum number of events
            
        Returns:
            List of failed OAuth events
        """
        try:
            start_time = time.time() - (hours * 3600)
            events = await self.redis.zrevrangebyscore(
                "idx:oauth:failures",
                "+inf",
                start_time,
                start=0,
                num=limit
            )
            
            return [json.loads(event) for event in events]
        except Exception as e:
            log_error(f"Failed to get failed OAuth events: {e}", component="oauth_events")
            return []
    
    async def reconstruct_oauth_flow(
        self,
        session_id: str
    ) -> List[Dict[str, Any]]:
        """Reconstruct a complete OAuth flow from events.
        
        Args:
            session_id: Session or state identifier
            
        Returns:
            List of events in the OAuth flow
        """
        # This would search for all events with matching state/session
        # Implementation depends on how session tracking is done
        pass


# Global OAuth event logger instance (initialized in main.py)
oauth_logger: Optional[OAuthEventLogger] = None


async def init_oauth_logger(redis_client):
    """Initialize the global OAuth event logger.
    
    Args:
        redis_client: Async Redis client
    """
    global oauth_logger
    oauth_logger = OAuthEventLogger(redis_client)


# Convenience functions for logging OAuth events
async def log_oauth_event(*args, **kwargs):
    """Log an OAuth event using the global logger."""
    if oauth_logger:
        # Use fire-and-forget pattern
        asyncio.create_task(oauth_logger.log_event(*args, **kwargs))


async def log_oauth_validation(*args, **kwargs):
    """Log a token validation event."""
    if oauth_logger:
        asyncio.create_task(oauth_logger.log_token_validation(*args, **kwargs))