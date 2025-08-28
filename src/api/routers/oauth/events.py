"""OAuth event query endpoints."""

from typing import Optional, List, Dict, Any
from datetime import datetime, timedelta
from fastapi import APIRouter, HTTPException, Request
import json

from ....logging.oauth_events import OAuthEventLogger

router = APIRouter()


@router.get("/events/ip/{ip}")
async def get_oauth_events_by_ip(
    request: Request,
    ip: str,
    hours: int = 24,
    limit: int = 1000
) -> Dict[str, Any]:
    """Get OAuth events for a specific IP address.
    
    Args:
        ip: Client IP address to query
        hours: Number of hours to look back (default: 24)
        limit: Maximum number of events to return (default: 1000)
    
    Returns:
        Dictionary with events list and metadata
    """
    # Get auth info from headers (set by proxy)
    auth_user = request.headers.get("X-Auth-User", "system")
    auth_scopes = request.headers.get("X-Auth-Scopes", "").split()
    
    # Check permissions - user scope required for reading
    if "user" not in auth_scopes and "admin" not in auth_scopes:
        raise HTTPException(403, "User or admin scope required")
    
    try:
        # Access storage from app state
        storage = request.app.state.async_storage
        
        # Calculate time range
        end_time = datetime.utcnow()
        start_time = end_time - timedelta(hours=hours)
        start_timestamp = start_time.timestamp()
        
        # Query events from Redis stream index by IP
        events = []
        index_key = f"idx:oauth:ip:{ip}"
        
        # Get event entries from the index (sorted set)
        # Use ZRANGEBYSCORE to get entries within the time range
        entries = await storage.redis_client.zrangebyscore(
            index_key,
            min=start_timestamp,
            max="+inf",
            start=0,
            num=limit
        )
        
        # Parse JSON entries
        for entry in entries:
            try:
                event = json.loads(entry)
                events.append(event)
            except json.JSONDecodeError:
                continue
        
        return {
            "events": events,
            "count": len(events),
            "ip": ip,
            "hours": hours,
            "start_time": start_time.isoformat(),
            "end_time": end_time.isoformat()
        }
        
    except Exception as e:
        raise HTTPException(500, f"Failed to query OAuth events: {str(e)}")


@router.get("/events/proxy/{proxy}")
async def get_oauth_events_by_proxy(
    request: Request,
    proxy: str,
    hours: int = 24,
    limit: int = 1000
) -> Dict[str, Any]:
    """Get OAuth events for a specific proxy hostname.
    
    Args:
        proxy: Proxy hostname to query
        hours: Number of hours to look back (default: 24)
        limit: Maximum number of events to return (default: 1000)
    
    Returns:
        Dictionary with events list and metadata
    """
    # Get auth info from headers (set by proxy)
    auth_user = request.headers.get("X-Auth-User", "system")
    auth_scopes = request.headers.get("X-Auth-Scopes", "").split()
    
    # Check permissions - user scope required for reading
    if "user" not in auth_scopes and "admin" not in auth_scopes:
        raise HTTPException(403, "User or admin scope required")
    
    try:
        # Access storage from app state
        storage = request.app.state.async_storage
        
        # Calculate time range
        end_time = datetime.utcnow()
        start_time = end_time - timedelta(hours=hours)
        start_timestamp = start_time.timestamp()
        
        # Query events from Redis stream index by proxy
        events = []
        index_key = f"idx:oauth:proxy:{proxy}"
        
        # Get event entries from the index (sorted set)
        # Use ZRANGEBYSCORE to get entries within the time range
        entries = await storage.redis_client.zrangebyscore(
            index_key,
            min=start_timestamp,
            max="+inf",
            start=0,
            num=limit
        )
        
        # Parse JSON entries
        for entry in entries:
            try:
                event = json.loads(entry)
                events.append(event)
            except json.JSONDecodeError:
                continue
        
        return {
            "events": events,
            "count": len(events),
            "proxy": proxy,
            "hours": hours,
            "start_time": start_time.isoformat(),
            "end_time": end_time.isoformat()
        }
        
    except Exception as e:
        raise HTTPException(500, f"Failed to query OAuth events: {str(e)}")


@router.get("/events/user/{user}")
async def get_oauth_events_by_user(
    request: Request,
    user: str,
    hours: int = 24,
    limit: int = 1000
) -> Dict[str, Any]:
    """Get OAuth events for a specific user.
    
    Args:
        user: Username to query
        hours: Number of hours to look back (default: 24)
        limit: Maximum number of events to return (default: 1000)
    
    Returns:
        Dictionary with events list and metadata
    """
    # Get auth info from headers (set by proxy)
    auth_user = request.headers.get("X-Auth-User", "system")
    auth_scopes = request.headers.get("X-Auth-Scopes", "").split()
    
    # Check permissions - user can only see their own events unless admin
    if "admin" not in auth_scopes and auth_user != user:
        raise HTTPException(403, "Can only view your own events without admin scope")
    
    try:
        # Access storage from app state
        storage = request.app.state.async_storage
        
        # Calculate time range
        end_time = datetime.utcnow()
        start_time = end_time - timedelta(hours=hours)
        start_timestamp = start_time.timestamp()
        
        # Query events from Redis stream index by user
        events = []
        index_key = f"idx:oauth:user:{user}"
        
        # Get event entries from the index (sorted set)
        # Use ZRANGEBYSCORE to get entries within the time range
        entries = await storage.redis_client.zrangebyscore(
            index_key,
            min=start_timestamp,
            max="+inf",
            start=0,
            num=limit
        )
        
        # Parse JSON entries
        for entry in entries:
            try:
                event = json.loads(entry)
                events.append(event)
            except json.JSONDecodeError:
                continue
        
        return {
            "events": events,
            "count": len(events),
            "user": user,
            "hours": hours,
            "start_time": start_time.isoformat(),
            "end_time": end_time.isoformat()
        }
        
    except Exception as e:
        raise HTTPException(500, f"Failed to query OAuth events: {str(e)}")