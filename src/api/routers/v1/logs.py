"""Log query API endpoints.

This module provides comprehensive log query endpoints for searching, filtering,
and analyzing HTTP request logs, OAuth activity, and system events.
"""

import logging
import json
import socket
from datetime import datetime, timezone, timedelta
from typing import Optional, List, Dict, Any
from fastapi import APIRouter, HTTPException, Depends, Query, Request, Response
from fastapi.responses import JSONResponse

from src.auth import AuthDep, AuthResult
from src.logging.request_logger import RequestLogger

logger = logging.getLogger(__name__)


def create_logs_router(storage):
    """Create the logs API router with all log query endpoints.
    
    Args:
        storage: Redis storage instance
    
    Returns:
        APIRouter with all log endpoints
    """
    router = APIRouter(tags=["logs"])
    
    # Initialize request logger with Redis
    request_logger = RequestLogger(redis_client=storage.redis_client if hasattr(storage, 'redis_client') else None)
    
    @router.get("/search")
    async def search_logs(
        request: Request,
        q: Optional[str] = Query(None, description="Search query"),
        hours: int = Query(24, ge=1, le=720, description="Hours to look back"),
        hostname: Optional[str] = Query(None, description="Filter by hostname"),
        status: Optional[int] = Query(None, description="Filter by HTTP status code"),
        method: Optional[str] = Query(None, description="Filter by HTTP method"),
        path: Optional[str] = Query(None, description="Filter by path pattern"),
        ip: Optional[str] = Query(None, description="Filter by client IP"),
        user: Optional[str] = Query(None, description="Filter by username"),
        limit: int = Query(100, ge=1, le=1000, description="Maximum results"),
        offset: int = Query(0, ge=0, description="Offset for pagination"),
        auth: AuthResult = Depends(AuthDep())
    ):
        """Search logs with flexible filters.
        
        Supports multiple filter criteria that can be combined.
        """
        try:
            # Build search parameters
            search_params = {
                'hours': hours,
                'limit': limit,
                'offset': offset
            }
            
            if q:
                search_params['query'] = q
            if hostname:
                search_params['hostname'] = hostname
            if status:
                search_params['status'] = status
            if method:
                search_params['method'] = method
            if path:
                search_params['path'] = path
            if ip:
                search_params['ip'] = ip
            if user:
                search_params['user'] = user
            
            # Use async storage for log queries
            if hasattr(request.app.state, 'async_storage'):
                async_storage = request.app.state.async_storage
                logs = await async_storage.search_logs(**search_params)
            else:
                # Fallback to request logger
                logs = await request_logger.search_logs(**search_params)
            
            return logs
            
        except Exception as e:
            logger.error(f"Error searching logs: {e}")
            raise HTTPException(500, f"Error searching logs: {str(e)}")
    
    
    @router.get("/ip/{ip}")
    async def get_logs_by_ip(
        request: Request,
        ip: str,
        hours: int = Query(24, ge=1, le=720, description="Hours to look back"),
        limit: int = Query(100, ge=1, le=1000, description="Maximum results"),
        auth: AuthResult = Depends(AuthDep())
    ):
        """Query logs by client IP address.
        
        Returns all requests from the specified IP address.
        """
        try:
            if hasattr(request.app.state, 'async_storage'):
                async_storage = request.app.state.async_storage
                logs = await async_storage.get_logs_by_ip(ip, hours=hours, limit=limit)
            else:
                logs = await request_logger.query_by_ip(ip, hours=hours, limit=limit)
            
            return {
                "ip": ip,
                "hours": hours,
                "total": len(logs),
                "logs": logs
            }
            
        except Exception as e:
            logger.error(f"Error querying logs by IP {ip}: {e}")
            raise HTTPException(500, f"Error querying logs: {str(e)}")
    
    
    @router.get("/host/{hostname}")
    async def get_logs_by_host(
        request: Request,
        hostname: str,
        hours: int = Query(24, ge=1, le=720, description="Hours to look back"),
        limit: int = Query(100, ge=1, le=1000, description="Maximum results"),
        auth: AuthResult = Depends(AuthDep())
    ):
        """Query logs by client hostname (FQDN from reverse DNS).
        
        Returns all requests from clients with the specified hostname.
        """
        try:
            # Try reverse DNS lookup if hostname looks like an IP
            try:
                socket.inet_aton(hostname)
                # It's an IP, do reverse DNS
                try:
                    hostname = socket.gethostbyaddr(hostname)[0]
                except:
                    pass  # Keep original if reverse DNS fails
            except:
                pass  # Not an IP, use as hostname
            
            if hasattr(request.app.state, 'async_storage'):
                async_storage = request.app.state.async_storage
                logs = await async_storage.get_logs_by_hostname(hostname, hours=hours, limit=limit)
            else:
                logs = await request_logger.query_by_hostname(hostname, hours=hours, limit=limit)
            
            return {
                "hostname": hostname,
                "hours": hours,
                "total": len(logs),
                "logs": logs
            }
            
        except Exception as e:
            logger.error(f"Error querying logs by hostname {hostname}: {e}")
            raise HTTPException(500, f"Error querying logs: {str(e)}")
    
    
    @router.get("/client/{client_id}")
    async def get_logs_by_client(
        request: Request,
        client_id: str,
        hours: int = Query(24, ge=1, le=720, description="Hours to look back"),
        limit: int = Query(100, ge=1, le=1000, description="Maximum results"),
        auth: AuthResult = Depends(AuthDep())
    ):
        """Query logs by OAuth client ID.
        
        Returns all requests authenticated with the specified OAuth client.
        """
        try:
            if hasattr(request.app.state, 'async_storage'):
                async_storage = request.app.state.async_storage
                logs = await async_storage.get_logs_by_client(client_id, hours=hours, limit=limit)
            else:
                # Fallback: search for client_id in logs
                logs = await request_logger.search_logs(
                    client_id=client_id,
                    hours=hours,
                    limit=limit
                )
            
            return {
                "client_id": client_id,
                "hours": hours,
                "total": len(logs) if isinstance(logs, list) else logs.get('total', 0),
                "logs": logs if isinstance(logs, list) else logs.get('logs', [])
            }
            
        except Exception as e:
            logger.error(f"Error querying logs by client {client_id}: {e}")
            raise HTTPException(500, f"Error querying logs: {str(e)}")
    
    
    @router.get("/errors")
    async def get_error_logs(
        request: Request,
        hours: int = Query(1, ge=1, le=168, description="Hours to look back"),
        include_warnings: bool = Query(False, description="Include 4xx errors"),
        limit: int = Query(50, ge=1, le=500, description="Maximum results"),
        auth: AuthResult = Depends(AuthDep())
    ):
        """Get recent error logs (5xx and optionally 4xx responses).
        
        Useful for monitoring application errors and issues.
        """
        try:
            # Get errors from async storage
            if hasattr(request.app.state, 'async_storage'):
                async_storage = request.app.state.async_storage
                errors = await async_storage.get_error_logs(
                    hours=hours,
                    include_4xx=include_warnings,
                    limit=limit
                )
            else:
                # Use request logger fallback
                errors = await request_logger.query_errors(hours=hours, limit=limit)
            
            # Filter by status code if needed
            if not include_warnings and isinstance(errors, list):
                errors = [e for e in errors if e.get('status', 0) >= 500]
            
            return {
                "hours": hours,
                "include_warnings": include_warnings,
                "total": len(errors) if isinstance(errors, list) else 0,
                "errors": errors if isinstance(errors, list) else []
            }
            
        except Exception as e:
            logger.error(f"Error querying error logs: {e}")
            raise HTTPException(500, f"Error querying logs: {str(e)}")
    
    
    @router.get("/events")
    async def get_event_statistics(
        request: Request,
        hours: int = Query(24, ge=1, le=720, description="Hours to analyze"),
        auth: AuthResult = Depends(AuthDep())
    ):
        """Get event statistics and aggregated metrics.
        
        Returns counts, rates, and distributions of various events.
        """
        try:
            if hasattr(request.app.state, 'async_storage'):
                async_storage = request.app.state.async_storage
                stats = await async_storage.get_event_statistics(hours=hours)
            else:
                stats = await request_logger.get_statistics(hours=hours)
            
            return stats
            
        except Exception as e:
            logger.error(f"Error getting event statistics: {e}")
            raise HTTPException(500, f"Error getting statistics: {str(e)}")
    
    
    @router.get("/stats")
    async def get_log_statistics(
        request: Request,
        hours: int = Query(24, ge=1, le=720, description="Hours to analyze"),
        auth: AuthResult = Depends(AuthDep())
    ):
        """Get comprehensive log statistics.
        
        Returns detailed statistics including request rates, error rates,
        response times, top paths, and user agents.
        """
        try:
            if hasattr(request.app.state, 'async_storage'):
                async_storage = request.app.state.async_storage
                stats = await async_storage.get_log_statistics(hours=hours)
            else:
                stats = await request_logger.get_statistics(hours=hours)
            
            # Add computed metrics
            if isinstance(stats, dict):
                total = stats.get('total_requests', 0)
                errors = stats.get('errors', 0)
                
                if total > 0:
                    stats['error_rate'] = round((errors / total) * 100, 2)
                    stats['success_rate'] = round(((total - errors) / total) * 100, 2)
                
                # Add time-based rates
                stats['requests_per_hour'] = round(total / hours if hours > 0 else 0, 2)
                stats['requests_per_minute'] = round(total / (hours * 60) if hours > 0 else 0, 2)
            
            return stats
            
        except Exception as e:
            logger.error(f"Error getting log statistics: {e}")
            raise HTTPException(500, f"Error getting statistics: {str(e)}")
    
    
    @router.get("/oauth/{ip}")
    async def get_oauth_activity(
        request: Request,
        ip: str,
        hours: int = Query(24, ge=1, le=720, description="Hours to look back"),
        limit: int = Query(100, ge=1, le=1000, description="Maximum results"),
        auth: AuthResult = Depends(AuthDep())
    ):
        """Get OAuth activity summary for a specific IP address.
        
        Returns OAuth-related events including authorizations, token exchanges,
        and API access.
        """
        try:
            oauth_events = []
            
            if hasattr(request.app.state, 'async_storage'):
                async_storage = request.app.state.async_storage
                # Get OAuth-specific events
                oauth_events = await async_storage.get_oauth_activity(
                    ip=ip,
                    hours=hours,
                    limit=limit
                )
            
            # If no OAuth-specific implementation, search general logs
            if not oauth_events:
                logs = await request_logger.search_logs(
                    ip=ip,
                    path="/authorize,/token,/introspect,/revoke",
                    hours=hours,
                    limit=limit
                )
                if isinstance(logs, dict):
                    oauth_events = logs.get('logs', [])
            
            return {
                "ip": ip,
                "hours": hours,
                "total": len(oauth_events),
                "oauth_activity": oauth_events
            }
            
        except Exception as e:
            logger.error(f"Error getting OAuth activity for {ip}: {e}")
            raise HTTPException(500, f"Error getting OAuth activity: {str(e)}")
    
    
    @router.get("/oauth-debug/{ip}")
    async def get_oauth_debug(
        request: Request,
        ip: str,
        hours: int = Query(24, ge=1, le=720, description="Hours to look back"),
        limit: int = Query(100, ge=1, le=1000, description="Maximum results"),
        auth: AuthResult = Depends(AuthDep(admin=True))
    ):
        """Get detailed OAuth debugging information for an IP address.
        
        Admin only. Returns detailed OAuth flow information including
        internal state transitions and error details.
        """
        try:
            debug_info = {
                "ip": ip,
                "hours": hours,
                "oauth_flows": [],
                "authorization_attempts": [],
                "token_exchanges": [],
                "introspection_requests": [],
                "errors": []
            }
            
            if hasattr(request.app.state, 'async_storage'):
                async_storage = request.app.state.async_storage
                # Get detailed OAuth debug info
                debug_data = await async_storage.get_oauth_debug(
                    ip=ip,
                    hours=hours,
                    limit=limit
                )
                if debug_data:
                    debug_info.update(debug_data)
            
            # Add general OAuth logs
            oauth_logs = await request_logger.search_logs(
                ip=ip,
                path="/authorize,/token,/callback,/introspect,/revoke",
                hours=hours,
                limit=limit
            )
            
            if isinstance(oauth_logs, dict):
                debug_info['raw_logs'] = oauth_logs.get('logs', [])
            
            return debug_info
            
        except Exception as e:
            logger.error(f"Error getting OAuth debug info for {ip}: {e}")
            raise HTTPException(500, f"Error getting debug info: {str(e)}")
    
    
    @router.get("/oauth-flow")
    async def track_oauth_flow(
        request: Request,
        client_id: Optional[str] = Query(None, description="OAuth client ID"),
        username: Optional[str] = Query(None, description="Username"),
        session_id: Optional[str] = Query(None, description="Session ID"),
        hours: int = Query(1, ge=1, le=24, description="Hours to look back"),
        auth: AuthResult = Depends(AuthDep())
    ):
        """Track OAuth authorization flows.
        
        Returns complete OAuth flows showing the sequence of authorization,
        callback, and token exchange events.
        """
        try:
            flows = []
            
            if hasattr(request.app.state, 'async_storage'):
                async_storage = request.app.state.async_storage
                flows = await async_storage.track_oauth_flows(
                    client_id=client_id,
                    username=username,
                    session_id=session_id,
                    hours=hours
                )
            
            # If no specific implementation, reconstruct from logs
            if not flows:
                search_params = {'hours': hours, 'limit': 1000}
                if client_id:
                    search_params['client_id'] = client_id
                if username:
                    search_params['user'] = username
                
                logs = await request_logger.search_logs(**search_params)
                
                # Group logs by session/flow
                # This is a simplified flow reconstruction
                if isinstance(logs, dict):
                    logs = logs.get('logs', [])
                
                # Group by approximate time windows (5 minute flows)
                flow_map = {}
                for log in logs if isinstance(logs, list) else []:
                    # Create flow key based on timestamp window
                    if 'timestamp' in log:
                        ts = datetime.fromisoformat(log['timestamp'].replace('Z', '+00:00'))
                        flow_key = f"{ts.strftime('%Y%m%d%H')}_{int(ts.minute / 5)}"
                        
                        if flow_key not in flow_map:
                            flow_map[flow_key] = {
                                'flow_id': flow_key,
                                'start_time': log['timestamp'],
                                'events': []
                            }
                        
                        flow_map[flow_key]['events'].append(log)
                        flow_map[flow_key]['end_time'] = log['timestamp']
                
                flows = list(flow_map.values())
            
            return {
                "filters": {
                    "client_id": client_id,
                    "username": username,
                    "session_id": session_id,
                    "hours": hours
                },
                "total_flows": len(flows),
                "flows": flows
            }
            
        except Exception as e:
            logger.error(f"Error tracking OAuth flows: {e}")
            raise HTTPException(500, f"Error tracking flows: {str(e)}")
    
    
    @router.post("/test")
    async def test_logging(
        request: Request,
        auth: AuthResult = Depends(AuthDep())
    ):
        """Test the logging system by generating test log entries.
        
        Creates various test log entries to verify the logging pipeline works.
        """
        try:
            test_entries = []
            timestamp = datetime.now(timezone.utc)
            
            # Generate test log entries
            test_data = [
                {
                    "timestamp": timestamp.isoformat(),
                    "client_ip": request.client.host if request.client else "127.0.0.1",
                    "hostname": request.headers.get("host", "test.example.com"),
                    "method": "GET",
                    "path": "/test/success",
                    "status_code": 200,
                    "response_time_ms": 42,
                    "user_id": auth.principal,
                    "message": "Test successful request"
                },
                {
                    "timestamp": (timestamp + timedelta(seconds=1)).isoformat(),
                    "client_ip": request.client.host if request.client else "127.0.0.1",
                    "hostname": request.headers.get("host", "test.example.com"),
                    "method": "POST",
                    "path": "/test/error",
                    "status_code": 500,
                    "response_time_ms": 150,
                    "user_id": auth.principal,
                    "error": "Test error entry",
                    "message": "Test error request"
                },
                {
                    "timestamp": (timestamp + timedelta(seconds=2)).isoformat(),
                    "client_ip": request.client.host if request.client else "127.0.0.1",
                    "hostname": request.headers.get("host", "test.example.com"),
                    "method": "GET",
                    "path": "/test/slow",
                    "status_code": 200,
                    "response_time_ms": 2500,
                    "user_id": auth.principal,
                    "message": "Test slow request"
                }
            ]
            
            # Log the test entries
            for entry in test_data:
                # Use async_storage if available
                if hasattr(request.app.state, 'async_storage'):
                    async_storage = request.app.state.async_storage
                    await async_storage.log_request(entry)
                elif hasattr(request_logger, 'log_request'):
                    await request_logger.log_request(entry)
                test_entries.append(entry)
                logger.info(f"Test log entry: {json.dumps(entry)}")
            
            return {
                "success": True,
                "status": "success",
                "message": "Test log entries created",
                "entries_created": len(test_entries),
                "test_data": test_entries
            }
            
        except Exception as e:
            logger.error(f"Error testing logging system: {e}")
            raise HTTPException(500, f"Error testing logs: {str(e)}")
    
    
    @router.delete("")
    async def clear_logs(
        request: Request,
        auth: AuthResult = Depends(AuthDep(admin=True))
    ):
        """Clear all log entries from storage.
        
        Admin only. Permanently deletes all log entries.
        """
        try:
            cleared_count = 0
            
            if hasattr(request.app.state, 'async_storage'):
                async_storage = request.app.state.async_storage
                cleared_count = await async_storage.clear_logs()
            else:
                # Clear using Redis patterns
                if storage.redis_client:
                    # Clear request logs
                    for key in storage.redis_client.scan_iter("req:*"):
                        storage.redis_client.delete(key)
                        cleared_count += 1
                    
                    # Clear indexes
                    for key in storage.redis_client.scan_iter("idx:req:*"):
                        storage.redis_client.delete(key)
                        cleared_count += 1
                    
                    # Clear stats
                    for key in storage.redis_client.scan_iter("stats:*"):
                        storage.redis_client.delete(key)
                        cleared_count += 1
            
            logger.info(f"Cleared {cleared_count} log entries")
            
            return {
                "status": "success",
                "message": f"Cleared {cleared_count} log entries",
                "cleared_count": cleared_count
            }
            
        except Exception as e:
            logger.error(f"Error clearing logs: {e}")
            raise HTTPException(500, f"Error clearing logs: {str(e)}")
    
    
    @router.get("/proxy/{hostname}")
    async def get_logs_by_proxy(
        request: Request,
        hostname: str,
        hours: int = Query(24, ge=1, le=720, description="Hours to look back"),
        limit: int = Query(100, ge=1, le=1000, description="Maximum results"),
        auth: AuthResult = Depends(AuthDep())
    ):
        """Query logs by proxy hostname.
        
        Returns all requests handled by the specified proxy.
        """
        try:
            if hasattr(request.app.state, 'async_storage'):
                async_storage = request.app.state.async_storage
                logs = await async_storage.get_logs_by_proxy(hostname, hours=hours, limit=limit)
            else:
                logs = await request_logger.query_by_hostname(hostname, hours=hours, limit=limit)
            
            return {
                "proxy_hostname": hostname,
                "hours": hours,
                "total": len(logs) if isinstance(logs, list) else 0,
                "logs": logs if isinstance(logs, list) else []
            }
            
        except Exception as e:
            logger.error(f"Error querying logs by proxy {hostname}: {e}")
            raise HTTPException(500, f"Error querying logs: {str(e)}")
    
    
    logger.info("Log query endpoints initialized successfully")
    return router