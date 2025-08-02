"""Log query API endpoints for searching and retrieving structured logs.

This module provides REST API endpoints for:
- Querying logs by IP address
- Querying logs by OAuth client ID
- Retrieving complete request flows by correlation ID
- Searching logs with various filters
- Exporting logs in different formats
"""

import json
import hashlib
import time
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Union
from enum import Enum

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, Field

from ....shared.logging import get_logger, get_request_logger
from ....storage import RedisStorage

# Set up logging
logger = get_logger(__name__)


class LogLevel(str, Enum):
    """Log level enumeration."""
    DEBUG = "DEBUG"
    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"
    CRITICAL = "CRITICAL"


class LogFormat(str, Enum):
    """Log export format."""
    JSON = "json"
    CSV = "csv"
    TEXT = "text"


class LogEntry(BaseModel):
    """Log entry model."""
    timestamp: float
    level: str
    component: str
    message: str
    correlation_id: Optional[str] = None
    ip: Optional[str] = None
    client_id: Optional[str] = None
    hostname: Optional[str] = None
    user_id: Optional[str] = None
    username: Optional[str] = None
    method: Optional[str] = None
    path: Optional[str] = None
    status: Optional[int] = None
    duration_ms: Optional[float] = None
    error: Optional[Dict] = None
    event: Optional[str] = None
    context: Optional[Dict] = Field(default_factory=dict)


class LogQueryResponse(BaseModel):
    """Log query response model."""
    total: int
    logs: List[LogEntry]
    query_params: Dict


class CorrelationFlowResponse(BaseModel):
    """Correlation flow response model."""
    correlation_id: str
    total_requests: int
    duration_ms: Optional[float] = None
    start_time: Optional[float] = None
    end_time: Optional[float] = None
    logs: List[LogEntry]
    flow_summary: Dict


def create_router(storage: RedisStorage) -> APIRouter:
    """Create the logs router with dependencies."""
    router = APIRouter(prefix="/logs", tags=["logs"])
    
    # Access Redis client directly for log queries
    redis_client = storage.redis_client
    
    async def verify_admin_token(request: Request):
        """Verify admin token for log access."""
        auth_header = request.headers.get("Authorization", "")
        if not auth_header.startswith("Bearer "):
            raise HTTPException(
                status_code=401,
                detail="Missing or invalid authorization header"
            )
        
        token = auth_header[7:]  # Remove "Bearer " prefix
        
        # Hash the token to match storage format
        token_hash = f"sha256:{hashlib.sha256(token.encode()).hexdigest()}"
        
        # Check if it's a valid token
        token_data = storage.get_api_token(token_hash)
        if not token_data:
            raise HTTPException(
                status_code=403,
                detail="Invalid token"
            )
        
        return token_data
    
    @router.get("/ip/{ip_address}", response_model=LogQueryResponse)
    async def query_logs_by_ip(
        ip_address: str,
        hours: int = Query(24, ge=1, le=168, description="Number of hours to look back"),
        level: Optional[LogLevel] = Query(None, description="Filter by log level"),
        event: Optional[str] = Query(None, description="Filter by event type"),
        limit: int = Query(100, ge=1, le=1000, description="Maximum number of logs to return"),
        offset: int = Query(0, ge=0, description="Offset for pagination"),
        _token: Dict = Depends(verify_admin_token)
    ):
        """Query logs by IP address.
        
        Returns all log entries from a specific IP address within the specified time range.
        """
        logger.info(f"Querying logs for IP: {ip_address}, hours: {hours}")
        
        # Get request logger
        request_logger = get_request_logger()
        if not request_logger:
            # Fallback to empty response if RequestLogger not available
            return LogQueryResponse(
                total=0,
                logs=[],
                query_params={
                    "ip_address": ip_address,
                    "hours": hours,
                    "level": level,
                    "event": event,
                    "limit": limit,
                    "offset": offset
                }
            )
        
        # Query logs using RequestLogger
        try:
            requests = await request_logger.query_by_ip(ip_address, hours, limit * 10)  # Get extra for filtering
            
            # Convert to LogEntry format
            logs = []
            for req in requests:
                # Build log entry from request data
                log_entry = {
                    "timestamp": float(req.get("timestamp", 0)),
                    "level": "ERROR" if int(req.get("status", 0)) >= 500 else "INFO",
                    "component": "http.request",
                    "message": f"{req.get('method', '')} {req.get('path', '')} -> {req.get('status', '')}",
                    "correlation_id": req.get("correlation_id"),
                    "ip": req.get("ip"),
                    "hostname": req.get("hostname"),
                    "method": req.get("method"),
                    "path": req.get("path"),
                    "status": int(req.get("status", 0)) if req.get("status") else None,
                    "duration_ms": float(req.get("duration_ms", 0)) if req.get("duration_ms") else None,
                    "event": "request",
                    "context": {
                        "user_agent": req.get("user_agent", ""),
                        "auth_user": req.get("auth_user", ""),
                        "query": req.get("query", "")
                    }
                }
                
                # Add error info if present
                if req.get("error_type"):
                    log_entry["error"] = {
                        "type": req.get("error_type"),
                        "message": req.get("error_message", "")
                    }
                
                logs.append(log_entry)
            
        except Exception as e:
            logger.error(f"Error querying request logs: {e}")
            logs = []
        
        # Apply filters
        if level:
            logs = [log for log in logs if log.get("level") == level.value]
        if event:
            logs = [log for log in logs if log.get("event", "").startswith(event)]
        
        # Sort by timestamp descending
        logs.sort(key=lambda x: x.get("timestamp", 0), reverse=True)
        
        # Apply pagination
        total = len(logs)
        logs = logs[offset:offset + limit]
        
        return LogQueryResponse(
            total=total,
            logs=[LogEntry(**log) for log in logs],
            query_params={
                "ip_address": ip_address,
                "hours": hours,
                "level": level,
                "event": event,
                "limit": limit,
                "offset": offset
            }
        )
    
    @router.get("/client/{client_id}", response_model=LogQueryResponse)
    async def query_logs_by_client(
        client_id: str,
        hours: int = Query(24, ge=1, le=168, description="Number of hours to look back"),
        level: Optional[LogLevel] = Query(None, description="Filter by log level"),
        event: Optional[str] = Query(None, description="Filter by event type"),
        limit: int = Query(100, ge=1, le=1000, description="Maximum number of logs to return"),
        offset: int = Query(0, ge=0, description="Offset for pagination"),
        _token: Dict = Depends(verify_admin_token)
    ):
        """Query logs by OAuth client ID.
        
        Returns all log entries from a specific OAuth client within the specified time range.
        """
        logger.info(f"Querying logs for client: {client_id}, hours: {hours}")
        
        # Query logs from Redis stream
        min_timestamp = time.time() - (hours * 3600)
        logs = []
        
        # Read from the Redis stream and filter by client ID
        try:
            stream_entries = redis_client.xrevrange("logs:stream", "+", "-", count=10000)
            
            for entry_id, data in stream_entries:
                if "data" in data:
                    log_entry = json.loads(data["data"])
                    
                    # Handle double-encoded JSON in message field
                    if log_entry.get("client_id") is None and isinstance(log_entry.get("message"), str):
                        try:
                            # Try to parse message as JSON
                            message_data = json.loads(log_entry["message"])
                            if isinstance(message_data, dict):
                                # Merge message data into log entry
                                log_entry.update(message_data)
                        except:
                            pass
                    
                    # Convert timestamp to Unix timestamp
                    timestamp_val = log_entry.get("timestamp", 0)
                    if isinstance(timestamp_val, str):
                        try:
                            # Parse ISO timestamp
                            dt = datetime.fromisoformat(timestamp_val.replace('Z', '+00:00'))
                            timestamp = dt.timestamp()
                        except:
                            timestamp = 0
                    else:
                        timestamp = float(timestamp_val)
                    
                    # Check timestamp and client ID match
                    if (timestamp >= min_timestamp and 
                        log_entry.get("client_id") == client_id):
                        # Update timestamp to float for LogEntry model
                        log_entry["timestamp"] = timestamp
                        logs.append(log_entry)
        except Exception as e:
            logger.error(f"Error reading from log stream: {e}")
        
        # Apply filters
        if level:
            logs = [log for log in logs if log.get("level") == level.value]
        if event:
            logs = [log for log in logs if log.get("event", "").startswith(event)]
        
        # Sort by timestamp descending
        logs.sort(key=lambda x: x.get("timestamp", 0), reverse=True)
        
        # Apply pagination
        total = len(logs)
        logs = logs[offset:offset + limit]
        
        return LogQueryResponse(
            total=total,
            logs=[LogEntry(**log) for log in logs],
            query_params={
                "client_id": client_id,
                "hours": hours,
                "level": level,
                "event": event,
                "limit": limit,
                "offset": offset
            }
        )
    
    @router.get("/correlation/{correlation_id}", response_model=CorrelationFlowResponse)
    async def get_correlation_flow(
        correlation_id: str,
        include_sub_requests: bool = Query(True, description="Include sub-requests in the flow"),
        _token: Dict = Depends(verify_admin_token)
    ):
        """Get complete request flow by correlation ID.
        
        Returns all log entries that are part of the same request flow,
        including OAuth authorization, token generation, and subsequent API calls.
        """
        logger.info(f"Retrieving correlation flow: {correlation_id}")
        
        # Query all logs for this correlation ID
        logs = []
        
        # Look for logs indexed by correlation
        index_key = f"logs:index:correlation:{correlation_id}"
        log_ids = redis_client.zrange(index_key, 0, -1)
        
        for log_id in log_ids:
            log_key = f"logs:entry:{log_id}"
            log_data = redis_client.get(log_key)
            if log_data:
                logs.append(json.loads(log_data))
        
        # Also check for sub-requests if requested
        if include_sub_requests:
            parent_pattern = f"logs:entry:{correlation_id}*"
            for key in redis_client.scan_iter(match=parent_pattern, count=100):
                log_data = redis_client.get(key)
                if log_data:
                    log_entry = json.loads(log_data)
                    if log_entry not in logs:
                        logs.append(log_entry)
        
        if not logs:
            raise HTTPException(
                status_code=404,
                detail=f"No logs found for correlation ID: {correlation_id}"
            )
        
        # Sort by timestamp
        logs.sort(key=lambda x: x.get("timestamp", 0))
        
        # Calculate flow metrics
        start_time = min(log["timestamp"] for log in logs)
        end_time = max(log["timestamp"] for log in logs)
        duration_ms = (end_time - start_time) * 1000
        
        # Build flow summary
        flow_summary = {
            "total_requests": len(logs),
            "error_count": sum(1 for log in logs if log.get("level") in ["ERROR", "CRITICAL"]),
            "warning_count": sum(1 for log in logs if log.get("level") == "WARNING"),
            "unique_ips": list(set(log.get("ip") for log in logs if log.get("ip"))),
            "unique_hosts": list(set(log.get("hostname") for log in logs if log.get("hostname"))),
            "events": {}
        }
        
        # Count events
        for log in logs:
            event = log.get("event", "unknown")
            flow_summary["events"][event] = flow_summary["events"].get(event, 0) + 1
        
        return CorrelationFlowResponse(
            correlation_id=correlation_id,
            total_requests=len(logs),
            duration_ms=duration_ms,
            start_time=start_time,
            end_time=end_time,
            logs=[LogEntry(**log) for log in logs],
            flow_summary=flow_summary
        )
    
    @router.get("/search", response_model=LogQueryResponse)
    async def search_logs(
        q: Optional[str] = Query(None, description="Search query for message content"),
        hours: int = Query(24, ge=1, le=168, description="Number of hours to look back"),
        level: Optional[LogLevel] = Query(None, description="Filter by log level"),
        event: Optional[str] = Query(None, description="Filter by event type"),
        hostname: Optional[str] = Query(None, description="Filter by hostname"),
        status_min: Optional[int] = Query(None, ge=100, le=599, description="Minimum HTTP status code"),
        status_max: Optional[int] = Query(None, ge=100, le=599, description="Maximum HTTP status code"),
        limit: int = Query(100, ge=1, le=1000, description="Maximum number of logs to return"),
        offset: int = Query(0, ge=0, description="Offset for pagination"),
        _token: Dict = Depends(verify_admin_token)
    ):
        """Search logs with various filters.
        
        Provides a flexible search interface for querying logs across multiple dimensions.
        """
        logger.info(f"Searching logs with query: {q}, filters: level={level}, event={event}, hostname={hostname}")
        
        # Get recent logs from the stream
        min_timestamp = time.time() - (hours * 3600)
        logs = []
        
        # Read from the Redis stream
        try:
            # Read stream entries from the beginning
            stream_entries = redis_client.xrevrange("logs:stream", "+", "-", count=10000)
            
            for entry_id, data in stream_entries:
                if "data" in data:
                    log_entry = json.loads(data["data"])
                    
                    # Handle double-encoded JSON in message field
                    if (log_entry.get("ip") is None and log_entry.get("hostname") is None and 
                        isinstance(log_entry.get("message"), str)):
                        try:
                            # Try to parse message as JSON
                            message_data = json.loads(log_entry["message"])
                            if isinstance(message_data, dict):
                                # Merge message data into log entry
                                log_entry.update(message_data)
                        except:
                            pass
                    
                    # Convert timestamp to Unix timestamp
                    timestamp_val = log_entry.get("timestamp", 0)
                    if isinstance(timestamp_val, str):
                        try:
                            # Parse ISO timestamp
                            dt = datetime.fromisoformat(timestamp_val.replace('Z', '+00:00'))
                            timestamp = dt.timestamp()
                        except:
                            timestamp = 0
                    else:
                        timestamp = float(timestamp_val)
                    
                    if timestamp >= min_timestamp:
                        # Update timestamp to float for LogEntry model
                        log_entry["timestamp"] = timestamp
                        logs.append(log_entry)
        except Exception as e:
            logger.error(f"Error reading from log stream: {e}")
            # Fallback to scanning for individual entries
            pattern = "logs:entry:*"
            for key in redis_client.scan_iter(match=pattern, count=100):
                log_data = redis_client.get(key)
                if log_data:
                    log_entry = json.loads(log_data)
                    if log_entry.get("timestamp", 0) >= min_timestamp:
                        logs.append(log_entry)
        
        # Apply filters
        filtered_logs = logs
        
        if q:
            # Simple text search in message
            filtered_logs = [
                log for log in filtered_logs 
                if q.lower() in log.get("message", "").lower()
            ]
        
        if level:
            filtered_logs = [log for log in filtered_logs if log.get("level") == level.value]
        
        if event:
            filtered_logs = [log for log in filtered_logs if log.get("event", "").startswith(event)]
        
        if hostname:
            filtered_logs = [log for log in filtered_logs if log.get("hostname") == hostname]
        
        if status_min is not None or status_max is not None:
            filtered_logs = [
                log for log in filtered_logs 
                if log.get("status") and (
                    (status_min is None or log["status"] >= status_min) and
                    (status_max is None or log["status"] <= status_max)
                )
            ]
        
        # Sort by timestamp descending
        filtered_logs.sort(key=lambda x: x.get("timestamp", 0), reverse=True)
        
        # Apply pagination
        total = len(filtered_logs)
        filtered_logs = filtered_logs[offset:offset + limit]
        
        return LogQueryResponse(
            total=total,
            logs=[LogEntry(**log) for log in filtered_logs],
            query_params={
                "q": q,
                "hours": hours,
                "level": level,
                "event": event,
                "hostname": hostname,
                "status_min": status_min,
                "status_max": status_max,
                "limit": limit,
                "offset": offset
            }
        )
    
    @router.get("/events", response_model=Dict[str, int])
    async def get_event_statistics(
        hours: int = Query(24, ge=1, le=168, description="Number of hours to look back"),
        _token: Dict = Depends(verify_admin_token)
    ):
        """Get event statistics.
        
        Returns a count of all event types in the specified time range.
        """
        # Scan recent logs for events
        min_timestamp = time.time() - (hours * 3600)
        event_counts = {}
        
        try:
            # Read from the Redis stream
            stream_entries = redis_client.xrevrange("logs:stream", "+", "-", count=10000)
            
            for entry_id, data in stream_entries:
                if "data" in data:
                    log_entry = json.loads(data["data"])
                    if log_entry.get("timestamp", 0) >= min_timestamp:
                        event = log_entry.get("event", "unknown")
                        event_counts[event] = event_counts.get(event, 0) + 1
        except Exception as e:
            logger.error(f"Error reading from log stream: {e}")
            # Fallback to scanning for individual entries
            pattern = "logs:entry:*"
            for key in redis_client.scan_iter(match=pattern, count=100):
                log_data = redis_client.get(key)
                if log_data:
                    log_entry = json.loads(log_data)
                    if log_entry.get("timestamp", 0) >= min_timestamp:
                        event = log_entry.get("event", "unknown")
                        event_counts[event] = event_counts.get(event, 0) + 1
        
        # Sort by count descending
        sorted_events = dict(sorted(event_counts.items(), key=lambda x: x[1], reverse=True))
        
        return sorted_events
    
    @router.get("/errors", response_model=LogQueryResponse)
    async def get_recent_errors(
        hours: int = Query(1, ge=1, le=24, description="Number of hours to look back"),
        include_warnings: bool = Query(False, description="Include warnings in addition to errors"),
        limit: int = Query(50, ge=1, le=500, description="Maximum number of logs to return"),
        _token: Dict = Depends(verify_admin_token)
    ):
        """Get recent errors and optionally warnings.
        
        Useful for monitoring and alerting on system issues.
        """
        logger.info(f"Retrieving recent errors, hours: {hours}, include_warnings: {include_warnings}")
        
        # Get recent logs
        min_timestamp = time.time() - (hours * 3600)
        error_logs = []
        
        try:
            # Read from the Redis stream
            stream_entries = redis_client.xrevrange("logs:stream", "+", "-", count=10000)
            
            for entry_id, data in stream_entries:
                if "data" in data:
                    log_entry = json.loads(data["data"])
                    if log_entry.get("timestamp", 0) >= min_timestamp:
                        level = log_entry.get("level")
                        if level in ["ERROR", "CRITICAL"] or (include_warnings and level == "WARNING"):
                            error_logs.append(log_entry)
        except Exception as e:
            logger.error(f"Error reading from log stream: {e}")
            # Fallback to scanning for individual entries
            pattern = "logs:entry:*"
            for key in redis_client.scan_iter(match=pattern, count=100):
                log_data = redis_client.get(key)
                if log_data:
                    log_entry = json.loads(log_data)
                    if log_entry.get("timestamp", 0) >= min_timestamp:
                        level = log_entry.get("level")
                        if level in ["ERROR", "CRITICAL"] or (include_warnings and level == "WARNING"):
                            error_logs.append(log_entry)
        
        # Sort by timestamp descending
        error_logs.sort(key=lambda x: x.get("timestamp", 0), reverse=True)
        
        # Apply limit
        total = len(error_logs)
        error_logs = error_logs[:limit]
        
        return LogQueryResponse(
            total=total,
            logs=[LogEntry(**log) for log in error_logs],
            query_params={
                "hours": hours,
                "include_warnings": include_warnings,
                "limit": limit
            }
        )
    
    return router