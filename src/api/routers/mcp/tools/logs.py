"""Log query and analysis MCP tools."""

import time
from typing import Any, Dict, List, Optional
from datetime import datetime, timezone, timedelta
import logging

from .base import BaseMCPTools

logger = logging.getLogger(__name__)


class LogTools(BaseMCPTools):
    """MCP tools for log management and analysis."""
    
    def register_tools(self):
        """Register all log management tools."""
        
        # Note: logs tool is already defined in mcp_server.py as query_logs
        # We'll add extended log tools here
        
        @self.mcp.tool(
            annotations={
                "title": "Query Logs by IP",
                "readOnlyHint": True,
                "destructiveHint": False,
                "idempotentHint": True,
                "openWorldHint": False
            }
        )
        async def logs_ip(
            ip: str,
            hours: int = 24,
            limit: int = 100,
            token: Optional[str] = None
        ) -> Dict[str, Any]:
            """Query logs by client IP address.
            
            Args:
                ip: Client IP address
                hours: Number of hours to search back
                limit: Maximum number of results
                token: Optional API token
                
            Returns:
                Dictionary with matching log entries
            """
            session_id = self.get_session_context()
            
            async with self.logger.trace_context(
                "mcp_tool_logs_ip",
                session_id=session_id,
                client_ip=ip
            ):
                user = "anonymous"
                if token:
                    try:
                        token_info = await self.validate_token(token)
                        user = token_info.get("name", "unknown")
                    except:
                        pass
                
                # Calculate time range
                start_time = time.time() - (hours * 3600)
                
                # Query logs from Redis using IP index
                logs = []
                try:
                    # Get log keys from IP index
                    index_key = f"idx:req:ip:{ip}"
                    log_keys = await self.storage.redis_client.zrevrange(index_key, 0, limit - 1)
                    
                    # Fetch log entries
                    if log_keys:
                        for key in log_keys:
                            if isinstance(key, bytes):
                                key = key.decode('utf-8')
                            log_data = await self.storage.redis_client.hgetall(key)
                            if log_data:
                                # Convert bytes to strings if needed
                                log_entry = {}
                                for k, v in log_data.items():
                                    if isinstance(k, bytes):
                                        k = k.decode('utf-8')
                                    if isinstance(v, bytes):
                                        v = v.decode('utf-8')
                                    log_entry[k] = v
                                logs.append(log_entry)
                except Exception as e:
                    logger.warning(f"Error querying logs by IP: {e}")
                    logs = []
                
                # Format logs
                formatted_logs = []
                for log in logs:
                    formatted_logs.append({
                        "timestamp": log.get("timestamp"),
                        "method": log.get("method"),
                        "path": log.get("path"),
                        "status_code": log.get("status_code"),
                        "hostname": log.get("hostname"),
                        "response_time": log.get("response_time_ms")
                    })
                
                # Log audit event
                await self.log_audit_event(
                    action="logs_ip",
                    session_id=session_id,
                    user=user,
                    details={"ip": ip, "hours": hours, "count": len(formatted_logs)}
                )
                
                # Match proxy-client API format
                return {
                    "ip": ip,
                    "hours": hours,
                    "total": len(formatted_logs),
                    "logs": formatted_logs
                }
        
        @self.mcp.tool(
            annotations={
                "title": "Query Logs by Proxy",
                "readOnlyHint": True,
                "destructiveHint": False,
                "idempotentHint": True,
                "openWorldHint": False
            }
        )
        async def logs_proxy(
            hostname: str,
            hours: int = 24,
            limit: int = 100,
            token: Optional[str] = None
        ) -> Dict[str, Any]:
            """Query logs by proxy hostname.
            
            Args:
                hostname: Proxy hostname
                hours: Number of hours to search back
                limit: Maximum number of results
                token: Optional API token
                
            Returns:
                Dictionary with matching log entries
            """
            session_id = self.get_session_context()
            
            async with self.logger.trace_context(
                "mcp_tool_logs_proxy",
                session_id=session_id,
                hostname=hostname
            ):
                user = "anonymous"
                if token:
                    try:
                        token_info = await self.validate_token(token)
                        user = token_info.get("name", "unknown")
                    except:
                        pass
                
                # Calculate time range
                start_time = time.time() - (hours * 3600)
                
                # Query logs from Redis using hostname index
                logs = []
                try:
                    # Get log keys from hostname index
                    index_key = f"idx:req:host:{hostname}"
                    log_keys = await self.storage.redis_client.zrevrange(index_key, 0, limit - 1)
                    
                    # Fetch log entries
                    if log_keys:
                        for key in log_keys:
                            if isinstance(key, bytes):
                                key = key.decode('utf-8')
                            log_data = await self.storage.redis_client.hgetall(key)
                            if log_data:
                                # Convert bytes to strings if needed
                                log_entry = {}
                                for k, v in log_data.items():
                                    if isinstance(k, bytes):
                                        k = k.decode('utf-8')
                                    if isinstance(v, bytes):
                                        v = v.decode('utf-8')
                                    log_entry[k] = v
                                logs.append(log_entry)
                except Exception as e:
                    logger.warning(f"Error querying logs by hostname: {e}")
                    logs = []
                
                # Format logs
                formatted_logs = []
                for log in logs:
                    formatted_logs.append({
                        "timestamp": log.get("timestamp"),
                        "client_ip": log.get("client_ip"),
                        "method": log.get("method"),
                        "path": log.get("path"),
                        "status_code": log.get("status_code"),
                        "response_time": log.get("response_time_ms")
                    })
                
                # Log audit event
                await self.log_audit_event(
                    action="logs_proxy",
                    session_id=session_id,
                    user=user,
                    details={"hostname": hostname, "hours": hours, "count": len(formatted_logs)}
                )
                
                # Match proxy-client API format for search endpoint with hostname filter
                return {
                    "total": len(formatted_logs),
                    "logs": formatted_logs,
                    "query_params": {
                        "hours": hours,
                        "limit": limit,
                        "offset": 0,
                        "hostname": hostname
                    }
                }
        
        @self.mcp.tool(
            annotations={
                "title": "Query Error Logs",
                "readOnlyHint": True,
                "destructiveHint": False,
                "idempotentHint": True,
                "openWorldHint": False
            }
        )
        async def logs_errors(
            hours: int = 1,
            limit: int = 20,
            include_warnings: bool = False,
            token: Optional[str] = None
        ) -> Dict[str, Any]:
            """Query error logs from the system.
            
            Args:
                hours: Number of hours to search back
                limit: Maximum number of results
                include_warnings: Include warning level logs
                token: Optional API token
                
            Returns:
                Dictionary with error log entries
            """
            session_id = self.get_session_context()
            
            async with self.logger.trace_context(
                "mcp_tool_logs_errors",
                session_id=session_id
            ):
                user = "anonymous"
                if token:
                    try:
                        token_info = await self.validate_token(token)
                        user = token_info.get("name", "unknown")
                    except:
                        pass
                
                # Calculate time range
                start_time = time.time() - (hours * 3600)
                
                # Query error logs from Redis
                logs = []
                try:
                    # Get error log keys from error index within time range
                    index_key = "idx:req:errors"
                    log_keys = await self.storage.redis_client.zrevrangebyscore(
                        index_key, 
                        "+inf",
                        start_time,
                        start=0,
                        num=limit * 2  # Get more to account for filtering
                    )
                    
                    # Fetch log entries
                    if log_keys:
                        for key in log_keys:
                            if isinstance(key, bytes):
                                key = key.decode('utf-8')
                            log_data = await self.storage.redis_client.hgetall(key)
                            if log_data:
                                # Convert bytes to strings if needed
                                log_entry = {}
                                for k, v in log_data.items():
                                    if isinstance(k, bytes):
                                        k = k.decode('utf-8')
                                    if isinstance(v, bytes):
                                        v = v.decode('utf-8')
                                    log_entry[k] = v
                                
                                # Filter by status code if include_warnings is False
                                status_code = int(log_entry.get('status', log_entry.get('status_code', 0)))
                                if not include_warnings and 400 <= status_code < 500:
                                    continue  # Skip 4xx errors if not including warnings
                                
                                logs.append(log_entry)
                                
                                # Stop if we have enough results
                                if len(logs) >= limit:
                                    break
                except Exception as e:
                    logger.warning(f"Error querying error logs: {e}")
                    logs = []
                
                # Format logs
                formatted_logs = []
                for log in logs:
                    formatted_logs.append({
                        "timestamp": log.get("timestamp"),
                        "client_ip": log.get("ip", log.get("client_ip")),
                        "hostname": log.get("hostname"),
                        "method": log.get("method"),
                        "path": log.get("path"),
                        "status_code": log.get("status", log.get("status_code")),
                        "response_time": log.get("response_time", log.get("response_time_ms")),
                        "error": log.get("error", log.get("message"))
                    })
                
                # Log audit event
                await self.log_audit_event(
                    action="logs_errors",
                    session_id=session_id,
                    user=user,
                    details={"hours": hours, "count": len(formatted_logs)}
                )
                
                # Match proxy-client API format
                return {
                    "errors": formatted_logs,
                    "total": len(formatted_logs),
                    "hours": hours,
                    "include_warnings": include_warnings
                }
        
        @self.mcp.tool(
            annotations={
                "title": "Get Log Statistics",
                "readOnlyHint": True,
                "destructiveHint": False,
                "idempotentHint": True,
                "openWorldHint": False
            }
        )
        async def logs_stats(
            hours: int = 24,
            token: Optional[str] = None
        ) -> Dict[str, Any]:
            """Get log statistics and metrics.
            
            Args:
                hours: Number of hours to analyze
                token: Optional API token
                
            Returns:
                Dictionary with log statistics
            """
            session_id = self.get_session_context()
            
            async with self.logger.trace_context(
                "mcp_tool_logs_stats",
                session_id=session_id
            ):
                user = "anonymous"
                if token:
                    try:
                        token_info = await self.validate_token(token)
                        user = token_info.get("name", "unknown")
                    except:
                        pass
                
                # Calculate time range
                start_time = time.time() - (hours * 3600)
                
                # Generate statistics (simplified for now, matching proxy-client format)
                # In a real implementation, this would query Redis statistics
                now = datetime.now(timezone.utc)
                start = datetime.fromtimestamp(start_time, tz=timezone.utc)
                
                # Match proxy-client API format for events/stats endpoint
                result = {
                    "total_requests": 0,
                    "unique_visitors": 0,
                    "errors": 0,
                    "average_response_time": 0,
                    "status_codes": {},
                    "top_paths": [],
                    "requests_by_hour": {},
                    "errors_by_hour": {}
                }
                
                # Try to get some basic stats from Redis if available
                try:
                    # Count total logs in the time range
                    # This is simplified - actual implementation would aggregate from Redis
                    pass
                except:
                    pass
                
                # Log audit event
                await self.log_audit_event(
                    action="logs_stats",
                    session_id=session_id,
                    user=user,
                    details={"hours": hours}
                )
                
                return result
        
        @self.mcp.tool(
            annotations={
                "title": "Clear Old Logs",
                "readOnlyHint": False,
                "destructiveHint": True,
                "idempotentHint": True,
                "openWorldHint": False
            }
        )
        async def logs_clear(
            days_to_keep: int = 7,
            admin_token: str = None
        ) -> Dict[str, Any]:
            """Clear old log entries.
            
            Args:
                days_to_keep: Number of days of logs to keep
                admin_token: Admin token for authentication (required)
                
            Returns:
                Dictionary with deletion status
            """
            session_id = self.get_session_context()
            
            async with self.logger.trace_context(
                "mcp_tool_logs_clear",
                session_id=session_id
            ):
                # Validate admin token
                token_info = await self.validate_token(admin_token, require_admin=True)
                user = token_info.get("name", "unknown")
                
                # Calculate cutoff time
                cutoff_time = time.time() - (days_to_keep * 86400)
                
                # Delete old logs
                deleted_count = await self.storage.delete_logs_before(cutoff_time)
                
                # Log audit event
                await self.log_audit_event(
                    action="logs_clear",
                    session_id=session_id,
                    user=user,
                    details={"days_to_keep": days_to_keep, "deleted_count": deleted_count}
                )
                
                return {
                    "status": "cleared",
                    "deleted_count": deleted_count,
                    "days_kept": days_to_keep,
                    "message": f"Deleted {deleted_count} log entries older than {days_to_keep} days"
                }