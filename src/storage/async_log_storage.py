"""Async Redis Streams logging implementation.

This module provides comprehensive async logging with Redis Streams,
following the patterns documented in CLAUDE.md.
"""

import json
import logging
import time
import socket
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional, Any
from collections import defaultdict

import redis.asyncio as redis
from redis.exceptions import RedisError

logger = logging.getLogger(__name__)


class AsyncLogStorage:
    """Async logging implementation using Redis Streams and indexes."""
    
    def __init__(self, redis_client):
        """Initialize with existing Redis client."""
        self.redis = redis_client
        self.stream_key = "stream:requests"
        self.consumer_group = "log-consumers"
        self.consumer_name = "log-consumer-1"
        
    async def initialize(self):
        """Initialize stream consumer group."""
        try:
            # Create consumer group if it doesn't exist
            await self.redis.xgroup_create(
                self.stream_key,
                self.consumer_group,
                id="$",
                mkstream=True
            )
            logger.info(f"Created consumer group {self.consumer_group}")
        except redis.ResponseError as e:
            if "BUSYGROUP" not in str(e):
                raise
            # Group already exists, that's fine
            logger.debug(f"Consumer group {self.consumer_group} already exists")
    
    async def log_request(self, log_entry: Dict[str, Any]) -> str:
        """Log a request to the unified Redis stream.
        
        This is now just a compatibility wrapper that writes directly to the unified stream.
        No more indexes, no more req: keys, just the stream.
        
        Args:
            log_entry: Dictionary containing request/response data
            
        Returns:
            Stream entry ID
        """
        try:
            # Get timestamp in milliseconds for streams
            timestamp_str = log_entry.get('timestamp', '')
            if timestamp_str:
                try:
                    # Try to parse ISO format
                    dt = datetime.fromisoformat(timestamp_str.replace('Z', '+00:00'))
                    timestamp_ms = int(dt.timestamp() * 1000)
                except:
                    # Assume it's already Unix timestamp
                    timestamp_ms = int(float(timestamp_str) * 1000) if timestamp_str else int(time.time() * 1000)
            else:
                timestamp_ms = int(time.time() * 1000)
                timestamp_str = datetime.fromtimestamp(timestamp_ms / 1000, tz=timezone.utc).isoformat()
            
            # Build the log entry for the unified stream
            stream_data = {
                'timestamp': str(timestamp_ms),  # Store as milliseconds for stream queries
                'timestamp_iso': timestamp_str,   # Also keep ISO format for display
                'client_ip': log_entry.get('client_ip', '127.0.0.1'),
                'client_hostname': log_entry.get('client_hostname', ''),
                'proxy_hostname': log_entry.get('proxy_hostname', ''),
                'method': log_entry.get('method', 'GET'),
                'path': log_entry.get('path', '/'),
                'query': log_entry.get('query', ''),
                'status_code': str(log_entry.get('status_code', 0)),
                'response_time_ms': str(log_entry.get('response_time_ms', 0)),
                'user_id': log_entry.get('user_id', 'anonymous'),
                'user_agent': log_entry.get('user_agent', ''),
                'referrer': log_entry.get('referrer', ''),
                'bytes_sent': str(log_entry.get('bytes_sent', 0)),
                'auth_type': log_entry.get('auth_type', ''),
                'oauth_client_id': log_entry.get('oauth_client_id', ''),
                'oauth_username': log_entry.get('oauth_username', ''),
                'error': log_entry.get('error', ''),
                'error_type': log_entry.get('error_type', ''),
                'message': log_entry.get('message', ''),
                'level': log_entry.get('level', 'INFO'),
                'component': log_entry.get('component', 'request_logger'),
                'log_type': 'http_request'
            }
            
            # Write to the unified log stream
            stream_id = await self.redis.xadd(
                "logs:all:stream",
                stream_data,
                maxlen=1000000,  # Keep last 1M entries
                approximate=True
            )
            
            logger.debug(f"Logged to unified stream with ID: {stream_id}")
            return stream_id
            
        except Exception as e:
            logger.error(f"Error logging request: {e}")
            return ""
    
    async def search_logs(self, **kwargs) -> Dict[str, Any]:
        """Search logs from Redis Streams.
        
        Queries the unified log stream for all log entries.
        """
        try:
            hours = kwargs.get('hours', 24)
            limit = kwargs.get('limit', 100)
            offset = kwargs.get('offset', 0)
            
            # Calculate time window (Redis streams use millisecond timestamps)
            now = datetime.now(timezone.utc)
            cutoff = now - timedelta(hours=hours)
            cutoff_ms = int(cutoff.timestamp() * 1000)
            now_ms = int(now.timestamp() * 1000)
            
            logger.info(f"Search logs from stream: cutoff={cutoff_ms}, now={now_ms}, hours={hours}")
            
            # Query the unified log stream
            # XREVRANGE returns entries in reverse chronological order
            stream_key = "logs:all:stream"
            
            # Build the count parameter (limit + offset to handle pagination)
            count = limit + offset if offset > 0 else limit
            
            # Query the stream
            entries = await self.redis.xrevrange(
                stream_key,
                max=now_ms,
                min=cutoff_ms,
                count=count
            )
            
            logger.info(f"Found {len(entries)} entries in stream {stream_key}")
            
            # Process entries and apply filters
            logs = []
            for entry_id, data in entries:
                # Skip entries before offset
                if offset > 0:
                    offset -= 1
                    continue
                
                # Stop if we have enough entries
                if len(logs) >= limit:
                    break
                
                # Apply filters
                if kwargs.get('client_ip') and data.get('client_ip') != kwargs['client_ip']:
                    continue
                if kwargs.get('proxy_hostname') and data.get('proxy_hostname') != kwargs['proxy_hostname']:
                    continue
                if kwargs.get('user') and data.get('user_id') != kwargs['user']:
                    continue
                if kwargs.get('status') and str(data.get('status_code', '')) != str(kwargs['status']):
                    continue
                if kwargs.get('method') and data.get('method') != kwargs['method']:
                    continue
                if kwargs.get('path') and kwargs['path'] not in data.get('path', ''):
                    continue
                
                # Apply query search across multiple fields
                if kwargs.get('query'):
                    query = kwargs['query']
                    # Parse structured queries like "method:GET" or "status:200"
                    if ':' in query:
                        field, value = query.split(':', 1)
                        field_lower = field.lower()
                        value_lower = value.lower()
                        
                        # Map field names to data keys
                        field_map = {
                            'method': 'method',
                            'status': 'status_code', 
                            'path': 'path',
                            'user': 'user_id',
                            'ip': 'client_ip',
                            'hostname': 'proxy_hostname',
                            'component': 'component',
                            'level': 'level',
                            'error': 'error'
                        }
                        
                        if field_lower in field_map:
                            data_field = field_map[field_lower]
                            data_value = str(data.get(data_field, '')).lower()
                            # For method comparison, need exact match
                            if field_lower == 'method':
                                if data_value != value_lower:
                                    continue
                            # For other fields, allow partial matching
                            elif value_lower not in data_value:
                                continue
                            # If we get here, the structured query matched, so keep this entry
                        else:
                            # Unknown field in structured query, skip this entry
                            continue
                    else:
                        # General text search across all fields
                        query_lower = query.lower()
                        searchable = [
                            data.get('path', ''),
                            data.get('method', ''),
                            data.get('message', ''),
                            data.get('user_id', ''),
                            data.get('client_ip', ''),
                            data.get('proxy_hostname', ''),
                            data.get('error', ''),
                            data.get('component', '')
                        ]
                        if not any(query_lower in str(field).lower() for field in searchable if field):
                            continue
                
                # Convert stream entry to log format
                log_entry = {
                    'timestamp': data.get('timestamp_iso') or data.get('timestamp', ''),
                    'client_ip': data.get('client_ip', ''),
                    'client_hostname': data.get('client_hostname', ''),
                    'proxy_hostname': data.get('proxy_hostname', ''),
                    'method': data.get('method', ''),
                    'path': data.get('path', ''),
                    'query': data.get('query', ''),
                    'status_code': int(data.get('status_code', 0)) if data.get('status_code') else int(data.get('status', 0)) if data.get('status') else 0,
                    'response_time_ms': float(data.get('response_time_ms', 0)) if data.get('response_time_ms') else float(data.get('duration_ms', 0)) if data.get('duration_ms') else 0.0,
                    'user_id': data.get('user_id', 'anonymous'),
                    'user_agent': data.get('user_agent', ''),
                    'referrer': data.get('referrer', ''),
                    'bytes_sent': int(data.get('bytes_sent', 0)) if data.get('bytes_sent') else 0,
                    'auth_type': data.get('auth_type', ''),
                    'oauth_client_id': data.get('oauth_client_id', ''),
                    'oauth_username': data.get('oauth_username', ''),
                    'message': data.get('message', ''),
                    'level': data.get('level', 'INFO'),
                    'component': data.get('component', ''),
                    'log_type': data.get('log_type', 'http_request'),
                    'error': data.get('error', ''),
                    'error_type': data.get('error_type', '')
                }
                
                logs.append(log_entry)
            
            return {
                'total': len(logs),
                'logs': logs,
                'query_params': kwargs
            }
        except Exception as e:
            logger.error(f"Error searching logs: {e}")
            return {'total': 0, 'logs': [], 'error': str(e)}
    
    async def get_logs_by_ip(self, client_ip: str, hours: int = 24, limit: int = 100) -> List[Dict]:
        """Get logs by client IP address."""
        result = await self.search_logs(client_ip=client_ip, hours=hours, limit=limit)
        return result.get('logs', [])
    
    async def get_logs_by_hostname(self, proxy_hostname: str, hours: int = 24, limit: int = 100) -> List[Dict]:
        """Get logs by proxy hostname."""
        result = await self.search_logs(proxy_hostname=proxy_hostname, hours=hours, limit=limit)
        return result.get('logs', [])
    
    async def get_logs_by_proxy(self, proxy_hostname: str, hours: int = 24, limit: int = 100) -> List[Dict]:
        """Get logs by proxy hostname."""
        return await self.get_logs_by_hostname(proxy_hostname, hours, limit)
    
    async def get_logs_by_client(self, client_id: str, hours: int = 24, limit: int = 100) -> List[Dict]:
        """Get logs by OAuth client ID."""
        # For OAuth clients, we'd need to track client_id in the log entry
        # For now, search in message/path for client_id
        result = await self.search_logs(query=client_id, hours=hours, limit=limit)
        return result.get('logs', [])
    
    async def get_error_logs(self, hours: int = 1, include_4xx: bool = False, limit: int = 50) -> List[Dict]:
        """Get error logs."""
        try:
            cutoff = datetime.now(timezone.utc) - timedelta(hours=hours)
            cutoff_timestamp = cutoff.timestamp()
            
            # Get error entries from index
            request_keys = await self.redis.zrevrangebyscore(
                "idx:req:errors",
                '+inf',
                cutoff_timestamp,
                start=0,
                num=limit
            )
            
            errors = []
            for req_key in request_keys:
                req_data = await self.redis.hgetall(req_key)
                if req_data:
                    status = int(req_data.get('status_code', 0))
                    if not include_4xx and status < 500:
                        continue
                    
                    errors.append({
                        'timestamp': req_data.get('timestamp', ''),
                        'client_ip': req_data.get('client_ip', ''),
                        'proxy_hostname': req_data.get('proxy_hostname', ''),
                        'client_hostname': req_data.get('client_hostname', ''),
                        'method': req_data.get('method', ''),
                        'path': req_data.get('path', ''),
                        'query': req_data.get('query', ''),  # Include query parameters
                        'status_code': status,
                        'error': req_data.get('error', ''),
                        'message': req_data.get('message', '')
                    })
            
            return errors
            
        except Exception as e:
            logger.error(f"Error getting error logs: {e}")
            return []
    
    async def get_event_statistics(self, hours: int = 24) -> Dict[str, Any]:
        """Get event statistics for the specified time period."""
        try:
            stats = {
                'total_requests': 0,
                'unique_visitors': 0,
                'errors': 0,
                'requests_by_hour': {},
                'errors_by_hour': {},
                'status_codes': defaultdict(int),
                'top_paths': [],
                'average_response_time': 0
            }
            
            # Get hourly stats for the period
            now = datetime.now(timezone.utc)
            for h in range(hours):
                hour_time = now - timedelta(hours=h)
                hour_key = f"stats:requests:{hour_time.strftime('%Y%m%d:%H')}"
                
                hour_stats = await self.redis.hgetall(hour_key)
                if hour_stats:
                    hour_total = int(hour_stats.get('total', 0))
                    stats['total_requests'] += hour_total
                    stats['requests_by_hour'][hour_time.strftime('%Y-%m-%d %H:00')] = hour_total
                    
                    # Count status codes
                    for key, value in hour_stats.items():
                        if key.startswith('status_'):
                            status = key.replace('status_', '')
                            stats['status_codes'][status] += int(value)
                            if int(status) >= 400:
                                stats['errors'] += int(value)
                
                # Get error stats
                error_key = f"stats:errors:{hour_time.strftime('%Y%m%d:%H')}"
                error_stats = await self.redis.hgetall(error_key)
                if error_stats:
                    hour_errors = sum(int(v) for v in error_stats.values())
                    stats['errors_by_hour'][hour_time.strftime('%Y-%m-%d %H:00')] = hour_errors
            
            # Get unique visitors (approximate with HyperLogLog)
            # This would need to aggregate across all hostnames
            # For now, return a placeholder
            stats['unique_visitors'] = len(set())  # Would use PFCOUNT
            
            return stats
            
        except Exception as e:
            logger.error(f"Error getting event statistics: {e}")
            return {}
    
    async def get_log_statistics(self, hours: int = 24) -> Dict[str, Any]:
        """Get comprehensive log statistics."""
        return await self.get_event_statistics(hours)
    
    async def get_oauth_activity(self, ip: str, hours: int = 24, limit: int = 100) -> List[Dict]:
        """Get OAuth activity for an IP."""
        # Search for OAuth-related paths
        result = await self.search_logs(
            ip=ip,
            hours=hours,
            limit=limit
        )
        
        oauth_logs = []
        for log in result.get('logs', []):
            if any(path in log.get('path', '') for path in ['/authorize', '/token', '/callback', '/introspect', '/revoke']):
                oauth_logs.append(log)
        
        return oauth_logs
    
    async def get_oauth_debug(self, ip: str, hours: int = 24, limit: int = 100) -> Dict[str, Any]:
        """Get detailed OAuth debug information."""
        oauth_logs = await self.get_oauth_activity(ip, hours, limit)
        
        debug_info = {
            'oauth_flows': [],
            'authorization_attempts': [],
            'token_exchanges': [],
            'errors': []
        }
        
        for log in oauth_logs:
            path = log.get('path', '')
            if '/authorize' in path:
                debug_info['authorization_attempts'].append(log)
            elif '/token' in path:
                debug_info['token_exchanges'].append(log)
            if log.get('status_code', 0) >= 400:
                debug_info['errors'].append(log)
        
        return debug_info
    
    async def track_oauth_flows(self, client_id: Optional[str] = None, 
                                username: Optional[str] = None,
                                session_id: Optional[str] = None,
                                hours: int = 1) -> List[Dict]:
        """Track OAuth authorization flows."""
        # This would need more sophisticated session tracking
        # For now, return grouped logs
        search_params = {'hours': hours, 'limit': 1000}
        if username:
            search_params['user'] = username
        
        result = await self.search_logs(**search_params)
        
        # Group logs into flows (simplified)
        flows = []
        current_flow = None
        
        for log in result.get('logs', []):
            if '/authorize' in log.get('path', ''):
                # Start new flow
                if current_flow:
                    flows.append(current_flow)
                current_flow = {
                    'flow_id': f"flow_{len(flows)}",
                    'start_time': log['timestamp'],
                    'events': [log]
                }
            elif current_flow:
                current_flow['events'].append(log)
                current_flow['end_time'] = log['timestamp']
        
        if current_flow:
            flows.append(current_flow)
        
        return flows
    
    async def clear_logs(self) -> int:
        """Clear all log entries."""
        try:
            cleared = 0
            
            # Use SCAN to iterate through keys safely
            cursor = 0
            while True:
                cursor, keys = await self.redis.scan(
                    cursor, 
                    match="req:*",
                    count=100
                )
                
                if keys:
                    await self.redis.delete(*keys)
                    cleared += len(keys)
                
                if cursor == 0:
                    break
            
            # Clear indexes
            for pattern in ["idx:req:*", "stats:*"]:
                cursor = 0
                while True:
                    cursor, keys = await self.redis.scan(
                        cursor,
                        match=pattern,
                        count=100
                    )
                    
                    if keys:
                        await self.redis.delete(*keys)
                        cleared += len(keys)
                    
                    if cursor == 0:
                        break
            
            # Clear the stream
            await self.redis.xtrim(self.stream_key, maxlen=0)
            
            logger.info(f"Cleared {cleared} log-related keys")
            return cleared
            
        except Exception as e:
            logger.error(f"Error clearing logs: {e}")
            return 0
    
    async def consume_stream(self, callback=None):
        """Consume log entries from the stream for real-time processing."""
        try:
            last_id = "$"
            while True:
                # Read from stream with blocking
                result = await self.redis.xreadgroup(
                    self.consumer_group,
                    self.consumer_name,
                    {self.stream_key: last_id},
                    block=1000  # 1 second timeout
                )
                
                if result:
                    for stream_name, entries in result:
                        for entry_id, data in entries:
                            if callback:
                                await callback(entry_id, data)
                            # Acknowledge processing
                            await self.redis.xack(self.stream_key, self.consumer_group, entry_id)
                            last_id = entry_id
                            
        except Exception as e:
            logger.error(f"Error consuming stream: {e}")