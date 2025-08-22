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
        """Log a request to Redis Streams with proper indexing.
        
        Args:
            log_entry: Dictionary containing request/response data
            
        Returns:
            Stream entry ID
        """
        try:
            # Get timestamp - convert to Unix if ISO format provided
            timestamp_str = log_entry.get('timestamp', '')
            if timestamp_str:
                try:
                    # Try to parse ISO format
                    dt = datetime.fromisoformat(timestamp_str.replace('Z', '+00:00'))
                    unix_timestamp = dt.timestamp()
                except:
                    # Assume it's already Unix timestamp
                    unix_timestamp = float(timestamp_str) if timestamp_str else time.time()
            else:
                unix_timestamp = time.time()
            
            # Also keep ISO format for display
            if not timestamp_str:
                timestamp_str = datetime.fromtimestamp(unix_timestamp, tz=timezone.utc).isoformat()
            
            client_ip = log_entry.get('ip', log_entry.get('client_ip', '127.0.0.1'))
            hostname = log_entry.get('hostname', '')
            method = log_entry.get('method', 'GET')
            path = log_entry.get('path', '/')
            status_code = log_entry.get('status', log_entry.get('status_code', 0))
            response_time_ms = log_entry.get('response_time', log_entry.get('response_time_ms', 0))
            user_id = log_entry.get('user', log_entry.get('user_id', ''))
            
            # Create request key using Unix timestamp for proper ordering
            req_key = f"req:{unix_timestamp}:{client_ip}"
            
            # Store request data as hash
            await self.redis.hset(req_key, mapping={
                'timestamp': timestamp_str,
                'ip': client_ip,
                'hostname': hostname,
                'method': method,
                'path': path,
                'query': log_entry.get('query', ''),  # Store query parameters
                'status': str(status_code),
                'response_time': str(response_time_ms),
                'user': user_id,
                'user_agent': log_entry.get('user_agent', ''),
                'referrer': log_entry.get('referrer', ''),
                'bytes_sent': str(log_entry.get('bytes_sent', 0)),
                'error': log_entry.get('error', ''),
                'message': log_entry.get('message', '')
            })
            
            # Set TTL for request data (7 days by default)
            await self.redis.expire(req_key, 7 * 24 * 3600)
            
            # Add to indexes with Unix timestamp score for proper sorting
            timestamp_score = unix_timestamp
            
            # Add to global "all logs" index
            await self.redis.zadd("idx:req:all", {req_key: timestamp_score})
            await self.redis.expire("idx:req:all", 7 * 24 * 3600)
            
            # Index by IP
            await self.redis.zadd(f"idx:req:ip:{client_ip}", {req_key: timestamp_score})
            await self.redis.expire(f"idx:req:ip:{client_ip}", 7 * 24 * 3600)
            
            # Index by hostname
            if hostname:
                await self.redis.zadd(f"idx:req:host:{hostname}", {req_key: timestamp_score})
                await self.redis.expire(f"idx:req:host:{hostname}", 7 * 24 * 3600)
            
            # Index by user
            if user_id:
                await self.redis.zadd(f"idx:req:user:{user_id}", {req_key: timestamp_score})
                await self.redis.expire(f"idx:req:user:{user_id}", 7 * 24 * 3600)
            
            # Index by status code
            await self.redis.zadd(f"idx:req:status:{status_code}", {req_key: timestamp_score})
            await self.redis.expire(f"idx:req:status:{status_code}", 7 * 24 * 3600)
            
            # Add to error index if error response
            if status_code >= 400:
                await self.redis.zadd("idx:req:errors", {req_key: timestamp_score})
                await self.redis.expire("idx:req:errors", 7 * 24 * 3600)
            
            # Add to slow request index if slow
            if response_time_ms > 1000:
                await self.redis.zadd("idx:req:slow", {req_key: timestamp_score})
                await self.redis.expire("idx:req:slow", 7 * 24 * 3600)
            
            # Publish to stream for real-time processing
            stream_data = {
                'data': json.dumps(log_entry),
                'timestamp': timestamp_str,
                'ip': client_ip,
                'hostname': hostname,
                'status': str(status_code)
            }
            stream_id = await self.redis.xadd(self.stream_key, stream_data)
            
            # Update hourly statistics
            hour_key = f"stats:requests:{datetime.now(timezone.utc).strftime('%Y%m%d:%H')}"
            await self.redis.hincrby(hour_key, 'total', 1)
            await self.redis.hincrby(hour_key, f'status_{status_code}', 1)
            await self.redis.expire(hour_key, 30 * 24 * 3600)  # 30 days
            
            if status_code >= 400:
                error_hour_key = f"stats:errors:{datetime.now(timezone.utc).strftime('%Y%m%d:%H')}"
                await self.redis.hincrby(error_hour_key, str(status_code), 1)
                await self.redis.expire(error_hour_key, 30 * 24 * 3600)
            
            # Track unique IPs with HyperLogLog
            if hostname:
                unique_key = f"stats:unique_ips:{hostname}:{datetime.now(timezone.utc).strftime('%Y%m%d:%H')}"
                await self.redis.pfadd(unique_key, client_ip)
                await self.redis.expire(unique_key, 7 * 24 * 3600)
            
            logger.debug(f"Logged request: {req_key} with stream ID: {stream_id}")
            return stream_id
            
        except Exception as e:
            logger.error(f"Error logging request: {e}")
            return ""
    
    async def search_logs(self, **kwargs) -> Dict[str, Any]:
        """Search logs with flexible filters.
        
        Supports filtering by query, hostname, status, method, path, ip, user.
        """
        try:
            hours = kwargs.get('hours', 24)
            limit = kwargs.get('limit', 100)
            offset = kwargs.get('offset', 0)
            
            # Calculate time window
            now = datetime.now(timezone.utc)
            cutoff = now - timedelta(hours=hours)
            cutoff_timestamp = cutoff.timestamp()
            
            logger.info(f"Search logs: now={now.timestamp()}, cutoff={cutoff_timestamp}, hours={hours}")
            
            # Determine which index to use based on filters
            index_key = None
            if kwargs.get('ip'):
                index_key = f"idx:req:ip:{kwargs['ip']}"
            elif kwargs.get('hostname'):
                index_key = f"idx:req:host:{kwargs['hostname']}"
            elif kwargs.get('user'):
                index_key = f"idx:req:user:{kwargs['user']}"
            elif kwargs.get('status'):
                index_key = f"idx:req:status:{kwargs['status']}"
            else:
                # Use the global "all logs" index when no specific filter
                index_key = "idx:req:all"
            
            # Get request keys from index
            request_keys = await self.redis.zrevrangebyscore(
                index_key,
                '+inf',
                cutoff_timestamp,
                start=offset,
                num=limit
            )
            
            logger.info(f"Found {len(request_keys)} keys in index {index_key} with cutoff {cutoff_timestamp}")
            
            # Fetch request data
            logs = []
            for req_key in request_keys:
                req_data = await self.redis.hgetall(req_key)
                if req_data:
                    # Apply additional filters
                    if kwargs.get('method') and req_data.get('method') != kwargs['method']:
                        continue
                    if kwargs.get('path') and kwargs['path'] not in req_data.get('path', ''):
                        continue
                    if kwargs.get('query') and kwargs['query'] not in json.dumps(req_data):
                        continue
                    
                    logs.append({
                        'timestamp': req_data.get('timestamp', ''),
                        'client_ip': req_data.get('ip', ''),
                        'hostname': req_data.get('hostname', ''),
                        'method': req_data.get('method', ''),
                        'path': req_data.get('path', ''),
                        'query': req_data.get('query', ''),  # Include query parameters
                        'status_code': int(req_data.get('status', 0)),
                        'response_time_ms': float(req_data.get('response_time', 0)),
                        'user_id': req_data.get('user', ''),
                        'error': req_data.get('error', ''),
                        'message': req_data.get('message', '')
                    })
            
            return {
                'total': len(logs),
                'logs': logs,
                'query_params': kwargs
            }
            
        except Exception as e:
            logger.error(f"Error searching logs: {e}")
            return {'total': 0, 'logs': [], 'error': str(e)}
    
    async def get_logs_by_ip(self, ip: str, hours: int = 24, limit: int = 100) -> List[Dict]:
        """Get logs by client IP address."""
        result = await self.search_logs(ip=ip, hours=hours, limit=limit)
        return result.get('logs', [])
    
    async def get_logs_by_hostname(self, hostname: str, hours: int = 24, limit: int = 100) -> List[Dict]:
        """Get logs by hostname."""
        result = await self.search_logs(hostname=hostname, hours=hours, limit=limit)
        return result.get('logs', [])
    
    async def get_logs_by_proxy(self, hostname: str, hours: int = 24, limit: int = 100) -> List[Dict]:
        """Get logs by proxy hostname (same as hostname)."""
        return await self.get_logs_by_hostname(hostname, hours, limit)
    
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
                    status = int(req_data.get('status', 0))
                    if not include_4xx and status < 500:
                        continue
                    
                    errors.append({
                        'timestamp': req_data.get('timestamp', ''),
                        'client_ip': req_data.get('ip', ''),
                        'hostname': req_data.get('hostname', ''),
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