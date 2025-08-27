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
    
    def _safe_int(self, value):
        """Safely convert a value to int, return None if not possible."""
        if value is None:
            return None
        try:
            return int(value)
        except (ValueError, TypeError):
            return None
        
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
    
    async def _add_to_indexes(self, stream_id: str, stream_data: Dict[str, str], timestamp_ms: int):
        """Add log entry to Redis indexes for efficient querying.
        
        Creates sorted set indexes by:
        - All logs (global)
        - Client IP
        - Proxy hostname
        - User ID
        - HTTP status code
        - HTTP method
        - Errors (4xx/5xx)
        
        Args:
            stream_id: Redis stream entry ID
            stream_data: Log entry data
            timestamp_ms: Timestamp in milliseconds (used as score)
        """
        try:
            # Use pipeline for efficiency
            pipe = self.redis.pipeline()
            
            # TTL for indexes (30 days)
            ttl_seconds = 30 * 24 * 60 * 60
            
            # Global index - all logs
            pipe.zadd("log:idx:all", {stream_id: timestamp_ms})
            pipe.expire("log:idx:all", ttl_seconds)
            
            # Index by client IP
            client_ip = stream_data.get('client_ip')
            if client_ip and client_ip != '127.0.0.1':
                pipe.zadd(f"log:idx:ip:{client_ip}", {stream_id: timestamp_ms})
                pipe.expire(f"log:idx:ip:{client_ip}", ttl_seconds)
            
            # Index by proxy hostname
            proxy_hostname = stream_data.get('proxy_hostname')
            if proxy_hostname:
                pipe.zadd(f"log:idx:host:{proxy_hostname}", {stream_id: timestamp_ms})
                pipe.expire(f"log:idx:host:{proxy_hostname}", ttl_seconds)
            
            # Index by user ID
            user_id = stream_data.get('user_id')
            if user_id and user_id != 'anonymous':
                pipe.zadd(f"log:idx:user:{user_id}", {stream_id: timestamp_ms})
                pipe.expire(f"log:idx:user:{user_id}", ttl_seconds)
            
            # Index by HTTP status code
            status_code = stream_data.get('status_code')
            if status_code and status_code != '0':
                pipe.zadd(f"log:idx:status:{status_code}", {stream_id: timestamp_ms})
                pipe.expire(f"log:idx:status:{status_code}", ttl_seconds)
                
                # Special index for errors
                try:
                    status_int = int(status_code)
                    if status_int >= 400:
                        pipe.zadd("log:idx:errors", {stream_id: timestamp_ms})
                        pipe.expire("log:idx:errors", ttl_seconds)
                except:
                    pass
            
            # Index by HTTP method (support both old and new field names)
            method = stream_data.get('request_method') or stream_data.get('method')
            if method:
                pipe.zadd(f"log:idx:method:{method}", {stream_id: timestamp_ms})
                pipe.expire(f"log:idx:method:{method}", ttl_seconds)
            
            # Index by request path
            # Support both old and new field names
            path = stream_data.get('request_path') or stream_data.get('path')
            if path and path != '/' and path != '':
                # Normalize path - remove query parameters for indexing
                clean_path = path.split('?')[0]
                pipe.zadd(f"log:idx:path:{clean_path}", {stream_id: timestamp_ms})
                pipe.expire(f"log:idx:path:{clean_path}", ttl_seconds)
            
            # Index by log level (for non-HTTP logs)
            level = stream_data.get('level')
            if level and level != 'INFO':
                pipe.zadd(f"log:idx:level:{level}", {stream_id: timestamp_ms})
                pipe.expire(f"log:idx:level:{level}", ttl_seconds)
            
            # Index by component
            component = stream_data.get('component')
            if component:
                pipe.zadd(f"log:idx:component:{component}", {stream_id: timestamp_ms})
                pipe.expire(f"log:idx:component:{component}", ttl_seconds)
            
            # Execute pipeline
            await pipe.execute()
            logger.debug(f"Added entry {stream_id} to indexes")
            
        except Exception as e:
            logger.error(f"Error adding to indexes: {e}")
    
    async def rebuild_indexes(self, hours: int = 24, batch_size: int = 1000):
        """Rebuild indexes from existing stream entries.
        
        Scans the stream and recreates all indexes. Useful for:
        - Initial migration from non-indexed logs
        - Recovering from index corruption
        - Adding new index types
        
        Args:
            hours: How many hours of logs to index (default 24)
            batch_size: Number of entries to process per batch
            
        Returns:
            Number of entries indexed
        """
        try:
            logger.info(f"Starting index rebuild for last {hours} hours")
            
            # Calculate time range
            now = datetime.now(timezone.utc)
            cutoff = now - timedelta(hours=hours)
            cutoff_ms = int(cutoff.timestamp() * 1000)
            now_ms = int(now.timestamp() * 1000)
            
            indexed_count = 0
            last_id = f"{now_ms}"
            
            while True:
                # Fetch batch of entries
                entries = await self.redis.xrevrange(
                    "logs:all:stream",
                    max=last_id,
                    min=cutoff_ms,
                    count=batch_size
                )
                
                if not entries:
                    break
                
                # Process entries
                for entry_id, data in entries:
                    timestamp_ms = int(data.get('timestamp', 0))
                    if timestamp_ms:
                        await self._add_to_indexes(entry_id, data, timestamp_ms)
                        indexed_count += 1
                    
                    # Update last_id for next batch (exclude current entry)
                    last_id = f"({entry_id}"
                
                logger.info(f"Indexed {indexed_count} entries so far...")
                
                # If we got fewer than batch_size, we're done
                if len(entries) < batch_size:
                    break
            
            logger.info(f"Index rebuild complete. Indexed {indexed_count} entries.")
            return indexed_count
            
        except Exception as e:
            logger.error(f"Error rebuilding indexes: {e}")
            return 0
    
    async def cleanup_old_indexes(self, days: int = 30):
        """Remove old entries from indexes.
        
        Removes entries older than specified days from all indexes.
        This helps keep indexes manageable in size.
        
        Args:
            days: Remove entries older than this many days
            
        Returns:
            Number of entries removed
        """
        try:
            logger.info(f"Cleaning indexes older than {days} days")
            
            # Calculate cutoff timestamp
            cutoff = datetime.now(timezone.utc) - timedelta(days=days)
            cutoff_ms = int(cutoff.timestamp() * 1000)
            
            removed_count = 0
            
            # Get all index keys
            index_keys = await self.redis.keys("log:idx:*")
            
            for key in index_keys:
                # Remove old entries from sorted set
                removed = await self.redis.zremrangebyscore(key, "-inf", cutoff_ms)
                removed_count += removed
                
                # If index is now empty, delete it
                if await self.redis.zcard(key) == 0:
                    await self.redis.delete(key)
                    logger.debug(f"Deleted empty index: {key}")
            
            logger.info(f"Cleanup complete. Removed {removed_count} old index entries.")
            return removed_count
            
        except Exception as e:
            logger.error(f"Error cleaning indexes: {e}")
            return 0
    
    async def log_request(self, log_entry: Dict[str, Any]) -> str:
        """Log a request to the unified Redis stream with proper indexing.
        
        Writes to stream and creates Redis indexes for efficient querying.
        
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
                'trace_id': log_entry.get('trace_id', ''),  # Request trace ID
                'client_ip': log_entry.get('client_ip', '127.0.0.1'),
                'client_hostname': log_entry.get('client_hostname', ''),
                'proxy_hostname': log_entry.get('proxy_hostname', ''),
                'method': log_entry.get('method', log_entry.get('request_method', 'GET')),
                'path': log_entry.get('path', log_entry.get('request_path', '/')),
                'query': log_entry.get('query', log_entry.get('request_query', '')),
                'status_code': str(log_entry.get('status_code', log_entry.get('status', 0))),
                'response_time_ms': str(log_entry.get('response_time_ms', log_entry.get('duration_ms', 0))),
                'user_id': log_entry.get('user_id', 'anonymous'),
                'user_agent': log_entry.get('user_agent', ''),
                'referrer': log_entry.get('referrer', ''),
                'bytes_sent': str(log_entry.get('bytes_sent', 0)),
                'auth_type': log_entry.get('auth_type', ''),
                'auth_user': log_entry.get('auth_user', log_entry.get('oauth_user', '')),  # Auth user
                'auth_scopes': log_entry.get('auth_scopes', ''),  # Auth scopes
                'auth_email': log_entry.get('auth_email', ''),  # Auth email
                'auth_client_id': log_entry.get('auth_client_id', log_entry.get('client_id', '')),  # Auth client ID
                'backend_url': log_entry.get('backend_url', ''),  # Backend URL for proxied requests
                'route_id': log_entry.get('route_id', ''),  # Route ID if matched
                'session_id': log_entry.get('session_id', ''),  # Session ID
                'worker_id': log_entry.get('worker_id', ''),  # Worker ID
                'mcp_session_id': log_entry.get('mcp_session_id', ''),  # MCP session
                'error': log_entry.get('error', ''),
                'error_type': log_entry.get('error_type', ''),
                'message': log_entry.get('message', ''),
                'level': log_entry.get('level', 'INFO'),
                'component': log_entry.get('component', 'unknown'),  # Component that generated the log
                'log_type': log_entry.get('log_type', 'http_request'),
                'response_type': log_entry.get('response_type', '')  # Type of response (route_forward, proxy_forward, error, etc.)
            }
            
            # Write to the unified log stream
            stream_id = await self.redis.xadd(
                "logs:all:stream",
                stream_data,
                maxlen=1000000,  # Keep last 1M entries
                approximate=True
            )
            
            # Add to Redis indexes for efficient querying
            await self._add_to_indexes(stream_id, stream_data, timestamp_ms)
            
            logger.debug(f"Logged to unified stream with ID: {stream_id} and indexed")
            return stream_id
            
        except Exception as e:
            logger.error(f"Error logging request: {e}")
            return ""
    
    async def search_logs(self, **kwargs) -> Dict[str, Any]:
        """Search logs using Redis indexes for efficient querying.
        
        Uses Redis sorted sets and ZREVRANGEBYSCORE for fast filtering
        instead of fetching all entries and filtering in Python.
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
            
            logger.info(f"Search logs using indexes: cutoff={cutoff_ms}, now={now_ms}, hours={hours}")
            logger.info(f"Search filters: client_ip={kwargs.get('client_ip')}, proxy_hostname={kwargs.get('proxy_hostname')}")
            
            # Determine which index to use based on filters
            index_key = None
            if kwargs.get('client_ip'):
                index_key = f"log:idx:ip:{kwargs['client_ip']}"
            elif kwargs.get('proxy_hostname'):
                index_key = f"log:idx:host:{kwargs['proxy_hostname']}"
            elif kwargs.get('user'):
                index_key = f"log:idx:user:{kwargs['user']}"
            elif kwargs.get('status'):
                index_key = f"log:idx:status:{kwargs['status']}"
            elif kwargs.get('method'):
                index_key = f"log:idx:method:{kwargs['method']}"
            elif kwargs.get('path'):
                # Normalize path - remove query parameters for indexing
                clean_path = kwargs['path'].split('?')[0]
                index_key = f"log:idx:path:{clean_path}"
            else:
                # No specific filter, use global index
                index_key = "log:idx:all"
            
            # Query the index using ZREVRANGEBYSCORE (reverse chronological order)
            # This returns entry IDs from the time range, already filtered!
            entry_ids = await self.redis.zrevrangebyscore(
                index_key,
                max=now_ms,
                min=cutoff_ms,
                start=offset,
                num=limit
            )
            
            logger.info(f"Found {len(entry_ids)} entries from index {index_key}")
            
            # If we have multiple filters, we need to intersect the results
            # (This is a simplified version - full implementation would use ZINTERSTORE)
            if len(entry_ids) > 0 and (
                (kwargs.get('client_ip') and kwargs.get('status')) or
                (kwargs.get('proxy_hostname') and kwargs.get('method'))
            ):
                # For now, we'll fetch and filter - but this could be optimized with ZINTERSTORE
                logger.debug("Multiple filters detected - using post-filtering")
            
            # Fetch the actual log data from the stream
            logs = []
            for entry_id in entry_ids:
                # Fetch entry from stream
                entries = await self.redis.xrange(
                    "logs:all:stream",
                    min=entry_id,
                    max=entry_id,
                    count=1
                )
                
                if entries:
                    _, data = entries[0]
                    
                    # Apply additional filters if needed (for multi-filter queries)
                    # This is much faster than before since we're only checking the already-filtered results
                    if kwargs.get('status') and index_key != f"log:idx:status:{kwargs['status']}":
                        if str(data.get('status_code', '')) != str(kwargs['status']):
                            continue
                    if kwargs.get('method') and index_key != f"log:idx:method:{kwargs['method']}":
                        if data.get('method') != kwargs['method']:
                            continue
                    # Only apply path filtering if we're not already using the path index
                    if kwargs.get('path'):
                        clean_path = kwargs['path'].split('?')[0]
                        if index_key != f"log:idx:path:{clean_path}":
                            # For secondary path filtering, check if the path matches
                            data_path = data.get('path', '')
                            if clean_path not in data_path:
                                continue
                    
                    # Apply query search if specified
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
                                'proxy_hostname': 'proxy_hostname',
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
                        'timestamp_unix': int(data.get('timestamp', 0)) if data.get('timestamp') else 0,
                        'client_ip': data.get('client_ip', ''),
                        'client_hostname': data.get('client_hostname', ''),
                        'proxy_hostname': data.get('proxy_hostname', ''),
                        # Standard field names with request_ prefix
                        'request_method': data.get('request_method') or data.get('method', ''),
                        'request_path': data.get('request_path') or data.get('path', ''),
                        'request_query': data.get('request_query') or data.get('query', ''),
                        'status_code': self._safe_int(data.get('status_code')) or self._safe_int(data.get('status')) or 0,
                        'response_time_ms': float(data.get('response_time_ms', 0)) if data.get('response_time_ms') else float(data.get('duration_ms', 0)) if data.get('duration_ms') else 0.0,
                        'user_id': data.get('user_id', 'anonymous'),
                        'user_agent': data.get('user_agent', ''),
                        'referrer': data.get('referrer', ''),
                        'referer': data.get('referer', ''),
                        'bytes_sent': int(data.get('bytes_sent', 0)) if data.get('bytes_sent') else 0,
                        'auth_type': data.get('auth_type', ''),
                        'auth_user': data.get('auth_user', ''),  # Auth user
                        'auth_scopes': data.get('auth_scopes', ''),  # Auth scopes
                        'auth_email': data.get('auth_email', ''),  # Auth email
                        'auth_client_id': data.get('auth_client_id', data.get('oauth_client_id', data.get('client_id', ''))),  # Auth client ID
                        'oauth_client_id': data.get('oauth_client_id') or data.get('client_id', ''),
                        'oauth_username': data.get('oauth_username') or data.get('oauth_user', data.get('auth_user', '')),
                        'message': data.get('message', ''),
                        'level': data.get('level', 'INFO'),
                        'component': data.get('component', 'unknown'),
                        'log_type': data.get('log_type') or data.get('type', 'http_request'),
                        'error': data.get('error', ''),
                        'error_type': data.get('error_type', ''),
                        'response_type': data.get('response_type', ''),  # Type of response
                        'route_id': data.get('route_id', ''),  # Route ID if matched
                        # Include additional debug fields
                        'headers': data.get('headers', ''),
                        'body': data.get('body', ''),
                        'backend_url': data.get('backend_url', ''),
                        'session_id': data.get('session_id', ''),
                        'trace_id': data.get('trace_id') or data.get('request_id', ''),
                        'event_type': data.get('event_type', ''),
                        'worker_id': data.get('worker_id', ''),
                        'mcp_session_id': data.get('mcp_session_id', '')  # MCP session if applicable
                    }
                    
                    logs.append(log_entry)
            
            # Enrich logs with metadata from trace storage
            enriched_logs = await self.get_logs_with_metadata(logs)
            
            return {
                'total': len(enriched_logs),
                'logs': enriched_logs,
                'query_params': kwargs
            }
        except Exception as e:
            logger.error(f"Error searching logs: {e}")
            return {'total': 0, 'logs': [], 'error': str(e)}
    
    async def get_logs_by_ip(self, client_ip: str, hours: int = 24, limit: int = 100) -> List[Dict]:
        """Get logs by client IP address."""
        logger.info(f"get_logs_by_ip called with: client_ip={client_ip}, hours={hours}, limit={limit}")
        result = await self.search_logs(client_ip=client_ip, hours=hours, limit=limit)
        logs = result.get('logs', [])
        logger.info(f"get_logs_by_ip returning {len(logs)} logs")
        return logs
    
    async def get_logs_by_hostname(self, proxy_hostname: str, hours: int = 24, limit: int = 100) -> List[Dict]:
        """Get logs by proxy hostname."""
        result = await self.search_logs(proxy_hostname=proxy_hostname, hours=hours, limit=limit)
        return result.get('logs', [])
    
    async def get_logs_by_proxy(self, proxy_hostname: str, hours: int = 24, limit: int = 100) -> List[Dict]:
        """Get logs by proxy hostname."""
        return await self.get_logs_by_hostname(proxy_hostname, hours, limit)
    
    async def get_logs_by_client(self, client_id: str, hours: int = 24, limit: int = 100) -> List[Dict]:
        """Get logs by client_id (which is the trace_id).
        
        This searches for logs with matching trace_id, since trace_id
        is used as the client_id in our system.
        """
        # Search for logs with matching trace_id (client_id is trace_id)
        result = await self.search_logs(trace_id=client_id, hours=hours, limit=limit)
        
        # The logs are already enriched with metadata by search_logs
        return result.get('logs', [])
    
    async def get_logs_with_metadata(self, logs: List[Dict]) -> List[Dict]:
        """Enrich logs with metadata from trace storage.
        
        Args:
            logs: List of log entries
            
        Returns:
            Enriched log entries with client_id, client_hostname, proxy_hostname
        """
        enriched_logs = []
        
        for log in logs:
            trace_id = log.get('trace_id')
            if trace_id:
                try:
                    # Try to get metadata from Redis
                    metadata_key = f"trace:metadata:{trace_id}"
                    metadata_json = await self.redis.get(metadata_key)
                    
                    if metadata_json:
                        metadata = json.loads(metadata_json)
                        # Merge metadata into log entry
                        log = {
                            **log,
                            "client_id": metadata.get("client_id", trace_id),
                            "client_hostname": metadata.get("client_hostname", log.get("client_hostname", "")),
                            "proxy_hostname": metadata.get("proxy_hostname", log.get("proxy_hostname", ""))
                        }
                except Exception as e:
                    logger.debug(f"Failed to get metadata for trace {trace_id}: {e}")
                    # Graceful degradation - continue without metadata
            
            # Ensure we always have client_id (fallback to trace_id)
            if not log.get('client_id') and trace_id:
                log['client_id'] = trace_id
                
            enriched_logs.append(log)
        
        return enriched_logs
    
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
            # This would need to aggregate across all proxy_hostnames
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
            client_ip=ip,
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