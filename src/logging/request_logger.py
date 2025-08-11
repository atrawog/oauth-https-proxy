"""Request logger with statistics support."""

import logging
from typing import Dict, Any, Optional, List
from datetime import datetime, timezone

logger = logging.getLogger(__name__)


class RequestLogger:
    """Request logger with statistics gathering."""
    
    def __init__(self, redis_client=None):
        """Initialize request logger."""
        self.redis_client = redis_client
        self._stats_cache = {}
    
    async def log_request(self, request_data: Dict[str, Any]):
        """Log a request."""
        # Basic logging for now
        logger.info(f"Request: {request_data}")
    
    async def get_statistics(self, hours: int = 24) -> Dict[str, Any]:
        """Get request statistics for the specified time period."""
        # Return empty stats for now
        return {
            "total_requests": 0,
            "unique_ips": 0,
            "errors": 0,
            "average_response_time": 0,
            "requests_by_hour": {},
            "errors_by_hour": {},
            "top_paths": [],
            "top_user_agents": [],
            "status_codes": {}
        }
    
    async def search_logs(self, **kwargs) -> Dict[str, Any]:
        """Search logs with filters."""
        return {
            "total": 0,
            "logs": [],
            "query_params": kwargs
        }
    
    async def get_logs_by_ip(self, ip: str, **kwargs) -> Dict[str, Any]:
        """Get logs by IP address."""
        return {
            "total": 0,
            "logs": [],
            "query_params": {"ip_address": ip, **kwargs}
        }
    
    async def get_errors(self, **kwargs) -> Dict[str, Any]:
        """Get error logs."""
        return {
            "total": 0,
            "logs": [],
            "query_params": {"type": "errors", **kwargs}
        }
    
    async def query_by_ip(self, ip: str, hours: int = 24, limit: int = 100) -> List[Dict[str, Any]]:
        """Query logs by client IP address."""
        if not self.redis_client:
            return []
        
        results = []
        try:
            # Use index to find requests from this IP
            index_key = f"idx:req:ip:{ip}"
            request_ids = await self.redis_client.zrevrange(
                index_key, 0, limit - 1
            )
            
            for req_id in request_ids:
                req_data = await self.redis_client.hgetall(req_id)
                if req_data:
                    results.append({
                        'timestamp': req_data.get('timestamp', ''),
                        'ip': req_data.get('ip', ''),
                        'method': req_data.get('method', ''),
                        'path': req_data.get('path', ''),
                        'status': int(req_data.get('status', 0)),
                        'response_time': float(req_data.get('response_time', 0)),
                        'hostname': req_data.get('hostname', ''),
                        'user': req_data.get('user', '')
                    })
        except Exception as e:
            logger.error(f"Error querying logs by IP: {e}")
        
        return results
    
    async def query_errors(self, hours: int = 24, limit: int = 100) -> List[Dict[str, Any]]:
        """Query error logs (4xx and 5xx responses)."""
        if not self.redis_client:
            return []
        
        results = []
        try:
            # Use error index
            error_key = "idx:req:errors"
            request_ids = await self.redis_client.zrevrange(
                error_key, 0, limit - 1
            )
            
            for req_id in request_ids:
                req_data = await self.redis_client.hgetall(req_id)
                if req_data:
                    status = int(req_data.get('status', 0))
                    if status >= 400:
                        results.append({
                            'timestamp': req_data.get('timestamp', ''),
                            'ip': req_data.get('ip', ''),
                            'method': req_data.get('method', ''),
                            'path': req_data.get('path', ''),
                            'status': status,
                            'error': req_data.get('error', ''),
                            'hostname': req_data.get('hostname', ''),
                            'user': req_data.get('user', '')
                        })
        except Exception as e:
            logger.error(f"Error querying error logs: {e}")
        
        return results
    
    async def query_by_hostname(self, hostname: str, hours: int = 24, limit: int = 100) -> List[Dict[str, Any]]:
        """Query logs by hostname."""
        if not self.redis_client:
            return []
        
        results = []
        try:
            # Use hostname index
            index_key = f"idx:req:host:{hostname}"
            request_ids = await self.redis_client.zrevrange(
                index_key, 0, limit - 1
            )
            
            for req_id in request_ids:
                req_data = await self.redis_client.hgetall(req_id)
                if req_data:
                    results.append({
                        'timestamp': req_data.get('timestamp', ''),
                        'ip': req_data.get('ip', ''),
                        'method': req_data.get('method', ''),
                        'path': req_data.get('path', ''),
                        'status': int(req_data.get('status', 0)),
                        'response_time': float(req_data.get('response_time', 0)),
                        'hostname': req_data.get('hostname', ''),
                        'user': req_data.get('user', '')
                    })
        except Exception as e:
            logger.error(f"Error querying logs by hostname: {e}")
        
        return results
    
    async def search_logs(self, query: str = None, hours: int = 24, 
                         event: str = None, level: str = None, 
                         hostname: str = None, limit: int = 100) -> List[Dict[str, Any]]:
        """Search logs with multiple filters."""
        if not self.redis_client:
            return []
        
        # For now, return empty results
        # Full implementation would filter by all parameters
        return []