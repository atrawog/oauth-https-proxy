"""Unified routing pipeline for HTTP and HTTPS requests.

This module provides a unified code path for processing both HTTP and HTTPS
requests after protocol-specific handling.
"""

import json
import time
import uuid
from dataclasses import dataclass
from typing import Dict, List, Optional, Union, Tuple
from enum import Enum

from fastapi import Request, Response
from ..proxy.routes import Route, RouteScope, RouteTargetType
from ..proxy.models import ProxyTarget
from ..shared.logger import log_debug, log_info, log_warning, log_error, log_trace


@dataclass
class NormalizedRequest:
    """Common format for all requests regardless of protocol."""
    request_id: str
    protocol: str  # 'http' or 'https'
    hostname: str
    path: str
    method: str
    headers: Dict[str, str]
    client_ip: str
    client_port: int
    body: bytes
    trace_id: str
    timestamp: float


class RoutingDecisionType(str, Enum):
    """Types of routing decisions."""
    ROUTE = "route"      # Matched a configured route
    PROXY = "proxy"      # Forward to proxy target
    NOT_FOUND = "not_found"  # No route or proxy found


@dataclass
class RoutingDecision:
    """Result of routing evaluation."""
    type: RoutingDecisionType
    target: Optional[str] = None  # URL or service name
    target_type: Optional[RouteTargetType] = None
    route_id: Optional[str] = None
    route: Optional[Route] = None  # Full route object for auth config access
    preserve_host: bool = False
    custom_headers: Optional[Dict[str, str]] = None


class RequestNormalizer:
    """Converts HTTP and HTTPS requests to common format."""
    
    def normalize_http(self, raw_data: bytes, client_info: Dict) -> NormalizedRequest:
        """Parse raw HTTP request into normalized format.
        
        Args:
            raw_data: Raw HTTP request bytes
            client_info: Dictionary with 'ip' and 'port' keys
            
        Returns:
            Normalized request object
        """
        # Parse HTTP request
        try:
            request_str = raw_data.decode('utf-8', errors='ignore')
            lines = request_str.split('\r\n')
            
            # Parse request line
            request_line = lines[0].split(' ') if lines else []
            method = request_line[0] if len(request_line) > 0 else 'GET'
            path = request_line[1] if len(request_line) > 1 else '/'
            
            # Parse headers
            headers = {}
            body_start = 0
            for i, line in enumerate(lines[1:], 1):
                if line == '':  # End of headers
                    body_start = i + 1
                    break
                if ':' in line:
                    key, value = line.split(':', 1)
                    headers[key.strip().lower()] = value.strip()
            
            # Extract hostname
            proxy_hostname = headers.get('host', '').split(':')[0]
            
            # Extract body if present
            body = b''
            if body_start < len(lines):
                body_lines = lines[body_start:]
                body = '\r\n'.join(body_lines).encode('utf-8')
            
            # Get or generate trace ID
            trace_id = headers.get('x-trace-id', str(uuid.uuid4()))
            
            return NormalizedRequest(
                request_id=str(uuid.uuid4()),
                protocol='http',
                hostname=proxy_hostname,
                path=path,
                method=method,
                headers=headers,
                client_ip=client_info.get('ip', '127.0.0.1'),
                client_port=client_info.get('port', 0),
                body=body,
                trace_id=trace_id,
                timestamp=time.time()
            )
            
        except Exception as e:
            log_error(f"Error normalizing HTTP request: {e}", component="normalizer")
            # Return minimal normalized request on error
            return NormalizedRequest(
                request_id=str(uuid.uuid4()),
                protocol='http',
                hostname='',
                path='/',
                method='GET',
                headers={},
                client_ip=client_info.get('ip', '127.0.0.1'),
                client_port=client_info.get('port', 0),
                body=b'',
                trace_id=str(uuid.uuid4()),
                timestamp=time.time()
            )
    
    def normalize_https(self, request: Request, client_info: Dict) -> NormalizedRequest:
        """Convert ASGI request to normalized format.
        
        Args:
            request: FastAPI/Starlette Request object
            client_info: Dictionary with 'ip' and 'port' keys
            
        Returns:
            Normalized request object
        """
        # Extract headers as dict
        headers = {}
        for key, value in request.headers.items():
            headers[key.lower()] = value
        
        # Extract hostname
        proxy_hostname = headers.get('host', '').split(':')[0]
        
        # Get or generate trace ID
        trace_id = headers.get('x-trace-id', str(uuid.uuid4()))
        
        return NormalizedRequest(
            request_id=str(uuid.uuid4()),
            protocol='https',
            hostname=proxy_hostname,  # Fixed: use 'hostname' not 'proxy_hostname'
            path=str(request.url.path),
            method=request.method.upper(),
            headers=headers,
            client_ip=client_info.get('ip', '127.0.0.1'),
            client_port=client_info.get('port', 0),
            body=b'',  # Body will be read later if needed
            trace_id=trace_id,
            timestamp=time.time()
        )


class SimpleCache:
    """Simple cache with TTL support."""
    
    def __init__(self, ttl=60):
        self.cache = {}  # key -> (value, expiry_time)
        self.ttl = ttl
    
    def get(self, key):
        """Get value from cache if not expired."""
        if key in self.cache:
            value, expiry = self.cache[key]
            if time.time() < expiry:
                return value
            else:
                del self.cache[key]
        return None
    
    def set(self, key, value):
        """Set value in cache with TTL."""
        expiry = time.time() + self.ttl
        self.cache[key] = (value, expiry)
    
    def __contains__(self, key):
        """Check if key exists and is not expired."""
        return self.get(key) is not None
    
    def pop(self, key, default=None):
        """Remove and return value from cache."""
        if key in self.cache:
            value, _ = self.cache.pop(key)
            return value
        return default
    
    def clear(self):
        """Clear all cache entries."""
        self.cache.clear()


class UnifiedRoutingEngine:
    """Single routing logic for all requests."""
    
    def __init__(self, storage):
        """Initialize routing engine with storage.
        
        Args:
            storage: Storage instance for retrieving routes and proxies
        """
        self.storage = storage
        self.route_cache = SimpleCache(ttl=60)
        
    async def process_request(self, normalized: NormalizedRequest) -> RoutingDecision:
        """Process any request through unified routing logic.
        
        Args:
            normalized: Normalized request object
            
        Returns:
            Routing decision with target information
        """
        log_debug(
            f"Processing {normalized.protocol} request: {normalized.method} {normalized.hostname}{normalized.path}",
            component="routing_engine"
        )
        
        # 1. Get applicable routes (with caching)
        routes = await self.get_routes_for_hostname(normalized.hostname)
        
        # 2. Match routes (same logic for HTTP and HTTPS!)
        matched_route = self.match_route(routes, normalized.path, normalized.method)
        
        if matched_route:
            log_info(
                f"Route matched: {matched_route.route_id} -> {matched_route.target_type}:{matched_route.target_value}",
                component="routing_engine"
            )
            
            target = await self.resolve_route_target(matched_route)
            
            return RoutingDecision(
                type=RoutingDecisionType.ROUTE,
                target=target,
                target_type=matched_route.target_type,
                route_id=matched_route.route_id,
                route=matched_route  # Pass the full route object for auth config access
            )
        
        # 3. Check for proxy target
        proxy = await self.get_proxy_target(normalized.hostname)
        if proxy and proxy.enabled:
            log_info(
                f"Proxy matched: {normalized.hostname} -> {proxy.target_url}",
                component="routing_engine"
            )
            
            return RoutingDecision(
                type=RoutingDecisionType.PROXY,
                target=proxy.target_url,
                preserve_host=proxy.preserve_host_header,
                custom_headers=proxy.custom_headers
            )
        
        log_warning(
            f"No route or proxy found for {normalized.hostname}{normalized.path}",
            component="routing_engine"
        )
        
        return RoutingDecision(type=RoutingDecisionType.NOT_FOUND)
    
    async def get_routes_for_hostname(self, proxy_hostname: str) -> List[Route]:
        """Get all applicable routes for a hostname.
        
        Uses caching to avoid repeated Redis lookups.
        
        Args:
            proxy_hostname: Hostname to get routes for
            
        Returns:
            List of applicable routes sorted by priority
        """
        # Check cache
        cache_key = f"routes:{proxy_hostname}"
        cached_routes = self.route_cache.get(cache_key)
        if cached_routes is not None:
            log_debug(f"Using cached routes for {proxy_hostname}: {len(cached_routes)} routes", component="routing_engine")
            return cached_routes
        
        # Load all routes from storage
        all_routes = []
        if hasattr(self.storage, 'list_routes'):
            all_routes = await self.storage.list_routes() if asyncio.iscoroutinefunction(self.storage.list_routes) else self.storage.list_routes()
        
        log_info(f"Loaded {len(all_routes)} total routes from storage for {proxy_hostname}", component="routing_engine")
        
        # Get proxy configuration for route filtering
        proxy_config = await self.get_proxy_target(proxy_hostname)  # Fixed: use correct variable name
        
        # Filter applicable routes
        applicable = []
        for route in all_routes:
            if not route.enabled:
                log_trace(f"Route {route.route_id} is disabled, skipping", component="routing_engine")
                continue
            
            # Check scope
            if route.scope == RouteScope.GLOBAL:
                # Global routes apply to all proxies
                log_debug(f"Route {route.route_id} ({route.path_pattern}) is GLOBAL scope, including", component="routing_engine")
                applicable.append(route)
            elif route.scope == RouteScope.PROXY and proxy_hostname in route.proxy_hostnames:  # Fixed: use correct variable name
                # Proxy-specific routes only for listed proxies
                log_debug(f"Route {route.route_id} ({route.path_pattern}) is PROXY scope and includes {proxy_hostname}, including", component="routing_engine")
                applicable.append(route)
            else:
                log_debug(f"Route {route.route_id} ({route.path_pattern}) scope={route.scope}, proxy_hostnames={route.proxy_hostnames}, NOT applicable to {proxy_hostname}", component="routing_engine")
        
        # Apply proxy-specific route filtering if configured
        if proxy_config:
            if proxy_config.route_mode == "none":
                # No routes apply
                applicable = []
            elif proxy_config.route_mode == "selective":
                # Only enabled routes apply
                applicable = [r for r in applicable if r.route_id in (proxy_config.enabled_routes or [])]
            else:  # route_mode == "all" (default)
                # All routes except disabled ones
                applicable = [r for r in applicable if r.route_id not in (proxy_config.disabled_routes or [])]
        
        # Sort by priority (higher first)
        applicable.sort(key=lambda r: r.priority, reverse=True)
        
        # Cache the result
        self.route_cache.set(cache_key, applicable)
        
        log_trace(f"Found {len(applicable)} routes for {proxy_hostname}", component="routing_engine")
        
        return applicable
    
    def match_route(self, routes: List[Route], path: str, method: str) -> Optional[Route]:
        """Match request against routes.
        
        Args:
            routes: List of routes sorted by priority
            path: Request path
            method: HTTP method
            
        Returns:
            First matching route or None
        """
        log_info(f"Matching {method} {path} against {len(routes)} routes", component="routing_engine")
        for route in routes:
            matches = route.matches(path, method)
            if matches:
                log_info(f"MATCHED route {route.route_id} ({route.path_pattern}) for {method} {path}", component="routing_engine")
                return route
            else:
                log_debug(f"Route {route.route_id} ({route.path_pattern}) does not match {method} {path}", component="routing_engine")
        log_warning(f"NO ROUTE MATCHED for {method} {path}", component="routing_engine")
        return None
    
    async def resolve_route_target(self, route: Route) -> Optional[str]:
        """Resolve route target to actual URL.
        
        Args:
            route: Route to resolve
            
        Returns:
            Target URL or None if not resolvable
        """
        if route.target_type == RouteTargetType.PORT:
            # Forward to localhost:port
            return f"http://localhost:{route.target_value}"
        
        elif route.target_type == RouteTargetType.SERVICE:
            # Look up service URL
            service_url = None
            if hasattr(self.storage, 'redis_client'):
                service_url = await self.storage.redis_client.get(f"service:url:{route.target_value}")
            
            if service_url:
                return service_url
            
            # Fallback to localhost:port if service has a port registered
            # This would need to be looked up from dispatcher's named_services
            log_warning(f"Service URL not found for {route.target_value}", component="routing_engine")
            return None
        
        elif route.target_type == RouteTargetType.HOSTNAME:
            # Forward to proxy handling this hostname
            proxy = await self.get_proxy_target(str(route.target_value))
            if proxy:
                return proxy.target_url
            return None
        
        elif route.target_type == RouteTargetType.URL:
            # Direct URL
            return str(route.target_value)
        
        return None
    
    async def get_proxy_target(self, proxy_hostname: str) -> Optional[ProxyTarget]:
        """Get proxy target for hostname.
        
        Args:
            proxy_hostname: Hostname to lookup
            
        Returns:
            ProxyTarget or None
        """
        if hasattr(self.storage, 'get_proxy_target'):
            import asyncio
            if asyncio.iscoroutinefunction(self.storage.get_proxy_target):
                return await self.storage.get_proxy_target(proxy_hostname)  # Fixed: use correct variable name
            else:
                return self.storage.get_proxy_target(proxy_hostname)  # Fixed: use correct variable name
        return None
    
    def invalidate_cache(self, proxy_hostname: str = None):
        """Invalidate route cache.
        
        Args:
            proxy_hostname: Specific hostname to invalidate, or None for all
        """
        if proxy_hostname:  # Fixed: use correct variable name
            cache_key = f"routes:{proxy_hostname}"
            self.route_cache.pop(cache_key, None)
            log_debug(f"Route cache invalidated for {proxy_hostname}", component="routing_engine")
        else:
            self.route_cache.clear()
            log_debug("Route cache cleared", component="routing_engine")


# Importing asyncio for async checking
import asyncio