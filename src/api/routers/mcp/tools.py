"""All MCP tools as simple decorated async functions."""

from typing import Dict, Any, List, Optional
import json
import time
from datetime import datetime, timezone

# ========== Proxy Management Tools ===========
async def proxy_list(include_details: bool = False, _storage=None, _logger=None) -> Dict[str, Any]:
    """List all configured proxy targets.
    
    Args:
        include_details: Include full proxy details
    
    Returns:
        Dictionary with proxy list
    """
    if _logger:
        _logger.debug("Listing proxies", include_details=include_details)
    
    proxies = await _storage.list_proxy_targets()
    
    if include_details:
        return {
            "proxies": [
                p.dict() if hasattr(p, 'dict') else p 
                for p in proxies
            ]
        }
    
    return {
        "proxies": [
            {
                "hostname": getattr(p, 'proxy_hostname', p.get('proxy_hostname')),
                "target": getattr(p, 'target_url', p.get('target_url'))
            }
            for p in proxies
        ],
        "count": len(proxies)
    }


async def proxy_create(
    hostname: str,
    target_url: str,
    enable_https: bool = True,
    auth_enabled: bool = False,
    _storage=None,
    _logger=None
) -> Dict[str, Any]:
    """Create a new proxy configuration.
    
    Args:
        hostname: Proxy hostname
        target_url: Target URL to proxy to
        enable_https: Enable HTTPS (requires certificate)
        auth_enabled: Enable OAuth authentication
    
    Returns:
        Status dictionary
    """
    if _logger:
        _logger.info(f"Creating proxy: {hostname} -> {target_url}")
    
    proxy_data = {
        "proxy_hostname": hostname,
        "target_url": target_url,
        "enable_http": True,
        "enable_https": enable_https,
        "auth_enabled": auth_enabled
    }
    
    await _storage.create_proxy_target(proxy_data)
    
    # Publish event
    await _storage.redis_client.xadd(
        "events:proxy",
        {"event": json.dumps({
            "type": "proxy_created",
            "hostname": hostname,
            "timestamp": datetime.now(timezone.utc).isoformat()
        })}
    )
    
    return {"status": "created", "hostname": hostname, "target": target_url}


async def proxy_delete(hostname: str, _storage=None, _logger=None) -> Dict[str, Any]:
    """Delete a proxy configuration.
    
    Args:
        hostname: Proxy hostname to delete
    
    Returns:
        Status dictionary
    """
    if _logger:
        _logger.info(f"Deleting proxy: {hostname}")
    
    await _storage.delete_proxy_target(hostname)
    
    # Publish event
    await _storage.redis_client.xadd(
        "events:proxy",
        {"event": json.dumps({
            "type": "proxy_deleted",
            "hostname": hostname,
            "timestamp": datetime.now(timezone.utc).isoformat()
        })}
    )
    
    return {"status": "deleted", "hostname": hostname}


async def proxy_show(hostname: str, _storage=None) -> Dict[str, Any]:
    """Show detailed proxy configuration.
    
    Args:
        hostname: Proxy hostname
    
    Returns:
        Proxy configuration details
    """
    proxy = await _storage.get_proxy_target(hostname)
    
    if not proxy:
        raise ValueError(f"Proxy '{hostname}' not found")
    
    if hasattr(proxy, 'dict'):
        return {"proxy": proxy.dict()}
    else:
        return {"proxy": proxy}


async def proxy_update(
    hostname: str,
    target_url: Optional[str] = None,
    auth_enabled: Optional[bool] = None,
    _storage=None,
    _logger=None
) -> Dict[str, Any]:
    """Update proxy configuration.
    
    Args:
        hostname: Proxy hostname
        target_url: New target URL (optional)
        auth_enabled: Enable/disable authentication (optional)
    
    Returns:
        Updated proxy configuration
    """
    proxy = await _storage.get_proxy_target(hostname)
    if not proxy:
        raise ValueError(f"Proxy '{hostname}' not found")
    
    updates = {}
    if target_url is not None:
        updates["target_url"] = target_url
    if auth_enabled is not None:
        updates["auth_enabled"] = auth_enabled
    
    if updates:
        await _storage.update_proxy_target(hostname, updates)
        if _logger:
            _logger.info(f"Updated proxy: {hostname}", updates=updates)
    
    return {"status": "updated", "hostname": hostname, "updates": updates}


# ========== Certificate Management Tools ==========

async def certificate_list(_storage=None) -> Dict[str, Any]:
    """List all SSL certificates."""
    certs = await _storage.list_certificates()
    
    return {
        "certificates": [
            {
                "name": getattr(c, 'cert_name', c.get('cert_name')),
                "domains": getattr(c, 'domains', c.get('domains', [])),
                "expires": getattr(c, 'expires_at', c.get('expires_at')),
                "issuer": getattr(c, 'issuer', c.get('issuer', 'Unknown'))
            }
            for c in certs
        ],
        "count": len(certs)
    }


async def certificate_request(domain: str, _storage=None, _logger=None) -> Dict[str, Any]:
    """Request a new SSL certificate for a domain.
    
    Args:
        domain: Domain to request certificate for
    
    Returns:
        Status dictionary
    """
    if _logger:
        _logger.info(f"Certificate requested for: {domain}")
    
    # Publish certificate request event
    await _storage.redis_client.xadd(
        "events:certificate",
        {"event": json.dumps({
            "type": "certificate_requested",
            "domain": domain,
            "timestamp": datetime.now(timezone.utc).isoformat()
        })}
    )
    
    return {"status": "requested", "domain": domain}


async def certificate_delete(cert_name: str, _storage=None, _logger=None) -> Dict[str, Any]:
    """Delete a certificate.
    
    Args:
        cert_name: Certificate name
    
    Returns:
        Status dictionary
    """
    await _storage.delete_certificate(cert_name)
    
    if _logger:
        _logger.info(f"Certificate deleted: {cert_name}")
    
    return {"status": "deleted", "cert_name": cert_name}


async def certificate_show(cert_name: str, _storage=None) -> Dict[str, Any]:
    """Show certificate details.
    
    Args:
        cert_name: Certificate name
    
    Returns:
        Certificate details
    """
    cert = await _storage.get_certificate(cert_name)
    
    if not cert:
        raise ValueError(f"Certificate '{cert_name}' not found")
    
    return {
        "certificate": {
            "name": cert.get("cert_name"),
            "domains": cert.get("domains", []),
            "expires": cert.get("expires_at"),
            "issuer": cert.get("issuer", "Unknown"),
            "created": cert.get("created_at")
        }
    }


# ========== Route Management Tools ==========

async def route_list(_storage=None) -> Dict[str, Any]:
    """List all routing rules."""
    routes = await _storage.list_routes()
    
    return {
        "routes": [
            {
                "id": getattr(r, 'route_id', r.get('route_id')),
                "path": getattr(r, 'path_pattern', r.get('path_pattern')),
                "target": getattr(r, 'target_value', r.get('target_value')),
                "priority": getattr(r, 'priority', r.get('priority', 100)),
                "enabled": getattr(r, 'enabled', r.get('enabled', True))
            }
            for r in routes
        ],
        "count": len(routes)
    }


async def route_create(
    path_pattern: str,
    target_url: str,
    priority: int = 100,
    _storage=None,
    _logger=None
) -> Dict[str, Any]:
    """Create a new routing rule.
    
    Args:
        path_pattern: Path pattern to match (e.g., /api/*)
        target_url: Target URL to route to
        priority: Route priority (higher = checked first)
    
    Returns:
        Created route details
    """
    route_id = path_pattern.replace('/', '_').strip('_')
    
    route_data = {
        "route_id": route_id,
        "path_pattern": path_pattern,
        "target_type": "url",
        "target_value": target_url,
        "priority": priority,
        "enabled": True
    }
    
    await _storage.create_route(route_data)
    
    if _logger:
        _logger.info(f"Route created: {path_pattern} -> {target_url}")
    
    return {"status": "created", "route": route_data}


async def route_delete(route_id: str, _storage=None, _logger=None) -> Dict[str, Any]:
    """Delete a routing rule.
    
    Args:
        route_id: Route ID to delete
    
    Returns:
        Status dictionary
    """
    await _storage.delete_route(route_id)
    
    if _logger:
        _logger.info(f"Route deleted: {route_id}")
    
    return {"status": "deleted", "route_id": route_id}


# ========== Service Management Tools ==========

async def service_list(_storage=None) -> Dict[str, Any]:
    """List all Docker services."""
    services = await _storage.list_services()
    
    return {
        "services": [
            {
                "name": getattr(s, 'service_name', s.get('service_name')),
                "type": getattr(s, 'service_type', s.get('service_type', 'unknown')),
                "status": getattr(s, 'status', s.get('status', 'unknown'))
            }
            for s in services
        ],
        "count": len(services)
    }


async def service_restart(service_name: str, _storage=None, _logger=None) -> Dict[str, Any]:
    """Restart a Docker service.
    
    Args:
        service_name: Service name to restart
    
    Returns:
        Status dictionary
    """
    # Publish restart event
    await _storage.redis_client.xadd(
        "events:service",
        {"event": json.dumps({
            "type": "service_restart_requested",
            "service": service_name,
            "timestamp": datetime.now(timezone.utc).isoformat()
        })}
    )
    
    if _logger:
        _logger.info(f"Service restart requested: {service_name}")
    
    return {"status": "restart_requested", "service": service_name}


# ========== Log Query Tools ==========

async def log_search(
    query: str = "",
    hours: int = 1,
    limit: int = 100,
    level: str = "INFO",
    _storage=None
) -> Dict[str, Any]:
    """Search logs from Redis Streams.
    
    Args:
        query: Search query (optional)
        hours: Hours to look back
        limit: Maximum results
        level: Minimum log level (DEBUG, INFO, WARNING, ERROR)
    
    Returns:
        Matching log entries
    """
    # Calculate time range
    end_time = time.time()
    start_time = end_time - (hours * 3600)
    
    try:
        # Read from log stream
        logs = await _storage.redis_client.xrevrange(
            "logs:all",
            max=f"{int(end_time * 1000)}",
            min=f"{int(start_time * 1000)}",
            count=limit * 2  # Get more to filter
        )
        
        # Parse and filter log entries
        entries = []
        level_map = {"DEBUG": 10, "INFO": 20, "WARNING": 30, "ERROR": 40}
        min_level = level_map.get(level.upper(), 20)
        
        for log_id, data in logs:
            try:
                log_data = json.loads(data.get(b'log', b'{}').decode())
                log_level = level_map.get(log_data.get('level', 'INFO').upper(), 20)
                
                if log_level >= min_level:
                    # Apply search filter
                    if not query or query.lower() in str(log_data).lower():
                        entries.append({
                            "timestamp": log_data.get('timestamp'),
                            "level": log_data.get('level'),
                            "message": log_data.get('message'),
                            "component": log_data.get('component')
                        })
                        
                        if len(entries) >= limit:
                            break
            except:
                continue
        
        return {"logs": entries, "count": len(entries), "query": query}
        
    except Exception as e:
        return {"logs": [], "error": str(e)}


async def log_errors(hours: int = 1, limit: int = 50, _storage=None) -> Dict[str, Any]:
    """Get recent error logs.
    
    Args:
        hours: Hours to look back
        limit: Maximum results
    
    Returns:
        Error log entries
    """
    return await log_search(query="", hours=hours, limit=limit, level="ERROR", _storage=_storage)


async def log_by_component(
    component: str,
    hours: int = 1,
    limit: int = 100,
    _storage=None
) -> Dict[str, Any]:
    """Get logs from specific component.
    
    Args:
        component: Component name (e.g., mcp, proxy, dispatcher)
        hours: Hours to look back
        limit: Maximum results
    
    Returns:
        Component log entries
    """
    result = await log_search(query=component, hours=hours, limit=limit, _storage=_storage)
    
    # Further filter by exact component match
    filtered_logs = [
        log for log in result.get("logs", [])
        if log.get("component") == component
    ]
    
    return {"logs": filtered_logs, "count": len(filtered_logs), "component": component}


async def log_stats(hours: int = 24, _storage=None) -> Dict[str, Any]:
    """Get log statistics.
    
    Args:
        hours: Hours to analyze
    
    Returns:
        Log statistics
    """
    result = await log_search(query="", hours=hours, limit=10000, level="DEBUG", _storage=_storage)
    
    logs = result.get("logs", [])
    
    # Calculate statistics
    stats = {
        "total": len(logs),
        "by_level": {},
        "by_component": {},
        "errors": 0,
        "warnings": 0
    }
    
    for log in logs:
        level = log.get("level", "INFO")
        component = log.get("component", "unknown")
        
        stats["by_level"][level] = stats["by_level"].get(level, 0) + 1
        stats["by_component"][component] = stats["by_component"].get(component, 0) + 1
        
        if level == "ERROR":
            stats["errors"] += 1
        elif level == "WARNING":
            stats["warnings"] += 1
    
    return stats


# ========== OAuth Tools ==========

async def oauth_session_list(_storage=None) -> Dict[str, Any]:
    """List active OAuth sessions."""
    # Get all OAuth session keys
    keys = await _storage.redis_client.keys("oauth:session:*")
    
    sessions = []
    for key in keys:
        session_data = await _storage.redis_client.get(key)
        if session_data:
            try:
                session = json.loads(session_data)
                sessions.append({
                    "session_id": session.get("session_id"),
                    "user": session.get("user"),
                    "created": session.get("created_at"),
                    "expires": session.get("expires_at")
                })
            except:
                continue
    
    return {"sessions": sessions, "count": len(sessions)}


async def oauth_revoke_session(session_id: str, _storage=None, _logger=None) -> Dict[str, Any]:
    """Revoke an OAuth session.
    
    Args:
        session_id: Session ID to revoke
    
    Returns:
        Status dictionary
    """
    key = f"oauth:session:{session_id}"
    deleted = await _storage.redis_client.delete(key)
    
    if _logger:
        _logger.info(f"OAuth session revoked: {session_id}")
    
    return {"status": "revoked" if deleted else "not_found", "session_id": session_id}


# ========== System Tools ==========

async def echo(message: str) -> str:
    """Echo a message for testing.
    
    Args:
        message: Message to echo
    
    Returns:
        Echoed message
    """
    return f"Echo: {message}"


async def health_check(_storage=None) -> Dict[str, Any]:
    """Check system health status."""
    health = {
        "status": "healthy",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "components": {}
    }
    
    # Check Redis
    try:
        await _storage.redis_client.ping()
        health["components"]["redis"] = "healthy"
    except:
        health["components"]["redis"] = "unhealthy"
        health["status"] = "degraded"
    
    # MCP is healthy if we're running
    health["components"]["mcp"] = "healthy"
    
    return health


async def system_info(_storage=None) -> Dict[str, Any]:
    """Get system information."""
    # Get Redis info
    redis_info = await _storage.redis_client.info()
    
    return {
        "redis": {
            "version": redis_info.get("redis_version", "unknown"),
            "memory_used": redis_info.get("used_memory_human", "unknown"),
            "connected_clients": redis_info.get("connected_clients", 0),
            "uptime_days": redis_info.get("uptime_in_days", 0)
        },
        "mcp": {
            "version": "3.0.0",
            "tools_count": len(_mcp_server.tools) if _mcp_server else 0
        }
    }


# ========== Test and Development Tools ==========

async def trigger_list_changed(
    resource_type: str = "tools",
    _storage=None,
    _logger=None,
    _server=None
) -> Dict[str, Any]:
    """Trigger a listChanged notification for testing.
    
    Args:
        resource_type: Type of resource (tools, prompts, or resources)
    
    Returns:
        Status dictionary
    """
    if _logger:
        _logger.info(f"Triggering listChanged for {resource_type}")
    
    if _server and hasattr(_server, 'send_list_changed_notification'):
        await _server.send_list_changed_notification(resource_type)
        return {
            "status": "notification_sent",
            "resource_type": resource_type,
            "active_sessions": len(_server.sse_connections) if hasattr(_server, 'sse_connections') else 0
        }
    
    return {
        "status": "error",
        "message": "Server not available or doesn't support notifications"
    }


async def add_test_tool(
    tool_name: str = "test_dynamic_tool",
    _storage=None,
    _logger=None,
    _server=None
) -> Dict[str, Any]:
    """Dynamically add a test tool to demonstrate listChanged notifications.
    
    Args:
        tool_name: Name of the test tool to add
    
    Returns:
        Status dictionary
    """
    if _logger:
        _logger.info(f"Adding test tool: {tool_name}")
    
    if _server:
        # Create a simple test function
        async def dynamic_test_tool():
            """A dynamically created test tool."""
            return {"message": f"Hello from {tool_name}"}
        
        # Register it
        _server.register_tool(tool_name, dynamic_test_tool)
        
        return {
            "status": "tool_added",
            "tool_name": tool_name,
            "total_tools": len(_server.tools) if hasattr(_server, 'tools') else 0
        }
    
    return {
        "status": "error",
        "message": "Server not available"
    }


async def remove_test_tool(
    tool_name: str = "test_dynamic_tool",
    _storage=None,
    _logger=None,
    _server=None
) -> Dict[str, Any]:
    """Remove a test tool to demonstrate listChanged notifications.
    
    Args:
        tool_name: Name of the test tool to remove
    
    Returns:
        Status dictionary
    """
    if _logger:
        _logger.info(f"Removing test tool: {tool_name}")
    
    if _server and hasattr(_server, 'tools') and tool_name in _server.tools:
        # Remove the tool
        del _server.tools[tool_name]
        
        # Send notification
        if hasattr(_server, 'send_list_changed_notification'):
            await _server.send_list_changed_notification("tools")
        
        return {
            "status": "tool_removed",
            "tool_name": tool_name,
            "remaining_tools": len(_server.tools)
        }
    
    return {
        "status": "error",
        "message": f"Tool '{tool_name}' not found or server not available"
    }


# ========== Workflow Tools ==========

async def workflow_create_proxy_with_cert(
    hostname: str,
    target_url: str,
    _storage=None,
    _logger=None
) -> Dict[str, Any]:
    """Create proxy and request certificate in one workflow.
    
    Args:
        hostname: Proxy hostname
        target_url: Target URL
    
    Returns:
        Workflow result
    """
    results = {"steps": []}
    
    # Step 1: Create proxy
    try:
        await proxy_create(hostname, target_url, True, False, _storage, _logger)
        results["steps"].append({"step": "create_proxy", "status": "success"})
    except Exception as e:
        results["steps"].append({"step": "create_proxy", "status": "failed", "error": str(e)})
        return results
    
    # Step 2: Request certificate
    try:
        await certificate_request(hostname, _storage, _logger)
        results["steps"].append({"step": "request_certificate", "status": "success"})
    except Exception as e:
        results["steps"].append({"step": "request_certificate", "status": "failed", "error": str(e)})
    
    results["status"] = "completed"
    results["hostname"] = hostname
    
    return results


async def workflow_cleanup_proxy(
    hostname: str,
    _storage=None,
    _logger=None
) -> Dict[str, Any]:
    """Delete proxy and associated resources.
    
    Args:
        hostname: Proxy hostname
    
    Returns:
        Workflow result
    """
    results = {"steps": [], "hostname": hostname}
    
    # Step 1: Delete proxy
    try:
        await proxy_delete(hostname, _storage, _logger)
        results["steps"].append({"step": "delete_proxy", "status": "success"})
    except Exception as e:
        results["steps"].append({"step": "delete_proxy", "status": "failed", "error": str(e)})
    
    # Step 2: Delete certificate (if exists)
    try:
        await certificate_delete(hostname, _storage, _logger)
        results["steps"].append({"step": "delete_certificate", "status": "success"})
    except:
        results["steps"].append({"step": "delete_certificate", "status": "skipped"})
    
    results["status"] = "completed"
    
    return results


# Function to register all tools after server is initialized
def setup_tools(server):
    """Setup all tools with the server instance."""
    # Register each tool function explicitly
    tools = [
        # Proxy tools
        proxy_list,
        proxy_create,
        proxy_delete,
        proxy_show,
        proxy_update,
        
        # Certificate tools
        certificate_list,
        certificate_request,
        certificate_delete,
        certificate_show,
        
        # Route tools
        route_list,
        route_create,
        route_delete,
        
        # Service tools
        service_list,
        service_restart,
        
        # Log tools
        log_search,
        log_errors,
        log_by_component,
        log_stats,
        
        # OAuth tools
        oauth_session_list,
        oauth_revoke_session,
        
        # System tools
        echo,
        health_check,
        system_info,
        
        # Workflow tools
        workflow_create_proxy_with_cert,
        workflow_cleanup_proxy,
        
        # Test and development tools
        trigger_list_changed,
        add_test_tool,
        remove_test_tool
    ]
    
    # Register all tools with the server
    for tool_func in tools:
        server.tool(tool_func)
    
    return len(tools)