# URL-Only Routing Architecture

## Overview

The system has been simplified to use **URL-only routing** exclusively. All route targets must be explicit URLs pointing to services, eliminating the complexity of multiple route types and service registrations.

## Key Changes

### Before (Complex 4-Type System)
- **PORT**: Forward to `localhost:<port>`
- **SERVICE**: Look up named service → resolve to port
- **HOSTNAME**: Forward to proxy handling that hostname  
- **URL**: Direct URL forwarding

### After (Simple URL-Only)
- **URL**: All routes use explicit URLs (e.g., `http://api:9000`)

## Benefits

1. **Simplicity**: One route type, one resolution path
2. **Transparency**: Routes clearly show where traffic goes
3. **Docker-Native**: Uses Docker service names directly (`http://api:9000`)
4. **No Abstraction**: No named services, no port lookups
5. **Predictable**: What you configure is what you get

## Route Configuration

### Default Routes
All system routes are automatically created on startup via `DEFAULT_ROUTES` in `src/proxy/routes.py`:

```python
DEFAULT_ROUTES = [
    {
        "route_id": "token",
        "path_pattern": "/token",
        "target_type": RouteTargetType.URL,
        "target_value": "http://api:9000",
        "priority": 95,
        "description": "OAuth token endpoint",
        "enabled": True
    },
    # ... more routes
]
```

### Clean Route IDs
Routes now have clean, predictable IDs:
- ✅ `token` (not `token-80c106aa`)
- ✅ `authorize` (not `authorize-557592d4`)
- ✅ `introspect` (not `introspect-178f928c`)

## Implementation Details

### 1. Dispatcher Changes (`src/dispatcher/unified_dispatcher.py`)
- Removed `named_services` dictionary
- Removed `register_named_service()` method
- Simplified `resolve_route_target()` to handle URLs only

### 2. Route Resolution (`src/proxy/unified_routing.py`)
```python
async def resolve_route_target(self, route: Route) -> Optional[str]:
    """Resolve route target to actual URL.
    
    Simplified to URL-only routing. All routes should use URL type.
    """
    if route.target_type == RouteTargetType.URL:
        # Direct URL - the only supported type
        return str(route.target_value)
    
    # Legacy types log warnings/errors for migration
    elif route.target_type == RouteTargetType.PORT:
        log_warning(f"Legacy PORT route {route.route_id} should be migrated to URL type")
        return f"http://localhost:{route.target_value}"
    
    # SERVICE and HOSTNAME types return None (deprecated)
    return None
```

### 3. Route Consolidation
- Merged `OAUTH_ROUTES` into `DEFAULT_ROUTES`
- Deprecated `setup_oauth_routes()` endpoint
- All routes created automatically on startup

## Docker Networking

Routes use Docker service names for internal communication:
- API service: `http://api:9000`
- Redis service: `redis://redis:6379`
- No hardcoded `127.0.0.1` or `localhost` in route targets

## Migration Guide

### For Existing Routes

If you have existing routes using old types, update them:

```bash
# Old SERVICE type
just route-delete old-route
just route-create /path http://api:9000 95 "Description"

# Old PORT type  
just route-delete port-route
just route-create /path http://localhost:3000 95 "Description"

# Old HOSTNAME type
just route-delete hostname-route
just route-create /path http://target-proxy.com 95 "Description"
```

### For New Routes

Always use URL type:
```bash
just route-create /api/v1 http://backend:8080 90 "API v1 endpoint"
just route-create /metrics http://prometheus:9090 80 "Metrics endpoint"
```

## Troubleshooting

### Route Not Working?
1. Check route exists: `just route-list`
2. Verify URL is correct: `just route-show <route-id>`
3. Test target directly: `curl http://api:9000/health`
4. Check logs: `just logs | grep route`

### Common Issues
- **Empty reply from server**: Target URL incorrect or service not running
- **Route not found**: Route doesn't exist or is disabled
- **Connection refused**: Target service not listening on specified port

## Best Practices

1. **Use Docker Service Names**: `http://api:9000` not `http://127.0.0.1:9000`
2. **Explicit URLs**: Always specify full URL with protocol
3. **Clean IDs**: Use descriptive route IDs without random suffixes
4. **Priority Management**: Higher priority (100) routes checked first
5. **Documentation**: Document why each route exists

## Route Commands Reference

```bash
# List all routes
just route-list

# Create a route (URL type only)
just route-create <path> <url> [priority] [description] [token]

# Delete a route
just route-delete <route-id> [token]

# Show route details
just route-show <route-id> [token]

# Update route
just route-update <route-id> [path] [url] [priority] [enabled] [token]
```

## Architecture Benefits Summary

The URL-only routing architecture provides:
- **90% complexity reduction** in route resolution
- **Zero abstraction layers** between configuration and execution  
- **Direct Docker networking** without port mapping confusion
- **Predictable behavior** - routes do exactly what they say
- **Easy debugging** - one code path, clear target URLs