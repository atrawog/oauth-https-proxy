# Per-Proxy Route Control

## Overview

This feature allows fine-grained control over which routes apply to each proxy target. Instead of having all routes apply globally, each proxy can now specify exactly which routes it wants to handle.

## Implementation Summary

### 1. Data Model Changes

Added to `ProxyTarget` model:
- `route_mode`: Controls how routes are filtered (all/selective/none)
- `enabled_routes`: List of route IDs explicitly enabled (for selective mode)
- `disabled_routes`: List of route IDs explicitly disabled (for all mode)

### 2. Route Matching Logic

Modified `UnifiedDispatcher.handle_http_connection()` to:
1. Extract hostname from request first
2. Load proxy configuration for that hostname
3. Apply route filtering based on proxy's route_mode
4. Match only applicable routes

### 3. API Endpoints

- `GET /proxy/targets/{hostname}/routes` - View route configuration
- `PUT /proxy/targets/{hostname}/routes` - Update route settings
- `POST /proxy/targets/{hostname}/routes/{route_id}/enable` - Enable specific route
- `POST /proxy/targets/{hostname}/routes/{route_id}/disable` - Disable specific route

### 4. CLI Commands

- `just proxy-routes-show <hostname>` - View current configuration
- `just proxy-routes-mode <hostname> <token> <mode>` - Set route mode
- `just proxy-route-enable <hostname> <route-id> <token>` - Enable route
- `just proxy-route-disable <hostname> <route-id> <token>` - Disable route
- `just proxy-routes-set <hostname> <token> <enabled> <disabled>` - Bulk update

### 5. Route Modes Explained

**all (default)**
- All global routes apply to the proxy
- Can explicitly disable specific routes
- Best for: General purpose proxies

**selective**
- No routes apply by default
- Must explicitly enable each route
- Best for: Restricted services, API versioning

**none**
- No path-based routing at all
- Only hostname routing applies
- Best for: Static content, simple forwarding

## Testing

Run comprehensive tests with:
```bash
just test-proxy-routes
```

Tests cover:
- Route mode switching
- Enabling/disabling specific routes
- Route filtering during request processing
- Bulk route updates

## Backwards Compatibility

- All existing proxies default to `route_mode: "all"`
- No changes required for existing deployments
- Seamless upgrade path