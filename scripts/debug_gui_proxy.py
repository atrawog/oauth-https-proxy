#!/usr/bin/env python3
"""Debug the GUI proxy configuration."""

import os
import redis
import json

redis_url = os.getenv('REDIS_URL')
r = redis.from_url(redis_url)

print("=== GUI PROXY CONFIGURATION DEBUG ===\n")

# Check proxy configuration
proxy_data = r.get('proxy:gui.atradev.org')
if proxy_data:
    proxy = json.loads(proxy_data)
    print("1. Proxy configuration for gui.atradev.org:")
    print(json.dumps(proxy, indent=2))
    
    # Check route mode
    route_mode = proxy.get('route_mode', 'all')
    print(f"\n2. Route mode: {route_mode}")
    
    if route_mode == 'selective':
        enabled_routes = proxy.get('enabled_routes', [])
        print(f"   Enabled routes: {enabled_routes}")
    elif route_mode == 'none':
        print("   ⚠️  NO ROUTES ARE ENABLED!")
    else:
        disabled_routes = proxy.get('disabled_routes', [])
        print(f"   Disabled routes: {disabled_routes}")
else:
    print("❌ No proxy found for gui.atradev.org")

# Check all routes
print("\n3. All available routes:")
route_keys = r.keys('route:*')
routes = []
for key in route_keys:
    if b':priority:' not in key:  # Skip priority index keys
        route_data = r.get(key)
        if route_data:
            route = json.loads(route_data)
            routes.append(route)

# Sort by priority
routes.sort(key=lambda x: x.get('priority', 0), reverse=True)

for route in routes:
    print(f"   - {route['path_pattern']} -> {route['target_type']}:{route['target_value']} (priority: {route['priority']})")

print("\n4. ANALYSIS:")
if proxy_data:
    proxy = json.loads(proxy_data)
    route_mode = proxy.get('route_mode', 'all')
    
    if route_mode == 'none':
        print("   ❌ PROBLEM FOUND: GUI proxy has route_mode='none'")
        print("   This means NO routes are forwarded, including API endpoints!")
        print("   The GUI can load the static files but API calls fail.")
    elif route_mode == 'selective':
        enabled = proxy.get('enabled_routes', [])
        if not enabled:
            print("   ❌ PROBLEM FOUND: GUI proxy has route_mode='selective' but no enabled routes!")
        else:
            print(f"   ⚠️  GUI proxy only forwards these routes: {enabled}")
    else:
        print("   ✓ GUI proxy should forward all routes (mode='all')")