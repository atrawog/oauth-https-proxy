#!/usr/bin/env python3
"""Set multiple routes for a proxy at once."""

import os
import sys
import requests
import json


def main():
    if len(sys.argv) < 5:
        print("Usage: proxy_routes_set.py <hostname> <token> <enabled-routes> <disabled-routes>")
        print("  enabled-routes: comma-separated list of route IDs to enable (or empty)")
        print("  disabled-routes: comma-separated list of route IDs to disable (or empty)")
        print("Example: proxy_routes_set.py api.example.com mytoken 'api-v1,api-v2' 'debug-route'")
        sys.exit(1)
    
    hostname = sys.argv[1]
    token = sys.argv[2]
    enabled_str = sys.argv[3]
    disabled_str = sys.argv[4]
    
    # Parse comma-separated lists
    enabled_routes = [r.strip() for r in enabled_str.split(',') if r.strip()] if enabled_str else []
    disabled_routes = [r.strip() for r in disabled_str.split(',') if r.strip()] if disabled_str else []
    
    base_url = os.getenv('TEST_BASE_URL', 'http://localhost:80')
    
    # First get current proxy configuration
    routes_url = f"{base_url}/proxy/targets/{hostname}/routes"
    try:
        resp = requests.get(routes_url)
        resp.raise_for_status()
        current_data = resp.json()
        route_mode = current_data['route_mode']
    except Exception as e:
        print(f"Error getting proxy configuration: {e}")
        sys.exit(1)
    
    # Prepare update based on mode
    if route_mode == 'none':
        print(f"Warning: Proxy {hostname} has route_mode='none' - no routes will apply")
        print("Change route mode first with: proxy-routes-mode")
        sys.exit(1)
    
    headers = {
        'Authorization': f'Bearer {token}',
        'Content-Type': 'application/json'
    }
    
    # Update routes based on mode
    if route_mode == 'selective':
        # For selective mode, we set the enabled list
        data = {
            'route_mode': 'selective',
            'enabled_routes': enabled_routes,
            'disabled_routes': []
        }
        print(f"Setting enabled routes for {hostname}: {', '.join(enabled_routes) if enabled_routes else 'None'}")
    else:  # all mode
        # For all mode, we set the disabled list
        data = {
            'route_mode': 'all',
            'enabled_routes': [],
            'disabled_routes': disabled_routes
        }
        print(f"Setting disabled routes for {hostname}: {', '.join(disabled_routes) if disabled_routes else 'None'}")
    
    # Update the proxy
    url = f"{base_url}/proxy/targets/{hostname}/routes"
    try:
        resp = requests.put(url, headers=headers, json=data)
        resp.raise_for_status()
        result = resp.json()
        
        print(f"Routes updated successfully for {hostname}")
        
        # Show final state
        if route_mode == 'selective':
            print(f"  Mode: selective - only these routes apply: {', '.join(enabled_routes) if enabled_routes else 'None'}")
        else:
            print(f"  Mode: all - all routes apply except: {', '.join(disabled_routes) if disabled_routes else 'None'}")
            
    except requests.exceptions.HTTPError as e:
        if e.response.status_code == 404:
            print(f"Error: Proxy target {hostname} not found")
        elif e.response.status_code == 403:
            print("Error: Access denied - you don't own this proxy")
        else:
            print(f"Error: {e.response.status_code} - {e.response.text}")
        sys.exit(1)
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()