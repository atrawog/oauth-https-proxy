#!/usr/bin/env python3
"""Set proxy route mode (all, selective, none)."""

import os
import sys
import requests
import json


def main():
    if len(sys.argv) < 4:
        print("Usage: proxy_routes_mode.py <hostname> <token> <mode>")
        print("  mode: all, selective, or none")
        sys.exit(1)
    
    hostname = sys.argv[1]
    token = sys.argv[2]
    mode = sys.argv[3]
    
    if mode not in ['all', 'selective', 'none']:
        print(f"Error: Invalid mode '{mode}'. Must be 'all', 'selective', or 'none'")
        sys.exit(1)
    
    base_url = os.getenv('TEST_BASE_URL', 'http://localhost:80')
    url = f"{base_url}/proxy/targets/{hostname}/routes"
    
    headers = {
        'Authorization': f'Bearer {token}',
        'Content-Type': 'application/json'
    }
    
    # When changing mode, clear the route lists
    data = {
        'route_mode': mode,
        'enabled_routes': [],
        'disabled_routes': []
    }
    
    try:
        resp = requests.put(url, headers=headers, json=data)
        resp.raise_for_status()
        result = resp.json()
        
        print(f"Route mode set to '{mode}' for {hostname}")
        
        if mode == 'selective':
            print("  - Only explicitly enabled routes will apply")
            print("  - Use 'proxy-route-enable' to enable specific routes")
        elif mode == 'all':
            print("  - All routes apply by default")
            print("  - Use 'proxy-route-disable' to disable specific routes")
        else:  # none
            print("  - No routes will apply")
            print("  - Only hostname-based routing will be used")
            
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