#!/usr/bin/env python3
"""Disable a specific route for a proxy target."""

import os
import sys
import requests


def main():
    if len(sys.argv) < 4:
        print("Usage: proxy_route_disable.py <hostname> <route-id> <token>")
        sys.exit(1)
    
    hostname = sys.argv[1]
    route_id = sys.argv[2]
    token = sys.argv[3]
    
    base_url = os.getenv('TEST_BASE_URL', 'http://localhost:80')
    url = f"{base_url}/proxy/targets/{hostname}/routes/{route_id}/disable"
    
    headers = {
        'Authorization': f'Bearer {token}'
    }
    
    try:
        resp = requests.post(url, headers=headers)
        resp.raise_for_status()
        result = resp.json()
        
        print(f"Route '{route_id}' disabled for {hostname}")
        
        # Show current route status
        routes_url = f"{base_url}/proxy/targets/{hostname}/routes"
        routes_resp = requests.get(routes_url)
        if routes_resp.ok:
            routes_data = routes_resp.json()
            if routes_data['route_mode'] == 'selective':
                enabled = routes_data['enabled_routes']
                if route_id in enabled:
                    print(f"  Route was removed from enabled list")
                print(f"  Enabled routes: {', '.join(enabled) if enabled else 'None'}")
            elif routes_data['route_mode'] == 'all':
                print(f"  Disabled routes: {', '.join(routes_data['disabled_routes'])}")
                
    except requests.exceptions.HTTPError as e:
        if e.response.status_code == 404:
            print(f"Error: Proxy target {hostname} or route {route_id} not found")
        elif e.response.status_code == 403:
            print("Error: Access denied - you don't own this proxy")
        elif e.response.status_code == 400:
            print(f"Error: {e.response.json().get('detail', 'Bad request')}")
        else:
            print(f"Error: {e.response.status_code} - {e.response.text}")
        sys.exit(1)
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()