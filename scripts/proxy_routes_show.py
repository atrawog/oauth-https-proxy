#!/usr/bin/env python3
"""Show route configuration for a proxy target."""

import os
import sys
import requests
import json
from tabulate import tabulate


def main():
    if len(sys.argv) < 2:
        print("Usage: proxy_routes_show.py <hostname>")
        sys.exit(1)
    
    hostname = sys.argv[1]
    api_url = os.getenv('TEST_API_URL', 'http://localhost:80')
    
    # No authentication needed for read operations
    url = f"{api_url}/proxy/targets/{hostname}/routes"
    
    try:
        resp = requests.get(url)
        resp.raise_for_status()
        data = resp.json()
        
        print(f"\nRoute configuration for {hostname}:")
        print(f"  Route mode: {data['route_mode']}")
        
        if data['route_mode'] == 'selective':
            print(f"  Enabled routes: {', '.join(data['enabled_routes']) if data['enabled_routes'] else 'None'}")
        elif data['route_mode'] == 'all':
            print(f"  Disabled routes: {', '.join(data['disabled_routes']) if data['disabled_routes'] else 'None'}")
        
        print(f"\nApplicable routes:")
        if data['applicable_routes']:
            table_data = []
            for route in data['applicable_routes']:
                table_data.append([
                    route['route_id'],
                    route['path_pattern'],
                    f"{route['target_type']}:{route['target_value']}",
                    route['priority'],
                    route.get('description', '')
                ])
            print(tabulate(table_data, headers=['Route ID', 'Path', 'Target', 'Priority', 'Description']))
        else:
            print("  No routes apply to this proxy")
            
    except requests.exceptions.HTTPError as e:
        if e.response.status_code == 404:
            print(f"Error: Proxy target {hostname} not found")
        else:
            print(f"Error: {e.response.status_code} - {e.response.text}")
        sys.exit(1)
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()