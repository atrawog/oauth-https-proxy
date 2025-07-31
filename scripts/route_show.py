#!/usr/bin/env python3
"""Show route details."""

import os
import sys
import requests
from datetime import datetime

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from scripts.test_utils import get_api_base_url


def show_route(route_id: str):
    """Show route details."""
    base_url = get_api_base_url()
    if not base_url:
        print("Error: Unable to determine API base URL")
        return False
    
    try:
        response = requests.get(f"{base_url}/api/v1/routes/{route_id}", timeout=10)
        response.raise_for_status()
        
        route = response.json()
        
        # Display route details
        print(f"Route: {route['route_id']}")
        print(f"  Path Pattern: {route['path_pattern']}")
        print(f"  Target Type: {route['target_type']}")
        print(f"  Target Value: {route['target_value']}")
        print(f"  Priority: {route['priority']}")
        print(f"  Methods: {', '.join(route['methods']) if route['methods'] else 'ALL'}")
        print(f"  Is Regex: {route['is_regex']}")
        print(f"  Enabled: {route['enabled']}")
        print(f"  Description: {route['description']}")
        print(f"  Created By: {route['created_by'] or 'Unknown'}")
        
        # Parse and format created_at
        created_at = datetime.fromisoformat(route['created_at'].replace('Z', '+00:00'))
        print(f"  Created At: {created_at.strftime('%Y-%m-%d %H:%M:%S %Z')}")
        
        return True
        
    except requests.exceptions.RequestException as e:
        if hasattr(e, 'response') and e.response.status_code == 404:
            print(f"Error: Route '{route_id}' not found")
        else:
            print(f"Error: Failed to get route: {e}")
        return False


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: route_show.py <route-id>")
        sys.exit(1)
    
    success = show_route(sys.argv[1])
    sys.exit(0 if success else 1)