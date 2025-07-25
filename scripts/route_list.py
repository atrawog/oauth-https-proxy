#!/usr/bin/env python3
"""List all routes."""

import os
import sys
import requests
from tabulate import tabulate

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from scripts.test_utils import get_api_base_url


def list_routes(token: str = None):
    """List all routes."""
    base_url = get_api_base_url()
    if not base_url:
        print("Error: Unable to determine API base URL")
        return False
    
    headers = {}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    
    try:
        response = requests.get(f"{base_url}/routes/", headers=headers, timeout=10)
        response.raise_for_status()
        
        routes = response.json()
        
        if not routes:
            print("No routes configured")
            return True
        
        # Format for display
        table_data = []
        for route in routes:
            methods = ",".join(route['methods']) if route['methods'] else "ALL"
            status = "✓" if route['enabled'] else "✗"
            regex = "RE" if route['is_regex'] else ""
            
            # Get owner/creator info
            owner = route.get('created_by', 'N/A')
            if not owner or owner == 'None':
                owner = 'system'
            
            table_data.append([
                route['priority'],
                route['route_id'],
                route['path_pattern'],
                f"{route['target_type']}:{route['target_value']}",
                methods,
                regex,
                status,
                owner,
                route['description'][:25] + "..." if len(route['description']) > 25 else route['description']
            ])
        
        headers = ["Priority", "ID", "Path", "Target", "Methods", "Regex", "Enabled", "Owner", "Description"]
        print(tabulate(table_data, headers=headers, tablefmt="grid"))
        print(f"\nTotal routes: {len(routes)}")
        
        return True
        
    except requests.exceptions.RequestException as e:
        print(f"Error: Failed to list routes: {e}")
        return False


if __name__ == "__main__":
    # Token is optional - if provided, sends authorization header
    token = sys.argv[1] if len(sys.argv) > 1 else None
    success = list_routes(token)
    sys.exit(0 if success else 1)