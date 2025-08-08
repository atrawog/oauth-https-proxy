#!/usr/bin/env python3
"""Test route visibility for a specific token."""

import os
import sys
import requests
from tabulate import tabulate

def test_route_visibility(token):
    """Test route visibility for a specific token."""
    api_url = os.getenv('API_URL', 'http://localhost')
    
    headers = {"Authorization": f"Bearer {token}"}
    
    # Test routes endpoint
    print(f"\n=== Testing /routes endpoint with token ===")
    try:
        response = requests.get(f"{api_url}/routes", headers=headers)
        response.raise_for_status()
        routes = response.json()
        
        print(f"\nTotal routes visible: {len(routes)}")
        
        if routes:
            table_data = []
            for route in routes:
                table_data.append([
                    route.get('route_id', 'N/A'),
                    route.get('path_pattern', 'N/A'),
                    route.get('priority', 'N/A'),
                    route.get('created_by', 'N/A')
                ])
            
            print(tabulate(table_data, 
                         headers=['Route ID', 'Path Pattern', 'Priority', 'Created By'],
                         tablefmt='grid'))
        else:
            print("No routes found!")
            
    except Exception as e:
        print(f"Error fetching routes: {e}")
        return False
    
    return True

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python test_token_route_visibility.py <token>")
        sys.exit(1)
    
    token = sys.argv[1]
    if not test_route_visibility(token):
        sys.exit(1)