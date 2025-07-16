#!/usr/bin/env python3
"""Delete a route."""

import os
import sys
import requests


def delete_route(route_id: str, token: str):
    """Delete a route."""
    base_url = os.getenv('BASE_URL')
    if not base_url:
        print("Error: BASE_URL must be set in .env")
        return False
    
    headers = {"Authorization": f"Bearer {token}"}
    
    try:
        response = requests.delete(f"{base_url}/routes/{route_id}", headers=headers, timeout=10)
        response.raise_for_status()
        
        result = response.json()
        print(f"✓ {result['message']}")
        
        return True
        
    except requests.exceptions.RequestException as e:
        if hasattr(e, 'response'):
            if e.response.status_code == 404:
                print(f"Error: Route '{route_id}' not found")
            elif e.response.status_code == 403:
                print(f"Error: {e.response.json().get('detail', 'Access denied')}")
            else:
                print(f"Error: Failed to delete route: {e}")
                if e.response.text:
                    print(f"Details: {e.response.text}")
        else:
            print(f"Error: Failed to delete route: {e}")
        return False


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: route_delete.py <route-id> <token>")
        sys.exit(1)
    
    success = delete_route(sys.argv[1], sys.argv[2])
    sys.exit(0 if success else 1)