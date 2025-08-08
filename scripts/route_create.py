#!/usr/bin/env python3
"""Create a new route."""

import os
import sys
import requests

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from scripts.test_utils import get_api_api_url


def create_route(path: str, target_type: str, target_value: str, token: str, 
                 priority: str = "50", methods: str = "", is_regex: str = "false", 
                 description: str = ""):
    """Create a new route."""
    api_url = get_api_api_url()
    if not api_url:
        print("Error: Unable to determine API base URL")
        return False
    
    headers = {"Authorization": f"Bearer {token}"}
    
    # Parse methods
    method_list = [m.strip().upper() for m in methods.split(",")] if methods else None
    
    # Parse boolean
    is_regex_bool = is_regex.lower() in ["true", "1", "yes"]
    
    # Convert target value to int if target type is port
    if target_type == "port":
        try:
            target_value = int(target_value)
        except ValueError:
            print(f"Error: Target value must be a number for port type")
            return False
    
    data = {
        "path_pattern": path,
        "target_type": target_type,
        "target_value": target_value,
        "priority": int(priority),
        "methods": method_list,
        "is_regex": is_regex_bool,
        "description": description,
        "enabled": True
    }
    
    try:
        response = requests.post(f"{api_url}/api/v1/routes/", json=data, headers=headers, timeout=10)
        response.raise_for_status()
        
        route = response.json()
        print("✓ Route created successfully")
        print(f"  ID: {route['route_id']}")
        print(f"  Path: {route['path_pattern']}")
        print(f"  Target: {route['target_type']}:{route['target_value']}")
        print(f"  Priority: {route['priority']}")
        if route['methods']:
            print(f"  Methods: {', '.join(route['methods'])}")
        if route['is_regex']:
            print(f"  Pattern Type: Regular Expression")
        if route['description']:
            print(f"  Description: {route['description']}")
        
        return True
        
    except requests.exceptions.RequestException as e:
        print(f"Error: Failed to create route: {e}")
        if hasattr(e, 'response') and e.response.text:
            print(f"Details: {e.response.text}")
        return False


if __name__ == "__main__":
    if len(sys.argv) < 5:
        print("Usage: route_create.py <path> <target-type> <target-value> <token> [priority] [methods] [is-regex] [description]")
        print("  target-type: port, instance, or hostname")
        print("  methods: comma-separated list (e.g., GET,POST)")
        print("  is-regex: true or false")
        sys.exit(1)
    
    args = sys.argv[1:9] + [""] * (9 - len(sys.argv))  # Pad with empty strings
    success = create_route(*args)
    sys.exit(0 if success else 1)