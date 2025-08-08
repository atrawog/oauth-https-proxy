#!/usr/bin/env python3
"""Update an existing route."""

import os
import sys
import requests
import argparse

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from scripts.test_utils import get_api_api_url


def update_route(route_id: str, token: str, **updates):
    """Update a route."""
    api_url = get_api_api_url()
    if not api_url:
        print("Error: Unable to determine API base URL")
        return False
    
    headers = {"Authorization": f"Bearer {token}"}
    
    # Build update data
    data = {}
    
    if updates.get('path'):
        data['path_pattern'] = updates['path']
    
    if updates.get('target_type'):
        data['target_type'] = updates['target_type']
    
    if updates.get('target_value'):
        target_value = updates['target_value']
        # Convert to int if updating to port type
        if updates.get('target_type') == 'port' or (not updates.get('target_type') and 'port' in str(target_value)):
            try:
                target_value = int(target_value)
            except ValueError:
                pass
        data['target_value'] = target_value
    
    if updates.get('priority'):
        data['priority'] = int(updates['priority'])
    
    if updates.get('methods'):
        data['methods'] = [m.strip().upper() for m in updates['methods'].split(",")]
    
    if updates.get('is_regex') is not None:
        data['is_regex'] = updates['is_regex'].lower() in ["true", "1", "yes"]
    
    if updates.get('description') is not None:
        data['description'] = updates['description']
    
    if updates.get('enabled') is not None:
        data['enabled'] = updates['enabled'].lower() in ["true", "1", "yes"]
    
    if not data:
        print("Error: No fields to update")
        return False
    
    try:
        response = requests.put(f"{api_url}/api/v1/routes/{route_id}", json=data, headers=headers, timeout=10)
        response.raise_for_status()
        
        route = response.json()
        print(f"✓ Route '{route_id}' updated successfully")
        
        return True
        
    except requests.exceptions.RequestException as e:
        if hasattr(e, 'response') and e.response.status_code == 404:
            print(f"Error: Route '{route_id}' not found")
        else:
            print(f"Error: Failed to update route: {e}")
            if hasattr(e, 'response') and e.response.text:
                print(f"Details: {e.response.text}")
        return False


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Update a route')
    parser.add_argument('route_id', help='Route ID')
    parser.add_argument('token', help='API token')
    parser.add_argument('--path', help='New path pattern')
    parser.add_argument('--target-type', help='New target type')
    parser.add_argument('--target-value', help='New target value')
    parser.add_argument('--priority', help='New priority')
    parser.add_argument('--methods', help='New methods (comma-separated)')
    parser.add_argument('--is-regex', help='Is regex pattern (true/false)')
    parser.add_argument('--description', help='New description')
    parser.add_argument('--enabled', help='Enable/disable route (true/false)')
    
    args = parser.parse_args()
    
    # Build updates dict
    updates = {}
    for field in ['path', 'target_type', 'target_value', 'priority', 'methods', 'is_regex', 'description', 'enabled']:
        value = getattr(args, field.replace('-', '_'))
        if value is not None:
            updates[field.replace('-', '_')] = value
    
    success = update_route(args.route_id, args.token, **updates)
    sys.exit(0 if success else 1)