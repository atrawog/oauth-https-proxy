#!/usr/bin/env python3
"""Bulk delete routes matching patterns."""

import os
import sys
import httpx
import time

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from scripts.test_utils import get_api_base_url, get_admin_token


def bulk_delete_routes(patterns):
    """Delete all routes matching given patterns."""
    base_url = get_api_base_url()
    if not base_url:
        print("Error: Unable to determine API base URL")
        return False
    
    # Get admin token
    token = get_admin_token()
    if not token:
        print("Error: Unable to get admin token")
        return False
    
    headers = {"Authorization": f"Bearer {token}"}
    
    # First, get all routes
    try:
        with httpx.Client() as client:
            response = client.get(f"{base_url}/api/v1/routes/", headers=headers, timeout=10)
            response.raise_for_status()
            routes = response.json()
    except httpx.HTTPError as e:
        print(f"Error: Failed to list routes: {e}")
        return False
    
    # Find routes to delete
    routes_to_delete = []
    for route in routes:
        route_id = route.get('route_id', '')
        for pattern in patterns:
            if pattern in route_id:
                routes_to_delete.append(route_id)
                break
    
    if not routes_to_delete:
        print("No routes found matching the patterns")
        return True
    
    print(f"Found {len(routes_to_delete)} routes to delete")
    
    # Delete routes
    deleted = 0
    failed = 0
    
    for route_id in routes_to_delete:
        try:
            with httpx.Client() as client:
                response = client.delete(f"{base_url}/api/v1/routes/{route_id}", headers=headers, timeout=10)
                response.raise_for_status()
                deleted += 1
                print(f"✓ Deleted: {route_id}")
        except httpx.HTTPError as e:
            failed += 1
            print(f"✗ Failed to delete {route_id}: {e}")
        
        # Small delay to avoid overwhelming the server
        time.sleep(0.1)
    
    print(f"\nSummary: {deleted} deleted, {failed} failed")
    return failed == 0


if __name__ == "__main__":
    # Delete routes containing "test", "bad-", and "webhook-method-route"
    patterns = ["test", "bad-", "webhook-method-route"]
    success = bulk_delete_routes(patterns)
    sys.exit(0 if success else 1)