#!/usr/bin/env python3
"""Test route functionality."""

import os
import sys
import requests
import time


def test_routes():
    """Test route CRUD operations."""
    api_url = os.getenv('API_URL')
    test_token = os.getenv('TEST_TOKEN')
    
    if not api_url:
        print("Error: API_URL must be set in .env")
        return False
    
    if not test_token:
        print("Error: TEST_TOKEN must be set in .env")
        print("Create a test token with: just token-generate test-routes")
        return False
    
    headers = {"Authorization": f"Bearer {test_token}"}
    success = True
    
    print("Testing route management functionality...\n")
    
    # Test 1: List routes
    print("1. Listing routes...")
    try:
        response = requests.get(f"{api_url}/routes", timeout=10)
        response.raise_for_status()
        routes = response.json()
        print(f"   ✓ Found {len(routes)} routes")
        
        # Check for default routes
        default_ids = ["acme-challenge", "api", "health"]
        found_defaults = [r['route_id'] for r in routes if r['route_id'] in default_ids]
        print(f"   ✓ Default routes present: {', '.join(found_defaults)}")
    except Exception as e:
        print(f"   ✗ Failed to list routes: {e}")
        success = False
    
    # Test 2: Create a test route
    print("\n2. Creating test route...")
    test_route_data = {
        "path_pattern": "/test/route/",
        "target_type": "instance",
        "target_value": "localhost",
        "priority": 75,
        "methods": ["GET", "POST"],
        "is_regex": False,
        "description": "Test route for validation",
        "enabled": True
    }
    
    try:
        response = requests.post(f"{api_url}/routes", json=test_route_data, headers=headers, timeout=10)
        response.raise_for_status()
        created_route = response.json()
        route_id = created_route['route_id']
        print(f"   ✓ Created route: {route_id}")
    except Exception as e:
        print(f"   ✗ Failed to create route: {e}")
        success = False
        return success
    
    # Test 3: Get route details
    print(f"\n3. Getting route details for {route_id}...")
    try:
        response = requests.get(f"{api_url}/routes/{route_id}", timeout=10)
        response.raise_for_status()
        route = response.json()
        print(f"   ✓ Retrieved route: {route['path_pattern']} -> {route['target_type']}:{route['target_value']}")
    except Exception as e:
        print(f"   ✗ Failed to get route: {e}")
        success = False
    
    # Test 4: Update route
    print(f"\n4. Updating route {route_id}...")
    update_data = {
        "priority": 85,
        "description": "Updated test route",
        "methods": ["GET", "POST", "PUT"]
    }
    
    try:
        response = requests.put(f"{api_url}/routes/{route_id}", json=update_data, headers=headers, timeout=10)
        response.raise_for_status()
        updated_route = response.json()
        print(f"   ✓ Updated priority to {updated_route['priority']}")
        print(f"   ✓ Updated methods to {', '.join(updated_route['methods'])}")
    except Exception as e:
        print(f"   ✗ Failed to update route: {e}")
        success = False
    
    # Test 5: Test regex route
    print("\n5. Creating regex route...")
    regex_route_data = {
        "path_pattern": "^/api/v[0-9]+/users/[0-9]+$",
        "target_type": "instance",
        "target_value": "api",
        "priority": 70,
        "methods": ["GET"],
        "is_regex": True,
        "description": "Regex route for user endpoints"
    }
    
    try:
        response = requests.post(f"{api_url}/routes", json=regex_route_data, headers=headers, timeout=10)
        response.raise_for_status()
        regex_route = response.json()
        regex_route_id = regex_route['route_id']
        print(f"   ✓ Created regex route: {regex_route_id}")
    except Exception as e:
        print(f"   ✗ Failed to create regex route: {e}")
        success = False
    
    # Test 6: Disable route
    print(f"\n6. Disabling route {route_id}...")
    try:
        response = requests.put(f"{api_url}/routes/{route_id}", 
                                json={"enabled": False}, headers=headers, timeout=10)
        response.raise_for_status()
        print(f"   ✓ Route disabled")
    except Exception as e:
        print(f"   ✗ Failed to disable route: {e}")
        success = False
    
    # Test 7: Delete routes
    print(f"\n7. Cleaning up test routes...")
    for rid in [route_id, regex_route_id]:
        try:
            response = requests.delete(f"{api_url}/routes/{rid}", headers=headers, timeout=10)
            response.raise_for_status()
            print(f"   ✓ Deleted route: {rid}")
        except Exception as e:
            print(f"   ✗ Failed to delete route {rid}: {e}")
            success = False
    
    # Test 8: Verify default routes cannot be deleted
    print("\n8. Verifying default route protection...")
    try:
        response = requests.delete(f"{api_url}/routes/acme-challenge", headers=headers, timeout=10)
        if response.status_code == 403:
            print(f"   ✓ Default route correctly protected")
        else:
            print(f"   ✗ Default route deletion should have been forbidden")
            success = False
    except Exception as e:
        print(f"   ✗ Unexpected error: {e}")
        success = False
    
    # Summary
    print("\n" + "="*50)
    if success:
        print("✓ All route tests passed!")
    else:
        print("✗ Some route tests failed")
    
    return success


if __name__ == "__main__":
    success = test_routes()
    sys.exit(0 if success else 1)