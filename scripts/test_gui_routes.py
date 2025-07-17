#!/usr/bin/env python3
"""Test route management through the web GUI API."""

import os
import sys
import requests
import json
import time


def test_gui_routes():
    """Test route management through GUI API calls."""
    base_url = os.getenv('BASE_URL', 'http://localhost:80')
    test_token = "acm_CJbdqvLf1-UcxB6w0d9eLcvuLI8IaMs9x3j6wB3b3lw"  # gui-admin token
    
    headers = {
        "Authorization": f"Bearer {test_token}",
        "Content-Type": "application/json"
    }
    
    print("Testing route management through Web GUI API...\n")
    
    # Test 1: List routes (simulating loadRoutes())
    print("1. Loading routes...")
    try:
        response = requests.get(f"{base_url}/routes", headers=headers, timeout=10)
        response.raise_for_status()
        routes = response.json()
        print(f"   ✓ Loaded {len(routes)} routes")
        
        # Display first few routes
        for route in routes[:3]:
            print(f"   - {route['path_pattern']} -> {route['target_type']}:{route['target_value']}")
    except Exception as e:
        print(f"   ✗ Failed to load routes: {e}")
        return False
    
    # Test 2: Create a route (simulating form submission)
    print("\n2. Creating route via GUI...")
    route_data = {
        "path_pattern": "/gui-test/",
        "target_type": "port",
        "target_value": 8080,
        "priority": 60,
        "methods": ["GET", "POST"],
        "is_regex": False,
        "description": "Test route created via GUI",
        "enabled": True
    }
    
    try:
        response = requests.post(f"{base_url}/routes", json=route_data, headers=headers, timeout=10)
        response.raise_for_status()
        created_route = response.json()
        route_id = created_route['route_id']
        print(f"   ✓ Created route: {route_id}")
        print(f"   - Path: {created_route['path_pattern']}")
        print(f"   - Target: {created_route['target_type']}:{created_route['target_value']}")
    except Exception as e:
        print(f"   ✗ Failed to create route: {e}")
        return False
    
    # Test 3: Toggle route (disable)
    print(f"\n3. Disabling route {route_id}...")
    try:
        response = requests.put(
            f"{base_url}/routes/{route_id}", 
            json={"enabled": False}, 
            headers=headers, 
            timeout=10
        )
        response.raise_for_status()
        updated = response.json()
        print(f"   ✓ Route disabled: enabled={updated['enabled']}")
    except Exception as e:
        print(f"   ✗ Failed to disable route: {e}")
    
    # Test 4: Toggle route (enable)
    print(f"\n4. Re-enabling route {route_id}...")
    try:
        response = requests.put(
            f"{base_url}/routes/{route_id}", 
            json={"enabled": True}, 
            headers=headers, 
            timeout=10
        )
        response.raise_for_status()
        updated = response.json()
        print(f"   ✓ Route enabled: enabled={updated['enabled']}")
    except Exception as e:
        print(f"   ✗ Failed to enable route: {e}")
    
    # Test 5: Delete route
    print(f"\n5. Deleting route {route_id}...")
    try:
        response = requests.delete(f"{base_url}/routes/{route_id}", headers=headers, timeout=10)
        response.raise_for_status()
        print(f"   ✓ Route deleted successfully")
    except Exception as e:
        print(f"   ✗ Failed to delete route: {e}")
    
    # Test 6: Test default route protection
    print("\n6. Testing default route protection...")
    try:
        response = requests.delete(f"{base_url}/routes/api", headers=headers, timeout=10)
        if response.status_code == 403:
            print(f"   ✓ Default route correctly protected (403 Forbidden)")
        else:
            print(f"   ✗ Expected 403, got {response.status_code}")
    except Exception as e:
        print(f"   ✗ Error: {e}")
    
    print("\n" + "="*50)
    print("✓ GUI route tests completed!")
    return True


if __name__ == "__main__":
    success = test_gui_routes()
    sys.exit(0 if success else 1)