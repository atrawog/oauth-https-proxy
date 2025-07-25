#!/usr/bin/env python3
"""Test per-proxy route filtering functionality."""

import os
import sys
import requests
import json
import time
import subprocess
from tabulate import tabulate


BASE_URL = os.getenv('TEST_BASE_URL', 'http://localhost:80')
ADMIN_TOKEN = os.getenv('ADMIN_TOKEN', '')

def run_command(cmd):
    """Run a shell command and return output."""
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    return result.returncode, result.stdout, result.stderr


def test_route_modes():
    """Test different route modes (all, selective, none)."""
    print("\n=== Testing Route Modes ===")
    
    # Create a test proxy
    print("\n1. Creating test proxy...")
    cmd = f'docker exec mcp-http-proxy-acme-certmanager-1 pixi run python scripts/proxy_create.py ' \
          f'route-test.example.com http://backend:8080 {ADMIN_TOKEN} false true false true'
    code, out, err = run_command(cmd)
    if code != 0:
        print(f"Failed to create proxy: {err}")
        return False
    print("✓ Proxy created")
    
    # Test default mode (should be 'all')
    print("\n2. Checking default route mode...")
    resp = requests.get(f"{BASE_URL}/api/v1/proxy/targets/route-test.example.com/routes")
    data = resp.json()
    assert data['route_mode'] == 'all', f"Expected 'all', got {data['route_mode']}"
    print(f"✓ Default mode is 'all'")
    print(f"  Applicable routes: {len(data['applicable_routes'])}")
    
    # Switch to selective mode
    print("\n3. Switching to selective mode...")
    cmd = f'docker exec mcp-http-proxy-acme-certmanager-1 pixi run python scripts/proxy_routes_mode.py ' \
          f'route-test.example.com {ADMIN_TOKEN} selective'
    code, out, err = run_command(cmd)
    assert code == 0, f"Failed to set mode: {err}"
    print("✓ Switched to selective mode")
    
    # Verify no routes apply in selective mode (none enabled)
    resp = requests.get(f"{BASE_URL}/api/v1/proxy/targets/route-test.example.com/routes")
    data = resp.json()
    assert data['route_mode'] == 'selective'
    assert len(data['applicable_routes']) == 0, "Expected no routes in selective mode"
    print("✓ No routes apply in selective mode by default")
    
    # Switch to none mode
    print("\n4. Switching to none mode...")
    cmd = f'docker exec mcp-http-proxy-acme-certmanager-1 pixi run python scripts/proxy_routes_mode.py ' \
          f'route-test.example.com {ADMIN_TOKEN} none'
    code, out, err = run_command(cmd)
    assert code == 0, f"Failed to set mode: {err}"
    print("✓ Switched to none mode")
    
    # Verify no routes apply in none mode
    resp = requests.get(f"{BASE_URL}/api/v1/proxy/targets/route-test.example.com/routes")
    data = resp.json()
    assert data['route_mode'] == 'none'
    assert len(data['applicable_routes']) == 0, "Expected no routes in none mode"
    print("✓ No routes apply in none mode")
    
    # Clean up
    cmd = f'docker exec mcp-http-proxy-acme-certmanager-1 pixi run python scripts/proxy_delete.py ' \
          f'route-test.example.com {ADMIN_TOKEN} false 1'
    run_command(cmd)
    
    return True


def test_selective_routes():
    """Test enabling specific routes in selective mode."""
    print("\n=== Testing Selective Route Enabling ===")
    
    # Create proxy and set to selective mode
    print("\n1. Creating proxy in selective mode...")
    cmd = f'docker exec mcp-http-proxy-acme-certmanager-1 pixi run python scripts/proxy_create.py ' \
          f'selective-test.example.com http://backend:8080 {ADMIN_TOKEN} false true false true'
    run_command(cmd)
    
    cmd = f'docker exec mcp-http-proxy-acme-certmanager-1 pixi run python scripts/proxy_routes_mode.py ' \
          f'selective-test.example.com {ADMIN_TOKEN} selective'
    run_command(cmd)
    print("✓ Proxy created in selective mode")
    
    # Get available routes
    print("\n2. Getting available routes...")
    resp = requests.get(f"{BASE_URL}/api/v1/routes", 
                       headers={'Authorization': f'Bearer {ADMIN_TOKEN}'})
    all_routes = resp.json()
    
    # Find ACME challenge route
    acme_route = None
    for route in all_routes:
        if 'acme-challenge' in route['path_pattern']:
            acme_route = route
            break
    
    if not acme_route:
        print("! No ACME challenge route found")
        return False
    
    print(f"✓ Found ACME route: {acme_route['route_id']}")
    
    # Enable the ACME route
    print("\n3. Enabling ACME route...")
    cmd = f'docker exec mcp-http-proxy-acme-certmanager-1 pixi run python scripts/proxy_route_enable.py ' \
          f'selective-test.example.com {acme_route["route_id"]} {ADMIN_TOKEN}'
    code, out, err = run_command(cmd)
    assert code == 0, f"Failed to enable route: {err}"
    print("✓ Route enabled")
    
    # Verify route is now applicable
    resp = requests.get(f"{BASE_URL}/api/v1/proxy/targets/selective-test.example.com/routes")
    data = resp.json()
    assert acme_route['route_id'] in data['enabled_routes']
    assert len(data['applicable_routes']) == 1
    assert data['applicable_routes'][0]['route_id'] == acme_route['route_id']
    print("✓ Route is now applicable to proxy")
    
    # Clean up
    cmd = f'docker exec mcp-http-proxy-acme-certmanager-1 pixi run python scripts/proxy_delete.py ' \
          f'selective-test.example.com {ADMIN_TOKEN} false 1'
    run_command(cmd)
    
    return True


def test_disabled_routes():
    """Test disabling specific routes in all mode."""
    print("\n=== Testing Route Disabling in All Mode ===")
    
    # Create proxy (default all mode)
    print("\n1. Creating proxy in all mode...")
    cmd = f'docker exec mcp-http-proxy-acme-certmanager-1 pixi run python scripts/proxy_create.py ' \
          f'disable-test.example.com http://backend:8080 {ADMIN_TOKEN} false true false true'
    run_command(cmd)
    print("✓ Proxy created")
    
    # Get initial routes
    resp = requests.get(f"{BASE_URL}/api/v1/proxy/targets/disable-test.example.com/routes")
    initial_data = resp.json()
    initial_count = len(initial_data['applicable_routes'])
    print(f"✓ Initial applicable routes: {initial_count}")
    
    # Find a route to disable
    if initial_count > 0:
        route_to_disable = initial_data['applicable_routes'][0]
        print(f"\n2. Disabling route: {route_to_disable['route_id']}")
        
        cmd = f'docker exec mcp-http-proxy-acme-certmanager-1 pixi run python scripts/proxy_route_disable.py ' \
              f'disable-test.example.com {route_to_disable["route_id"]} {ADMIN_TOKEN}'
        code, out, err = run_command(cmd)
        assert code == 0, f"Failed to disable route: {err}"
        print("✓ Route disabled")
        
        # Verify route is disabled
        resp = requests.get(f"{BASE_URL}/api/v1/proxy/targets/disable-test.example.com/routes")
        data = resp.json()
        assert route_to_disable['route_id'] in data['disabled_routes']
        assert len(data['applicable_routes']) == initial_count - 1
        
        # Verify the disabled route is not in applicable routes
        applicable_ids = [r['route_id'] for r in data['applicable_routes']]
        assert route_to_disable['route_id'] not in applicable_ids
        print("✓ Route no longer applies to proxy")
    
    # Clean up
    cmd = f'docker exec mcp-http-proxy-acme-certmanager-1 pixi run python scripts/proxy_delete.py ' \
          f'disable-test.example.com {ADMIN_TOKEN} false 1'
    run_command(cmd)
    
    return True


def test_bulk_route_set():
    """Test setting multiple routes at once."""
    print("\n=== Testing Bulk Route Setting ===")
    
    # Create proxy
    print("\n1. Creating proxy...")
    cmd = f'docker exec mcp-http-proxy-acme-certmanager-1 pixi run python scripts/proxy_create.py ' \
          f'bulk-test.example.com http://backend:8080 {ADMIN_TOKEN} false true false true'
    run_command(cmd)
    
    # Get available routes
    resp = requests.get(f"{BASE_URL}/api/v1/routes", 
                       headers={'Authorization': f'Bearer {ADMIN_TOKEN}'})
    all_routes = resp.json()
    
    if len(all_routes) >= 2:
        # Switch to selective mode and enable multiple routes
        print("\n2. Setting selective mode with multiple routes...")
        cmd = f'docker exec mcp-http-proxy-acme-certmanager-1 pixi run python scripts/proxy_routes_mode.py ' \
              f'bulk-test.example.com {ADMIN_TOKEN} selective'
        run_command(cmd)
        
        # Enable first two routes
        route_ids = f"{all_routes[0]['route_id']},{all_routes[1]['route_id']}"
        cmd = f'docker exec mcp-http-proxy-acme-certmanager-1 pixi run python scripts/proxy_routes_set.py ' \
              f'bulk-test.example.com {ADMIN_TOKEN} "{route_ids}" ""'
        code, out, err = run_command(cmd)
        assert code == 0, f"Failed to set routes: {err}"
        print("✓ Multiple routes enabled")
        
        # Verify
        resp = requests.get(f"{BASE_URL}/api/v1/proxy/targets/bulk-test.example.com/routes")
        data = resp.json()
        assert len(data['enabled_routes']) == 2
        assert len(data['applicable_routes']) == 2
        print("✓ Both routes are applicable")
    
    # Clean up
    cmd = f'docker exec mcp-http-proxy-acme-certmanager-1 pixi run python scripts/proxy_delete.py ' \
          f'bulk-test.example.com {ADMIN_TOKEN} false 1'
    run_command(cmd)
    
    return True


def main():
    """Run all tests."""
    if not ADMIN_TOKEN:
        print("Error: ADMIN_TOKEN not set")
        sys.exit(1)
    
    print("Starting per-proxy route tests...")
    
    tests = [
        ("Route Modes", test_route_modes),
        ("Selective Routes", test_selective_routes),
        ("Disabled Routes", test_disabled_routes),
        ("Bulk Route Set", test_bulk_route_set)
    ]
    
    results = []
    for name, test_func in tests:
        try:
            success = test_func()
            results.append([name, "✓ PASSED" if success else "✗ FAILED"])
        except Exception as e:
            print(f"\nError in {name}: {e}")
            results.append([name, f"✗ ERROR: {str(e)[:50]}"])
    
    # Summary
    print("\n" + "="*50)
    print("TEST SUMMARY")
    print("="*50)
    print(tabulate(results, headers=["Test", "Result"]))
    
    # Overall result
    failed = sum(1 for _, result in results if "✗" in result)
    if failed == 0:
        print("\n✓ All tests passed!")
        return 0
    else:
        print(f"\n✗ {failed} tests failed")
        return 1


if __name__ == "__main__":
    sys.exit(main())