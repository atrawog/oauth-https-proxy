#!/usr/bin/env python3
"""Test that both old and new API v1 paths work correctly."""

import os
import sys
import requests
from typing import List, Tuple

# Get configuration from environment
API_URL = os.environ.get('API_URL', 'http://localhost:80')
TOKEN = os.environ.get('ADMIN_TOKEN', 'acme')

# Test endpoints - old path and new path
ENDPOINTS_TO_TEST = [
    # (old_path, new_path, method, requires_auth)
    ("/certificates/", "/api/v1/certificates/", "GET", True),
    ("/proxy/targets/", "/api/v1/proxy/targets/", "GET", True),
    ("/tokens/", "/api/v1/tokens/", "GET", True),
    ("/routes/", "/api/v1/routes/", "GET", False),
    ("/instances/", "/api/v1/instances/", "GET", True),
    ("/resources/", "/api/v1/resources/", "GET", False),
    ("/oauth/clients", "/api/v1/oauth/clients", "GET", False),
    ("/health", "/health", "GET", False),  # Should remain at root
]

def test_endpoint(path: str, method: str, requires_auth: bool) -> Tuple[bool, str]:
    """Test a single endpoint."""
    try:
        headers = {}
        if requires_auth:
            headers["Authorization"] = f"Bearer {TOKEN}"
        
        url = f"{API_URL}{path}"
        
        if method == "GET":
            response = requests.get(url, headers=headers)
        else:
            raise ValueError(f"Unsupported method: {method}")
        
        # Check if response is successful (2xx) or expected error (401 for auth required)
        if response.status_code < 300:
            return True, f"Success ({response.status_code})"
        elif response.status_code == 401 and requires_auth and not headers.get("Authorization"):
            return True, "Auth required (401)"
        else:
            return False, f"Failed ({response.status_code}): {response.text[:100]}"
            
    except requests.exceptions.ConnectionError:
        return False, "Connection failed"
    except Exception as e:
        return False, str(e)

def main():
    """Run all tests."""
    print(f"Testing API v1 migration...")
    print(f"Base URL: {API_URL}")
    print(f"Using token: {'Yes' if TOKEN else 'No'}")
    print("-" * 80)
    
    all_passed = True
    results = []
    
    # Test each endpoint pair
    for old_path, new_path, method, requires_auth in ENDPOINTS_TO_TEST:
        print(f"\nTesting: {old_path} → {new_path}")
        
        # Test old path
        old_success, old_msg = test_endpoint(old_path, method, requires_auth)
        print(f"  Old path ({old_path}): {'✓' if old_success else '✗'} {old_msg}")
        
        # Test new path (skip if it's the same as old)
        if new_path != old_path:
            new_success, new_msg = test_endpoint(new_path, method, requires_auth)
            print(f"  New path ({new_path}): {'✓' if new_success else '✗'} {new_msg}")
        else:
            new_success = old_success
            print(f"  New path: N/A (root endpoint)")
        
        # Both should work for backwards compatibility
        if not (old_success and new_success):
            all_passed = False
            results.append(f"FAILED: {old_path}")
        else:
            results.append(f"PASSED: {old_path}")
    
    # Test OAuth protocol endpoints (should remain at root)
    print("\n" + "-" * 80)
    print("Testing OAuth protocol endpoints (should remain at root):")
    
    oauth_endpoints = [
        "/authorize",
        "/token", 
        "/verify",
        "/.well-known/oauth-authorization-server",
        "/jwks"
    ]
    
    for endpoint in oauth_endpoints:
        success, msg = test_endpoint(endpoint, "GET", False)
        print(f"  {endpoint}: {'✓' if success else '✗'} {msg}")
        if endpoint.startswith("/.well-known") or endpoint == "/jwks":
            # These should return 200
            if not success or "200" not in msg:
                all_passed = False
        # Other OAuth endpoints may require proper requests
    
    # Summary
    print("\n" + "=" * 80)
    print("SUMMARY:")
    print("-" * 80)
    for result in results:
        print(f"  {result}")
    
    if all_passed:
        print("\n✓ All tests passed! Both old and new API paths are working.")
        return 0
    else:
        print("\n✗ Some tests failed. Please check the implementation.")
        return 1

if __name__ == "__main__":
    sys.exit(main())