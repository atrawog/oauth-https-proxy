#!/usr/bin/env python3
"""Test that old endpoints are removed and only v1 endpoints work."""

import os
import requests

BASE_URL = os.environ.get('BASE_URL', 'http://localhost:80')
TOKEN = os.environ.get('ADMIN_TOKEN', 'acm_rYq7mL2Gzh95YgpIiGxjfig4t4swu37UaWrUgLhbDQY')

def test_endpoint(path, expected_status=None):
    """Test an endpoint and return status code."""
    try:
        headers = {"Authorization": f"Bearer {TOKEN}"}
        response = requests.get(f"{BASE_URL}{path}", headers=headers)
        return response.status_code, response.text[:100] if response.text else ""
    except Exception as e:
        return 0, str(e)

print("Testing API v1 Migration Complete")
print("=" * 60)

# Test old endpoints should return 404
old_endpoints = [
    "/certificates/",
    "/proxy/targets/", 
    "/tokens/",
    "/routes/",
    "/instances/",
    "/resources/"
]

print("\n1. Testing old endpoints (should be 404 or 502):")
all_old_removed = True
for endpoint in old_endpoints:
    status, msg = test_endpoint(endpoint)
    # Accept 404 (not found) or 502 (proxy error - no target) as "removed"
    is_removed = status in [404, 502]
    print(f"  {endpoint:<25} {status} {'✓' if is_removed else '✗'}")
    if not is_removed:
        all_old_removed = False
        print(f"    Response: {msg}")

# Test new endpoints should work
new_endpoints = [
    "/api/v1/certificates/",
    "/api/v1/proxy/targets/",
    "/api/v1/tokens/",
    "/api/v1/routes/",
    "/api/v1/instances/",
    "/api/v1/resources/"
]

print("\n2. Testing new v1 endpoints (should be 200):")
all_new_work = True
for endpoint in new_endpoints:
    status, msg = test_endpoint(endpoint)
    is_success = status == 200
    print(f"  {endpoint:<35} {status} {'✓' if is_success else '✗'}")
    if not is_success:
        all_new_work = False
        print(f"    Response: {msg}")

# Test OAuth protocol endpoints remain at root
print("\n3. Testing OAuth protocol endpoints (should remain at root):")
oauth_endpoints = [
    ("/.well-known/oauth-authorization-server", 200),
    ("/jwks", 200),
    ("/health", 200)
]

all_oauth_work = True
for endpoint, expected in oauth_endpoints:
    status, msg = test_endpoint(endpoint)
    is_expected = status == expected
    print(f"  {endpoint:<45} {status} {'✓' if is_expected else '✗'}")
    if not is_expected:
        all_oauth_work = False

# Summary
print("\n" + "=" * 60)
print("SUMMARY:")
print(f"  Old endpoints removed: {'✓' if all_old_removed else '✗'}")
print(f"  New v1 endpoints working: {'✓' if all_new_work else '✗'}")
print(f"  OAuth endpoints at root: {'✓' if all_oauth_work else '✗'}")

if all_old_removed and all_new_work and all_oauth_work:
    print("\n✓ Migration complete! All old endpoints removed, v1 endpoints working.")
    exit(0)
else:
    print("\n✗ Migration incomplete. Check the results above.")
    exit(1)