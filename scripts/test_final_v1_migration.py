#!/usr/bin/env python3
"""Final test to verify API v1 migration is complete and working."""

import os
import requests

API_URL = os.environ.get('API_URL', 'http://localhost:80')
TOKEN = os.environ.get('ADMIN_TOKEN', 'acm_rYq7mL2Gzh95YgpIiGxjfig4t4swu37UaWrUgLhbDQY')

print("Final API v1 Migration Test")
print("=" * 60)

# Test a few key operations
headers = {"Authorization": f"Bearer {TOKEN}"}

tests = [
    ("List tokens", "GET", "/api/v1/tokens/"),
    ("List certificates", "GET", "/api/v1/certificates/"),
    ("List proxies", "GET", "/api/v1/proxy/targets/"),
    ("List routes", "GET", "/api/v1/routes/"),
    ("Get health", "GET", "/health"),
    ("Get OAuth metadata", "GET", "/.well-known/oauth-authorization-server"),
]

all_pass = True

for name, method, path in tests:
    try:
        if method == "GET":
            response = requests.get(f"{API_URL}{path}", headers=headers if "api/v1" in path else {})
        
        if response.status_code == 200:
            print(f"✓ {name:<20} {path:<45} OK")
        else:
            print(f"✗ {name:<20} {path:<45} {response.status_code}")
            all_pass = False
    except Exception as e:
        print(f"✗ {name:<20} {path:<45} ERROR: {e}")
        all_pass = False

# Test that old paths don't work
print("\nVerifying old paths are removed:")
old_paths = ["/tokens/", "/certificates/", "/proxy/targets/", "/routes/"]

for path in old_paths:
    try:
        response = requests.get(f"{API_URL}{path}", headers=headers)
        if response.status_code in [404, 502]:
            print(f"✓ {path:<30} Removed ({response.status_code})")
        else:
            print(f"✗ {path:<30} Still exists ({response.status_code})")
            all_pass = False
    except Exception as e:
        print(f"? {path:<30} ERROR: {e}")

print("\n" + "=" * 60)
if all_pass:
    print("✓ All tests passed! API v1 migration is complete.")
else:
    print("✗ Some tests failed. Check the results above.")

exit(0 if all_pass else 1)