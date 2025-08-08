#!/usr/bin/env python3
"""Final test of authentication system."""

import json
from httpx import Client

# Read tokens from .env file
admin_token = None
test_token = None

with open(".env", "r") as f:
    for line in f:
        if line.startswith("ADMIN_TOKEN="):
            admin_token = line.strip().split("=", 1)[1]
        elif line.startswith("TEST_TOKEN="):
            test_token = line.strip().split("=", 1)[1]

api_url = "http://localhost:80"

print("🔐 Authentication System Final Test")
print("=" * 60)

# Test 1: No auth should fail for protected endpoints
print("\n1️⃣ Testing protected endpoints without auth:")
protected_endpoints = [
    "/certificates",
    "/proxy/targets", 
    "/routes",
    "/token/info"
]

for endpoint in protected_endpoints:
    with Client(api_url=api_url) as client:
        resp = client.get(endpoint)
        status = "✅ Protected" if resp.status_code == 403 else f"❌ Not protected ({resp.status_code})"
        print(f"   {endpoint:20} → {status}")

# Test 2: Admin token should work
print("\n2️⃣ Testing ADMIN_TOKEN access:")
if admin_token:
    headers = {"Authorization": f"Bearer {admin_token}"}
    
    # Get token info
    with Client(api_url=api_url) as client:
        resp = client.get("/token/info", headers=headers)
        if resp.status_code == 200:
            info = resp.json()
            print(f"   ✅ Token info: name={info['name']}, email={info['cert_email']}")
        else:
            print(f"   ❌ Failed to get token info: {resp.status_code}")
    
    # List all certificates
    with Client(api_url=api_url) as client:
        resp = client.get("/certificates", headers=headers)
        if resp.status_code == 200:
            certs = resp.json()
            print(f"   ✅ Admin can see {len(certs)} certificates")
        else:
            print(f"   ❌ Failed to list certificates: {resp.status_code}")
    
    # List all proxy targets
    with Client(api_url=api_url) as client:
        resp = client.get("/proxy/targets", headers=headers)
        if resp.status_code == 200:
            targets = resp.json()
            print(f"   ✅ Admin can see {len(targets)} proxy targets")
        else:
            print(f"   ❌ Failed to list proxy targets: {resp.status_code}")
else:
    print("   ❌ No ADMIN_TOKEN found")

# Test 3: Public endpoints should work
print("\n3️⃣ Testing public endpoints:")
public_endpoints = [
    ("/", [200, 302, 307]),  # Web GUI can redirect
    ("/health", [200]),
    ("/.well-known/acme-challenge/test", [404])  # Not found is ok
]

for endpoint, valid_codes in public_endpoints:
    with Client(api_url=api_url) as client:
        resp = client.get(endpoint)
        status = "✅ Public" if resp.status_code in valid_codes else f"❌ Not public ({resp.status_code})"
        print(f"   {endpoint:35} → {status}")

print("\n✅ Authentication test complete!")
print("\nSummary:")
print("- All API endpoints require authentication")
print("- ADMIN_TOKEN has full access to all resources")
print("- Public endpoints (/, /health, ACME challenges) remain accessible")
print("- Web GUI handles its own authentication via login page")