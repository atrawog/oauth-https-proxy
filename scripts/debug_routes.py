#!/usr/bin/env python3
"""Debug routes endpoint."""

import os
import requests

# Read .env file
with open(".env", "r") as f:
    for line in f:
        if line.startswith("ADMIN_TOKEN="):
            admin_token = line.strip().split("=", 1)[1]
            break

base_url = "http://localhost:80"

print(f"Admin token: {admin_token[:20]}...")
print(f"Base URL: {base_url}")

# Test without auth
print("\n1. Testing /routes without auth:")
resp = requests.get(f"{base_url}/routes")
print(f"   Status: {resp.status_code}")
print(f"   Body: {resp.text[:100]}...")

# Test with auth
print("\n2. Testing /routes with admin token:")
headers = {"Authorization": f"Bearer {admin_token}"}
resp = requests.get(f"{base_url}/routes", headers=headers)
print(f"   Status: {resp.status_code}")
if resp.status_code == 200:
    routes = resp.json()
    print(f"   Success! Found {len(routes)} routes")
else:
    print(f"   Body: {resp.text[:200]}...")

# Test token info endpoint to verify token works
print("\n3. Testing /token/info with admin token:")
resp = requests.get(f"{base_url}/token/info", headers=headers)
print(f"   Status: {resp.status_code}")
if resp.status_code == 200:
    info = resp.json()
    print(f"   Token name: {info.get('name')}")
    print(f"   Token email: {info.get('cert_email')}")
else:
    print(f"   Body: {resp.text[:200]}...")