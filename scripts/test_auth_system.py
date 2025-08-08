#!/usr/bin/env python3
"""Test the authentication system with regular tokens and ADMIN_TOKEN."""

import os
import json
from httpx import Client

# Environment already loaded by just
api_url = os.environ.get("API_URL", "http://localhost:80")
admin_token = os.environ.get("ADMIN_TOKEN")
test_token = os.environ.get("TEST_TOKEN")

# If env vars not loaded, check .env file
if not admin_token or not test_token:
    try:
        with open(".env", "r") as f:
            for line in f:
                if line.startswith("ADMIN_TOKEN="):
                    admin_token = line.strip().split("=", 1)[1]
                elif line.startswith("TEST_TOKEN="):
                    test_token = line.strip().split("=", 1)[1]
    except:
        pass

print(f"🔐 Testing Authentication System")
print(f"=" * 60)
print(f"Base URL: {api_url}")
print(f"Admin Token: {admin_token[:20]}..." if admin_token else "No admin token!")
print(f"Test Token: {test_token[:20]}..." if test_token else "No test token!")
print()

# Test endpoints
test_endpoints = [
    ("GET", "/"),  # Web GUI - should be public
    ("GET", "/health"),  # Health check - should be public
    ("GET", "/.well-known/acme-challenge/test"),  # ACME - must be public
    ("GET", "/certificates"),  # Should require auth
    ("GET", "/certificates/test/status"),  # Should require auth
    ("GET", "/certificates/test"),  # Should require auth
    ("GET", "/proxy/targets"),  # Should require auth
    ("GET", "/proxy/targets/test.example.com"),  # Should require auth
    ("GET", "/routes"),  # Should require auth
    ("GET", "/routes/test"),  # Should require auth
    ("GET", "/token/info"),  # Should require auth
]

def test_endpoint(method, path, token=None):
    """Test an endpoint with optional authentication."""
    headers = {}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    
    with Client(api_url=api_url) as client:
        try:
            response = getattr(client, method.lower())(path, headers=headers)
            return response.status_code, response.text[:100] if response.text else "Empty"
        except Exception as e:
            return "Error", str(e)

print("🧪 Testing endpoints without authentication:")
print("-" * 60)
for method, path in test_endpoints:
    status, body = test_endpoint(method, path)
    if path in ["/", "/health", "/.well-known/acme-challenge/test"]:
        expected = "✅ (public endpoint)" if status in [200, 302, 404] else "❌ (should be public!)"
    else:
        expected = "✅ (protected)" if status == 403 else "❌ (should be protected!)"
    print(f"{method:6} {path:40} → {status:3} {expected}")

print()
print("🧪 Testing endpoints with TEST_TOKEN:")
print("-" * 60)
if test_token:
    for method, path in test_endpoints:
        if path not in ["/", "/health", "/.well-known/acme-challenge/test"]:
            status, body = test_endpoint(method, path, test_token)
            expected = "✅" if status in [200, 404] else "❌"
            print(f"{method:6} {path:40} → {status:3} {expected}")
else:
    print("⚠️  No TEST_TOKEN available")

print()
print("🧪 Testing endpoints with ADMIN_TOKEN:")
print("-" * 60)
if admin_token:
    for method, path in test_endpoints:
        if path not in ["/", "/health", "/.well-known/acme-challenge/test"]:
            status, body = test_endpoint(method, path, admin_token)
            expected = "✅" if status in [200, 404] else "❌"
            print(f"{method:6} {path:40} → {status:3} {expected}")
    
    # Test admin-specific access
    print()
    print("🧪 Testing ADMIN_TOKEN special access:")
    print("-" * 60)
    
    # Get all certificates (admin should see all)
    with Client(api_url=api_url) as client:
        response = client.get("/certificates", headers={"Authorization": f"Bearer {admin_token}"})
        if response.status_code == 200:
            certs = response.json()
            print(f"✅ Admin can see {len(certs)} certificates (all certificates)")
        else:
            print(f"❌ Failed to list certificates: {response.status_code}")
    
    # Get token info
    with Client(api_url=api_url) as client:
        response = client.get("/token/info", headers={"Authorization": f"Bearer {admin_token}"})
        if response.status_code == 200:
            info = response.json()
            print(f"✅ Admin token info: name={info.get('name')}, email={info.get('cert_email')}")
        else:
            print(f"❌ Failed to get token info: {response.status_code}")
else:
    print("⚠️  No ADMIN_TOKEN available")

print()
print("✅ Authentication system test complete!")