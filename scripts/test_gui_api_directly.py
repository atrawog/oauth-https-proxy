#!/usr/bin/env python3
"""Test GUI API endpoints directly."""

import requests

print("=== TESTING GUI API ENDPOINTS ===\n")

BASE_URL = "https://gui.atradev.org"
ADMIN_TOKEN = "acm_PikI3FoqDXghOEHdP9lf9wcf0zlEdK2AV9DvPinF-Us"

headers = {
    "Authorization": f"Bearer {ADMIN_TOKEN}",
    "Accept": "application/json"
}

# Test 1: Static files
print("1. Testing static file access:")
response = requests.get(f"{BASE_URL}/", verify=False)
print(f"   GET / -> Status: {response.status_code}")
print(f"   Content-Type: {response.headers.get('content-type', 'Unknown')}")
print(f"   Has HTML: {'<html' in response.text.lower()}")

# Test 2: API endpoint - Health
print("\n2. Testing /health endpoint:")
response = requests.get(f"{BASE_URL}/health", verify=False)
print(f"   GET /health -> Status: {response.status_code}")
if response.status_code == 200:
    print(f"   Response: {response.json()}")

# Test 3: API endpoint - Token info
print("\n3. Testing /token/info endpoint:")
try:
    response = requests.get(f"{BASE_URL}/token/info", headers=headers, verify=False, timeout=5)
    print(f"   GET /token/info -> Status: {response.status_code}")
    if response.status_code == 200:
        print(f"   Response: {response.json()}")
except requests.exceptions.Timeout:
    print("   ❌ Request timed out!")
except Exception as e:
    print(f"   ❌ Error: {e}")

# Test 4: API endpoint - Certificates
print("\n4. Testing /certificates endpoint:")
try:
    response = requests.get(f"{BASE_URL}/api/v1/certificates", headers=headers, verify=False, timeout=5)
    print(f"   GET /certificates -> Status: {response.status_code}")
    if response.status_code == 200:
        certs = response.json()
        print(f"   Number of certificates: {len(certs)}")
except requests.exceptions.Timeout:
    print("   ❌ Request timed out!")
except Exception as e:
    print(f"   ❌ Error: {e}")

# Test 5: Check if it's a redirect issue
print("\n5. Testing redirect behavior:")
response = requests.get(f"{BASE_URL}/api/v1/certificates", headers=headers, verify=False, allow_redirects=False)
print(f"   GET /certificates (no redirects) -> Status: {response.status_code}")
if response.status_code in [301, 302, 303, 307, 308]:
    print(f"   Redirects to: {response.headers.get('Location', 'Unknown')}")

print("\n6. ANALYSIS:")
print("   If static files work but API calls fail/timeout:")
print("   → The proxy is not forwarding API requests correctly")
print("   → Or there's a routing issue for non-static paths")