#!/usr/bin/env python3
"""Test the Settings tab flow step by step."""

import requests
import json

BASE_URL = "http://localhost:80"
TOKEN = "acm_e5AGpHJd2qxWocqBn6lXDBV_6AvD02R-A6AhdmSK8uA"

print("="*60)
print("Testing Settings Tab Flow")
print("="*60)

# Step 1: Test direct API call
print("\n1. Testing direct API call to /token/info")
headers = {"Authorization": f"Bearer {TOKEN}"}
response = requests.get(f"{BASE_URL}/token/info", headers=headers)
print(f"   Status: {response.status_code}")
if response.status_code == 200:
    print(f"   Response: {json.dumps(response.json(), indent=2)}")
else:
    print(f"   Error: {response.text}")

# Step 2: Test without Bearer prefix (common JS mistake)
print("\n2. Testing without 'Bearer' prefix")
headers2 = {"Authorization": TOKEN}
response2 = requests.get(f"{BASE_URL}/token/info", headers=headers2)
print(f"   Status: {response2.status_code}")
print(f"   Expected: 403 (Not authenticated)")

# Step 3: Test with malformed header
print("\n3. Testing with lowercase 'bearer'")
headers3 = {"Authorization": f"bearer {TOKEN}"}
response3 = requests.get(f"{BASE_URL}/token/info", headers=headers3)
print(f"   Status: {response3.status_code}")

# Step 4: Test with no auth
print("\n4. Testing with no authorization header")
response4 = requests.get(f"{BASE_URL}/token/info")
print(f"   Status: {response4.status_code}")
print(f"   Expected: 403 (Not authenticated)")

# Step 5: Check if token exists in storage
print("\n5. Checking token in storage (via debug endpoint)")
response5 = requests.get(f"{BASE_URL}/certificates", headers=headers)
print(f"   Can access protected endpoint: {response5.status_code == 200}")

print("\n" + "="*60)
print("CONCLUSION:")
if response.status_code == 200:
    print("✅ API endpoint works correctly with proper authorization")
    print("❌ Issue is likely in the JavaScript frontend")
    print("\nPossible JavaScript issues:")
    print("- Token not being stored correctly in localStorage")
    print("- Token being cleared before Settings tab is clicked")
    print("- Authorization header not being sent properly")
else:
    print("❌ API endpoint has issues")
    
print("="*60)