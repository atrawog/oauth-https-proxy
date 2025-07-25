#!/usr/bin/env python3
"""Debug what's happening with the GUI when ADMIN logs in."""

import requests
import json

print("=== DEBUGGING GUI ISSUE ===\n")

# Get ADMIN token from environment or use known value
ADMIN_TOKEN = "acm_PikI3FoqDXghOEHdP9lf9wcf0zlEdK2AV9DvPinF-Us"
BASE_URL = "http://localhost"

print("1. Testing ADMIN token directly:")
headers = {"Authorization": f"Bearer {ADMIN_TOKEN}"}

# Test token info
response = requests.get(f"{BASE_URL}/token/info", headers=headers)
print(f"   Token info status: {response.status_code}")
if response.status_code == 200:
    info = response.json()
    print(f"   Response: {json.dumps(info, indent=2)}")
    
# Test certificates endpoint
print("\n2. Testing /certificates endpoint with ADMIN token:")
response = requests.get(f"{BASE_URL}/api/v1/certificates", headers=headers)
print(f"   Status: {response.status_code}")
if response.status_code == 200:
    certs = response.json()
    print(f"   Number of certificates returned: {len(certs)}")
    if certs:
        print("   First certificate:")
        print(f"     - Name: {certs[0].get('cert_name')}")
        print(f"     - Domains: {certs[0].get('domains')}")
        print(f"     - Status: {certs[0].get('status')}")

# Test proxies endpoint
print("\n3. Testing /proxy/targets endpoint with ADMIN token:")
response = requests.get(f"{BASE_URL}/api/v1/proxy/targets", headers=headers)
print(f"   Status: {response.status_code}")
if response.status_code == 200:
    proxies = response.json()
    print(f"   Number of proxies returned: {len(proxies)}")
    if proxies:
        print("   First proxy:")
        print(f"     - Hostname: {proxies[0].get('hostname')}")
        print(f"     - Target: {proxies[0].get('target_url')}")

# Test routes endpoint
print("\n4. Testing /routes endpoint with ADMIN token:")
response = requests.get(f"{BASE_URL}/api/v1/routes", headers=headers)
print(f"   Status: {response.status_code}")
if response.status_code == 200:
    routes = response.json()
    print(f"   Number of routes returned: {len(routes)}")

print("\n5. ANALYSIS:")
print("   - If ADMIN sees 0 certificates/proxies in the GUI but the API returns 4/5:")
print("     → The GUI JavaScript might be filtering incorrectly")
print("     → Check browser console for JavaScript errors")
print("     → Try hard refresh (Ctrl+Shift+R) to clear cache")
print("   - If ADMIN sees all resources in the GUI:")
print("     → The GUI is working correctly")
print("     → The issue might be user confusion about the UI")

print("\n6. To test in browser:")
print(f"   1. Go to https://gui.atradev.org/")
print(f"   2. Enter token: {ADMIN_TOKEN}")
print(f"   3. Click Login")
print(f"   4. Check if header shows 'Authenticated as: ADMIN'")
print(f"   5. Check if Certificates tab shows 4 certificates")
print(f"   6. Open browser console (F12) and check for errors")