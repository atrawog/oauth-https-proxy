#!/usr/bin/env python3
"""Ultimate GUI debugging - simulate exactly what happens in the browser."""

import requests
import json

print("=== ULTIMATE GUI DEBUG ===\n")

# Step 1: Load the GUI page
print("STEP 1: Loading GUI page")
response = requests.get("https://gui.atradev.org/", verify=False)
print(f"Status: {response.status_code}")
print(f"Page contains 'certificates-list' div: {'certificates-list' in response.text}")
print(f"Page contains app.js script: {'app.js' in response.text}")

# Step 2: Check what app.js contains
print("\nSTEP 2: Checking app.js")
response = requests.get("https://gui.atradev.org/static/app.js", verify=False)
print(f"Status: {response.status_code}")
print(f"Contains loadCertificates function: {'loadCertificates' in response.text}")
print(f"Contains ownership code: {'ownership-banner' in response.text}")

# Step 3: Simulate exact API calls the JavaScript makes
print("\nSTEP 3: Simulating JavaScript API calls")
token = "acm_PikI3FoqDXghOEHdP9lf9wcf0zlEdK2AV9DvPinF-Us"
headers = {"Authorization": f"Bearer {token}"}

# 3.1: Token info (called during login)
print("\n3.1. POST login simulation:")
response = requests.get("https://gui.atradev.org/token/info", headers=headers, verify=False)
print(f"   /token/info status: {response.status_code}")
if response.status_code == 200:
    token_info = response.json()
    print(f"   Token name: {token_info['name']}")
    print(f"   Is ADMIN: {token_info['name'] == 'ADMIN'}")

# 3.2: Certificates (called by loadCertificates)
print("\n3.2. GET /certificates:")
response = requests.get("https://gui.atradev.org/certificates", headers=headers, verify=False)
print(f"   Status: {response.status_code}")
if response.status_code == 200:
    certs = response.json()
    print(f"   Number returned: {len(certs)}")
    if certs:
        print(f"   First cert: {certs[0]['cert_name']}")
        
# 3.3: Proxies
print("\n3.3. GET /proxy/targets:")
response = requests.get("https://gui.atradev.org/proxy/targets", headers=headers, verify=False)
print(f"   Status: {response.status_code}")
if response.status_code == 200:
    proxies = response.json()
    print(f"   Number returned: {len(proxies)}")
    
# 3.4: Routes
print("\n3.4. GET /routes:")
response = requests.get("https://gui.atradev.org/routes", headers=headers, verify=False)
print(f"   Status: {response.status_code}")
if response.status_code == 200:
    routes = response.json()
    print(f"   Number returned: {len(routes)}")

print("\n" + "="*50)
print("CONCLUSION:")
print("If all API calls return data but GUI shows empty:")
print("1. Check browser console for JavaScript errors")
print("2. Check if certificates-list innerHTML is being set")
print("3. Use browser DevTools to debug loadCertificates()")
print("4. Check if there's a race condition in the code")
print("\nTo debug in browser:")
print("1. Open https://gui.atradev.org/")
print("2. Open DevTools (F12)")
print("3. Go to Console tab")
print("4. Type: api.getCertificates().then(d => console.log(d))")
print("5. Check what data is returned")
print("="*50)