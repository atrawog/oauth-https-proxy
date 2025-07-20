#!/usr/bin/env python3
"""Simulate EXACTLY what happens when using the GUI in a browser."""

import requests
import json

# Use session to maintain cookies like a browser
session = requests.Session()
session.verify = False  # Ignore SSL warnings

GUI_URL = "https://gui.atradev.org"
ADMIN_TOKEN = "acm_PikI3FoqDXghOEHdP9lf9wcf0zlEdK2AV9DvPinF-Us"

print("=== SIMULATING BROWSER GUI USAGE ===\n")

# Step 1: Load the main page
print("STEP 1: User navigates to https://gui.atradev.org/")
response = session.get(f"{GUI_URL}/")
print(f"Status: {response.status_code}")
print(f"Page title found: {'MCP Proxy Manager' in response.text}")

# Step 2: User enters token and clicks login
print("\nSTEP 2: User enters ADMIN token and clicks Login")
print(f"Token: {ADMIN_TOKEN}")

# The JavaScript would make these calls:
# First, test the token
print("\nSTEP 3: JavaScript tests the token (api.getCertificates)")
headers = {"Authorization": f"Bearer {ADMIN_TOKEN}"}
try:
    response = session.get(f"{GUI_URL}/certificates", headers=headers)
    print(f"GET /certificates - Status: {response.status_code}")
    if response.status_code != 200:
        print(f"Response: {response.text}")
except Exception as e:
    print(f"ERROR: {e}")

# Then get token info
print("\nSTEP 4: JavaScript gets token info")
try:
    response = session.get(f"{GUI_URL}/token/info", headers=headers)
    print(f"GET /token/info - Status: {response.status_code}")
    if response.status_code == 200:
        token_info = response.json()
        print(f"Token name: {token_info.get('name')}")
        print(f"Token email: {token_info.get('cert_email')}")
except Exception as e:
    print(f"ERROR: {e}")

# Step 5: JavaScript loads certificates (default tab)
print("\nSTEP 5: JavaScript loads certificates (loadCertificates)")
try:
    response = session.get(f"{GUI_URL}/certificates", headers=headers)
    print(f"GET /certificates - Status: {response.status_code}")
    if response.status_code == 200:
        certs = response.json()
        print(f"Certificates returned: {len(certs)}")
        if len(certs) > 0:
            print("\nCertificates found:")
            for cert in certs:
                print(f"  - {cert['cert_name']}: {', '.join(cert['domains'])}")
        else:
            print("NO CERTIFICATES RETURNED!")
    else:
        print(f"ERROR: Status {response.status_code}")
        print(f"Response: {response.text}")
except Exception as e:
    print(f"ERROR: {e}")

# Step 6: User clicks Proxies tab
print("\nSTEP 6: User clicks Proxies tab (loadProxyTargets)")
try:
    response = session.get(f"{GUI_URL}/proxy/targets", headers=headers)
    print(f"GET /proxy/targets - Status: {response.status_code}")
    if response.status_code == 200:
        proxies = response.json()
        print(f"Proxies returned: {len(proxies)}")
        if len(proxies) > 0:
            print("\nProxies found:")
            for proxy in proxies:
                print(f"  - {proxy['hostname']} -> {proxy['target_url']}")
        else:
            print("NO PROXIES RETURNED!")
    else:
        print(f"ERROR: Status {response.status_code}")
        print(f"Response: {response.text}")
except Exception as e:
    print(f"ERROR: {e}")

# Step 7: User clicks Routes tab
print("\nSTEP 7: User clicks Routes tab (loadRoutes)")
try:
    response = session.get(f"{GUI_URL}/routes", headers=headers)
    print(f"GET /routes - Status: {response.status_code}")
    if response.status_code == 200:
        routes = response.json()
        print(f"Routes returned: {len(routes)}")
        if len(routes) > 0:
            print("\nRoutes found:")
            for route in routes:
                print(f"  - {route['path_pattern']} -> {route['target_type']}:{route['target_value']} (priority: {route['priority']})")
        else:
            print("NO ROUTES RETURNED!")
    else:
        print(f"ERROR: Status {response.status_code}")
        print(f"Response: {response.text}")
except Exception as e:
    print(f"ERROR: {e}")

print("\n" + "="*60)
print("SUMMARY:")
print("This is EXACTLY what the browser JavaScript sees.")
print("If any of the above failed or returned empty, that's the problem.")
print("="*60)