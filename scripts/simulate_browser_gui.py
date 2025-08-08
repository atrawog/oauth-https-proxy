#!/usr/bin/env python3
"""Simulate exactly what happens in the browser when using the GUI."""

import requests
import json

print("=== SIMULATING BROWSER GUI BEHAVIOR ===\n")

ADMIN_TOKEN = "acm_PikI3FoqDXghOEHdP9lf9wcf0zlEdK2AV9DvPinF-Us"
API_URL = "http://localhost"

print("STEP 1: User goes to https://gui.atradev.org/")
print("        Browser loads index.html and app.js")

print("\nSTEP 2: User enters ADMIN token and clicks Login")
print(f"        Token: {ADMIN_TOKEN}")

print("\nSTEP 3: JavaScript calls /token/info")
headers = {"Authorization": f"Bearer {ADMIN_TOKEN}"}
response = requests.get(f"{API_URL}/token/info", headers=headers)
if response.status_code == 200:
    token_info = response.json()
    print(f"        Response: {json.dumps(token_info, indent=2)}")
    print(f"        → currentTokenInfo.name = '{token_info['name']}'")
    print(f"        → Is ADMIN? {token_info['name'] == 'ADMIN'}")
    print(f"        → Ownership banner: {'HIDDEN' if token_info['name'] == 'ADMIN' else 'SHOWN'}")
    print(f"        → Auth status: 'Authenticated as: {token_info['name']}'")

print("\nSTEP 4: JavaScript loads certificates (loadCertificates())")
response = requests.get(f"{API_URL}/api/v1/certificates", headers=headers)
if response.status_code == 200:
    certs = response.json()
    print(f"        API returns: {len(certs)} certificates")
    print("        JavaScript checks: if (data.length === 0)")
    print(f"        → Condition is: {len(certs) == 0}")
    if len(certs) == 0:
        print("        → Would show: 'No certificates found. Create your first certificate!'")
    else:
        print("        → Shows list of certificates:")
        for cert in certs[:2]:
            print(f"          • {cert['cert_name']} - {', '.join(cert['domains'])}")

print("\nSTEP 5: JavaScript loads proxies (loadProxies())")
response = requests.get(f"{API_URL}/api/v1/proxy/targets", headers=headers)
if response.status_code == 200:
    proxies = response.json()
    print(f"        API returns: {len(proxies)} proxy targets")
    if len(proxies) == 0:
        print("        → Would show: 'No proxy targets found. Create your first proxy!'")
    else:
        print("        → Shows list of proxies:")
        for proxy in proxies[:2]:
            print(f"          • {proxy['hostname']} → {proxy['target_url']}")

print("\nSTEP 6: JavaScript loads routes (loadRoutes())")
response = requests.get(f"{API_URL}/api/v1/routes", headers=headers)
if response.status_code == 200:
    routes = response.json()
    print(f"        API returns: {len(routes)} routes")
    print("        → Shows list of routes (visible to all users)")

print("\n" + "="*60)
print("CONCLUSION:")
print("The GUI should show ALL resources when logged in as ADMIN.")
print("If it doesn't, possible causes:")
print("1. Browser cache serving old JavaScript")
print("2. JavaScript errors in console")
print("3. Network issues preventing API calls")
print("4. User accidentally using wrong token")
print("\nTO FIX: Hard refresh the browser (Ctrl+Shift+R)")
print("="*60)