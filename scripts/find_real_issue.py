#!/usr/bin/env python3
"""Find the REAL issue with the GUI."""

import requests
from bs4 import BeautifulSoup
import re

print("=== FINDING THE REAL GUI ISSUE ===\n")

# Step 1: Get the actual HTML
print("1. Fetching the GUI HTML...")
response = requests.get("https://gui.atradev.org/", verify=False)
soup = BeautifulSoup(response.text, 'html.parser')

# Check if certificates-list div exists
cert_list_div = soup.find('div', id='certificates-list')
if cert_list_div:
    print("   ✓ certificates-list div found")
    print(f"   Current content: {cert_list_div.get_text().strip()}")
else:
    print("   ✗ certificates-list div NOT FOUND!")

# Step 2: Check JavaScript includes
print("\n2. Checking JavaScript includes...")
script_tags = soup.find_all('script')
for script in script_tags:
    src = script.get('src', '')
    if src:
        print(f"   - Script: {src}")

# Step 3: Check app.js directly
print("\n3. Checking app.js content...")
response = requests.get("https://gui.atradev.org/static/app.js", verify=False)
js_content = response.text

# Check for critical functions
functions_to_check = [
    'loadCertificates',
    'showDashboard', 
    'switchTab',
    'getCertificates',
    'currentTokenInfo'
]

for func in functions_to_check:
    if func in js_content:
        print(f"   ✓ {func} found")
        # Find where it's called
        if func == 'loadCertificates':
            # Check all places it's called
            calls = re.findall(r'loadCertificates\(\)[;\s]', js_content)
            print(f"     Called {len(calls)} times")
            
            # Check if it's called in showDashboard
            if 'showDashboard' in js_content:
                dashboard_start = js_content.find('function showDashboard')
                dashboard_end = js_content.find('\n}', dashboard_start) + 2
                dashboard_func = js_content[dashboard_start:dashboard_end]
                if 'loadCertificates()' in dashboard_func:
                    print("     ✓ Called in showDashboard()")
                else:
                    print("     ✗ NOT called in showDashboard()!")
    else:
        print(f"   ✗ {func} NOT FOUND!")

# Step 4: Check initialization
print("\n4. Checking initialization code...")
if 'window.onload' in js_content or 'document.addEventListener' in js_content:
    print("   ✓ Page initialization found")
    # Check what happens on load
    if 'checkAuth()' in js_content:
        print("   ✓ checkAuth() called on load")
else:
    print("   ✗ No initialization code found!")

# Step 5: Test with a real browser simulation
print("\n5. Simulating full browser flow...")
session = requests.Session()
session.verify = False

# Load page
session.get("https://gui.atradev.org/")
print("   - Page loaded")

# Login
token = "acm_PikI3FoqDXghOEHdP9lf9wcf0zlEdK2AV9DvPinF-Us"
headers = {"Authorization": f"Bearer {token}"}

# Check what happens after login
response = session.get("https://gui.atradev.org/certificates", headers=headers)
if response.status_code == 200:
    certs = response.json()
    print(f"   - API returns {len(certs)} certificates")
else:
    print(f"   - API error: {response.status_code}")

print("\n" + "="*60)
print("CONCLUSION:")
print("The issue is likely one of these:")
print("1. loadCertificates() is not being called after login")
print("2. DOM updates are failing due to JavaScript errors")
print("3. There's a race condition in the code")
print("4. The browser is caching old JavaScript")
print("="*60)