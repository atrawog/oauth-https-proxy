#!/usr/bin/env python3
"""ACTUALLY test the login flow and see what happens."""

import requests
from bs4 import BeautifulSoup
import json
import re

session = requests.Session()
session.verify = False

GUI_URL = "https://gui.atradev.org"
ADMIN_TOKEN = "acm_PikI3FoqDXghOEHdP9lf9wcf0zlEdK2AV9DvPinF-Us"

print("=== ACTUAL LOGIN FLOW TEST ===\n")

# Step 1: Load the page
print("1. Loading GUI page...")
response = session.get(f"{GUI_URL}/")
soup = BeautifulSoup(response.text, 'html.parser')

# Check initial state
login_section = soup.find('div', id='login-section')
dashboard_section = soup.find('div', id='dashboard-section')
print(f"   Login section classes: {login_section.get('class', [])}")
print(f"   Dashboard section classes: {dashboard_section.get('class', [])}")

# Step 2: Get app.js and analyze the login flow
print("\n2. Analyzing app.js login flow...")
response = session.get(f"{GUI_URL}/static/app.js")
js_content = response.text

# Find handleLogin function
login_match = re.search(r'async function handleLogin\(\)[\s\S]*?(?=\n(?:async )?function|\nconst|\n//|\Z)', js_content)
if login_match:
    print("   Found handleLogin function")
    login_func = login_match.group(0)
    
    # Check what happens after successful login
    if 'showDashboard()' in login_func:
        print("   ✓ Calls showDashboard() after successful login")
    else:
        print("   ✗ Does NOT call showDashboard()!")

# Find showDashboard function
dashboard_match = re.search(r'function showDashboard\(\)[\s\S]*?(?=\n(?:async )?function|\nconst|\n//|\Z)', js_content)
if dashboard_match:
    print("\n3. Analyzing showDashboard function...")
    dashboard_func = dashboard_match.group(0)
    
    # Check what it does
    if 'loadCertificates()' in dashboard_func:
        print("   ✓ Calls loadCertificates()")
    else:
        print("   ✗ Does NOT call loadCertificates()!")
        
    if "classList.add('hidden')" in dashboard_func:
        print("   ✓ Hides login section")
    if "classList.remove('hidden')" in dashboard_func:
        print("   ✓ Shows dashboard section")

# Step 3: Simulate the exact API calls after login
print("\n4. Simulating post-login API calls...")
headers = {"Authorization": f"Bearer {ADMIN_TOKEN}"}

# Test token
response = session.get(f"{GUI_URL}/certificates", headers=headers)
print(f"   GET /certificates: {response.status_code}")

# Get token info
response = session.get(f"{GUI_URL}/token/info", headers=headers)
print(f"   GET /token/info: {response.status_code}")
if response.status_code == 200:
    token_info = response.json()
    print(f"   currentTokenInfo will be: {json.dumps(token_info)}")

# Load certificates (what loadCertificates does)
response = session.get(f"{GUI_URL}/certificates", headers=headers)
if response.status_code == 200:
    certs = response.json()
    print(f"\n5. loadCertificates() will receive: {len(certs)} certificates")
    
    # Check what should happen to the DOM
    print("\n6. What SHOULD happen to certificates-list div:")
    if len(certs) == 0:
        print("   - Should show: 'No certificates found. Create your first certificate!'")
    else:
        print("   - Should create certificate cards for:")
        for cert in certs:
            print(f"     • {cert['cert_name']} - {', '.join(cert['domains'])}")

# Check for potential issues
print("\n7. Checking for potential issues...")

# Check if there's an error handler
if 'catch (error)' in js_content:
    error_count = js_content.count('catch (error)')
    print(f"   - Found {error_count} error handlers")
    
# Check if innerHTML is actually set
if 'listContainer.innerHTML = certificates.map' in js_content:
    print("   ✓ innerHTML is set with certificate data")
else:
    print("   ✗ innerHTML might not be set correctly")

# Check for console.log statements
if 'console.log' in js_content:
    log_count = js_content.count('console.log')
    print(f"   - Found {log_count} console.log statements")

print("\n" + "="*60)
print("ANALYSIS:")
print("If the GUI still shows empty after login, check:")
print("1. Browser console for JavaScript errors")
print("2. Network tab to see if API calls succeed")
print("3. Elements tab to see if innerHTML is actually updated")
print("4. Console for any logged messages")
print("="*60)