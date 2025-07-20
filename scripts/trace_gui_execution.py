#!/usr/bin/env python3
"""Trace exactly what happens when the GUI loads and after login."""

import requests
import json
import re

session = requests.Session()
session.verify = False

GUI_URL = "https://gui.atradev.org"
ADMIN_TOKEN = "acm_PikI3FoqDXghOEHdP9lf9wcf0zlEdK2AV9DvPinF-Us"

print("=== TRACING GUI EXECUTION ===\n")

# Get app.js
print("1. Getting app.js to trace execution flow...")
response = session.get(f"{GUI_URL}/static/app.js")
js_content = response.text

# Find the DOMContentLoaded handler
print("\n2. What happens when page loads (DOMContentLoaded):")
dom_match = re.search(r'document\.addEventListener\([\'"]DOMContentLoaded[\'"][\s\S]*?\}\);', js_content)
if dom_match:
    dom_handler = dom_match.group(0)
    print("   Found DOMContentLoaded handler")
    
    # Check the flow
    if 'api.token' in dom_handler:
        print("   ✓ Checks for existing token in localStorage")
    if 'showDashboard()' in dom_handler:
        print("   ✓ Calls showDashboard() if token exists")
    if 'showLogin()' in dom_handler:
        print("   ✓ Calls showLogin() if no token")

# Find showDashboard
print("\n3. What showDashboard() does:")
show_dash_match = re.search(r'function showDashboard\(\)[^{]*\{[\s\S]*?\n\}', js_content)
if show_dash_match:
    show_dash = show_dash_match.group(0)
    
    # Check what it does
    actions = []
    if "loginSection.classList.add('hidden')" in show_dash:
        actions.append("Hides login section")
    if "dashboardSection.classList.remove('hidden')" in show_dash:
        actions.append("Shows dashboard section")
    if "loadCertificates()" in show_dash:
        actions.append("Calls loadCertificates()")
    
    for action in actions:
        print(f"   ✓ {action}")

# Find loadCertificates
print("\n4. What loadCertificates() does:")
load_certs_match = re.search(r'async function loadCertificates\(\)[^{]*\{[\s\S]*?^\}', js_content, re.MULTILINE)
if load_certs_match:
    load_certs = load_certs_match.group(0)
    
    # Key steps
    if "getElementById('certificates-list')" in load_certs:
        print("   ✓ Gets certificates-list element")
    if "innerHTML = '<div class=\"loading\">" in load_certs:
        print("   ✓ Shows loading message")
    if "await api.getCertificates()" in load_certs:
        print("   ✓ Fetches certificates from API")
    if "listContainer.innerHTML = certificates.map" in load_certs:
        print("   ✓ Updates innerHTML with certificate cards")

# Now test the actual flow
print("\n5. Testing actual API and DOM update flow:")

# Step 1: Check if logged in (simulating localStorage check)
print("   a) Checking if token exists: NO (first visit)")
print("      → Should call showLogin()")

# Step 2: After login
print("\n   b) After entering token and clicking login:")
headers = {"Authorization": f"Bearer {ADMIN_TOKEN}"}

# Test token
response = session.get(f"{GUI_URL}/certificates", headers=headers)
print(f"      - Test token: {response.status_code}")

# Get token info
response = session.get(f"{GUI_URL}/token/info", headers=headers)
print(f"      - Get token info: {response.status_code}")

# Load certificates
response = session.get(f"{GUI_URL}/certificates", headers=headers)
if response.status_code == 200:
    certs = response.json()
    print(f"      - Load certificates: {len(certs)} returned")
    
    print("\n   c) What should be in certificates-list div:")
    for cert in certs:
        print(f"      • Card for: {cert['cert_name']} - {', '.join(cert['domains'])}")

# Check for potential issues in the code
print("\n6. Potential issues found:")
issues = []

# Check if there's a tab visibility issue
if 'tab-content' in js_content and 'hidden' in js_content:
    # Count tab-related hide/show operations
    tab_hide_count = js_content.count("classList.add('hidden')")
    tab_show_count = js_content.count("classList.remove('hidden')")
    if tab_hide_count > tab_show_count:
        issues.append("More hide operations than show - tabs might stay hidden")

# Check if certificates-list is ever cleared
if "innerHTML = ''" in js_content:
    issues.append("innerHTML might be cleared somewhere")

# Check for race conditions
if 'setTimeout' in js_content or 'setInterval' in js_content:
    issues.append("Timing/async issues possible")

if issues:
    for issue in issues:
        print(f"   ⚠️  {issue}")
else:
    print("   ✓ No obvious issues found")

print("\n" + "="*60)
print("CONCLUSION:")
print("The code flow looks correct. If data doesn't appear:")
print("1. Check browser console for JavaScript errors")
print("2. Check if certificates-list element exists in DOM")
print("3. Verify tab visibility (CSS classes)")
print("4. Look for race conditions in async code")
print("="*60)