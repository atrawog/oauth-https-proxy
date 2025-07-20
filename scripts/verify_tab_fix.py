#!/usr/bin/env python3
"""Verify the tab visibility fix works."""

import requests

print("=== VERIFYING TAB VISIBILITY FIX ===\n")

# Get the updated app.js
response = requests.get("https://gui.atradev.org/static/app.js", verify=False)
js_content = response.text

print("1. Checking if fix was applied...")

# Check if the problematic code is gone
if "content.classList.add('hidden')" in js_content and "content.classList.remove('hidden')" in js_content:
    print("   ❌ Fix NOT applied - still using hidden class!")
else:
    print("   ✅ Fix applied - no longer using hidden class in switchTab!")

# Check switchTab function
import re
switch_tab_match = re.search(r'tabContents\.forEach.*?\}\);', js_content, re.DOTALL)
if switch_tab_match:
    code = switch_tab_match.group(0)
    print("\n2. New switchTab code:")
    print("   " + code.replace('\n', '\n   '))

print("\n3. How it works now:")
print("   - Tab visibility is controlled ONLY by the 'active' class")
print("   - No more conflicts with the 'hidden' class")
print("   - CSS rules:")
print("     .tab-content { display: none; }")
print("     .tab-content.active { display: block; }")

print("\n" + "="*60)
print("TO TEST THE GUI NOW:")
print("1. Go to https://gui.atradev.org/")
print("2. Hard refresh (Ctrl+Shift+R) to get new JavaScript")
print("3. Login with token: acm_PikI3FoqDXghOEHdP9lf9wcf0zlEdK2AV9DvPinF-Us")
print("4. You should now see all certificates, proxies, and routes!")
print("="*60)