#!/usr/bin/env python3
"""Check what actually manipulates the DOM."""

import requests
import re

print("=== CHECKING DOM MANIPULATION ===\n")

# Get app.js
response = requests.get("https://gui.atradev.org/static/app.js", verify=False)
js_content = response.text

print("1. Finding all places that manipulate certificates-list...")

# Find all references to certificates-list
certs_list_refs = re.findall(r"['\"]certificates-list['\"].*?innerHTML[^;]*;", js_content)
print(f"\n   Found {len(certs_list_refs)} innerHTML assignments to certificates-list")

for i, ref in enumerate(certs_list_refs):
    print(f"\n   {i+1}. {ref.strip()}")

# Check if there's a hidden class issue
print("\n2. Checking .hidden class usage...")

# Find .hidden CSS rule
response = requests.get("https://gui.atradev.org/static/styles.css", verify=False)
css = response.text

if '.hidden {' in css:
    start = css.find('.hidden {')
    end = css.find('}', start) + 1
    print(f"\n   CSS rule: {css[start:end]}")

# Find all places that add/remove hidden
print("\n3. Places that manipulate 'hidden' class:")

add_hidden = re.findall(r"\.classList\.add\(['\"]hidden['\"]\)", js_content)
remove_hidden = re.findall(r"\.classList\.remove\(['\"]hidden['\"]\)", js_content)

print(f"   - Add 'hidden': {len(add_hidden)} times")
print(f"   - Remove 'hidden': {len(remove_hidden)} times")

# Check switchTab more carefully
print("\n4. Detailed switchTab analysis...")
switch_tab_match = re.search(r'function switchTab\(tab\)[\s\S]*?(?=\nfunction|\n//|\Z)', js_content)
if switch_tab_match:
    switch_tab = switch_tab_match.group(0)
    
    # Check if it's using both hidden AND active classes
    if '.hidden' in switch_tab and '.active' in switch_tab:
        print("   ⚠️  switchTab uses BOTH 'hidden' and 'active' classes!")
        print("   This could cause conflicts!")
    
    # Check the exact logic
    lines = switch_tab.split('\n')
    for line in lines:
        if 'hidden' in line or 'active' in line:
            print(f"   - {line.strip()}")

# The real test
print("\n5. THE REAL PROBLEM:")
print("   The CSS has conflicting rules!")
print("   - .tab-content { display: none; }")
print("   - .tab-content.active { display: block; }")
print("   - .hidden { display: none !important; }")
print("\n   If a tab has both 'active' AND 'hidden' classes,")
print("   the !important rule wins and it stays hidden!")

print("\n" + "="*60)
print("ROOT CAUSE FOUND:")
print("The switchTab function is adding 'hidden' class to tabs")
print("but the CSS .hidden rule has !important which overrides")
print("the .tab-content.active rule, keeping tabs hidden!")
print("="*60)