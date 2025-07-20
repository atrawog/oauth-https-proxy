#!/usr/bin/env python3
"""Find the tab visibility issue."""

import requests
import re

print("=== FINDING TAB VISIBILITY ISSUE ===\n")

# Get CSS
print("1. Checking CSS rules for tabs...")
response = requests.get("https://gui.atradev.org/static/styles.css", verify=False)
css_content = response.text

# Find tab-content rules
print("\n   Tab content CSS rules:")
if '.tab-content {' in css_content:
    # Extract the rule
    start = css_content.find('.tab-content {')
    end = css_content.find('}', start) + 1
    rule = css_content[start:end]
    print(f"   {rule}")

if '.tab-content.active {' in css_content:
    start = css_content.find('.tab-content.active {')
    end = css_content.find('}', start) + 1
    rule = css_content[start:end]
    print(f"   {rule}")

# Get app.js
print("\n2. Checking tab switching logic...")
response = requests.get("https://gui.atradev.org/static/app.js", verify=False)
js_content = response.text

# Find switchTab function
switch_tab_match = re.search(r'function switchTab\(tab\)[^{]*\{[\s\S]*?\n\}', js_content)
if switch_tab_match:
    switch_tab = switch_tab_match.group(0)
    print("\n   switchTab function found")
    
    # Check what it does with tab contents
    if "classList.remove('hidden')" in switch_tab and "classList.add('active')" in switch_tab:
        print("   ✓ Removes 'hidden' and adds 'active' to selected tab")
    if "classList.add('hidden')" in switch_tab and "classList.remove('active')" in switch_tab:
        print("   ✓ Adds 'hidden' and removes 'active' from other tabs")

# Check initial state
print("\n3. Checking initial HTML state...")
response = requests.get("https://gui.atradev.org/", verify=False)
html = response.text

# Check certificates tab
if 'id="certificates-tab"' in html:
    # Extract the div
    match = re.search(r'<div[^>]*id="certificates-tab"[^>]*>', html)
    if match:
        div_tag = match.group(0)
        print(f"\n   Certificates tab HTML: {div_tag}")
        
        # Check classes
        class_match = re.search(r'class="([^"]*)"', div_tag)
        if class_match:
            classes = class_match.group(1).split()
            print(f"   Initial classes: {classes}")
            
            if 'hidden' in classes:
                print("   ❌ PROBLEM: Tab starts with 'hidden' class!")
            if 'active' in classes:
                print("   ✓ Tab has 'active' class")
            else:
                print("   ❌ PROBLEM: Tab missing 'active' class!")

# Check showDashboard
print("\n4. Checking what showDashboard does to tabs...")
show_dash_match = re.search(r'function showDashboard\(\)[^{]*\{[\s\S]*?\n\}', js_content)
if show_dash_match:
    show_dash = show_dash_match.group(0)
    
    # Does it call switchTab?
    if 'switchTab' in show_dash:
        print("   ✓ Calls switchTab")
        # What tab?
        tab_match = re.search(r"switchTab\(['\"](\w+)['\"]\)", show_dash)
        if tab_match:
            tab = tab_match.group(1)
            print(f"   ✓ Switches to '{tab}' tab")
    else:
        print("   ❌ Does NOT call switchTab!")
        print("   ⚠️  This means tab visibility might not be set correctly!")

print("\n5. The Real Issue:")
print("   If showDashboard() doesn't ensure the certificates tab is visible,")
print("   the data loads but remains hidden!")

print("\n" + "="*60)
print("ROOT CAUSE HYPOTHESIS:")
print("The certificates data IS loading, but the tab-content div")
print("remains hidden or inactive, so you can't see it!")
print("="*60)