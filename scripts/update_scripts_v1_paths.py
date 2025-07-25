#!/usr/bin/env python3
"""Update all Python scripts to use /api/v1/ paths."""

import os
import re
import glob

# Scripts to update
scripts_to_update = [
    "test_full_implementation.py",
    "test_email_settings.py",
    "test_settings_flow.py",
    "test_gui_api_directly.py",
    "simulate_browser_gui.py",
    "debug_gui_issue.py",
    "test_gui_actual_behavior.py",
    "test_proxy_routes.py",
    "test_gui_visibility_fix.py",
    "test_gui_auth.py"
]

# Define replacements
replacements = [
    # Direct path replacements
    (r'f"\{BASE_URL\}/certificates"', 'f"{BASE_URL}/api/v1/certificates"'),
    (r'f"\{BASE_URL\}/certificates/', 'f"{BASE_URL}/api/v1/certificates/'),
    (r'"\{BASE_URL\}/certificates"', '"{BASE_URL}/api/v1/certificates"'),
    
    (r'f"\{BASE_URL\}/proxy/targets"', 'f"{BASE_URL}/api/v1/proxy/targets"'),
    (r'f"\{BASE_URL\}/proxy/targets/', 'f"{BASE_URL}/api/v1/proxy/targets/'),
    (r'"\{BASE_URL\}/proxy/targets"', '"{BASE_URL}/api/v1/proxy/targets"'),
    
    (r'f"\{BASE_URL\}/tokens"', 'f"{BASE_URL}/api/v1/tokens"'),
    (r'f"\{BASE_URL\}/tokens/', 'f"{BASE_URL}/api/v1/tokens/'),
    
    (r'f"\{BASE_URL\}/routes"', 'f"{BASE_URL}/api/v1/routes"'),
    (r'f"\{BASE_URL\}/routes/', 'f"{BASE_URL}/api/v1/routes/'),
    (r'"\{BASE_URL\}/routes"', '"{BASE_URL}/api/v1/routes"'),
    
    (r'f"\{BASE_URL\}/instances"', 'f"{BASE_URL}/api/v1/instances"'),
    (r'f"\{BASE_URL\}/instances/', 'f"{BASE_URL}/api/v1/instances/'),
    
    (r'f"\{BASE_URL\}/resources"', 'f"{BASE_URL}/api/v1/resources"'),
    (r'f"\{BASE_URL\}/resources/', 'f"{BASE_URL}/api/v1/resources/'),
    
    (r'f"\{BASE_URL\}/oauth/', 'f"{BASE_URL}/api/v1/oauth/'),
]

total_replacements = 0

for script_name in scripts_to_update:
    script_path = f"scripts/{script_name}"
    
    if not os.path.exists(script_path):
        print(f"Warning: {script_path} not found")
        continue
    
    # Read file
    with open(script_path, 'r') as f:
        content = f.read()
    
    # Save original for comparison
    original_content = content
    
    # Apply replacements
    for pattern, replacement in replacements:
        content = re.sub(pattern, replacement, content)
    
    # Write if changed
    if content != original_content:
        with open(script_path, 'w') as f:
            f.write(content)
        
        # Count changes
        changes = 0
        for pattern, _ in replacements:
            changes += len(re.findall(pattern, original_content))
        
        total_replacements += changes
        print(f"Updated {script_name} ({changes} replacements)")
    else:
        print(f"No changes needed for {script_name}")

print(f"\nTotal replacements made: {total_replacements}")