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
    (r'f"\{API_URL\}/certificates"', 'f"{API_URL}/api/v1/certificates"'),
    (r'f"\{API_URL\}/certificates/', 'f"{API_URL}/api/v1/certificates/'),
    (r'"\{API_URL\}/certificates"', '"{API_URL}/api/v1/certificates"'),
    
    (r'f"\{API_URL\}/proxy/targets"', 'f"{API_URL}/api/v1/proxy/targets"'),
    (r'f"\{API_URL\}/proxy/targets/', 'f"{API_URL}/api/v1/proxy/targets/'),
    (r'"\{API_URL\}/proxy/targets"', '"{API_URL}/api/v1/proxy/targets"'),
    
    (r'f"\{API_URL\}/tokens"', 'f"{API_URL}/api/v1/tokens"'),
    (r'f"\{API_URL\}/tokens/', 'f"{API_URL}/api/v1/tokens/'),
    
    (r'f"\{API_URL\}/routes"', 'f"{API_URL}/api/v1/routes"'),
    (r'f"\{API_URL\}/routes/', 'f"{API_URL}/api/v1/routes/'),
    (r'"\{API_URL\}/routes"', '"{API_URL}/api/v1/routes"'),
    
    (r'f"\{API_URL\}/instances"', 'f"{API_URL}/api/v1/instances"'),
    (r'f"\{API_URL\}/instances/', 'f"{API_URL}/api/v1/instances/'),
    
    (r'f"\{API_URL\}/resources"', 'f"{API_URL}/api/v1/resources"'),
    (r'f"\{API_URL\}/resources/', 'f"{API_URL}/api/v1/resources/'),
    
    (r'f"\{API_URL\}/oauth/', 'f"{API_URL}/api/v1/oauth/'),
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