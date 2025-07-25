#!/usr/bin/env python3
"""Fix remaining imports in v1 modules that reference parent modules."""

import os
import re

# Directory containing the v1 modules
v1_dir = "src/api/routers/v1"

# Files to update
files = [
    "oauth_admin.py",
    "routes.py", 
    "proxies.py",
    "certificates.py"
]

# Update patterns - add one more dot for modules outside src/api
updates = [
    # proxy.routes imports
    (r'from \.\.\.proxy\.routes import', 'from ....proxy.routes import'),
    
    # certmanager imports (in inline imports)
    (r'from \.\.\.certmanager\.models import', 'from ....certmanager.models import'),
    (r'from \.\.\.certmanager\.async_acme import', 'from ....certmanager.async_acme import'),
    
    # dispatcher imports
    (r'from \.\.\.dispatcher\.unified_dispatcher import', 'from ....dispatcher.unified_dispatcher import'),
]

for filename in files:
    filepath = os.path.join(v1_dir, filename)
    
    if not os.path.exists(filepath):
        print(f"Warning: {filepath} not found")
        continue
    
    # Read file
    with open(filepath, 'r') as f:
        content = f.read()
    
    # Apply updates
    modified = False
    for pattern, replacement in updates:
        new_content = re.sub(pattern, replacement, content)
        if new_content != content:
            modified = True
            content = new_content
    
    # Write updated content if modified
    if modified:
        with open(filepath, 'w') as f:
            f.write(content)
        print(f"Updated {filename}")
    else:
        print(f"No changes needed for {filename}")

print("Import fixes complete!")