#!/usr/bin/env python3
"""Update imports and router configurations for v1 endpoint modules."""

import os
import re

# Directory containing the v1 modules
v1_dir = "src/api/routers/v1"

# Files to update
files = [
    "certificates.py",
    "proxies.py", 
    "tokens.py",
    "routes.py",
    "instances.py",
    "resources.py",
    "oauth_status.py",
    "oauth_admin.py"
]

# Update patterns
updates = [
    # Update relative imports (add one more level)
    (r'from \.\.auth import', 'from ...auth import'),
    (r'from \.\.models import', 'from ...models import'),
    (r'from \.\.oauth\.models import', 'from ...oauth.models import'),
    (r'from \.\.config import', 'from ...config import'),
    
    # Remove prefix from routers (except special cases)
    (r'APIRouter\(prefix="/certificates", tags=', 'APIRouter(tags='),
    (r'APIRouter\(prefix="/tokens", tags=', 'APIRouter(tags='),
    (r'APIRouter\(prefix="/routes", tags=', 'APIRouter(tags='),
    (r'APIRouter\(prefix="/instances", tags=', 'APIRouter(tags='),
    (r'APIRouter\(prefix="/resources", tags=', 'APIRouter(tags='),
    (r'APIRouter\(prefix="/oauth", tags=', 'APIRouter(tags='),
    
    # Special case: proxy/targets needs to keep its sub-path
    (r'APIRouter\(prefix="/proxy/targets", tags=', 'APIRouter(prefix="/targets", tags='),
    
    # OAuth admin keeps its sub-path
    (r'APIRouter\(prefix="/oauth/admin", tags=', 'APIRouter(prefix="/admin", tags='),
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
    for pattern, replacement in updates:
        content = re.sub(pattern, replacement, content)
    
    # Write updated content
    with open(filepath, 'w') as f:
        f.write(content)
    
    print(f"Updated {filename}")

print("All v1 modules updated!")