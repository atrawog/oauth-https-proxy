#!/usr/bin/env python3
"""Update all API endpoint paths in justfile to use /api/v1/."""

import re

# Read justfile
with open('justfile', 'r') as f:
    content = f.read()

# Define all endpoint replacements
replacements = [
    # Token endpoints
    (r'"\${BASE_URL}/tokens/generate"', '"${BASE_URL}/api/v1/tokens/generate"'),
    (r'"\${BASE_URL}/tokens/formatted"', '"${BASE_URL}/api/v1/tokens/formatted"'),
    (r'"\${BASE_URL}/tokens/email"', '"${BASE_URL}/api/v1/tokens/email"'),
    (r'"\${BASE_URL}/tokens/info"', '"${BASE_URL}/api/v1/tokens/info"'),
    
    # Certificate endpoints
    (r'"\${BASE_URL}/certificates/"', '"${BASE_URL}/api/v1/certificates/"'),
    (r'"\${BASE_URL}/certificates/\$\{', '"${BASE_URL}/api/v1/certificates/${'),
    
    # Proxy endpoints
    (r'"\${BASE_URL}/proxy/targets/"', '"${BASE_URL}/api/v1/proxy/targets/"'),
    (r'"\${BASE_URL}/proxy/targets/formatted"', '"${BASE_URL}/api/v1/proxy/targets/formatted"'),
    (r'"\${BASE_URL}/proxy/targets/\$\{', '"${BASE_URL}/api/v1/proxy/targets/${'),
    (r'"\${BASE_URL}/proxy/targets/\{\{', '"${BASE_URL}/api/v1/proxy/targets/{{'),
    
    # Route endpoints
    (r'"\${BASE_URL}/routes/formatted"', '"${BASE_URL}/api/v1/routes/formatted"'),
    (r'"\${BASE_URL}/routes/"', '"${BASE_URL}/api/v1/routes/"'),
    (r'"http://localhost:9000/routes/"', '"http://localhost:9000/api/v1/routes/"'),
    
    # Instance endpoints
    (r'"\${BASE_URL}/instances/"', '"${BASE_URL}/api/v1/instances/"'),
    (r'"\${BASE_URL}/instances/\$\{', '"${BASE_URL}/api/v1/instances/${'),
    (r'"\${BASE_URL}/instances/\{\{', '"${BASE_URL}/api/v1/instances/{{'),
    (r'"\${BASE_URL}/instances"', '"${BASE_URL}/api/v1/instances"'),
    
    # OAuth admin endpoints
    (r'"\${BASE_URL}/oauth/admin/setup-routes"', '"${BASE_URL}/api/v1/oauth/admin/setup-routes"'),
    
    # Also update hardcoded localhost URLs
    (r'http://localhost/proxy/targets/', 'http://localhost/api/v1/proxy/targets/'),
]

# Apply replacements
for pattern, replacement in replacements:
    content = re.sub(pattern, replacement, content)

# Write updated content
with open('justfile', 'w') as f:
    f.write(content)

print("Updated justfile with /api/v1/ paths!")

# Count how many replacements were made
updated_count = 0
for pattern, _ in replacements:
    # Remove regex escapes for counting
    clean_pattern = pattern.replace('\\', '').replace('$', '').replace('{', '').replace('}', '')
    if '/api/v1/' not in clean_pattern:
        updated_count += len(re.findall(pattern, content))

print(f"Total endpoints updated: {updated_count}")