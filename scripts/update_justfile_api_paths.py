#!/usr/bin/env python3
"""Update all API endpoint paths in justfile to use /api/v1/."""

import re

# Read justfile
with open('justfile', 'r') as f:
    content = f.read()

# Define all endpoint replacements
replacements = [
    # Token endpoints
    (r'"\${API_URL}/tokens/generate"', '"${API_URL}/api/v1/tokens/generate"'),
    (r'"\${API_URL}/tokens/formatted"', '"${API_URL}/api/v1/tokens/formatted"'),
    (r'"\${API_URL}/tokens/email"', '"${API_URL}/api/v1/tokens/email"'),
    (r'"\${API_URL}/tokens/info"', '"${API_URL}/api/v1/tokens/info"'),
    
    # Certificate endpoints
    (r'"\${API_URL}/certificates/"', '"${API_URL}/api/v1/certificates/"'),
    (r'"\${API_URL}/certificates/\$\{', '"${API_URL}/api/v1/certificates/${'),
    
    # Proxy endpoints
    (r'"\${API_URL}/proxy/targets/"', '"${API_URL}/api/v1/proxy/targets/"'),
    (r'"\${API_URL}/proxy/targets/formatted"', '"${API_URL}/api/v1/proxy/targets/formatted"'),
    (r'"\${API_URL}/proxy/targets/\$\{', '"${API_URL}/api/v1/proxy/targets/${'),
    (r'"\${API_URL}/proxy/targets/\{\{', '"${API_URL}/api/v1/proxy/targets/{{'),
    
    # Route endpoints
    (r'"\${API_URL}/routes/formatted"', '"${API_URL}/api/v1/routes/formatted"'),
    (r'"\${API_URL}/routes/"', '"${API_URL}/api/v1/routes/"'),
    (r'"http://localhost:9000/routes/"', '"http://localhost:9000/api/v1/routes/"'),
    
    # Instance endpoints
    (r'"\${API_URL}/instances/"', '"${API_URL}/api/v1/instances/"'),
    (r'"\${API_URL}/instances/\$\{', '"${API_URL}/api/v1/instances/${'),
    (r'"\${API_URL}/instances/\{\{', '"${API_URL}/api/v1/instances/{{'),
    (r'"\${API_URL}/instances"', '"${API_URL}/api/v1/instances"'),
    
    # OAuth admin endpoints
    (r'"\${API_URL}/oauth/admin/setup-routes"', '"${API_URL}/api/v1/oauth/admin/setup-routes"'),
    
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