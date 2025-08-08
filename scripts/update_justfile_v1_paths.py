#!/usr/bin/env python3
"""Update all API endpoint paths in justfile to use /api/v1/."""

import re

# Read justfile
with open('justfile', 'r') as f:
    content = f.read()

# Count replacements
replacements_made = 0

# Define all endpoint replacements with more specific patterns
replacements = [
    # Token endpoints - match the exact patterns from justfile
    (r'"\$\{API_URL\}/tokens/generate"', '"${API_URL}/api/v1/tokens/generate"'),
    (r'"\$\{API_URL\}/tokens/formatted"', '"${API_URL}/api/v1/tokens/formatted"'),
    (r'"\$\{API_URL\}/tokens/email"', '"${API_URL}/api/v1/tokens/email"'),
    (r'"\$\{API_URL\}/tokens/info"', '"${API_URL}/api/v1/tokens/info"'),
    
    # Certificate endpoints
    (r'"\$\{API_URL\}/certificates/"', '"${API_URL}/api/v1/certificates/"'),
    (r'"\$\{API_URL\}/certificates/\{\{name\}\}"', '"${API_URL}/api/v1/certificates/{{name}}"'),
    
    # Proxy endpoints
    (r'"\$\{API_URL\}/proxy/targets/"', '"${API_URL}/api/v1/proxy/targets/"'),
    (r'"\$\{API_URL\}/proxy/targets/formatted"', '"${API_URL}/api/v1/proxy/targets/formatted"'),
    (r'"\$\{API_URL\}/proxy/targets/\{\{hostname\}\}', '"${API_URL}/api/v1/proxy/targets/{{hostname}}'),
    
    # Route endpoints
    (r'"\$\{API_URL\}/routes/formatted"', '"${API_URL}/api/v1/routes/formatted"'),
    (r'"http://localhost:9000/routes/"', '"http://localhost:9000/api/v1/routes/"'),
    
    # Instance endpoints
    (r'"\$\{API_URL\}/instances/"', '"${API_URL}/api/v1/instances/"'),
    (r'"\$\{API_URL\}/instances/\{\{name\}\}"', '"${API_URL}/api/v1/instances/{{name}}"'),
    (r'"\$\{API_URL\}/instances"', '"${API_URL}/api/v1/instances"'),
    
    # OAuth admin endpoints
    (r'"\$\{API_URL\}/oauth/admin/setup-routes"', '"${API_URL}/api/v1/oauth/admin/setup-routes"'),
    
    # Hardcoded localhost URLs in mcp-echo-setup
    (r'http://localhost/proxy/targets/auth\.\$\{BASE_DOMAIN\}', 'http://localhost/api/v1/proxy/targets/auth.${BASE_DOMAIN}'),
    (r'http://localhost/proxy/targets/echo-stateful\.\$\{BASE_DOMAIN\}', 'http://localhost/api/v1/proxy/targets/echo-stateful.${BASE_DOMAIN}'),
    (r'http://localhost/proxy/targets/echo-stateless\.\$\{BASE_DOMAIN\}', 'http://localhost/api/v1/proxy/targets/echo-stateless.${BASE_DOMAIN}'),
    (r'http://localhost/proxy/targets/fetcher\.\$\{BASE_DOMAIN\}', 'http://localhost/api/v1/proxy/targets/fetcher.${BASE_DOMAIN}'),
    (r'http://localhost/proxy/targets/echo-stateless\.\$\{BASE_DOMAIN\}/auth', 'http://localhost/api/v1/proxy/targets/echo-stateless.${BASE_DOMAIN}/auth'),
    (r'http://localhost/proxy/targets/echo-stateful\.\$\{BASE_DOMAIN\}/auth', 'http://localhost/api/v1/proxy/targets/echo-stateful.${BASE_DOMAIN}/auth'),
]

# Apply replacements
original_content = content
for pattern, replacement in replacements:
    new_content = re.sub(pattern, replacement, content)
    if new_content != content:
        replacements_made += len(re.findall(pattern, content))
        content = new_content

# Write updated content
with open('justfile', 'w') as f:
    f.write(content)

print(f"Updated justfile with /api/v1/ paths!")
print(f"Total replacements made: {replacements_made}")

# Show a few examples of what changed
if replacements_made > 0:
    print("\nExample changes:")
    for i, (pattern, replacement) in enumerate(replacements[:5]):
        # Clean up the pattern for display
        clean_pattern = pattern.replace('\\', '').replace('$', '$').replace('{', '{').replace('}', '}')
        clean_replacement = replacement.replace('\\', '')
        print(f"  {clean_pattern} → {clean_replacement}")