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
    (r'"\$\{BASE_URL\}/tokens/generate"', '"${BASE_URL}/api/v1/tokens/generate"'),
    (r'"\$\{BASE_URL\}/tokens/formatted"', '"${BASE_URL}/api/v1/tokens/formatted"'),
    (r'"\$\{BASE_URL\}/tokens/email"', '"${BASE_URL}/api/v1/tokens/email"'),
    (r'"\$\{BASE_URL\}/tokens/info"', '"${BASE_URL}/api/v1/tokens/info"'),
    
    # Certificate endpoints
    (r'"\$\{BASE_URL\}/certificates/"', '"${BASE_URL}/api/v1/certificates/"'),
    (r'"\$\{BASE_URL\}/certificates/\{\{name\}\}"', '"${BASE_URL}/api/v1/certificates/{{name}}"'),
    
    # Proxy endpoints
    (r'"\$\{BASE_URL\}/proxy/targets/"', '"${BASE_URL}/api/v1/proxy/targets/"'),
    (r'"\$\{BASE_URL\}/proxy/targets/formatted"', '"${BASE_URL}/api/v1/proxy/targets/formatted"'),
    (r'"\$\{BASE_URL\}/proxy/targets/\{\{hostname\}\}', '"${BASE_URL}/api/v1/proxy/targets/{{hostname}}'),
    
    # Route endpoints
    (r'"\$\{BASE_URL\}/routes/formatted"', '"${BASE_URL}/api/v1/routes/formatted"'),
    (r'"http://localhost:9000/routes/"', '"http://localhost:9000/api/v1/routes/"'),
    
    # Instance endpoints
    (r'"\$\{BASE_URL\}/instances/"', '"${BASE_URL}/api/v1/instances/"'),
    (r'"\$\{BASE_URL\}/instances/\{\{name\}\}"', '"${BASE_URL}/api/v1/instances/{{name}}"'),
    (r'"\$\{BASE_URL\}/instances"', '"${BASE_URL}/api/v1/instances"'),
    
    # OAuth admin endpoints
    (r'"\$\{BASE_URL\}/oauth/admin/setup-routes"', '"${BASE_URL}/api/v1/oauth/admin/setup-routes"'),
    
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