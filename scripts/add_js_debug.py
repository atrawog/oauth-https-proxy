#!/usr/bin/env python3
"""Add debug logging to JavaScript."""

import re

# Read the current app.js
with open('/home/atrawog/AI/atrawog/mcp-http-proxy/acme_certmanager/static/app.js', 'r') as f:
    content = f.read()

# Add debug logging to loadTokenInfo
content = re.sub(
    r'async function loadTokenInfo\(\) \{',
    '''async function loadTokenInfo() {
    console.log('[DEBUG] loadTokenInfo called');
    console.log('[DEBUG] api.token:', api.token);''',
    content
)

# Add debug logging before the fetch
content = re.sub(
    r"const response = await fetch\('/token/info', \{",
    '''console.log('[DEBUG] Making request to /token/info');
        const response = await fetch('/token/info', {''',
    content
)

# Add debug logging for the response
content = re.sub(
    r"if \(!response\.ok\) throw new Error\('Failed to load token info'\);",
    '''if (!response.ok) {
            console.error('[DEBUG] Response not OK:', response.status, response.statusText);
            throw new Error('Failed to load token info');
        }
        console.log('[DEBUG] Response OK, data received');''',
    content
)

# Write the updated content
with open('/home/atrawog/AI/atrawog/mcp-http-proxy/acme_certmanager/static/app.js', 'w') as f:
    f.write(content)

print("Debug logging added to app.js")