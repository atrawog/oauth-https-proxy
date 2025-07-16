#!/usr/bin/env python3
"""Remove debug logging from JavaScript."""

import re

# Read the current app.js
with open('/home/atrawog/AI/atrawog/mcp-http-proxy/acme_certmanager/static/app.js', 'r') as f:
    content = f.read()

# Remove all console.log lines with [DEBUG]
content = re.sub(r'\s*console\.(log|error)\(\'\[DEBUG\][^\']+\'[^)]*\);?\n', '', content)

# Write the updated content
with open('/home/atrawog/AI/atrawog/mcp-http-proxy/acme_certmanager/static/app.js', 'w') as f:
    f.write(content)

print("Debug logging removed from app.js")