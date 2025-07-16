#!/usr/bin/env python3
"""Fix the loadTokenInfo function to handle missing token gracefully."""

import re

# Read the current app.js
with open('/home/atrawog/AI/atrawog/mcp-http-proxy/acme_certmanager/static/app.js', 'r') as f:
    content = f.read()

# Replace the loadTokenInfo function with a fixed version
fixed_function = '''async function loadTokenInfo() {
    console.log('[DEBUG] loadTokenInfo called');
    console.log('[DEBUG] api.token:', api.token);
    
    // Check if token exists
    if (!api.token) {
        console.error('[DEBUG] No token available');
        showNotification('Please login first', 'error');
        return;
    }
    
    try {
        console.log('[DEBUG] Making request to /token/info');
        const response = await fetch('/token/info', {
            headers: {
                'Authorization': `Bearer ${api.token}`
            }
        });
        
        if (!response.ok) {
            console.error('[DEBUG] Response not OK:', response.status, response.statusText);
            throw new Error('Failed to load token info');
        }
        console.log('[DEBUG] Response OK, data received');
        
        const data = await response.json();
        console.log('[DEBUG] Token info data:', data);
        
        // Update token info display
        document.getElementById('token-name').textContent = data.name || 'N/A';
        document.getElementById('token-preview').textContent = data.hash_preview || 'N/A';
        document.getElementById('current-email-value').textContent = data.cert_email || '(not set)';
        
        // Update email input placeholder
        const emailInput = document.getElementById('cert-email');
        if (emailInput && data.cert_email) {
            emailInput.placeholder = data.cert_email;
        }
    } catch (error) {
        console.error('Error loading token info:', error);
        showNotification('Failed to load token information', 'error');
    }
}'''

# Find and replace the loadTokenInfo function
pattern = r'async function loadTokenInfo\(\) \{[^}]+(?:\{[^}]+\}[^}]+)*\}'
content = re.sub(pattern, fixed_function, content, flags=re.DOTALL)

# Write the updated content
with open('/home/atrawog/AI/atrawog/mcp-http-proxy/acme_certmanager/static/app.js', 'w') as f:
    f.write(content)

print("loadTokenInfo function fixed!")