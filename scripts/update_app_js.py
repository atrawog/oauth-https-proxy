#!/usr/bin/env python3
"""Update app.js to handle settings tab and remove email fields."""

import re

# Read the current app.js
with open('/home/atrawog/AI/atrawog/mcp-http-proxy/acme_certmanager/static/app.js', 'r') as f:
    content = f.read()

# 1. Remove email from certificate creation
content = re.sub(
    r'email: formData\.get\(\'email\'\),\s*',
    '',
    content
)

# 2. Remove cert_email from proxy creation
content = re.sub(
    r'cert_email: formData\.get\(\'cert_email\'\),\s*',
    '',
    content
)

# 3. Add settings tab to switchTab function
content = re.sub(
    r'(if \(tab === \'certificates\'\) \{\s*loadCertificates\(\);\s*\} else if \(tab === \'proxy\'\) \{\s*loadProxyTargets\(\);\s*\})',
    r'\1 else if (tab === \'settings\') {\n        loadTokenInfo();\n    }',
    content
)

# 4. Add settings-related event listeners after the other form event listeners
content = re.sub(
    r'(newProxyForm\.addEventListener\(\'submit\', handleNewProxyTarget\);)',
    r'\1\n\n// Settings form listener\nconst emailSettingsForm = document.getElementById(\'email-settings-form\');\nif (emailSettingsForm) {\n    emailSettingsForm.addEventListener(\'submit\', handleEmailUpdate);\n}',
    content
)

# 5. Add settings functions before the closing IIFE
settings_functions = '''
// Settings Management
async function loadTokenInfo() {
    try {
        const response = await fetch('/token/info', {
            headers: {
                'Authorization': `Bearer ${api.token}`
            }
        });
        
        if (!response.ok) throw new Error('Failed to load token info');
        
        const data = await response.json();
        
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
}

async function handleEmailUpdate(e) {
    e.preventDefault();
    
    const formData = new FormData(e.target);
    const certEmail = formData.get('cert_email');
    
    if (!certEmail) {
        showNotification('Please enter a valid email address', 'error');
        return;
    }
    
    try {
        const response = await fetch('/token/email', {
            method: 'PUT',
            headers: {
                'Authorization': `Bearer ${api.token}`,
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ cert_email: certEmail })
        });
        
        if (!response.ok) {
            const error = await response.json();
            throw new Error(error.detail || 'Failed to update email');
        }
        
        const result = await response.json();
        showNotification(result.message || 'Email updated successfully', 'success');
        
        // Reload token info to show updated email
        loadTokenInfo();
        
        // Clear the form
        e.target.reset();
    } catch (error) {
        showNotification(`Error: ${error.message}`, 'error');
    }
}

'''

# Insert the settings functions before the window event listener
# First check if functions already exist
if 'loadTokenInfo' not in content:
    content = re.sub(
        r'(// Clean up intervals on page unload)',
        settings_functions + r'\1',
        content
    )

# Write the updated content
with open('/home/atrawog/AI/atrawog/mcp-http-proxy/acme_certmanager/static/app.js', 'w') as f:
    f.write(content)

print("app.js updated successfully!")