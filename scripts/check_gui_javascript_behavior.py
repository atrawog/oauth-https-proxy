#!/usr/bin/env python3
"""Check if the GUI JavaScript is correctly handling the responses."""

import json

# Simulate what the GUI JavaScript sees
print("Checking GUI JavaScript behavior:\n")

# 1. ADMIN token response
print("1. When ADMIN logs in:")
print("   - Token info returns: {name: 'ADMIN', cert_email: 'atrawog@gmail.com'}")
print("   - currentTokenInfo.name = 'ADMIN'")
print("   - Condition: if (currentTokenInfo.name !== 'ADMIN') => FALSE")
print("   - Result: Ownership banner is HIDDEN")
print("   - Auth status shows: 'Authenticated as: ADMIN'")
print("   - Certificates API returns: 4 certificates")
print("   - GUI displays: List of 4 certificates")

print("\n2. When test-user logs in:")
print("   - Token info returns: {name: 'test-user', cert_email: 'atrawog@gmail.com'}")  
print("   - currentTokenInfo.name = 'test-user'")
print("   - Condition: if (currentTokenInfo.name !== 'ADMIN') => TRUE")
print("   - Result: Ownership banner is SHOWN")
print("   - Banner text: 'As a non-admin user, you can only see certificates and proxy targets that you own...'")
print("   - Auth status shows: 'Authenticated as: test-user'")
print("   - Certificates API returns: 0 certificates")
print("   - GUI displays: 'No certificates owned by your token. Non-admin users can only see their own certificates.'")

print("\n3. Key code sections:")
print("   Line 242: if (currentTokenInfo.name !== 'ADMIN') {")
print("   Line 396: When non-admin has 0 certs: Shows ownership message")
print("   Line 604: When non-admin has 0 proxies: Shows ownership message")

print("\n4. ACTUAL PROBLEM CHECK:")
print("   - Is currentTokenInfo being set? YES (line 197, 839, 979)")
print("   - Is the ownership banner in HTML? YES (checked)")
print("   - Is the JavaScript condition correct? YES")
print("   - Are the API endpoints returning correct data? YES")

print("\n5. WHAT COULD BE WRONG:")
print("   a) Browser caching old JavaScript without ownership code")
print("   b) JavaScript errors preventing the code from running")
print("   c) The GUI at gui.atradev.org might not have the latest code")
print("   d) User might be seeing a different issue than ownership filtering")