#!/usr/bin/env python3
"""Verify web GUI has been updated correctly."""

import requests
from bs4 import BeautifulSoup

# Get the HTML
response = requests.get("http://localhost:80")
soup = BeautifulSoup(response.text, 'html.parser')

print("="*60)
print("WEB GUI VERIFICATION")
print("="*60)

# Check title
title = soup.find('title').text
print(f"\n1. Page Title: {title}")
print(f"   ✅ Correct" if title == "MCP Proxy Manager" else f"   ❌ Wrong - expected 'MCP Proxy Manager'")

# Check header
h1 = soup.find('h1').text
print(f"\n2. Header: {h1}")
print(f"   ✅ Correct" if h1 == "MCP Proxy Manager" else f"   ❌ Wrong - expected 'MCP Proxy Manager'")

# Check for Settings tab
settings_tab = soup.find('button', {'data-tab': 'settings'})
print(f"\n3. Settings Tab: {'Found' if settings_tab else 'Not Found'}")
print(f"   ✅ Correct" if settings_tab else f"   ❌ Missing Settings tab")

# Check certificate form for email field
cert_form = soup.find('form', {'id': 'new-certificate-form'})
if cert_form:
    email_fields = cert_form.find_all('input', {'type': 'email'})
    print(f"\n4. Certificate Form Email Fields: {len(email_fields)}")
    print(f"   ✅ Correct - no email field" if len(email_fields) == 0 else f"   ❌ Wrong - found {len(email_fields)} email field(s)")
    
    # List all fields in certificate form
    print("\n   Certificate form fields:")
    for inp in cert_form.find_all('input'):
        if inp.get('type') != 'submit':
            print(f"   - {inp.get('name', 'unnamed')} ({inp.get('type', 'text')})")
    for sel in cert_form.find_all('select'):
        print(f"   - {sel.get('name', 'unnamed')} (select)")

# Check proxy form for email field
proxy_form = soup.find('form', {'id': 'new-proxy-form'})
if proxy_form:
    email_fields = proxy_form.find_all('input', {'type': 'email'})
    print(f"\n5. Proxy Form Email Fields: {len(email_fields)}")
    print(f"   ✅ Correct - no email field" if len(email_fields) == 0 else f"   ❌ Wrong - found {len(email_fields)} email field(s)")
    
    # List all fields in proxy form
    print("\n   Proxy form fields:")
    for inp in proxy_form.find_all('input'):
        if inp.get('type') != 'submit':
            print(f"   - {inp.get('name', 'unnamed')} ({inp.get('type', 'text') or inp.get('type')})")

# Check settings form
settings_form = soup.find('form', {'id': 'email-settings-form'})
if settings_form:
    email_fields = settings_form.find_all('input', {'type': 'email'})
    print(f"\n6. Settings Form Email Fields: {len(email_fields)}")
    print(f"   ✅ Correct - has email field" if len(email_fields) == 1 else f"   ❌ Wrong - expected 1 email field, found {len(email_fields)}")

print("\n" + "="*60)