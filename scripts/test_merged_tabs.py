#!/usr/bin/env python3
"""Test the merged tabs in the web GUI."""

import sys
import os
import requests
from time import sleep

# Add the app directory to the Python path
sys.path.insert(0, '/app')

# Get base URL from environment
API_URL = os.getenv('API_URL', 'http://localhost:80')

def test_web_gui():
    """Test the merged tabs functionality."""
    print("Testing merged tabs in web GUI...")
    
    # 1. Test home page loads
    print("\n1. Testing home page...")
    response = requests.get(API_URL)
    if response.status_code == 200:
        print("   ✓ Home page loads successfully")
        
        # Check for new tab structure
        if 'data-tab="certificates"' in response.text and 'data-tab="proxies"' in response.text:
            print("   ✓ New tab structure found")
        else:
            print("   ✗ New tab structure not found")
            
        # Check for Add buttons
        if 'id="add-certificate-btn"' in response.text and 'id="add-proxy-btn"' in response.text:
            print("   ✓ Add buttons found")
        else:
            print("   ✗ Add buttons not found")
            
        # Check that old tabs are removed
        if 'data-tab="new-certificate"' not in response.text and 'data-tab="new-proxy"' not in response.text:
            print("   ✓ Old tabs removed")
        else:
            print("   ✗ Old tabs still present")
    else:
        print(f"   ✗ Failed to load home page: {response.status_code}")
    
    # 2. Test static files
    print("\n2. Testing static files...")
    
    # Test CSS
    css_response = requests.get(f"{API_URL}/static/styles.css")
    if css_response.status_code == 200:
        print("   ✓ CSS file loads")
        if '.tab-header' in css_response.text and '.form-container' in css_response.text:
            print("   ✓ New CSS classes found")
        else:
            print("   ✗ New CSS classes not found")
    else:
        print(f"   ✗ CSS file failed: {css_response.status_code}")
    
    # Test JavaScript
    js_response = requests.get(f"{API_URL}/static/app.js")
    if js_response.status_code == 200:
        print("   ✓ JavaScript file loads")
        if 'toggleCertificateForm' in js_response.text and 'toggleProxyForm' in js_response.text:
            print("   ✓ Toggle functions found")
        else:
            print("   ✗ Toggle functions not found")
            
        if "tab === 'proxies'" in js_response.text:
            print("   ✓ Updated tab name found")
        else:
            print("   ✗ Still using old tab name")
    else:
        print(f"   ✗ JavaScript file failed: {js_response.status_code}")
    
    print("\n✅ Web GUI test complete!")
    print("\nTo manually test:")
    print("1. Open http://localhost:80 in a browser")
    print("2. Login with a token")
    print("3. Check that Certificates and Proxies tabs show lists with Add buttons")
    print("4. Click Add buttons to toggle forms")

if __name__ == "__main__":
    test_web_gui()