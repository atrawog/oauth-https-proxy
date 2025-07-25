#!/usr/bin/env python3
"""Test what the GUI actually shows by simulating browser requests."""

import requests
import os

BASE_URL = "http://localhost"

def test_gui_login_and_display():
    """Test GUI login and what it displays."""
    
    # Test 1: Check if GUI is accessible
    print("1. Testing GUI accessibility...")
    response = requests.get(BASE_URL)
    print(f"   - Status: {response.status_code}")
    print(f"   - Title present: {'MCP Proxy Manager' in response.text}")
    print(f"   - Login form present: {'Bearer Token:' in response.text}")
    
    # Test 2: Test with ADMIN token
    admin_token = os.getenv("ADMIN_TOKEN", "acm_PikI3FoqDXghOEHdP9lf9wcf0zlEdK2AV9DvPinF-Us")
    print(f"\n2. Testing ADMIN token API access...")
    headers = {"Authorization": f"Bearer {admin_token}"}
    
    # Get token info
    response = requests.get(f"{BASE_URL}/token/info", headers=headers)
    print(f"   - Token info status: {response.status_code}")
    if response.status_code == 200:
        info = response.json()
        print(f"   - Token name: {info.get('name')}")
        print(f"   - Token email: {info.get('cert_email')}")
    
    # Get certificates
    response = requests.get(f"{BASE_URL}/api/v1/certificates", headers=headers)
    print(f"\n   - Certificates endpoint status: {response.status_code}")
    if response.status_code == 200:
        certs = response.json()
        print(f"   - Number of certificates: {len(certs)}")
        
    # Get proxies
    response = requests.get(f"{BASE_URL}/api/v1/proxy/targets", headers=headers)
    print(f"\n   - Proxies endpoint status: {response.status_code}")
    if response.status_code == 200:
        proxies = response.json()
        print(f"   - Number of proxies: {len(proxies)}")
        
    # Get routes
    response = requests.get(f"{BASE_URL}/api/v1/routes", headers=headers)
    print(f"\n   - Routes endpoint status: {response.status_code}")
    if response.status_code == 200:
        routes = response.json()
        print(f"   - Number of routes: {len(routes)}")
        
    # Test 3: Check ownership banner elements
    print(f"\n3. Checking GUI ownership elements...")
    response = requests.get(BASE_URL)
    print(f"   - Ownership banner HTML present: {'ownership-banner' in response.text}")
    print(f"   - Ownership message span present: {'ownership-message' in response.text}")
    print(f"   - Info banner CSS present: {'info-banner' in response.text}")
    
    # Test 4: Test with non-admin token
    test_token = "acm_f9G_B9zCTR3OC_RkKb8Ki9p5o3VHkPN5lpXD6MY_Ef4"
    print(f"\n4. Testing test-user token API access...")
    headers = {"Authorization": f"Bearer {test_token}"}
    
    # Get token info
    response = requests.get(f"{BASE_URL}/token/info", headers=headers)
    print(f"   - Token info status: {response.status_code}")
    if response.status_code == 200:
        info = response.json()
        print(f"   - Token name: {info.get('name')}")
        
    # Get certificates
    response = requests.get(f"{BASE_URL}/api/v1/certificates", headers=headers)
    print(f"\n   - Certificates endpoint status: {response.status_code}")
    if response.status_code == 200:
        certs = response.json()
        print(f"   - Number of certificates: {len(certs)}")

if __name__ == "__main__":
    test_gui_login_and_display()