#!/usr/bin/env python3
"""Demonstrate web GUI login with token."""

import requests

def demo_login():
    """Show that tokens work for web GUI login."""
    base_url = "http://localhost:80"
    
    # Test with the admin token
    token = "acm_GKoa0Ox2IBYhLXxcf_ZFXlTpK-jLbWKJOBRzjCNsIDU"
    headers = {"Authorization": f"Bearer {token}"}
    
    print("=== Web GUI Token Authentication Demo ===\n")
    
    # 1. Access protected endpoint
    print("1. Testing token authentication...")
    response = requests.get(f"{base_url}/certificates", headers=headers)
    
    if response.status_code == 200:
        print(f"✓ Successfully authenticated with token: admin-token")
        print(f"✓ Can access certificates endpoint")
        certs = response.json()
        print(f"✓ User owns {len(certs)} certificate(s)")
    else:
        print(f"✗ Authentication failed: {response.status_code}")
    
    # 2. Show web GUI is accessible
    print("\n2. Web GUI access:")
    print(f"✓ Open browser to: {base_url}")
    print(f"✓ Login with token: {token}")
    print(f"✓ Token name: admin-token")
    
    print("\n=== Summary ===")
    print("Tokens generated with 'just token-generate' can be used to:")
    print("- Login to the web GUI at http://localhost:80")
    print("- Access API endpoints programmatically")
    print("- Manage certificates owned by that token")


if __name__ == "__main__":
    demo_login()