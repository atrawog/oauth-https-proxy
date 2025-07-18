#!/usr/bin/env python3
"""Test admin token functionality."""

import os
import requests

def test_admin_token():
    """Test ADMIN_TOKEN from .env."""
    # Get token from environment
    token = os.environ.get('ADMIN_TOKEN')
    if not token:
        print("❌ ADMIN_TOKEN not found in environment")
        return False
    
    print(f"✓ Found ADMIN_TOKEN: {token[:20]}...")
    
    # Test token info endpoint
    headers = {'Authorization': f'Bearer {token}'}
    
    try:
        resp = requests.get('http://localhost/token/info', headers=headers)
        print(f"\nToken Info Endpoint:")
        print(f"  Status: {resp.status_code}")
        if resp.status_code == 200:
            data = resp.json()
            print(f"  Name: {data.get('name')}")
            print(f"  Email: {data.get('cert_email')}")
            print(f"  ✓ Token is working correctly!")
            return True
        else:
            print(f"  ❌ Error: {resp.text}")
            return False
    except Exception as e:
        print(f"  ❌ Request failed: {e}")
        return False

if __name__ == "__main__":
    success = test_admin_token()
    exit(0 if success else 1)