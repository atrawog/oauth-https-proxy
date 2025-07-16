#!/usr/bin/env python3
"""Test certificate email settings functionality."""

import os
import sys
import time
import requests
from tabulate import tabulate

# Add the parent directory to sys.path so we can import from acme_certmanager
sys.path.insert(0, '/app')

from acme_certmanager.storage import RedisStorage

# Configuration
BASE_URL = os.getenv("TEST_BASE_URL", "http://localhost:80")

# Initialize storage
storage = RedisStorage(os.getenv("REDIS_URL"))

def test_email_settings(token_name: str):
    """Test email settings functionality."""
    print(f"\n{'='*60}")
    print("Testing Email Settings")
    print(f"{'='*60}\n")
    
    # Get token from storage
    token_data = storage.get_api_token_by_name(token_name)
    if not token_data:
        print(f"❌ Token '{token_name}' not found")
        return
    
    token = token_data.get('token')
    current_email = token_data.get('cert_email', '(not set)')
    
    print(f"Token: {token_name}")
    print(f"Current Email: {current_email}")
    
    headers = {"Authorization": f"Bearer {token}"}
    
    # Test 1: Get token info
    print("\n1. Testing /token/info endpoint...")
    try:
        response = requests.get(f"{BASE_URL}/token/info", headers=headers)
        if response.status_code == 200:
            info = response.json()
            print(f"✅ Token info retrieved:")
            print(f"   Name: {info.get('name')}")
            print(f"   Email: {info.get('cert_email', '(not set)')}")
            print(f"   Preview: {info.get('hash_preview')}")
        else:
            print(f"❌ Failed: {response.status_code} - {response.text}")
    except Exception as e:
        print(f"❌ Error: {e}")
    
    # Test 2: Update email
    new_email = f"test-{int(time.time())}@example.com"
    print(f"\n2. Testing email update to: {new_email}")
    try:
        response = requests.put(
            f"{BASE_URL}/token/email",
            headers=headers,
            json={"cert_email": new_email}
        )
        if response.status_code == 200:
            result = response.json()
            print(f"✅ Email updated: {result.get('message')}")
        else:
            print(f"❌ Failed: {response.status_code} - {response.text}")
    except Exception as e:
        print(f"❌ Error: {e}")
    
    # Test 3: Verify update
    print("\n3. Verifying email update...")
    try:
        response = requests.get(f"{BASE_URL}/token/info", headers=headers)
        if response.status_code == 200:
            info = response.json()
            if info.get('cert_email') == new_email:
                print(f"✅ Email successfully updated to: {new_email}")
            else:
                print(f"❌ Email not updated. Current: {info.get('cert_email')}")
        else:
            print(f"❌ Failed: {response.status_code} - {response.text}")
    except Exception as e:
        print(f"❌ Error: {e}")
    
    # Test 4: Create proxy without email (should use token email)
    print("\n4. Testing proxy creation with token email...")
    hostname = f"test-{int(time.time())}.example.com"
    try:
        response = requests.post(
            f"{BASE_URL}/proxy/targets",
            headers=headers,
            json={
                "hostname": hostname,
                "target_url": os.getenv("TEST_PROXY_TARGET_URL", "https://example.com"),
                # Note: NOT providing cert_email - should use token's email
            }
        )
        if response.status_code == 200:
            result = response.json()
            print(f"✅ Proxy created for {hostname}")
            print(f"   Certificate status: {result.get('certificate_status')}")
            
            # Cleanup
            print("\n   Cleaning up proxy...")
            delete_response = requests.delete(
                f"{BASE_URL}/proxy/targets/{hostname}",
                headers=headers,
                params={"delete_certificate": "true"}
            )
            if delete_response.status_code == 200:
                print("   ✅ Proxy cleaned up")
        else:
            print(f"❌ Failed: {response.status_code} - {response.text}")
    except Exception as e:
        print(f"❌ Error: {e}")
    
    print(f"\n{'='*60}\n")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: test_email_settings.py <token-name>")
        print("\nExample:")
        print("  test_email_settings.py test-token")
        sys.exit(1)
    
    token_name = sys.argv[1]
    test_email_settings(token_name)