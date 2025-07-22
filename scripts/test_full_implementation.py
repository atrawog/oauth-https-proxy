#!/usr/bin/env python3
"""Full end-to-end test of the MCP Proxy Manager implementation."""

import os
import sys
import time
import requests
from tabulate import tabulate

# Add the parent directory to sys.path
sys.path.insert(0, '/app')

from src.storage import RedisStorage

# Configuration
BASE_URL = os.getenv("TEST_BASE_URL", "http://localhost:80")

# Initialize storage
storage = RedisStorage(os.getenv("REDIS_URL"))

def test_full_implementation():
    """Test the complete implementation."""
    print("\n" + "="*80)
    print("MCP PROXY MANAGER - FULL IMPLEMENTATION TEST")
    print("="*80)
    
    # Step 1: Create a test token with email
    print("\n1. Creating test token with certificate email...")
    token_name = f"test-token-{int(time.time())}"
    cert_email = "test@example.com"
    
    # Simulate token creation (normally done via `just token-generate`)
    token = f"acm_{os.urandom(32).hex()}"
    token_hash = f"sha256_{os.urandom(16).hex()}"
    
    if storage.store_api_token(token_hash, token_name, token, cert_email):
        print(f"   ✅ Token created: {token_name}")
        print(f"   ✅ Certificate email: {cert_email}")
    else:
        print("   ❌ Failed to create token")
        return
    
    headers = {"Authorization": f"Bearer {token}"}
    
    # Step 2: Test token info endpoint
    print("\n2. Testing token info endpoint...")
    try:
        response = requests.get(f"{BASE_URL}/token/info", headers=headers)
        if response.status_code == 200:
            info = response.json()
            print(f"   ✅ Token info retrieved")
            print(f"      Name: {info.get('name')}")
            print(f"      Email: {info.get('cert_email')}")
        else:
            print(f"   ❌ Failed: {response.status_code}")
    except Exception as e:
        print(f"   ❌ Error: {e}")
    
    # Step 3: Update certificate email
    print("\n3. Testing email update...")
    new_email = "updated@example.com"
    try:
        response = requests.put(
            f"{BASE_URL}/token/email",
            headers=headers,
            json={"cert_email": new_email}
        )
        if response.status_code == 200:
            print(f"   ✅ Email updated to: {new_email}")
        else:
            print(f"   ❌ Failed: {response.status_code}")
    except Exception as e:
        print(f"   ❌ Error: {e}")
    
    # Step 4: Create proxy target without providing email
    print("\n4. Creating proxy target (should use token's email)...")
    hostname = f"test-proxy-{int(time.time())}.example.com"
    try:
        response = requests.post(
            f"{BASE_URL}/proxy/targets",
            headers=headers,
            json={
                "hostname": hostname,
                "target_url": os.getenv("TEST_PROXY_TARGET_URL", "https://example.com"),
                "acme_directory_url": os.getenv("ACME_STAGING_URL")
                # Note: NOT providing cert_email
            }
        )
        if response.status_code == 200:
            result = response.json()
            print(f"   ✅ Proxy target created: {hostname}")
            print(f"      Certificate status: {result.get('certificate_status')}")
            print(f"      Certificate name: {result.get('cert_name')}")
        else:
            print(f"   ❌ Failed: {response.status_code} - {response.text}")
    except Exception as e:
        print(f"   ❌ Error: {e}")
    
    # Step 5: List proxy targets (authenticated)
    print("\n5. Listing proxy targets (authenticated - should see only owned)...")
    try:
        response = requests.get(f"{BASE_URL}/proxy/targets", headers=headers)
        if response.status_code == 200:
            targets = response.json()
            print(f"   ✅ Found {len(targets)} proxy target(s)")
            for target in targets:
                print(f"      - {target.get('hostname')} -> {target.get('target_url')}")
        else:
            print(f"   ❌ Failed: {response.status_code}")
    except Exception as e:
        print(f"   ❌ Error: {e}")
    
    # Step 6: Test public access (no auth)
    print("\n6. Testing public access (no authentication)...")
    try:
        response = requests.get(f"{BASE_URL}/proxy/targets")
        if response.status_code == 200:
            targets = response.json()
            print(f"   ✅ Public access works - found {len(targets)} proxy target(s)")
        else:
            print(f"   ❌ Failed: {response.status_code}")
    except Exception as e:
        print(f"   ❌ Error: {e}")
    
    # Step 7: Create certificate directly
    print("\n7. Creating certificate directly (should use token's email)...")
    cert_name = f"test-cert-{int(time.time())}"
    try:
        response = requests.post(
            f"{BASE_URL}/certificates",
            headers=headers,
            json={
                "cert_name": cert_name,
                "domain": f"test-cert-{int(time.time())}.example.com",
                "acme_directory_url": os.getenv("ACME_STAGING_URL")
                # Note: NOT providing email
            }
        )
        if response.status_code == 200:
            print(f"   ✅ Certificate generation started: {cert_name}")
        else:
            print(f"   ❌ Failed: {response.status_code} - {response.text}")
    except Exception as e:
        print(f"   ❌ Error: {e}")
    
    # Step 8: Web GUI check
    print("\n8. Verifying Web GUI...")
    try:
        response = requests.get(BASE_URL)
        if response.status_code == 200:
            content = response.text
            checks = [
                ("Title is 'MCP Proxy Manager'", '<title>MCP Proxy Manager</title>' in content),
                ("Settings tab exists", 'data-tab="settings"' in content),
                ("No email in cert form", 'new-certificate-form' in content and 
                    not ('type="email"' in content.split('new-certificate-form')[1].split('</form>')[0])),
                ("No email in proxy form", 'new-proxy-form' in content and 
                    not ('type="email"' in content.split('new-proxy-form')[1].split('</form>')[0])),
                ("Email field in settings", 'email-settings-form' in content and 
                    'type="email"' in content.split('email-settings-form')[1].split('</form>')[0])
            ]
            
            for check_name, passed in checks:
                print(f"   {'✅' if passed else '❌'} {check_name}")
        else:
            print(f"   ❌ Failed to load web GUI: {response.status_code}")
    except Exception as e:
        print(f"   ❌ Error: {e}")
    
    # Step 9: Cleanup
    print("\n9. Cleaning up...")
    try:
        # Delete proxy target
        if 'hostname' in locals():
            response = requests.delete(
                f"{BASE_URL}/proxy/targets/{hostname}",
                headers=headers,
                params={"delete_certificate": "true"}
            )
            print(f"   {'✅' if response.status_code == 200 else '❌'} Deleted proxy target")
        
        # Delete token
        if storage.delete_api_token(token_hash):
            print(f"   ✅ Deleted test token")
        else:
            print(f"   ❌ Failed to delete token")
    except Exception as e:
        print(f"   ❌ Cleanup error: {e}")
    
    print("\n" + "="*80)
    print("TEST COMPLETE")
    print("="*80 + "\n")

if __name__ == "__main__":
    test_full_implementation()