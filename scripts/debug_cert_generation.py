#!/usr/bin/env python3
"""Debug certificate generation issue."""

import os
import sys
import requests
import time
import json

def debug_cert_generation():
    """Debug the certificate generation process."""
    api_url = os.getenv('API_URL')
    if not api_url:
        print("Error: API_URL must be set in .env")
        return
    
    # Generate a test token
    print("1. Generating test token...")
    sys.path.insert(0, '/app')
    from src.api.auth import generate_token, hash_token
    from src.storage import RedisStorage
    
    token = generate_token()
    token_hash = hash_token(token)
    token_name = f"debug-token-{int(time.time())}"
    
    # Store token
    redis_url = os.getenv("REDIS_URL")
    storage = RedisStorage(redis_url)
    if storage.store_api_token(token_hash, token_name, token):
        print(f"   ✓ Token created: {token_name}")
        print(f"   Token: {token}")
    else:
        print("   ✗ Failed to store token")
        return
    
    # Create certificate request
    cert_name = f"debug-cert-{int(time.time())}"
    print(f"\n2. Creating certificate: {cert_name}")
    
    headers = {"Authorization": f"Bearer {token}"}
    # Get test configuration from environment
    test_domain_base = os.getenv('TEST_DOMAIN_BASE')
    test_email = os.getenv('TEST_EMAIL')
    acme_staging_url = os.getenv('ACME_STAGING_URL')
    
    if not all([test_domain_base, test_email, acme_staging_url]):
        print("Error: TEST_DOMAIN_BASE, TEST_EMAIL, and ACME_STAGING_URL must be set in .env")
        return
    
    test_email_domain = test_email.split('@')[1]
    
    cert_data = {
        "domain": f"debug-{int(time.time())}.{test_domain_base}",
        "email": f"debug{int(time.time())}@{test_email_domain}",
        "cert_name": cert_name,
        "acme_directory_url": acme_staging_url
    }
    
    response = requests.post(
        f"{api_url}/certificates",
        json=cert_data,
        headers=headers
    )
    
    print(f"   Response status: {response.status_code}")
    print(f"   Response: {json.dumps(response.json(), indent=2)}")
    
    if response.status_code != 200:
        print("   ✗ Certificate creation failed")
        return
    
    # Check status immediately
    print("\n3. Checking certificate status...")
    for i in range(10):
        time.sleep(1)
        
        # Check generation status
        status_response = requests.get(
            f"{api_url}/certificates/{cert_name}/status",
            headers=headers
        )
        print(f"   Attempt {i+1}: {status_response.json()}")
        
        # Also try to get the certificate
        cert_response = requests.get(
            f"{api_url}/certificates/{cert_name}",
            headers=headers
        )
        if cert_response.status_code == 200:
            print(f"   ✓ Certificate found!")
            cert = cert_response.json()
            print(f"   Status: {cert.get('status')}")
            break
        else:
            print(f"   Certificate not found yet (status: {cert_response.status_code})")
    
    # Clean up
    print(f"\n4. Cleaning up...")
    storage.delete_api_token(token_hash)
    print("   ✓ Token deleted")

if __name__ == "__main__":
    debug_cert_generation()