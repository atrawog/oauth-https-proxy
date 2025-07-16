#!/usr/bin/env python
"""Test authorization system with cleanup."""

import httpx
import os
import sys
import time

def main():
    base_url = os.getenv("TEST_BASE_URL")
    
    if len(sys.argv) < 2:
        print("Usage: test_auth.py <api-token>")
        sys.exit(1)
    
    token = sys.argv[1]
    cert_name = None
    
    try:
        # Test without token (should fail)
        print("1. Testing without token (should fail)...")
        try:
            response = httpx.post(
                f"{base_url}/certificates",
                json={
                    "domain": "test-noauth.atradev.org",
                    "email": "test@atradev.org",
                    "cert_name": "test-noauth",
                    "acme_directory_url": os.getenv("ACME_STAGING_URL")
                }
            )
            print(f"   Status: {response.status_code}")
            print(f"   Response: {response.text[:200]}")
        except Exception as e:
            print(f"   Error: {e}")
        
        # Test with token
        print("\n2. Testing with valid token...")
        headers = {"Authorization": f"Bearer {token}"}
        response = httpx.post(
            f"{base_url}/certificates",
            json={
                "domain": "test-auth.atradev.org",
                "email": "test@atradev.org",
                "cert_name": "test-auth",
                "acme_directory_url": os.getenv("ACME_STAGING_URL")
            },
            headers=headers,
            timeout=10
        )
        print(f"   Status: {response.status_code}")
        print(f"   Response: {response.json()}")
        
        if response.status_code == 200:
            cert_name = response.json()["cert_name"]
            
            # Wait a bit for certificate to be stored
            print("   Waiting for certificate to be stored...")
            time.sleep(3)
            
            # Test getting certificate (public, should work without auth)
            print("\n3. Testing GET certificate (public endpoint)...")
            response = httpx.get(f"{base_url}/certificates/{cert_name}")
            print(f"   Status: {response.status_code}")
            
            # Test renewing with wrong token (should fail)
            print("\n4. Testing renew with wrong token (should fail)...")
            wrong_headers = {"Authorization": "Bearer acm_wrong_token_12345"}
            response = httpx.post(
                f"{base_url}/certificates/{cert_name}/renew",
                headers=wrong_headers
            )
            print(f"   Status: {response.status_code}")
            print(f"   Response: {response.text[:200]}")
            
            # Test renewing with correct token
            print("\n5. Testing renew with correct token...")
            response = httpx.post(
                f"{base_url}/certificates/{cert_name}/renew",
                headers=headers
            )
            print(f"   Status: {response.status_code}")
            
            # Test deleting domain with correct token
            print("\n6. Testing delete domain with correct token...")
            response = httpx.delete(
                f"{base_url}/certificates/{cert_name}/domains/test-auth.atradev.org",
                headers=headers
            )
            print(f"   Status: {response.status_code}")
            print(f"   Response: {response.json() if response.status_code == 200 else response.text[:200]}")
    
    finally:
        # Cleanup: Delete the certificate if it was created
        if cert_name:
            print(f"\nCleaning up certificate: {cert_name}")
            try:
                with httpx.Client() as client:
                    delete_response = client.delete(
                        f"{base_url}/certificates/{cert_name}",
                        headers={"Authorization": f"Bearer {token}"}
                    )
                    if delete_response.status_code == 200:
                        print("✓ Certificate deleted successfully")
                    elif delete_response.status_code == 404:
                        print("✓ Certificate already deleted")
                    else:
                        print(f"⚠ Failed to delete certificate: {delete_response.status_code}")
            except Exception as e:
                print(f"⚠ Error during cleanup: {e}")


if __name__ == "__main__":
    main()