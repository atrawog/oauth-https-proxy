#!/usr/bin/env python3
"""Test public certificate access without authentication."""

import os
import requests
import sys

def test_public_access():
    """Test that certificate read operations work without authentication."""
    base_url = os.getenv('BASE_URL', 'http://localhost:80')
    
    print("Testing public certificate access (no authentication)...\n")
    
    # Test 1: List all certificates without auth
    print("1. Testing GET /certificates (list all)...")
    try:
        response = requests.get(f"{base_url}/certificates")
        if response.status_code == 200:
            certs = response.json()
            print(f"   ✓ Success: Found {len(certs)} certificates")
            if certs:
                cert_name = certs[0].get('cert_name', 'unknown')
                print(f"   ✓ First certificate: {cert_name}")
            else:
                print("   ℹ No certificates found (expected if none exist)")
                return True
        else:
            print(f"   ✗ Failed: {response.status_code}")
            return False
    except Exception as e:
        print(f"   ✗ Error: {e}")
        return False
    
    # Test 2: Get specific certificate without auth
    if certs:
        cert_name = certs[0].get('cert_name')
        if cert_name:
            print(f"\n2. Testing GET /certificates/{cert_name} (get specific)...")
            try:
                response = requests.get(f"{base_url}/certificates/{cert_name}")
                if response.status_code == 200:
                    cert = response.json()
                    print(f"   ✓ Success: Retrieved certificate '{cert_name}'")
                    print(f"   ✓ Domains: {', '.join(cert.get('domains', []))}")
                else:
                    print(f"   ✗ Failed: {response.status_code}")
                    return False
            except Exception as e:
                print(f"   ✗ Error: {e}")
                return False
            
            # Test 3: Check certificate status without auth
            print(f"\n3. Testing GET /certificates/{cert_name}/status...")
            try:
                response = requests.get(f"{base_url}/certificates/{cert_name}/status")
                if response.status_code == 200:
                    status = response.json()
                    print(f"   ✓ Success: Status = {status.get('status', 'unknown')}")
                else:
                    print(f"   ✗ Failed: {response.status_code}")
                    return False
            except Exception as e:
                print(f"   ✗ Error: {e}")
                return False
    
    # Test 4: Verify write operations require auth
    print("\n4. Testing that write operations require authentication...")
    
    # Try to create certificate without auth (should fail)
    print("   - POST /certificates (should fail)...")
    try:
        response = requests.post(
            f"{base_url}/certificates",
            json={
                "domain": "test.example.com",
                "email": "test@example.com",
                "cert_name": "test-cert"
            }
        )
        if response.status_code == 403 or response.status_code == 401:
            print("     ✓ Correctly rejected (401/403)")
        else:
            print(f"     ✗ Unexpected status: {response.status_code}")
            return False
    except Exception as e:
        print(f"     ✗ Error: {e}")
        return False
    
    print("\n✅ All public access tests passed!")
    print("\nSummary:")
    print("- Certificate listing works without authentication")
    print("- Certificate details can be viewed without authentication")
    print("- Certificate status can be checked without authentication")
    print("- Write operations correctly require authentication")
    
    return True


if __name__ == "__main__":
    if not test_public_access():
        sys.exit(1)