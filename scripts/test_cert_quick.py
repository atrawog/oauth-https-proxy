#!/usr/bin/env python
"""Quick certificate test with cleanup."""

import httpx
import json
import os
import time
import sys

# Get base URL from .env
base_url = os.getenv("TEST_BASE_URL")
assert base_url, "TEST_BASE_URL not set"

# Get auth token if provided
token = sys.argv[1] if len(sys.argv) > 1 else None

# Create client with auth if token provided
client = httpx.Client(base_url=base_url)
if token:
    client.headers["Authorization"] = f"Bearer {token}"

cert_name = None
try:
    print("Requesting certificate...")
    response = client.post('/certificates', json={
        'domain': 'test.atradev.org',
        'email': 'test@atradev.org',
        'cert_name': 'test-quick',
        'acme_directory_url': os.getenv("ACME_STAGING_URL")
    })

    print(f"Status: {response.status_code}")
    result = response.json()
    print(f"Response: {result}")

    if response.status_code == 200 and result.get("status") == "accepted":
        # Poll for completion
        cert_name = result["cert_name"]
        print(f"\nPolling for completion...")
        
        for i in range(60):
            time.sleep(2)
            status_response = client.get(f"/certificates/{cert_name}/status")
            status = status_response.json()
            print(f"  Attempt {i+1}: {status['status']} - {status['message']}")
            
            if status["status"] in ["completed", "failed"]:
                break
        
        if status["status"] == "completed":
            cert_response = client.get(f"/certificates/{cert_name}")
            if cert_response.status_code == 200:
                cert = cert_response.json()
                print(f"\nSUCCESS! Certificate issued for: {cert['domains']}")
                print(f"Expires: {cert['expires_at']}")
                print(f"Certificate valid: {cert['fullchain_pem'].startswith('-----BEGIN CERTIFICATE-----')}")
            else:
                print(f"\nFailed to retrieve certificate: {cert_response.status_code}")
        else:
            print(f"\nCertificate generation failed!")
    else:
        print(f"Error: {response.text[:500]}")

finally:
    # Cleanup: Delete the certificate if it was created
    if cert_name and token:
        print(f"\nCleaning up certificate: {cert_name}")
        try:
            delete_response = client.delete(f"/certificates/{cert_name}")
            if delete_response.status_code == 200:
                print("✓ Certificate deleted successfully")
            else:
                print(f"⚠ Failed to delete certificate: {delete_response.status_code}")
        except Exception as e:
            print(f"⚠ Error during cleanup: {e}")
    
    client.close()