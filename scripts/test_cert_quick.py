#!/usr/bin/env python
"""Quick certificate test."""

import httpx
import json
import os

# Get base URL from .env
base_url = os.getenv("TEST_BASE_URL")
assert base_url, "TEST_BASE_URL must be set in .env"

client = httpx.Client(base_url=base_url, timeout=180)

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
    
    import time
    for i in range(60):
        time.sleep(2)
        status_response = client.get(f"/certificates/{cert_name}/status")
        status = status_response.json()
        print(f"  Attempt {i+1}: {status['status']} - {status['message']}")
        
        if status["status"] in ["completed", "failed"]:
            break
    
    # Try to get the certificate
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