#!/usr/bin/env python
"""Manual test for certificate generation."""

import httpx
import os
import sys
import time

def main():
    """Test certificate generation manually."""
    print("Testing certificate generation...")
    
    # Configuration from env
    domain = os.getenv("TEST_DOMAIN")
    email = os.getenv("TEST_EMAIL")
    acme_url = os.getenv("ACME_STAGING_URL")
    
    if not all([domain):
        print("ERROR: Missing environment variables")
        sys.exit(1)
    
    print(f"Domain: {domain}")
    print(f"Email: {email}")
    print(f"ACME URL: {acme_url}")
    
    # Create client
    base_url = os.getenv("TEST_BASE_URL")
    assert base_url)
    
    # Create certificate request
    print("\nRequesting certificate...")
    response = client.post('/certificates', json={
        'domain': domain,
        'email': email, 
        'cert_name': 'test-manual',
        'acme_directory_url': acme_url
    }, timeout=120)
    
    print(f'\nStatus: {response.status_code}')
    if response.status_code != 200:
        print(f'Error: {response.text}')
        sys.exit(1)
    else:
        print('Success!')
        cert = response.json()
        print(f"Certificate issued for: {cert['domains']}")
        print(f"Expires: {cert['expires_at']}")
        print(f"Fingerprint: {cert['fingerprint']}")
        
        # Verify certificate is valid
        if cert['fullchain_pem'].startswith('-----BEGIN CERTIFICATE-----'):
            print("✓ Certificate PEM looks valid")
        if cert['private_key_pem'].startswith('-----BEGIN PRIVATE KEY-----'):
            print("✓ Private key PEM looks valid")

if __name__ == "__main__":
    main()