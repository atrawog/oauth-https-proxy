#!/usr/bin/env python
"""Manual test for certificate generation with cleanup."""

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
    
    if not all([domain, email, acme_url]):
        print("ERROR: Missing environment variables")
        sys.exit(1)
    
    print(f"Domain: {domain}")
    print(f"Email: {email}")
    print(f"ACME URL: {acme_url}")
    
    # Get auth token if provided
    token = sys.argv[1] if len(sys.argv) > 1 else None
    
    # Create client
    api_url = os.getenv("TEST_API_URL")
    assert api_url, "TEST_API_URL not set"
    
    cert_name = 'test-manual'
    cert_created = False
    
    with httpx.Client(api_url=api_url) as client:
        # Add auth if token provided
        if token:
            client.headers["Authorization"] = f"Bearer {token}"
        
        try:
            # Create certificate request
            print("\nRequesting certificate...")
            response = client.post('/certificates', json={
                'domain': domain,
                'email': email, 
                'cert_name': cert_name,
                'acme_directory_url': acme_url
            }, timeout=120)
            
            print(f'\nStatus: {response.status_code}')
            if response.status_code == 200:
                result = response.json()
                if result.get("status") == "accepted":
                    cert_created = True
                    print('Certificate generation started!')
                    
                    # Poll for completion
                    print("\nPolling for completion...")
                    for i in range(60):
                        time.sleep(2)
                        status_response = client.get(f"/certificates/{cert_name}/status")
                        if status_response.status_code == 200:
                            status = status_response.json()
                            print(f"  Attempt {i+1}: {status['status']} - {status['message']}")
                            
                            if status["status"] == "completed":
                                # Get the certificate
                                cert_response = client.get(f"/certificates/{cert_name}")
                                if cert_response.status_code == 200:
                                    cert = cert_response.json()
                                    print(f"\nCertificate issued for: {cert['domains']}")
                                    print(f"Expires: {cert['expires_at']}")
                                    print(f"Fingerprint: {cert['fingerprint']}")
                                    
                                    # Verify certificate is valid
                                    if cert['fullchain_pem'].startswith('-----BEGIN CERTIFICATE-----'):
                                        print("✓ Certificate PEM looks valid")
                                    if cert['private_key_pem'].startswith('-----BEGIN PRIVATE KEY-----'):
                                        print("✓ Private key PEM looks valid")
                                break
                            elif status["status"] == "failed":
                                print("\nCertificate generation failed!")
                                break
                else:
                    # Synchronous response (backward compatibility)
                    cert = result
                    cert_created = True
                    print('Success!')
                    print(f"Certificate issued for: {cert['domains']}")
                    print(f"Expires: {cert['expires_at']}")
                    print(f"Fingerprint: {cert['fingerprint']}")
                    
                    # Verify certificate is valid
                    if cert['fullchain_pem'].startswith('-----BEGIN CERTIFICATE-----'):
                        print("✓ Certificate PEM looks valid")
                    if cert['private_key_pem'].startswith('-----BEGIN PRIVATE KEY-----'):
                        print("✓ Private key PEM looks valid")
            else:
                print(f'Error: {response.text}')
                sys.exit(1)
        
        finally:
            # Cleanup: Delete the certificate if it was created and we have a token
            if cert_created and token:
                print(f"\nCleaning up certificate: {cert_name}")
                try:
                    delete_response = client.delete(f"/certificates/{cert_name}")
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