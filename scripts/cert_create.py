#!/usr/bin/env python3
"""Create a new certificate via ACME."""

import sys
import os
import requests

def create_certificate(cert_name: str, domain: str, email: str, token: str, staging: bool = False):
    """Create a new certificate."""
    if not all([cert_name, domain, email, token]):
        print("Error: All parameters are required")
        return False
    
    api_url = os.getenv('API_URL')

    
    if not api_url:

    
        print("Error: API_URL must be set in .env")

    
        return False
    headers = {"Authorization": f"Bearer {token}"}
    
    data = {
        "cert_name": cert_name,
        "domain": domain,
        "email": email,
        "acme_directory_url": (
            "https://acme-staging-v02.api.letsencrypt.org/directory" if staging
            else "https://acme-v02.api.letsencrypt.org/directory"
        )
    }
    
    try:
        response = requests.post(
            f"{api_url}/certificates",
            json=data,
            headers=headers
        )
        
        if response.status_code == 200:
            result = response.json()
            print(f"✓ Certificate generation started")
            print(f"  Name: {cert_name}")
            print(f"  Domain: {domain}")
            print(f"  Email: {email}")
            print(f"  Environment: {'Staging' if staging else 'Production'}")
            print(f"\n{result.get('message', '')}")
            print(f"\nCheck status with: just cert-status {cert_name}")
            return True
        else:
            error = response.json() if response.headers.get('content-type') == 'application/json' else {}
            print(f"✗ Failed to create certificate: {error.get('detail', response.text)}")
            return False
            
    except Exception as e:
        print(f"✗ Error: {e}")
        return False


if __name__ == "__main__":
    if len(sys.argv) < 5:
        print("Usage: cert_create.py <cert_name> <domain> <email> <token> [staging]")
        sys.exit(1)
    
    cert_name = sys.argv[1]
    domain = sys.argv[2]
    email = sys.argv[3]
    token = sys.argv[4]
    staging = len(sys.argv) > 5 and sys.argv[5].lower() in ['staging', 'true', '1']
    
    if not create_certificate(cert_name, domain, email, token, staging):
        sys.exit(1)