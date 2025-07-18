#!/usr/bin/env python3
"""Create a multi-domain certificate via ACME."""

import sys
import os
import requests
import time

def create_multi_domain_certificate(cert_name: str, domains: str, email: str, token: str, staging: bool = False):
    """Create a multi-domain certificate."""
    if not all([cert_name, domains, email, token]):
        print("Error: All parameters are required")
        return False
    
    base_url = os.getenv('BASE_URL')
    if not base_url:
        print("Error: BASE_URL must be set in .env")
        return False
    
    headers = {"Authorization": f"Bearer {token}"}
    
    # Parse domains
    domain_list = [d.strip() for d in domains.split(',') if d.strip()]
    if not domain_list:
        print("Error: No valid domains provided")
        return False
    
    data = {
        "cert_name": cert_name,
        "domains": domain_list,
        "email": email,
        "acme_directory_url": (
            "https://acme-staging-v02.api.letsencrypt.org/directory" if staging
            else "https://acme-v02.api.letsencrypt.org/directory"
        )
    }
    
    try:
        print(f"Creating multi-domain certificate '{cert_name}'...")
        print(f"  Domains: {', '.join(domain_list)}")
        print(f"  Email: {email}")
        print(f"  Environment: {'Staging' if staging else 'Production'}")
        print("")
        
        response = requests.post(
            f"{base_url}/certificates/multi-domain",
            json=data,
            headers=headers
        )
        
        if response.status_code == 200:
            result = response.json()
            print(f"✓ Certificate generation started")
            print(f"  {result.get('message', '')}")
            print(f"\nCheck status with: just cert-status {cert_name}")
            
            # Option to wait for completion
            if "--wait" in sys.argv:
                print("\nWaiting for certificate generation...")
                max_attempts = 30
                for attempt in range(max_attempts):
                    time.sleep(2)
                    
                    status_response = requests.get(
                        f"{base_url}/certificates/{cert_name}/status",
                        headers=headers
                    )
                    
                    if status_response.status_code == 200:
                        status_data = status_response.json()
                        status = status_data.get('status', 'unknown')
                        
                        if status == 'completed':
                            print("\n✓ Certificate generated successfully!")
                            return True
                        elif status == 'failed':
                            print(f"\n✗ Certificate generation failed: {status_data.get('message', 'Unknown error')}")
                            return False
                        else:
                            print(f"  ... {status_data.get('message', 'Generating...')}", end='\r')
                else:
                    print("\n✗ Certificate generation timed out")
                    return False
            
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
        print("Usage: cert_create_multi.py <cert_name> <domains> <email> <token> [staging]")
        print("")
        print("Examples:")
        print('  cert_create_multi.py echo-services "echo-stateful.atradev.org,echo-stateless.atradev.org" admin@example.com $TOKEN')
        print('  cert_create_multi.py api-cert "api.example.com,api-v2.example.com" admin@example.com $TOKEN staging')
        print("")
        print("Options:")
        print("  staging - Use Let's Encrypt staging environment")
        print("  --wait  - Wait for certificate generation to complete")
        sys.exit(1)
    
    cert_name = sys.argv[1]
    domains = sys.argv[2]
    email = sys.argv[3]
    token = sys.argv[4]
    staging = len(sys.argv) > 5 and sys.argv[5].lower() in ['staging', 'true', '1']
    
    if not create_multi_domain_certificate(cert_name, domains, email, token, staging):
        sys.exit(1)