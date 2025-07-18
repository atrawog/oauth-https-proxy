#!/usr/bin/env python3
"""Create a wildcard certificate via ACME."""

import sys
import os
import requests
import time

def create_wildcard_certificate(cert_name: str, base_domain: str, email: str, token: str, staging: bool = False):
    """Create a wildcard certificate for a base domain."""
    if not all([cert_name, base_domain, email, token]):
        print("Error: All parameters are required")
        return False
    
    base_url = os.getenv('BASE_URL')
    if not base_url:
        print("Error: BASE_URL must be set in .env")
        return False
    
    headers = {"Authorization": f"Bearer {token}"}
    
    # Create wildcard and base domain entries
    domains = [f"*.{base_domain}", base_domain]
    
    data = {
        "cert_name": cert_name,
        "domains": domains,
        "email": email,
        "acme_directory_url": (
            "https://acme-staging-v02.api.letsencrypt.org/directory" if staging
            else "https://acme-v02.api.letsencrypt.org/directory"
        )
    }
    
    try:
        print(f"Creating wildcard certificate '{cert_name}'...")
        print(f"  Base domain: {base_domain}")
        print(f"  Will cover: {', '.join(domains)}")
        print(f"  Email: {email}")
        print(f"  Environment: {'Staging' if staging else 'Production'}")
        
        # Note about DNS challenge requirement
        print("\n⚠️  IMPORTANT: Wildcard certificates require DNS-01 challenge")
        print("  You will need to add a TXT record to your DNS:")
        print(f"  _acme-challenge.{base_domain}")
        print("  The value will be provided during certificate generation.")
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
                max_attempts = 60  # Longer wait for DNS propagation
                for attempt in range(max_attempts):
                    time.sleep(3)
                    
                    status_response = requests.get(
                        f"{base_url}/certificates/{cert_name}/status",
                        headers=headers
                    )
                    
                    if status_response.status_code == 200:
                        status_data = status_response.json()
                        status = status_data.get('status', 'unknown')
                        
                        if status == 'completed':
                            print("\n✓ Wildcard certificate generated successfully!")
                            return True
                        elif status == 'failed':
                            print(f"\n✗ Certificate generation failed: {status_data.get('message', 'Unknown error')}")
                            if 'DNS' in status_data.get('message', ''):
                                print("\n  Hint: Make sure you've added the required DNS TXT record")
                            return False
                        else:
                            print(f"  ... {status_data.get('message', 'Generating...')}", end='\r')
                else:
                    print("\n✗ Certificate generation timed out")
                    print("  Wildcard certificates can take longer due to DNS propagation")
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
        print("Usage: cert_create_wildcard.py <cert_name> <base_domain> <email> <token> [staging]")
        print("")
        print("Examples:")
        print('  cert_create_wildcard.py myapp-wildcard myapp.com admin@example.com $TOKEN')
        print('  cert_create_wildcard.py staging-wildcard staging.example.com admin@example.com $TOKEN staging')
        print("")
        print("This will create a certificate covering:")
        print("  - *.base_domain (all subdomains)")
        print("  - base_domain (the root domain)")
        print("")
        print("Options:")
        print("  staging - Use Let's Encrypt staging environment")
        print("  --wait  - Wait for certificate generation to complete")
        print("")
        print("⚠️  Note: Wildcard certificates require DNS-01 challenge validation")
        print("  Currently only HTTP-01 is implemented. This command prepares")
        print("  the request but may fail during validation.")
        sys.exit(1)
    
    cert_name = sys.argv[1]
    base_domain = sys.argv[2]
    email = sys.argv[3]
    token = sys.argv[4]
    staging = len(sys.argv) > 5 and sys.argv[5].lower() in ['staging', 'true', '1']
    
    if not create_wildcard_certificate(cert_name, base_domain, email, token, staging):
        sys.exit(1)