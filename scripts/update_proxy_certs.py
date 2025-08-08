#!/usr/bin/env python3
"""Update proxy targets to reference their certificates."""

import sys
import os
import requests
from dotenv import load_dotenv

load_dotenv()

def update_proxy_certificates():
    """Update proxy targets to reference their generated certificates."""
    api_url = os.getenv('API_URL')
    admin_token = os.getenv('ADMIN_TOKEN')
    
    if not all([api_url, admin_token]):
        print("Error: API_URL and ADMIN_TOKEN must be set in .env")
        return False
    
    headers = {"Authorization": f"Bearer {admin_token}"}
    
    # Get all proxy targets
    print("Fetching proxy targets...")
    response = requests.get(f"{api_url}/proxy/targets", headers=headers)
    if response.status_code != 200:
        print(f"Failed to get proxy targets: {response.status_code}")
        return False
    
    proxies = response.json()
    
    # Get all certificates
    print("Fetching certificates...")
    response = requests.get(f"{api_url}/certificates", headers=headers)
    if response.status_code != 200:
        print(f"Failed to get certificates: {response.status_code}")
        return False
    
    certificates = response.json()
    
    # Create a map of domain to certificate name
    domain_to_cert = {}
    for cert in certificates:
        for domain in cert.get('domains', []):
            domain_to_cert[domain] = cert['cert_name']
    
    print(f"\nFound {len(certificates)} certificate(s) for {len(domain_to_cert)} domain(s)")
    
    # Update proxies
    updated_count = 0
    for proxy in proxies:
        hostname = proxy['hostname']
        current_cert = proxy.get('cert_name')
        expected_cert = domain_to_cert.get(hostname)
        
        if expected_cert and current_cert != expected_cert:
            print(f"\nUpdating {hostname}:")
            print(f"  Current cert: {current_cert or '(none)'}")
            print(f"  New cert: {expected_cert}")
            
            # Update proxy
            update_data = {"cert_name": expected_cert}
            response = requests.put(
                f"{api_url}/proxy/targets/{hostname}",
                json=update_data,
                headers=headers
            )
            
            if response.status_code == 200:
                print(f"  ✓ Updated successfully")
                updated_count += 1
            else:
                print(f"  ✗ Failed to update: {response.status_code}")
                error = response.json() if response.headers.get('content-type') == 'application/json' else {}
                print(f"    Error: {error.get('detail', response.text)}")
    
    if updated_count > 0:
        print(f"\n✓ Updated {updated_count} proxy target(s)")
    else:
        print("\nNo proxy targets needed updating")
    
    return True


if __name__ == "__main__":
    if not update_proxy_certificates():
        sys.exit(1)