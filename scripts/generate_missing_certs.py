#!/usr/bin/env python3
"""Generate certificates for all HTTPS-enabled proxies without certificates."""

import sys
import os
import json
import time
import requests
from dotenv import load_dotenv

load_dotenv()

def generate_missing_certificates(use_staging=True):
    """Generate certificates for all proxies that have HTTPS enabled but no certificate."""
    api_url = os.getenv('API_URL')
    admin_token = os.getenv('ADMIN_TOKEN')
    admin_email = os.getenv('ADMIN_EMAIL', 'atrawog@gmail.com')
    
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
    proxies_needing_certs = []
    
    # Find proxies with HTTPS enabled but no certificate
    for proxy in proxies:
        if proxy.get('enable_https', True) and not proxy.get('cert_name'):
            proxies_needing_certs.append(proxy)
    
    if not proxies_needing_certs:
        print("All HTTPS-enabled proxies already have certificates!")
        return True
    
    print(f"\nFound {len(proxies_needing_certs)} proxy(ies) needing certificates:")
    for proxy in proxies_needing_certs:
        print(f"  - {proxy['hostname']}")
    
    # Generate certificates
    environment = "Staging" if use_staging else "Production"
    acme_url = ("https://acme-staging-v02.api.letsencrypt.org/directory" if use_staging 
                else "https://acme-v02.api.letsencrypt.org/directory")
    
    print(f"\nGenerating {environment} certificates...")
    
    generated_certs = []
    for proxy in proxies_needing_certs:
        hostname = proxy['hostname']
        cert_name = f"proxy-{hostname.replace('.', '-')}"
        
        print(f"\nGenerating certificate for {hostname}...")
        
        cert_data = {
            "cert_name": cert_name,
            "domain": hostname,
            "email": admin_email,
            "acme_directory_url": acme_url
        }
        
        response = requests.post(
            f"{api_url}/certificates",
            json=cert_data,
            headers=headers
        )
        
        if response.status_code == 200:
            result = response.json()
            print(f"  ✓ Certificate generation started: {result.get('message', '')}")
            generated_certs.append({
                "hostname": hostname,
                "cert_name": cert_name,
                "status": "started"
            })
        else:
            print(f"  ✗ Failed to start certificate generation: {response.status_code}")
            error = response.json() if response.headers.get('content-type') == 'application/json' else {}
            print(f"    Error: {error.get('detail', response.text)}")
    
    if not generated_certs:
        print("\nNo certificates were generated successfully.")
        return False
    
    # Wait for certificates to complete
    print(f"\nWaiting for {len(generated_certs)} certificate(s) to complete...")
    print("This may take a minute...")
    
    max_attempts = 30  # 30 attempts * 2 seconds = 60 seconds max
    for attempt in range(max_attempts):
        time.sleep(2)
        
        all_complete = True
        for cert_info in generated_certs:
            if cert_info["status"] in ["completed", "failed"]:
                continue
            
            # Check status
            response = requests.get(
                f"{api_url}/certificates/{cert_info['cert_name']}/status",
                headers=headers
            )
            
            if response.status_code == 200:
                status_data = response.json()
                status = status_data.get("status", "unknown")
                
                if status == "completed":
                    cert_info["status"] = "completed"
                    print(f"  ✓ {cert_info['hostname']}: Certificate generated successfully")
                elif status == "failed":
                    cert_info["status"] = "failed"
                    print(f"  ✗ {cert_info['hostname']}: Certificate generation failed")
                    print(f"    Error: {status_data.get('message', 'Unknown error')}")
                else:
                    all_complete = False
        
        if all_complete:
            break
        
        # Show progress
        in_progress = sum(1 for c in generated_certs if c["status"] == "started")
        if in_progress > 0:
            print(f"  ... {in_progress} certificate(s) still generating...", end='\r')
    
    # Summary
    print("\n\nSummary:")
    completed = sum(1 for c in generated_certs if c["status"] == "completed")
    failed = sum(1 for c in generated_certs if c["status"] == "failed")
    
    print(f"  Completed: {completed}")
    print(f"  Failed: {failed}")
    
    if completed > 0:
        print(f"\n✓ Successfully generated {completed} {environment.lower()} certificate(s)")
        print("\nNext steps:")
        if use_staging:
            print("  1. Test the staging certificates")
            print("  2. Run this script with --production to generate production certificates")
        else:
            print("  Your production certificates are ready!")
    
    return completed > 0


if __name__ == "__main__":
    # Check for --production flag
    use_staging = "--production" not in sys.argv
    
    if not generate_missing_certificates(use_staging):
        sys.exit(1)