#!/usr/bin/env python3
"""Convert a certificate from staging to production and update proxy associations."""

import sys
import os
import requests
import time

def convert_to_production(cert_name: str, token: str):
    """Convert certificate to production and maintain proxy associations."""
    api_url = os.getenv('API_URL')
    if not api_url:
        print("Error: API_URL must be set in .env")
        return False
    
    headers = {"Authorization": f"Bearer {token}"}
    
    try:
        # First, find all proxies using this certificate
        print(f"Checking for proxies using certificate {cert_name}...")
        response = requests.get(f"{api_url}/proxy/targets", headers=headers)
        if response.status_code != 200:
            print(f"Failed to get proxy targets: {response.status_code}")
            return False
        
        proxies = response.json()
        affected_proxies = []
        for proxy in proxies:
            if proxy.get('cert_name') == cert_name:
                affected_proxies.append(proxy['hostname'])
                print(f"  Found proxy: {proxy['hostname']}")
        
        if affected_proxies:
            print(f"\nThis certificate is used by {len(affected_proxies)} proxy target(s)")
        
        # Convert certificate to production
        print(f"\nConverting certificate {cert_name} to production...")
        response = requests.post(
            f"{api_url}/certificates/{cert_name}/convert-to-production",
            headers=headers
        )
        
        if response.status_code != 200:
            error = response.json() if response.headers.get('content-type') == 'application/json' else {}
            print(f"✗ Failed to convert certificate: {error.get('detail', response.text)}")
            return False
        
        result = response.json()
        print(f"✓ {result.get('message', 'Conversion started')}")
        
        # Wait for certificate generation
        print("\nWaiting for production certificate generation...")
        max_attempts = 30
        for attempt in range(max_attempts):
            time.sleep(2)
            
            response = requests.get(f"{api_url}/certificates/{cert_name}/status", headers=headers)
            if response.status_code == 200:
                status_data = response.json()
                status = status_data.get('status', 'unknown')
                
                if status == 'completed':
                    print("✓ Production certificate generated successfully")
                    break
                elif status == 'failed':
                    print(f"✗ Certificate generation failed: {status_data.get('message', 'Unknown error')}")
                    return False
                else:
                    print(f"  ... {status_data.get('message', 'Generating...')}", end='\r')
        else:
            print("\n✗ Certificate generation timed out")
            return False
        
        # Re-attach certificate to affected proxies
        if affected_proxies:
            print(f"\nRe-attaching certificate to {len(affected_proxies)} proxy target(s)...")
            for hostname in affected_proxies:
                print(f"  Updating {hostname}...", end='')
                update_data = {"cert_name": cert_name}
                response = requests.put(
                    f"{api_url}/proxy/targets/{hostname}",
                    json=update_data,
                    headers=headers
                )
                
                if response.status_code == 200:
                    print(" ✓")
                else:
                    print(f" ✗ (Error: {response.status_code})")
        
        print(f"\n✓ Successfully converted {cert_name} to production")
        if affected_proxies:
            print(f"  Certificate re-attached to all proxy targets")
        
        return True
        
    except Exception as e:
        print(f"✗ Error: {e}")
        return False


if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: cert_to_production.py <cert_name> <token>")
        sys.exit(1)
    
    cert_name = sys.argv[1]
    token = sys.argv[2]
    
    if not convert_to_production(cert_name, token):
        sys.exit(1)