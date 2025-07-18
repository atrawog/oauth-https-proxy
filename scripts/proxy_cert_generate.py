#!/usr/bin/env python3
"""Generate a certificate for an existing proxy target."""

import sys
import os
import requests
import time

def generate_proxy_certificate(hostname: str, token: str, staging: bool = False):
    """Generate a certificate for an existing proxy and update its cert_name."""
    base_url = os.getenv('BASE_URL')
    if not base_url:
        print("Error: BASE_URL must be set in .env")
        return False
    
    headers = {"Authorization": f"Bearer {token}"}
    
    # Get proxy target
    try:
        response = requests.get(f"{base_url}/proxy/targets/{hostname}", headers=headers)
        if response.status_code == 404:
            print(f"✗ Proxy target {hostname} not found")
            return False
        elif response.status_code != 200:
            error = response.json() if response.headers.get('content-type') == 'application/json' else {}
            print(f"✗ Failed to get proxy target: {error.get('detail', response.text)}")
            return False
        
        proxy = response.json()
        
        # Check if HTTPS is enabled
        if not proxy.get('enable_https', True):
            print(f"✗ HTTPS is disabled for {hostname}")
            print("  Enable HTTPS first with: just proxy-update {hostname} --enable-https=true")
            return False
        
        # Generate certificate name
        cert_name = f"proxy-{hostname.replace('.', '-')}"
        
        # Check if proxy already has a certificate
        if proxy.get('cert_name'):
            print(f"⚠ Proxy already has certificate: {proxy['cert_name']}")
            print("  This will create a new certificate and replace the existing one.")
        
        # Get token info for email
        response = requests.get(f"{base_url}/token/info", headers=headers)
        if response.status_code != 200:
            print("✗ Failed to get token info")
            return False
        
        token_info = response.json()
        email = token_info.get('cert_email')
        if not email:
            print("✗ No certificate email configured for token")
            print("  Set email with: just token-email-update <email>")
            return False
        
        # Create certificate
        print(f"Generating {'staging' if staging else 'production'} certificate for {hostname}...")
        
        cert_data = {
            "cert_name": cert_name,
            "domain": hostname,
            "email": email,
            "acme_directory_url": (
                "https://acme-staging-v02.api.letsencrypt.org/directory" if staging
                else "https://acme-v02.api.letsencrypt.org/directory"
            )
        }
        
        response = requests.post(f"{base_url}/certificates", json=cert_data, headers=headers)
        
        if response.status_code != 200:
            error = response.json() if response.headers.get('content-type') == 'application/json' else {}
            print(f"✗ Failed to create certificate: {error.get('detail', response.text)}")
            return False
        
        result = response.json()
        print(f"✓ {result.get('message', 'Certificate generation started')}")
        
        # Wait for certificate generation
        print("Waiting for certificate generation...")
        max_attempts = 30
        for attempt in range(max_attempts):
            time.sleep(2)
            
            response = requests.get(f"{base_url}/certificates/{cert_name}/status", headers=headers)
            if response.status_code == 200:
                status_data = response.json()
                status = status_data.get('status', 'unknown')
                
                if status == 'completed':
                    print("✓ Certificate generated successfully")
                    break
                elif status == 'failed':
                    print(f"✗ Certificate generation failed: {status_data.get('message', 'Unknown error')}")
                    return False
                else:
                    print(f"  ... {status_data.get('message', 'Generating...')}", end='\r')
        else:
            print("\n✗ Certificate generation timed out")
            return False
        
        # Update proxy with certificate name
        print(f"\nUpdating proxy to use certificate...")
        update_data = {"cert_name": cert_name}
        response = requests.put(
            f"{base_url}/proxy/targets/{hostname}",
            json=update_data,
            headers=headers
        )
        
        if response.status_code == 200:
            print(f"✓ Proxy updated with certificate: {cert_name}")
            print(f"\nCertificate Details:")
            print(f"  Name: {cert_name}")
            print(f"  Domain: {hostname}")
            print(f"  Email: {email}")
            print(f"  Environment: {'Staging' if staging else 'Production'}")
            return True
        else:
            error = response.json() if response.headers.get('content-type') == 'application/json' else {}
            print(f"✗ Failed to update proxy: {error.get('detail', response.text)}")
            return False
            
    except Exception as e:
        print(f"✗ Error: {e}")
        return False


if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: proxy_cert_generate.py <hostname> <token> [staging]")
        sys.exit(1)
    
    hostname = sys.argv[1]
    token = sys.argv[2]
    staging = len(sys.argv) > 3 and sys.argv[3].lower() in ['staging', 'true', '1']
    
    if not generate_proxy_certificate(hostname, token, staging):
        sys.exit(1)