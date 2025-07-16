#!/usr/bin/env python3
"""Create a new proxy target."""

import sys
import os
import requests

def create_proxy_target(hostname: str, target_url: str, token: str, staging: bool = False, preserve_host: bool = True):
    """Create a new proxy target."""
    if not all([hostname, target_url, token]):
        print("Error: All parameters are required")
        return False
    
    base_url = os.getenv('BASE_URL')
    if not base_url:
        print("Error: BASE_URL must be set in .env")
        return False
    
    headers = {"Authorization": f"Bearer {token}"}
    
    data = {
        "hostname": hostname,
        "target_url": target_url,
        "preserve_host_header": preserve_host
    }
    
    # Add staging ACME directory URL if requested
    if staging:
        data["acme_directory_url"] = "https://acme-staging-v02.api.letsencrypt.org/directory"
    
    try:
        response = requests.post(
            f"{base_url}/proxy/targets",
            json=data,
            headers=headers
        )
        
        if response.status_code == 200:
            result = response.json()
            proxy_target = result.get("proxy_target", {})
            cert_status = result.get("certificate_status", "")
            
            print(f"✓ Proxy target created successfully")
            print(f"  Hostname: {proxy_target.get('hostname')}")
            print(f"  Target URL: {proxy_target.get('target_url')}")
            print(f"  Certificate: {proxy_target.get('cert_name')}")
            print(f"  Enabled: {proxy_target.get('enabled', True)}")
            print(f"  Preserve Host: {proxy_target.get('preserve_host_header', True)}")
            print(f"  Environment: {'Staging' if staging else 'Production'}")
            
            if cert_status:
                print(f"\n{cert_status}")
                print(f"\nCheck certificate status with: just cert-status {proxy_target.get('cert_name')}")
            
            return True
        else:
            error = response.json() if response.headers.get('content-type') == 'application/json' else {}
            print(f"✗ Failed to create proxy target: {error.get('detail', response.text)}")
            return False
            
    except Exception as e:
        print(f"✗ Error: {e}")
        return False


if __name__ == "__main__":
    if len(sys.argv) < 4:
        print("Usage: proxy_create.py <hostname> <target_url> <token> [staging] [preserve_host]")
        sys.exit(1)
    
    hostname = sys.argv[1]
    target_url = sys.argv[2]
    token = sys.argv[3]
    staging = len(sys.argv) > 4 and sys.argv[4].lower() in ['staging', 'true', '1']
    preserve_host = True if len(sys.argv) <= 5 else sys.argv[5].lower() in ['true', '1']
    
    if not create_proxy_target(hostname, target_url, token, staging, preserve_host):
        sys.exit(1)