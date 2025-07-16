#!/usr/bin/env python3
"""Enable a proxy target."""

import sys
import os
import requests

def enable_proxy_target(hostname: str, token: str):
    """Enable a proxy target."""
    if not hostname or not token:
        print("Error: Hostname and token are required")
        return False
    
    base_url = os.getenv('BASE_URL')
    if not base_url:
        print("Error: BASE_URL must be set in .env")
        return False
    
    headers = {"Authorization": f"Bearer {token}"}
    
    try:
        # Update the proxy target to enable it
        response = requests.put(
            f"{base_url}/proxy/targets/{hostname}",
            json={"enabled": True},
            headers=headers
        )
        
        if response.status_code == 200:
            proxy = response.json()
            print(f"✓ Proxy target '{hostname}' enabled successfully")
            print(f"  Target URL: {proxy.get('target_url')}")
            print(f"  Certificate: {proxy.get('cert_name')}")
            return True
        elif response.status_code == 404:
            print(f"✗ Proxy target '{hostname}' not found")
            return False
        elif response.status_code == 403:
            print(f"✗ Access denied - you don't own proxy target '{hostname}'")
            return False
        else:
            error = response.json() if response.headers.get('content-type') == 'application/json' else {}
            print(f"✗ Failed to enable proxy target: {error.get('detail', response.text)}")
            return False
            
    except Exception as e:
        print(f"✗ Error: {e}")
        return False


if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: proxy_enable.py <hostname> <token>")
        sys.exit(1)
    
    hostname = sys.argv[1]
    token = sys.argv[2]
    
    if not enable_proxy_target(hostname, token):
        sys.exit(1)