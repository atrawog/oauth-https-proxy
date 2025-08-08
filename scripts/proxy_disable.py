#!/usr/bin/env python3
"""Disable a proxy target."""

import sys
import os
import requests

def disable_proxy_target(hostname: str, token: str):
    """Disable a proxy target."""
    if not hostname or not token:
        print("Error: Hostname and token are required")
        return False
    
    api_url = os.getenv('API_URL')
    if not api_url:
        print("Error: API_URL must be set in .env")
        return False
    
    headers = {"Authorization": f"Bearer {token}"}
    
    try:
        # Update the proxy target to disable it
        response = requests.put(
            f"{api_url}/proxy/targets/{hostname}",
            json={"enabled": False},
            headers=headers
        )
        
        if response.status_code == 200:
            proxy = response.json()
            print(f"✓ Proxy target '{hostname}' disabled successfully")
            print(f"  Target URL: {proxy.get('target_url')}")
            print(f"  Certificate: {proxy.get('cert_name')}")
            print(f"\n⚠ Note: The proxy target is now disabled and will not forward requests")
            return True
        elif response.status_code == 404:
            print(f"✗ Proxy target '{hostname}' not found")
            return False
        elif response.status_code == 403:
            print(f"✗ Access denied - you don't own proxy target '{hostname}'")
            return False
        else:
            error = response.json() if response.headers.get('content-type') == 'application/json' else {}
            print(f"✗ Failed to disable proxy target: {error.get('detail', response.text)}")
            return False
            
    except Exception as e:
        print(f"✗ Error: {e}")
        return False


if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: proxy_disable.py <hostname> <token>")
        sys.exit(1)
    
    hostname = sys.argv[1]
    token = sys.argv[2]
    
    if not disable_proxy_target(hostname, token):
        sys.exit(1)