#!/usr/bin/env python3
"""Show proxy target details."""

import sys
import os
import requests
import json
from datetime import datetime

def show_proxy_target(hostname: str):
    """Display proxy target details."""
    if not hostname:
        print("Error: Hostname is required")
        return False
    
    base_url = os.getenv('BASE_URL')
    if not base_url:
        print("Error: BASE_URL must be set in .env")
        return False
    
    try:
        response = requests.get(
            f"{base_url}/proxy/targets/{hostname}"
        )
        
        if response.status_code == 200:
            proxy = response.json()
            
            print(f"=== Proxy Target: {hostname} ===\n")
            print(f"Target URL: {proxy.get('target_url', 'Unknown')}")
            print(f"Certificate: {proxy.get('cert_name', 'N/A')}")
            print(f"Enabled: {'Yes' if proxy.get('enabled', True) else 'No'}")
            print(f"HTTP Enabled: {'Yes' if proxy.get('enable_http', True) else 'No'}")
            print(f"HTTPS Enabled: {'Yes' if proxy.get('enable_https', True) else 'No'}")
            print(f"Preserve Host Header: {'Yes' if proxy.get('preserve_host_header', True) else 'No'}")
            print(f"Owner: {proxy.get('created_by', 'Unknown')}")
            
            # Parse dates
            created = proxy.get('created_at')
            if created:
                created_dt = datetime.fromisoformat(created.replace('Z', '+00:00'))
                print(f"Created: {created_dt.strftime('%Y-%m-%d %H:%M UTC')}")
            
            # Show custom headers if any
            custom_headers = proxy.get('custom_headers')
            if custom_headers:
                print("\nCustom Headers:")
                for key, value in custom_headers.items():
                    print(f"  {key}: {value}")
            
            # Show URL examples based on enabled protocols
            print("\nExample URLs:")
            if proxy.get('enable_http', True):
                print(f"  http://{hostname}/ → {proxy.get('target_url', 'Unknown')}")
                print(f"  http://{hostname}/api/v1 → {proxy.get('target_url', 'Unknown')}/api/v1")
            if proxy.get('enable_https', True):
                print(f"  https://{hostname}/ → {proxy.get('target_url', 'Unknown')}")
                print(f"  https://{hostname}/api/v1 → {proxy.get('target_url', 'Unknown')}/api/v1")
            
            return True
        elif response.status_code == 404:
            print(f"✗ Proxy target '{hostname}' not found")
            return False
        else:
            error = response.json() if response.headers.get('content-type') == 'application/json' else {}
            print(f"✗ Error: {error.get('detail', response.text)}")
            return False
            
    except Exception as e:
        print(f"✗ Error: {e}")
        return False


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: proxy_show.py <hostname>")
        sys.exit(1)
    
    hostname = sys.argv[1]
    
    if not show_proxy_target(hostname):
        sys.exit(1)