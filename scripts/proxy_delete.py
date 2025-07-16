#!/usr/bin/env python3
"""Delete a proxy target."""

import sys
import os
import requests
import argparse

def delete_proxy_target(hostname: str, token: str, delete_certificate: bool = False, force: bool = False):
    """Delete a proxy target."""
    if not hostname or not token:
        print("Error: Hostname and token are required")
        return False
    
    base_url = os.getenv('BASE_URL')
    if not base_url:
        print("Error: BASE_URL must be set in .env")
        return False
    
    headers = {"Authorization": f"Bearer {token}"}
    
    try:
        # First get the proxy target to show details
        response = requests.get(
            f"{base_url}/proxy/targets/{hostname}",
            headers=headers
        )
        
        if response.status_code == 404:
            print(f"✗ Proxy target '{hostname}' not found")
            return False
        elif response.status_code != 200:
            print(f"✗ Failed to get proxy target: {response.status_code}")
            return False
        
        proxy = response.json()
        
        # Confirm deletion
        if not force:
            print(f"=== Proxy Target Details ===")
            print(f"Hostname: {hostname}")
            print(f"Target URL: {proxy.get('target_url', 'Unknown')}")
            print(f"Certificate: {proxy.get('cert_name', 'N/A')}")
            print(f"Owner: {proxy.get('created_by', 'Unknown')}")
            print(f"Enabled: {'Yes' if proxy.get('enabled', True) else 'No'}")
            
            if delete_certificate and proxy.get('cert_name'):
                print(f"\n⚠ WARNING: This will also delete the certificate '{proxy.get('cert_name')}'!")
            
            confirm = input(f"\nAre you sure you want to delete proxy target '{hostname}'? (yes/no): ")
            if confirm.lower() != 'yes':
                print("Deletion cancelled.")
                return False
        
        # Delete the proxy target
        print(f"\nDeleting proxy target '{hostname}'...")
        
        params = {}
        if delete_certificate:
            params['delete_certificate'] = 'true'
        
        response = requests.delete(
            f"{base_url}/proxy/targets/{hostname}",
            headers=headers,
            params=params
        )
        
        if response.status_code in [200, 204]:
            print(f"✓ Proxy target '{hostname}' deleted successfully")
            if delete_certificate and proxy.get('cert_name'):
                print(f"✓ Certificate '{proxy.get('cert_name')}' also deleted")
            return True
        elif response.status_code == 403:
            print(f"✗ Access denied - you don't own proxy target '{hostname}'")
            return False
        else:
            error = response.json() if response.headers.get('content-type') == 'application/json' else {}
            print(f"✗ Failed to delete proxy target: {error.get('detail', response.text)}")
            return False
        
    except Exception as e:
        print(f"✗ Error: {e}")
        return False


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Delete a proxy target')
    parser.add_argument('hostname', help='Hostname of the proxy target')
    parser.add_argument('token', help='API token for authentication')
    parser.add_argument('--delete-certificate', action='store_true', 
                       help='Also delete the associated certificate')
    parser.add_argument('--force', action='store_true',
                       help='Skip confirmation prompt')
    
    args = parser.parse_args()
    
    if not delete_proxy_target(args.hostname, args.token, 
                              args.delete_certificate, args.force):
        sys.exit(1)