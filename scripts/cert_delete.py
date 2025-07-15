#!/usr/bin/env python3
"""Delete a certificate."""

import sys
import os
import requests

def delete_certificate(cert_name: str, token: str, force: bool = False):
    """Delete a certificate by removing all its domains."""
    if not cert_name or not token:
        print("Error: Certificate name and token are required")
        return False
    
    base_url = os.getenv('BASE_URL', 'http://localhost:80')
    headers = {"Authorization": f"Bearer {token}"}
    
    try:
        # First get the certificate to see its domains
        response = requests.get(
            f"{base_url}/certificates/{cert_name}",
            headers=headers
        )
        
        if response.status_code == 404:
            print(f"✗ Certificate '{cert_name}' not found")
            return False
        elif response.status_code == 403:
            print(f"✗ Access denied - you don't own certificate '{cert_name}'")
            return False
        elif response.status_code != 200:
            print(f"✗ Failed to get certificate: {response.status_code}")
            return False
        
        cert = response.json()
        domains = cert.get('domains', [])
        
        if not domains:
            print(f"Certificate '{cert_name}' has no domains")
            return True
        
        # Confirm deletion
        if not force:
            print(f"=== Certificate Details ===")
            print(f"Name: {cert_name}")
            print(f"Domains: {', '.join(domains)}")
            print(f"Status: {cert.get('status', 'Unknown')}")
            
            confirm = input(f"\nAre you sure you want to delete certificate '{cert_name}'? (yes/no): ")
            if confirm.lower() != 'yes':
                print("Deletion cancelled.")
                return False
        
        # Delete by removing all domains (API design limitation)
        print(f"\nDeleting certificate '{cert_name}'...")
        
        # Remove each domain (the last one will delete the certificate)
        for i, domain in enumerate(domains):
            response = requests.delete(
                f"{base_url}/certificates/{cert_name}/domains/{domain}",
                headers=headers
            )
            
            if response.status_code in [200, 204]:
                if i < len(domains) - 1:
                    print(f"  ✓ Removed domain: {domain}")
                else:
                    print(f"  ✓ Removed last domain: {domain}")
                    print(f"\n✓ Certificate '{cert_name}' deleted successfully")
            else:
                print(f"  ✗ Failed to remove domain {domain}: {response.status_code}")
                return False
        
        return True
        
    except Exception as e:
        print(f"✗ Error: {e}")
        return False


if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: cert_delete.py <cert_name> <token> [--force]")
        sys.exit(1)
    
    cert_name = sys.argv[1]
    token = sys.argv[2]
    force = '--force' in sys.argv
    
    if not delete_certificate(cert_name, token, force):
        sys.exit(1)